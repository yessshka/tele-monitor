#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import re
import subprocess
import time
import sqlite3
import os
from datetime import datetime, timedelta, time as dt_time
from typing import Dict, Tuple, List, Optional

# ИМПОРТЫ для .env и часовых поясов
from dotenv import load_dotenv
import pytz

import psutil
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes

# ИМПОРТЫ для ГРАФИКОВ
try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("WARNING: matplotlib not found. /chart command will be disabled.")
    print("Run: pip install matplotlib")

# --- КОНФИГУРАЦИЯ ---

# 1. Загружаем "секреты" из .env файла
load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")
WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0") # По умолчанию 'wg0'

if not BOT_TOKEN or not ADMIN_CHAT_ID:
    print("="*50)
    print("КРИТИЧЕСКАЯ ОШИБКА: BOT_TOKEN или ADMIN_CHAT_ID не найдены.")
    print("Пожалуйста, создайте файл .env и добавьте их.")
    print("="*50)
    exit(1)

# 2. Настройки прочие
DB_FILE = "vpn_telemetry.db"
TZ_MOSCOW = pytz.timezone("Europe/Moscow")
CPU_THRESHOLD = 80.0
MEM_THRESHOLD = 80.0
NET_THRESHOLD_MBPS = 500.0
CHECK_INTERVAL_SECONDS = 60

# 3. Словарь пиров
# Отредактируйте этот список, добавив своих реальных пиров
PEER_NAMES = {
    "10.66.66.2": "Client_PC",
    "10.66.66.3": "Client_Phone_1",
    "10.66.66.4": "Client_Phone_2",
    "10.66.66.5": "User_PC_1",
    "10.66.66.6": "User_Phone_1",
    # ... и так далее
}

# 4. Квоты трафика (в ГБ)
# Отредактируйте квоты в соответствии с PEER_NAMES
PEER_QUOTAS = {
    "10.66.66.2": 250, 
    "10.66.66.3": 100,
    "10.66.66.4": 75,
    "10.66.66.5": 100,
    "10.66.66.6": 75,
    # ... и так далее
}

# --- НАСТРОЙКА ЛОГИРОВАНИЯ ---
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# --- ГЛОБАЛЬНОЕ СОСТОЯНИЕ (IN-MEMORY) ---
alert_states = {
    "cpu": False,
    "mem": False,
    "net": False,
}

# Отслеживание отправленных алертов о квотах
quota_alert_sent = {}

net_io_history = {
    "last_check_time": time.time(),
    "last_bytes_sent": 0,
    "last_bytes_recv": 0,
}

# --- СЛОЙ РАБОТЫ С БАЗОЙ ДАННЫХ ---

def init_db():
    """
    Инициализирует структуру базы данных SQLite.
    Создает таблицу для хранения исторических снэпшотов трафика.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                peer_ip TEXT NOT NULL,
                rx_bytes INTEGER NOT NULL,
                tx_bytes INTEGER NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp_ip 
            ON traffic_snapshots (timestamp, peer_ip)
        ''')
        
        conn.commit()
        conn.close()
        logger.info(f"База данных {DB_FILE} успешно инициализирована.")
    except Exception as e:
        logger.error(f"Критическая ошибка инициализации БД: {e}")

def save_traffic_snapshot(peers_data: Dict):
    """
    Сохраняет текущий срез данных по всем пирам в базу.
    peers_data: Dict[IP, Dict[rx, tx, ...]]
    """
    if not peers_data:
        return

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        now_utc = datetime.now(pytz.utc)
        
        data_rows = []
        for ip, data in peers_data.items():
            data_rows.append((now_utc, ip, data["rx"], data["tx"]))
        
        cursor.executemany(
            'INSERT INTO traffic_snapshots (timestamp, peer_ip, rx_bytes, tx_bytes) VALUES (?,?,?,?)',
            data_rows
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Ошибка записи снэпшота в БД: {e}")

def calculate_traffic_delta(peer_ip: str, start_dt: datetime, end_dt: datetime) -> Tuple[int, int]:
    """
    Вычисляет потребленный трафик за период [start_dt, end_dt].
    Реализует логику обработки сброса счетчиков (перезагрузки).
    Возвращает кортеж (rx_delta, tx_delta).
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # 1. Находим запись, ближайшую к началу периода (но не позже start_dt)
    cursor.execute('''
        SELECT rx_bytes, tx_bytes FROM traffic_snapshots
        WHERE peer_ip =? AND timestamp <=?
        ORDER BY timestamp DESC LIMIT 1
    ''', (peer_ip, start_dt))
    start_row = cursor.fetchone()
    
    # 2. Находим запись, ближайшую к концу периода (обычно "сейчас")
    cursor.execute('''
        SELECT rx_bytes, tx_bytes FROM traffic_snapshots
        WHERE peer_ip =? AND timestamp <=?
        ORDER BY timestamp DESC LIMIT 1
    ''', (peer_ip, end_dt))
    end_row = cursor.fetchone()
    
    conn.close()
    
    if not start_row or not end_row:
        # Недостаточно данных для периода
        return 0, 0
        
    start_rx, start_tx = start_row
    end_rx, end_tx = end_row
    
    if end_rx < start_rx or end_tx < start_tx:
        # Был сброс счетчика, считаем трафик с нуля
        return end_rx, end_tx
    
    return (end_rx - start_rx), (end_tx - start_tx)

# --- СИСТЕМНЫЕ МЕТРИКИ И WIREGUARD ---

def get_system_metrics():
    """Собирает метрики CPU, RAM и сети."""
    cpu_usage = psutil.cpu_percent(interval=1)
    mem_info = psutil.virtual_memory()
    mem_usage = mem_info.percent

    global net_io_history
    current_time = time.time()
    
    if net_io_history["last_bytes_sent"] == 0:
        net_counters = psutil.net_io_counters()
        net_io_history["last_bytes_sent"] = net_counters.bytes_sent
        net_io_history["last_bytes_recv"] = net_counters.bytes_recv
        net_io_history["last_check_time"] = current_time
        net_upload_mbps, net_download_mbps = 0.0, 0.0
    else:
        time_delta = current_time - net_io_history["last_check_time"]
        current_net_counters = psutil.net_io_counters()
        
        bytes_sent_delta = current_net_counters.bytes_sent - net_io_history["last_bytes_sent"]
        bytes_recv_delta = current_net_counters.bytes_recv - net_io_history["last_bytes_recv"]

        if time_delta > 0 and bytes_sent_delta >= 0:
            net_upload_mbps = (bytes_sent_delta * 8) / (time_delta * 1_000_000)
            net_download_mbps = (bytes_recv_delta * 8) / (time_delta * 1_000_000)
        else:
            net_upload_mbps, net_download_mbps = 0.0, 0.0

        net_io_history["last_check_time"] = current_time
        net_io_history["last_bytes_sent"] = current_net_counters.bytes_sent
        net_io_history["last_bytes_recv"] = current_net_counters.bytes_recv

    return {
        "cpu": cpu_usage,
        "mem": mem_usage,
        "upload_mbps": net_upload_mbps,
        "download_mbps": net_download_mbps,
        "total_mbps": net_upload_mbps + net_download_mbps,
    }

def get_wg_peer_stats() -> Dict:
    """
    ОБНОВЛЕНО: Парсит 'wg show all dump'
    Возвращает словарь: { 'ip': {'rx':.., 'tx':.., 'handshake':.., 'pubkey':..} }
    """
    try:
        result = subprocess.run(
            ["sudo", "wg", "show", "all", "dump"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10
        )
        
        stats = {}
        # Индексы:       0      1         2      3          4            5           6   7      8
        #           iface  pubkey    psk   endpoint   allowed_ips  handshake   rx  tx  keepalive
        for line in result.stdout.strip().splitlines():
            parts = line.split('\t')
            # Убедимся, что строка содержит все нужные части
            if len(parts) >= 8:
                pubkey = parts[1]
                allowed_ips = parts[4]
                handshake = int(parts[5])
                rx_bytes = int(parts[6])
                tx_bytes = int(parts[7])
                
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', allowed_ips)
                if ip_match:
                    ip_addr = ip_match.group(1)
                    if ip_addr in PEER_NAMES:
                        stats[ip_addr] = {
                            "rx": rx_bytes,
                            "tx": tx_bytes,
                            "handshake": handshake,
                            "pubkey": pubkey
                        }
        return stats

    except subprocess.CalledProcessError as e:
        logger.error(f"Ошибка выполнения wg show: {e.stderr}")
        return {}
    except Exception as e:
        logger.error(f"Непредвиденная ошибка парсинга WG: {e}")
        return {}

def format_bytes(size: float) -> str:
    """Преобразует байты в человекочитаемый формат (MB, GB)."""
    power = 1024
    n = 0
    power_labels = {0 : 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    while size > power and n < 4:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}"

# --- НОВАЯ УТИЛИТА: ПРОВЕРКА АДМИНА ---
def is_admin(update: Update) -> bool:
    """Проверяет, является ли пользователь админом (из ADMIN_CHAT_ID)."""
    if not update.effective_user:
        return False
    # Сравниваем ID как строки для надежности
    return str(update.effective_user.id) == str(ADMIN_CHAT_ID)


# --- ОБРАБОТЧИКИ TELEGRAM ---

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Приветственное сообщение."""
    await update.message.reply_html(
        "<b>🤖 VPN Monitor Bot v2.1</b>\n\n"
        "Система мониторинга и учета трафика активна.\n"
        "<b>Доступные команды:</b>\n"
        "/monitoring - Текущая нагрузка сервера\n"
        "/active_wg - Список пиров (полный)\n"
        "/online - Кто сейчас в сети\n"
        "/chart <code>&lt;имя&gt;</code> - График трат за 7 дней\n\n"
        "<b>Админ-команды:</b>\n"
        "/test_quota - (Тест) Запуск отчета по квотам\n"
        "/block <code>&lt;имя&gt;</code> - Заблокировать пира\n"
        "/unblock - Разблокировать всех (перезапуск WG)\n"
    )

async def monitoring_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Вывод мгновенной системной статистики."""
    m = get_system_metrics()
    uptime = str(timedelta(seconds=int(time.time() - psutil.boot_time())))
    
    msg = (
        f"<b>📊 Состояние сервера</b>\n"
        f"🖥 CPU: <code>{m['cpu']}%</code>\n"
        f"🧠 RAM: <code>{m['mem']}%</code>\n"
        f"📡 Net Up: <code>{m['upload_mbps']:.1f} Mbps</code>\n"
        f"📡 Net Down: <code>{m['download_mbps']:.1f} Mbps</code>\n"
        f"⏱ Uptime: {uptime}"
    )
    await update.message.reply_html(msg)

async def active_wg_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Вывод текущего состояния пиров (из памяти ядра)."""
    try:
        res = subprocess.run(["sudo", "wg", "show"], capture_output=True, text=True)
        raw_output = res.stdout
        
        processed_lines = []
        if raw_output:
            for line in raw_output.splitlines():
                ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                suffix = ""
                for ip in ips:
                    if ip in PEER_NAMES:
                        suffix = f" <b>({PEER_NAMES[ip]})</b>"
                        break
                safe_line = line.replace('<', '&lt;').replace('>', '&gt;')
                processed_lines.append(safe_line + suffix)
            text = "\n".join(processed_lines)
        else:
            text = "Интерфейс не активен или нет пиров."
            
        await update.message.reply_html(f"<b>🛡 Активные пиры:</b>\n<pre>{text}</pre>")
    except Exception as e:
        await update.message.reply_text(f"Ошибка: {e}")

#
# --- ТЕСТОВАЯ КОМАНДА ---
#
async def test_quota_job(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    ВРЕМЕННАЯ КОМАНДА: Ручной запуск ежедневного отчета
    для проверки логики квот.
    """
    if not is_admin(update):
        await update.message.reply_text("⛔️ Эта команда только для админа.")
        return

    if not update.effective_user:
        return
        
    logger.info(f"Ручной запуск daily_report_job по команде от {update.effective_user.id}")
    await update.message.reply_text("⏳ Запускаю ежедневный отчет для проверки квот... "
                                    "Результат (и алерты) будут отправлены в главный чат.")
    try:
        await daily_report_job(context)
        await update.message.reply_text("✅ Проверка завершена.")
    except Exception as e:
        logger.error(f"Ошибка при ручном запуске daily_report_job: {e}")
        await update.message.reply_text(f"Ошибка при проверке: {e}")

#
# --- ТАБЛО (/online) ---
#
async def online_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Показывает, кто из пиров сейчас онлайн (handshake < 3 мин)."""
    stats = get_wg_peer_stats()
    if not stats:
        await update.message.reply_html("Не удалось получить статистику WG.")
        return

    now = time.time()
    online_peers = []
    # 3 минуты = 180 секунд
    HANDSHAKE_THRESHOLD = 180 

    for ip, data in stats.items():
        time_since_handshake = now - data["handshake"]
        if time_since_handshake < HANDSHAKE_THRESHOLD:
            name = PEER_NAMES.get(ip, ip)
            online_peers.append(name)
    
    if not online_peers:
        await update.message.reply_html("<b>🟢 В сети (0):</b>\nНет активных пиров.")
        return

    message = f"<b>🟢 В сети ({len(online_peers)}):</b>\n"
    message += "\n".join([f"• {name}" for name in sorted(online_peers)])
    await update.message.reply_html(message)

#
# --- АНАЛИТИК (/chart) ---
#
async def chart_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Рисует график потребления трафика за 7 дней для пира."""
    if not MATPLOTLIB_AVAILABLE:
        await update.message.reply_text("Ошибка: Модуль matplotlib не установлен на сервере.")
        return
    
    if not context.args:
        await update.message.reply_text("Использование: /chart <имя_пира>")
        return
        
    peer_name_req = context.args[0].lower()
    peer_ip = None
    peer_name = ""

    # Ищем IP по имени
    for ip, name in PEER_NAMES.items():
        if name.lower() == peer_name_req:
            peer_ip = ip
            peer_name = name
            break
            
    if not peer_ip:
        await update.message.reply_text(f"Пир с именем '{peer_name_req}' не найден.")
        return

    await update.message.reply_text(f"⏳ Собираю данные для графика '{peer_name}'...")

    try:
        labels = []
        values_gb = []
        now_utc = datetime.now(pytz.utc)

        # Собираем данные за 7 дней (включая сегодня)
        for i in range(6, -1, -1):
            target_day_start = (now_utc - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
            target_day_end = target_day_start.replace(hour=23, minute=59, second=59)
            
            rx, tx = calculate_traffic_delta(peer_ip, target_day_start, target_day_end)
            total_gb = (rx + tx) / (1024**3) # Конвертируем в ГБ
            
            labels.append(target_day_start.strftime("%d.%m"))
            values_gb.append(total_gb)

        # Рисуем график
        plt.figure(figsize=(10, 6))
        plt.bar(labels, values_gb, color="#4c8cf5")
        plt.title(f"Трафик для '{peer_name}' (Последние 7 дней)")
        plt.ylabel("Трафик (ГБ)")
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        # Сохраняем в файл
        chart_file = f"/tmp/wg_chart_{peer_ip}.png"
        plt.savefig(chart_file)
        plt.close() # Важно закрыть, чтобы не утекала память

        # Отправляем фото
        with open(chart_file, 'rb') as photo:
            await update.message.reply_photo(photo)
            
        os.remove(chart_file) # Удаляем временный файл

    except Exception as e:
        logger.error(f"Ошибка создания графика: {e}")
        await update.message.reply_text(f"Не удалось создать график: {e}")


#
# --- ПРИВРАТНИК (/block, /unblock) ---
#
async def block_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """(Админ) Блокирует пира, удаляя его из live-конфига WG."""
    if not is_admin(update):
        await update.message.reply_text("⛔️ Эта команда только для админа.")
        return

    if not context.args:
        await update.message.reply_text("Использование: /block <имя_пира>")
        return
        
    peer_name_req = context.args[0].lower()
    peer_ip = None
    peer_name = ""

    for ip, name in PEER_NAMES.items():
        if name.lower() == peer_name_req:
            peer_ip = ip
            peer_name = name
            break
            
    if not peer_ip:
        await update.message.reply_text(f"Пир с именем '{peer_name_req}' не найден.")
        return

    try:
        stats = get_wg_peer_stats()
        if peer_ip not in stats:
            await update.message.reply_text(f"Не удалось найти PublicKey для '{peer_name}'.")
            return
            
        pubkey = stats[peer_ip]["pubkey"]
        
        # Блокируем пира (удаляем из сессии)
        subprocess.run(
            ["sudo", "wg", "set", WG_INTERFACE, "peer", pubkey, "remove"],
            check=True, capture_output=True
        )
        
        logger.info(f"ADMIN: Пир '{peer_name}' заблокирован по команде.")
        await update.message.reply_html(f"🔴 Пир <b>{peer_name}</b> был отключен (заблокирован).")

    except subprocess.CalledProcessError as e:
        logger.error(f"Ошибка блокировки пира: {e.stderr.decode()}")
        await update.message.reply_text(f"Ошибка выполнения wg: {e.stderr.decode()}")
    except Exception as e:
        logger.error(f"Ошибка в /block: {e}")
        await update.message.reply_text(f"Ошибка: {e}")

async def unblock_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """(Админ) Перезапускает сервис WG, восстанавливая всех пиров из конфига."""
    if not is_admin(update):
        await update.message.reply_text("⛔️ Эта команда только для админа.")
        return

    try:
        await update.message.reply_text(f"⏳ Перезапускаю интерфейс `wg-quick@{WG_INTERFACE}`..."
                                        "\n(Это восстановит всех пиров из конфига)")
        
        # "Кувалда" - перезапускаем сервис, чтобы он перечитал конфиг
        subprocess.run(
            ["sudo", "systemctl", "restart", f"wg-quick@{WG_INTERFACE}.service"],
            check=True, capture_output=True
        )
        
        logger.info(f"ADMIN: Интерфейс WG перезапущен по команде /unblock.")
        await update.message.reply_html("✅ <b>Готово!</b>\nВсе пиры восстановлены из файла конфигурации.")

    except subprocess.CalledProcessError as e:
        logger.error(f"Ошибка перезапуска WG: {e.stderr.decode()}")
        await update.message.reply_text(f"Ошибка выполнения systemctl: {e.stderr.decode()}")
    except Exception as e:
        logger.error(f"Ошибка в /unblock: {e}")
        await update.message.reply_text(f"Ошибка: {e}")


# --- ФОНОВЫЕ ЗАДАЧИ (JOBS) ---

async def traffic_snapshot_job(context: ContextTypes.DEFAULT_TYPE):
    """
    Задача, выполняемая каждые 10 минут.
    Снимает показания счетчиков и сохраняет в БД.
    """
    stats = get_wg_peer_stats()
    if stats:
        save_traffic_snapshot(stats)
        # logger.info("Снэпшот трафика сохранен.")

async def daily_report_job(context: ContextTypes.DEFAULT_TYPE):
    """
    Генерация и отправка ежедневного отчета в 21:00 МСК.
    Включает: топ пользователей за день, общий трафик за месяц.
    """
    logger.info("Формирование ежедневного отчета...")
    
    now_msk = datetime.now(TZ_MOSCOW)
    start_of_day_msk = now_msk.replace(hour=0, minute=0, second=0, microsecond=0)
    start_of_day_utc = start_of_day_msk.astimezone(pytz.utc)
    start_of_month_msk = now_msk.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    start_of_month_utc = start_of_month_msk.astimezone(pytz.utc)
    now_utc = datetime.now(pytz.utc)
    
    current_stats = get_wg_peer_stats()
    # Убедимся, что current_stats не пустой, прежде чем сохранять
    if current_stats:
        save_traffic_snapshot(current_stats)
    
    user_metrics = []
    total_month_traffic = 0
    
    for ip, name in PEER_NAMES.items():
        rx_day, tx_day = calculate_traffic_delta(ip, start_of_day_utc, now_utc)
        day_sum = rx_day + tx_day
        
        rx_month, tx_month = calculate_traffic_delta(ip, start_of_month_utc, now_utc)
        month_sum = rx_month + tx_month
        
        total_month_traffic += month_sum
        
        #
        # --- ЛОГИКА ПРОВЕРКИ КВОТ ---
        #
        global quota_alert_sent
        quota_gb = PEER_QUOTAS.get(ip)
        
        if quota_gb: # Если квота для этого IP установлена
            month_gb = month_sum / (1024**3) # Переводим трафик в ГБ
            
            # Проверяем, превышена ли квота и не отправляли ли мы уже алерт
            if month_gb > quota_gb and not quota_alert_sent.get(ip):
                alert_text = (
                    f"❗️<b>Превышение месячной квоты!</b>\n\n"
                    f"Пир <b>{name}</b> ({ip}) использовал <b>{month_gb:.2f} ГБ</b>.\n"
                    f"Установленный лимит: <b>{quota_gb} ГБ</b>."
                )
                # Отправляем алерт (независимо от отчета)
                await context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=alert_text, parse_mode=ParseMode.HTML)
                quota_alert_sent[ip] = True # Помечаем, что алерт отправлен
        #
        # --- КОНЕЦ ЛОГИКИ КВОТ ---
        #
        
        if day_sum > 0 or month_sum > 0:
            user_metrics.append({
                "name": name,
                "day": day_sum,
                "month": month_sum
            })
    
    user_metrics.sort(key=lambda x: x["day"], reverse=True)
    
    lines = []
    lines.append(f"<b>📊 Ежедневный отчет {now_msk.strftime('%d.%m.%Y')}</b>\n")
    lines.append(f"<i>Общий трафик за месяц: {format_bytes(total_month_traffic)}</i>\n")
    lines.append("<b>Топ пользователей за день:</b>")
    
    if not user_metrics:
        lines.append("Нет активности.")
    
    for idx, u in enumerate(user_metrics, 1):
        icon = "🥇" if idx == 1 else "🥈" if idx == 2 else "🥉" if idx == 3 else "👤"
        lines.append(
            f"{icon} <b>{u['name']}</b>: {format_bytes(u['day'])} "
            f"(Мес: {format_bytes(u['month'])})"
        )
    
    report_text = "\n".join(lines)
    await context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=report_text, parse_mode=ParseMode.HTML)

async def payment_reminder_job(context: ContextTypes.DEFAULT_TYPE):
    """
    Напоминание об оплате (проверка в 12:00, сработка 5-го числа).
    Также сбрасывает флаги алертов о квотах 1-го числа.
    """
    now_msk = datetime.now(TZ_MOSCOW)
    
    #
    # --- ЛОГИКА СБРОСА КВОТ ---
    #
    # 1-го числа каждого месяца сбрасываем флаги алертов
    if now_msk.day == 1:
        global quota_alert_sent
        if quota_alert_sent: # Если словарь не пуст
            logger.info("Новый месяц! Сброс флагов оповещений о квотах.")
            quota_alert_sent = {}
    #
    # --- КОНЕЦ ЛОГИКИ СБРОСА ---
    #

    if now_msk.day == 5:
        msg = (
            "💰 <b>Финансовое уведомление</b>\n\n"
            "Сегодня 5-е число. Напоминание:\n"
            "1. Оплатить VPS-хостинг.\n"
            "2. Проверить поступление взносов от пользователей."
        )
        await context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=msg, parse_mode=ParseMode.HTML)

async def system_alert_job(context: ContextTypes.DEFAULT_TYPE):
    """
    Периодическая проверка ресурсов (каждую минуту).
    Отправляет алерты при превышении порогов.
    """
    global alert_states
    m = get_system_metrics()
    
    alerts = []
    
    if m["cpu"] > CPU_THRESHOLD and not alert_states["cpu"]:
        alerts.append(f"🚨 High CPU Usage: {m['cpu']}%")
        alert_states["cpu"] = True
    elif m["cpu"] < CPU_THRESHOLD and alert_states["cpu"]:
        alert_states["cpu"] = False
        
    if m["mem"] > MEM_THRESHOLD and not alert_states["mem"]:
        alerts.append(f"🚨 Low Memory: {m['mem']}% used")
        alert_states["mem"] = True
    elif m["mem"] < MEM_THRESHOLD and alert_states["mem"]:
        alert_states["mem"] = False

    if alerts:
        text = "\n".join(alerts)
        await context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=text)

#
# --- ЗАДАЧА ОЧИСТКИ ---
#
async def cleanup_old_data_job(context: ContextTypes.DEFAULT_TYPE):
    """
    Удаляет старые снэпшоты (старше 90 дней) и сжимает БД.
    Запускается ежедневно в 04:00 МСК.
    """
    # Устанавливаем порог: 90 дней назад
    cutoff_date = datetime.now(pytz.utc) - timedelta(days=90)
    conn = None
    
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        logger.info(f"Запуск очистки БД: удаление записей старше {cutoff_date.date()}...")
        
        # 1. Удаляем старые данные
        cursor.execute(
            "DELETE FROM traffic_snapshots WHERE timestamp < ?", 
            (cutoff_date,)
        )
        conn.commit()
        
        # Узнаем, сколько строк было удалено
        deleted_count = cursor.rowcount
        
        if deleted_count > 0:
            logger.info(f"Удалено {deleted_count} старых записей.")
            
            # 2. Сжимаем файл БД, чтобы вернуть место системе
            # VACUUM перестраивает БД и освобождает место
            logger.info("Выполняю VACUUM для сжатия файла БД...")
            conn.execute("VACUUM")
            logger.info("Сжатие БД завершено.")
        else:
            logger.info("Старых записей для удаления не найдено.")
            
    except Exception as e:
        logger.error(f"Ошибка во время очистки БД: {e}")
    finally:
        if conn:
            conn.close()

# --- ТОЧКА ВХОДА ---

def main():
    # 0. Проверка matplotlib
    if not MATPLOTLIB_AVAILABLE:
        logger.warning("Matplotlib не найден. Команда /chart будет недоступна.")
        
    # 1. Инициализация БД
    init_db()
    
    # 2. Построение приложения
    application = Application.builder().token(BOT_TOKEN).build()
    
    if not application.job_queue:
        logger.critical("Не удалось инициализировать JobQueue. Проверьте зависимости.")
        return

    job_queue = application.job_queue

    # 3. Регистрация команд
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("monitoring", monitoring_command))
    application.add_handler(CommandHandler("active_wg", active_wg_command))
    application.add_handler(CommandHandler("test_quota", test_quota_job))
    application.add_handler(CommandHandler("online", online_command))
    if MATPLOTLIB_AVAILABLE:
        application.add_handler(CommandHandler("chart", chart_command))
    application.add_handler(CommandHandler("block", block_command))
    application.add_handler(CommandHandler("unblock", unblock_command))

    # 4. Планирование задач
    
    # А. Мониторинг ресурсов: раз в 60 сек
    job_queue.run_repeating(system_alert_job, interval=CHECK_INTERVAL_SECONDS, first=10)
    
    # Б. Снэпшот трафика: раз в 10 минут (600 сек)
    job_queue.run_repeating(traffic_snapshot_job, interval=600, first=30)
    
    # В. Ежедневный отчет в 21:00 МСК
    report_time = dt_time(hour=21, minute=0, tzinfo=TZ_MOSCOW)
    job_queue.run_daily(daily_report_job, time=report_time)
    
    # Г. Напоминание об оплате
    reminder_check_time = dt_time(hour=12, minute=0, tzinfo=TZ_MOSCOW)
    job_queue.run_daily(payment_reminder_job, time=reminder_check_time)
    
    #
    # Д. Ежедневная очистка БД в 04:00 МСК
    #
    cleanup_time = dt_time(hour=4, minute=0, tzinfo=TZ_MOSCOW)
    job_queue.run_daily(cleanup_old_data_job, time=cleanup_time)


    # 5. Запуск
    logger.info("Бот запущен и готов к работе.")
    application.run_polling()

if __name__ == "__main__":
    main()
