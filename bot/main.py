#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import re
import subprocess
import time
import sqlite3
import os
import asyncio  # НУЖНО ДЛЯ SPEEDTEST
import json     # НУЖНО ДЛЯ .ENV
from datetime import datetime, timedelta, time as dt_time
from typing import Dict, Tuple, List, Optional

import pytz
import psutil
from dotenv import load_dotenv  # НУЖНО ДЛЯ .ENV
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes
from telegram.error import BadRequest  # НУЖНО ДЛЯ РЕДАКТИРОВАНИЯ СООБЩЕНИЙ

# ГРАФИКИ
try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("WARNING: matplotlib not found. Charts disabled.")

# --- КОНФИГУРАЦИЯ (Загружается из .env) ---

# Загружаем переменные окружения из .env файла
load_dotenv()

# Токен вашего бота от @BotFather
BOT_TOKEN = os.getenv("BOT_TOKEN")

# Ваш Telegram ID (для админских прав и личных отчетов)
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")

# ID вашего публичного канала (начинается с -100).
CHANNEL_ID = os.getenv("CHANNEL_ID", "")

# Имя интерфейса WireGuard
WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0")

# Настройки БД и часового пояса
DB_FILE = os.getenv("DB_FILE", "vpn_telemetry.db")
TZ_MOSCOW = pytz.timezone(os.getenv("TIMEZONE", "Europe/Moscow"))

# Пороги алертов
CPU_THRESHOLD = float(os.getenv("CPU_THRESHOLD", 80.0))
MEM_THRESHOLD = float(os.getenv("MEM_THRESHOLD", 80.0))
NET_THRESHOLD_MBPS = float(os.getenv("NET_THRESHOLD_MBPS", 500.0))
CHECK_INTERVAL_SECONDS = int(os.getenv("CHECK_INTERVAL_SECONDS", 60))

# --- ВАШИ ПИРЫ (Загружаются как JSON из .env) ---
try:
    PEER_NAMES = json.loads(os.getenv("PEER_NAMES", "{}"))
except json.JSONDecodeError:
    print("WARNING: Не удалось прочитать PEER_NAMES из .env. Используется пустой словарь.")
    PEER_NAMES = {}

# --- КВОТЫ ПОЛЬЗОВАТЕЛЕЙ (в ГБ) (Загружаются как JSON из .env) ---
try:
    # os.getenv вернет строку, json.loads превратит ее в dict.
    raw_quotas = json.loads(os.getenv("PEER_QUOTAS", "{}"))
    # Конвертируем значения в числа (ГБ)
    PEER_QUOTAS = {k: int(v) for k, v in raw_quotas.items()}
except (json.JSONDecodeError, ValueError):
    print("WARNING: Не удалось прочитать PEER_QUOTAS из .env. Используется пустой словарь.")
    PEER_QUOTAS = {}

# --- ПРОВЕРКА КРИТИЧЕСКИХ ПЕРЕМЕННЫХ ---
if not BOT_TOKEN:
    raise ValueError("Критическая ошибка: BOT_TOKEN не найден в .env файле.")
if not ADMIN_CHAT_ID:
    raise ValueError("Критическая ошибка: ADMIN_CHAT_ID не найден в .env файле.")
if not PEER_NAMES:
    print("WARNING: PEER_NAMES не определены. Функционал, связанный с пирами, будет ограничен.")


# --- ЛОГИРОВАНИЕ ---
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# --- ГЛОБАЛЬНОЕ СОСТОЯНИЕ ---
alert_states = {"cpu": False, "mem": False, "net": False}
quota_alert_sent = {}
net_io_history = {"last_check": time.time(), "sent": 0, "recv": 0}

# --- РАБОТА С БД ---

def init_db():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS traffic_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                peer_ip TEXT NOT NULL,
                rx_bytes INTEGER NOT NULL,
                tx_bytes INTEGER NOT NULL)''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ts_ip ON traffic_snapshots (timestamp, peer_ip)')
        cursor.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)''')
        conn.commit()
        conn.close()
    except Exception as e: logger.error(f"DB Init Error: {e}")

def get_setting(key: str) -> Optional[str]:
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key=?", (key,))
        res = cur.fetchone()
        conn.close()
        return res[0] if res else None
    except: return None

def set_setting(key: str, value: str):
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
        conn.commit()
        conn.close()
    except Exception as e: logger.error(f"Set Setting Error: {e}")

def save_traffic_snapshot(peers_data: Dict):
    if not peers_data: return
    try:
        conn = sqlite3.connect(DB_FILE)
        now_utc = datetime.now(pytz.utc)
        data = [(now_utc, ip, d["rx"], d["tx"]) for ip, d in peers_data.items()]
        conn.executemany('INSERT INTO traffic_snapshots (timestamp, peer_ip, rx_bytes, tx_bytes) VALUES (?,?,?,?)', data)
        conn.commit(); conn.close()
    except Exception as e: logger.error(f"Snapshot Error: {e}")

def calculate_traffic_delta(peer_ip: str, start_dt: datetime, end_dt: datetime) -> Tuple[int, int]:
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    start_s = start_dt.isoformat()
    end_s = end_dt.isoformat()
    cur.execute('SELECT rx_bytes, tx_bytes FROM traffic_snapshots WHERE peer_ip=? AND timestamp<=? ORDER BY timestamp DESC LIMIT 1', (peer_ip, start_dt))
    start = cur.fetchone()
    cur.execute('SELECT rx_bytes, tx_bytes FROM traffic_snapshots WHERE peer_ip=? AND timestamp<=? ORDER BY timestamp DESC LIMIT 1', (peer_ip, end_dt))
    end = cur.fetchone()
    conn.close()
    
    if not start or not end: return 0, 0
    if end[0] < start[0] or end[1] < start[1]: return end # Reboot logic
    return (end[0] - start[0]), (end[1] - start[1])

# --- СИСТЕМА И WG ---

def get_system_metrics():
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory().percent
    now = time.time()
    net = psutil.net_io_counters()
    delta_t = now - net_io_history["last_check"]
    if delta_t <= 0: delta_t = 1
    up_mbps = ((net.bytes_sent - net_io_history["sent"]) * 8) / (delta_t * 1e6)
    down_mbps = ((net.bytes_recv - net_io_history["recv"]) * 8) / (delta_t * 1e6)
    net_io_history.update({"last_check": now, "sent": net.bytes_sent, "recv": net.bytes_recv})
    return {"cpu": cpu, "mem": mem, "up": max(0, up_mbps), "down": max(0, down_mbps)}

def get_wg_peer_stats() -> Dict:
    try:
        res = subprocess.run(["sudo", "wg", "show", "all", "dump"], capture_output=True, text=True, timeout=5)
        stats = {}
        for line in res.stdout.strip().splitlines():
            parts = line.split('\t')
            if len(parts) >= 8:
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', parts[4])
                if ip_match and ip_match.group(1) in PEER_NAMES:
                    stats[ip_match.group(1)] = {
                        "rx": int(parts[6]), "tx": int(parts[7]),
                        "handshake": int(parts[5]), "pubkey": parts[1]
                    }
        return stats
    except: return {}

def format_bytes(size: float) -> str:
    power, n = 1024, 0
    labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
    while size > power and n < 4:
        size /= power; n += 1
    return f"{size:.2f} {labels[n]}"

def format_bytes_ru_caps(size: float) -> str:
    """Специальный формат для итогов месяца: ТЕРАБАЙТА, ГИГАБАЙТА"""
    power, n = 1024, 0
    # Склонения упрощены для "Всего прокачано ..."
    labels = {0: 'БАЙТ', 1: 'КИЛОБАЙТА', 2: 'МЕГАБАЙТА', 3: 'ГИГАБАЙТА', 4: 'ТЕРАБАЙТА'}
    while size > power and n < 4:
        size /= power; n += 1
    return f"{size:.1f} {labels[n]}"

def get_ru_month(date_obj, case='nominative'):
    """Возвращает название месяца на русском."""
    months_nom = ["Январь", "Февраль", "Март", "Апрель", "Май", "Июнь", 
                  "Июль", "Август", "Сентябрь", "Октябрь", "Ноябрь", "Декабрь"]
    months_gen = ["января", "февраля", "марта", "апреля", "мая", "июня", 
                  "июля", "августа", "сентября", "октября", "ноября", "декабря"]
    idx = date_obj.month - 1
    return months_gen[idx] if case == 'genitive' else months_nom[idx]

def is_admin(update: Update) -> bool:
    return str(update.effective_user.id) == str(ADMIN_CHAT_ID) if update.effective_user else False

# --- КОМАНДЫ ---

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Приветственное сообщение."""
    await update.message.reply_html(
        "<b>🤖 VPN Monitor Bot v3.0</b>\n\n"
        "Система мониторинга и учета трафика активна.\n"
        "<b>Доступные команды:</b>\n"
        "/monitoring - Текущая нагрузка сервера\n"
        "/online - Кто сейчас в сети\n"
        "/active_wg - Список пиров (полный)\n"
        "/chart <code>&lt;имя&gt;</code> - График потребления за 7 дней\n\n"
        "<b>Админ-команды:</b>\n"
        "/broadcast - Опубликовать анонс техработ\n"
        "/block <code>&lt;имя&gt;</code> - Заблокировать пира\n"
        "/unblock - Разблокировать всех (перезапуск WG)\n"
        "/force_dash - Принудительно обновить табло\n"
        "/test_quota - (Тест) Запуск отчета по квотам\n"
        "/test_speed - (Тест) Запуск проверки скорости\n"
    )

async def monitoring_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Вывод мгновенной системной статистики."""
    m = get_system_metrics()
    uptime = str(timedelta(seconds=int(time.time() - psutil.boot_time())))
    
    msg = (
        f"<b>📊 Состояние сервера</b>\n"
        f"🖥 CPU: <code>{m['cpu']}%</code>\n"
        f"🧠 RAM: <code>{m['mem']}%</code>\n"
        f"📡 Net Up: <code>{m['up']:.1f} Mbps</code>\n"
        f"📡 Net Down: <code>{m['down']:.1f} Mbps</code>\n"
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

async def broadcast_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update): return
    if not CHANNEL_ID: 
        await update.message.reply_text("❌ ID канала не настроен.")
        return
    if not context.args:
        await update.message.reply_text("Текст?")
        return
    try:
        # Заголовок "ОБЪЯВЛЕНИЕ"
        user_text = " ".join(context.args)
        message_text = f"📢 <b>ОБЪЯВЛЕНИЕ</b>\n{user_text}"
        
        await context.bot.send_message(chat_id=CHANNEL_ID, text=message_text, parse_mode=ParseMode.HTML)
        await update.message.reply_text("✅ Опубликовано.")
    except Exception as e: await update.message.reply_text(f"Ошибка: {e}")

async def chart_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not MATPLOTLIB_AVAILABLE:
        await update.message.reply_text("Ошибка: модуль matplotlib не установлен.")
        return

    target_ip = None
    chart_title = ""
    
    # 1. Если аргумент есть - ищем конкретного пира
    if context.args:
        name_req = context.args[0].lower()
        target_ip = next((ip for ip, n in PEER_NAMES.items() if n.lower() == name_req), None)
        if not target_ip:
            await update.message.reply_text("Пир не найден.")
            return
        chart_title = f"Трафик: {PEER_NAMES[target_ip]}"
    
    # 2. Если аргумента нет - будем строить общий (target_ip останется None)
    else:
        chart_title = "Общий трафик (Все пиры)"

    await update.message.reply_text("⏳ Рисую график...")

    try:
        labels = []
        values = []
        now_utc = datetime.now(pytz.utc)

        # Собираем данные за 7 дней
        for i in range(6, -1, -1):
            start = (now_utc - timedelta(days=i)).replace(hour=0, minute=0, second=0)
            end = start.replace(hour=23, minute=59, second=59)
            
            total_gb = 0
            
            if target_ip:
                # Данные для одного пира
                rx, tx = calculate_traffic_delta(target_ip, start, end)
                total_gb = (rx + tx) / (1024**3)
            else:
                # Данные для ВСЕХ пиров (суммируем)
                day_sum_bytes = 0
                for ip in PEER_NAMES:
                    rx, tx = calculate_traffic_delta(ip, start, end)
                    day_sum_bytes += (rx + tx)
                total_gb = day_sum_bytes / (1024**3)
            
            labels.append(start.strftime("%d.%m"))
            values.append(total_gb)

        # Рисуем
        plt.figure(figsize=(10, 6))
        plt.bar(labels, values, color="#4c8cf5")
        plt.title(chart_title)
        plt.ylabel("Трафик (ГБ)")
        plt.grid(axis='y', alpha=0.7)
        
        f = f"/tmp/chart_temp.png"
        plt.savefig(f)
        plt.close()
        
        with open(f, 'rb') as p: 
            await update.message.reply_photo(p)
        os.remove(f)

    except Exception as e:
        logger.error(f"Chart Error: {e}")
        await update.message.reply_text(f"Ошибка при создании графика: {e}")

# --- ЗАДАЧИ (JOBS) ---

async def live_dashboard_job(context: ContextTypes.DEFAULT_TYPE):
    """Обновляет табло в канале (на русском)."""
    if not CHANNEL_ID or CHANNEL_ID == "": return
    sys = get_system_metrics()
    wg = get_wg_peer_stats()
    now_ts = time.time()
    active_count = sum(1 for d in wg.values() if now_ts - d['handshake'] < 180)
    uptime = str(timedelta(seconds=int(time.time() - psutil.boot_time())))
    
    text = (
        f"🟢 <b>СТАТУС СИСТЕМЫ: ОНЛАЙН</b>\n\n"
        f"⏱ <b>Аптайм:</b> {uptime}\n"
        f"👥 <b>Активных пользователей:</b> {active_count} / {len(PEER_NAMES)}\n"
        f"📉 <b>Загрузка:</b> CPU {sys['cpu']}% | RAM {sys['mem']}%\n"
        f"⚡️ <b>Сеть:</b> ▲ {sys['up']:.1f} Мбит/с | ▼ {sys['down']:.1f} Мбит/с\n\n"
        f"<i>Обновлено: {datetime.now(TZ_MOSCOW).strftime('%H:%M:%S')} МСК</i>"
    )

    msg_id = get_setting("dashboard_msg_id")
    try:
        if msg_id:
            try:
                await context.bot.edit_message_text(chat_id=CHANNEL_ID, message_id=int(msg_id), text=text, parse_mode=ParseMode.HTML)
            except BadRequest: pass
        else: raise Exception
    except:
        try:
            msg = await context.bot.send_message(chat_id=CHANNEL_ID, text=text, parse_mode=ParseMode.HTML)
            await context.bot.pin_chat_message(chat_id=CHANNEL_ID, message_id=msg.message_id)
            set_setting("dashboard_msg_id", str(msg.message_id))
        except: pass

async def weekly_speedtest_job(context: ContextTypes.DEFAULT_TYPE):
    if not CHANNEL_ID or CHANNEL_ID == "": 
        return
        
    try:
        cmd = ["speedtest-cli", "--simple"]
    
        res = await asyncio.to_thread(
            subprocess.run, 
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=300 # 5 минут
        )
    
        #
        if res.returncode == 0:
            output = res.stdout.replace("Ping:", "📶 <b>Ping:</b>").replace("Download:", "⬇️ <b>Download:</b>").replace("Upload:", "⬆️ <b>Upload:</b>")
            msg = f"🚀 <b>Еженедельный тест скорости</b>\n\n{output}\n<i>Сервер работает стабильно!</i>"
            await context.bot.send_message(chat_id=CHANNEL_ID, text=msg, parse_mode=ParseMode.HTML)
        else:
            # Этот код будет выполняться, если speedtest-cli завершится с ошибкой
            logger.error(f"Speedtest-CLI FAILED (Code: {res.returncode}): {res.stderr}")
            # (Опционально) Сообщаем админу
            await context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=f"⚠️ Тест скорости провалился:\n<code>{res.stderr}</code>", parse_mode=ParseMode.HTML)

    except asyncio.TimeoutError:
         # Эта ошибка возникнет, если сработает timeout=300
        logger.error("Speedtest-CLI Error: Process timed out.")
    except Exception as e: 
        # Эта ошибка сработает, если 'speedtest-cli' не найден (FileNotFoundError)
        logger.error(f"Speedtest Error (likely not installed?): {e}")
        # (Опционально) Сообщаем админу
        await context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=f"⚠️ Тест скорости не запущен:\n<code>{e}</code>", parse_mode=ParseMode.HTML)

async def test_speed_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """(АДМИН) Ручной запуск теста скорости"""
    if not is_admin(update):
        return

    await update.message.reply_text("⏳ Запускаю тест скорости... Это может занять несколько минут.")

    # Вызываем нужную нам задачу
    await weekly_speedtest_job(context)

    await update.message.reply_text("✅ Тест завершен. Проверьте канал или логи.")

async def monthly_public_report_job(context: ContextTypes.DEFAULT_TYPE):
    """
    Публикует статистику за ПРОШЛЫЙ месяц.
    Находит самый активный день и форматирует трафик.
    """
    if not CHANNEL_ID or CHANNEL_ID == "": return
    
    # 1. Определяем границы прошлого месяца
    now = datetime.now(pytz.utc)
    # Первый день текущего месяца
    first_day_curr = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    # Последний день прошлого месяца
    last_day_prev = first_day_curr - timedelta(seconds=1)
    # Первый день прошлого месяца
    first_day_prev = last_day_prev.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    # Имя прошлого месяца для заголовка
    month_name = get_ru_month(first_day_prev, 'genitive')
    
    # 2. Считаем статистику
    total_traffic = 0
    busiest_day_date = None
    max_day_traffic = 0
    
    # Проходим по всем дням прошлого месяца
    curr_day = first_day_prev
    while curr_day <= last_day_prev:
        next_day = curr_day + timedelta(days=1)
        day_end = next_day - timedelta(seconds=1)
        
        day_traffic_sum = 0
        # Суммируем трафик всех пиров за этот день
        for ip in PEER_NAMES:
            rx, tx = calculate_traffic_delta(ip, curr_day, day_end)
            day_traffic_sum += (rx + tx)
        
        total_traffic += day_traffic_sum
        
        if day_traffic_sum > max_day_traffic:
            max_day_traffic = day_traffic_sum
            busiest_day_date = curr_day
            
        curr_day = next_day

    # 3. Форматируем самый активный день
    if busiest_day_date:
        busiest_day_str = f"{busiest_day_date.day} {get_ru_month(busiest_day_date, 'genitive')}"
    else:
        busiest_day_str = "Нет данных"

    # 4. Отправляем сообщение
    msg = (
        f"📊 <b>Итоги {month_name.title()}</b>\n"
        f"🌐 Всего прокачано трафика: <b>{format_bytes_ru_caps(total_traffic)}</b> 🤯\n"
        f"👥 Самый активный день: <b>{busiest_day_str}</b>\n\n"
        "Спасибо, что остаетесь с нами!"
    )
    await context.bot.send_message(chat_id=CHANNEL_ID, text=msg, parse_mode=ParseMode.HTML)

async def payment_reminder_job(context: ContextTypes.DEFAULT_TYPE):
    now_msk = datetime.now(TZ_MOSCOW)
    
    # Сброс квот 1-го числа
    if now_msk.day == 1:
        global quota_alert_sent; quota_alert_sent = {}
    
    if now_msk.day == 5:
        # 1. АДМИНУ
        admin_msg = (
            "💰 <b>Финансовое уведомление</b>\n\n"
            "Сегодня 5-е число. Напоминание:\n"
            "1. Оплатить VPS-хостинг.\n"
            "2. Проверить поступление взносов от пользователей."
        )
        try: await context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=admin_msg, parse_mode=ParseMode.HTML)
        except: pass

        # 2. В КАНАЛ
        if CHANNEL_ID and CHANNEL_ID != "":
            public_msg = (
                "🔔 <b>Ежемесячное напоминание</b>\n\n"
                "На календаре 5-е число — время продлить доступ к сервису, "
                "имя которого сейчас лучше не называть 🤫\n\n"
                "💳 <b>Реквизиты:</b> прежние.\n\n"
                "<i>Спасибо, что остаетесь с нами!</i>"
            )
            try: await context.bot.send_message(chat_id=CHANNEL_ID, text=public_msg, parse_mode=ParseMode.HTML)
            except: pass

async def daily_report_job(context: ContextTypes.DEFAULT_TYPE):
    """Ежедневный отчет АДМИНУ."""
    now_msk = datetime.now(TZ_MOSCOW)
    start_day_utc = now_msk.replace(hour=0, minute=0, second=0).astimezone(pytz.utc)
    start_month_utc = now_msk.replace(day=1, hour=0, minute=0, second=0).astimezone(pytz.utc)
    now_utc = datetime.now(pytz.utc)
    
    current_stats = get_wg_peer_stats()
    if current_stats: save_traffic_snapshot(current_stats)
    
    user_metrics = []
    total_month = 0
    global quota_alert_sent
    
    for ip, name in PEER_NAMES.items():
        rx_d, tx_d = calculate_traffic_delta(ip, start_day_utc, now_utc)
        day_sum = rx_d + tx_d
        rx_m, tx_m = calculate_traffic_delta(ip, start_month_utc, now_utc)
        month_sum = rx_m + tx_m
        total_month += month_sum
        
        quota = PEER_QUOTAS.get(ip)
        if quota:
            m_gb = month_sum / (1024**3)
            if m_gb > quota and not quota_alert_sent.get(ip):
                await context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=f"❗️<b>Лимит!</b>\n{name}: {m_gb:.1f}/{quota}GB", parse_mode=ParseMode.HTML)
                quota_alert_sent[ip] = True
        
        if day_sum > 0 or month_sum > 0:
            user_metrics.append({"name": name, "day": day_sum, "month": month_sum})
            
    user_metrics.sort(key=lambda x: x["day"], reverse=True)
    
    # ФОРМАТИРОВАНИЕ ЕЖЕДНЕВНОГО ОТЧЕТА
    report = f"📊 <b>Ежедневный отчет {now_msk.strftime('%d.%m.%Y')}</b>\n\n"
    report += f"Общий трафик за месяц: <b>{format_bytes(total_month)}</b>\n\n"
    report += "Топ пользователей за день:\n"
    
    if not user_metrics:
        report += "Нет активности."
    
    for i, u in enumerate(user_metrics, 1):
        if i == 1: icon = "🥇"
        elif i == 2: icon = "🥈"
        elif i == 3: icon = "🥉"
        else: icon = "👤"
        
        report += f"{icon} {u['name']}: {format_bytes(u['day'])} (Мес: {format_bytes(u['month'])})\n"
        
    await context.bot.send_message(chat_id=ADMIN_CHAT_ID, text=report, parse_mode=ParseMode.HTML)

async def traffic_snapshot_job(context: ContextTypes.DEFAULT_TYPE):
    stats = get_wg_peer_stats()
    if stats: save_traffic_snapshot(stats)

async def system_alert_job(context: ContextTypes.DEFAULT_TYPE):
    global alert_states; m = get_system_metrics(); alerts = []
    if m["cpu"] > CPU_THRESHOLD and not alert_states["cpu"]: alerts.append(f"🚨 CPU: {m['cpu']}%"); alert_states["cpu"] = True
    elif m["cpu"] < CPU_THRESHOLD: alert_states["cpu"] = False
    if m["mem"] > MEM_THRESHOLD and not alert_states["mem"]: alerts.append(f"🚨 RAM: {m['mem']}%"); alert_states["mem"] = True
    elif m["mem"] < MEM_THRESHOLD: alert_states["mem"] = False
    if alerts: await context.bot.send_message(chat_id=ADMIN_CHAT_ID, text="\n".join(alerts))

async def cleanup_old_data_job(context: ContextTypes.DEFAULT_TYPE):
    cutoff = datetime.now(pytz.utc) - timedelta(days=90)
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute("DELETE FROM traffic_snapshots WHERE timestamp < ?", (cutoff.isoformat(),))
        conn.commit(); conn.execute("VACUUM"); conn.close()
    except: pass

# --- УПРАВЛЕНИЕ ТАБЛО И ПИРАМИ ---
async def force_dash_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update): return
    await live_dashboard_job(context)
    await update.message.reply_text("✅ Табло обновлено.")

async def online_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    stats = get_wg_peer_stats()
    now = time.time()
    online = [PEER_NAMES.get(ip, ip) for ip, d in stats.items() if now - d['handshake'] < 180]
    if not online: await update.message.reply_html("Нет активных пиров.")
    else: await update.message.reply_html(f"<b>🟢 В сети ({len(online)}):</b>\n" + "\n".join([f"• {n}" for n in sorted(online)]))

async def block_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update) or not context.args: return
    peer_req = context.args[0].lower()
    ip_target = next((ip for ip, n in PEER_NAMES.items() if n.lower() == peer_req), None)
    if not ip_target: return
    
    stats = get_wg_peer_stats()
    if ip_target in stats:
        subprocess.run(["sudo", "wg", "set", WG_INTERFACE, "peer", stats[ip_target]["pubkey"], "remove"])
        await update.message.reply_text(f"🔴 {PEER_NAMES[ip_target]} заблокирован.")

async def unblock_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update): return
    subprocess.run(["sudo", "systemctl", "restart", f"wg-quick@{WG_INTERFACE}.service"])
    await update.message.reply_text("✅ Все разблокированы.")

async def test_quota_job(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if is_admin(update): await daily_report_job(context)

# --- MAIN ---

def main():
    init_db()
    app = Application.builder().token(BOT_TOKEN).build()
    jq = app.job_queue

    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("broadcast", broadcast_command))
    app.add_handler(CommandHandler("force_dash", force_dash_command))
    app.add_handler(CommandHandler("online", online_command))
    if MATPLOTLIB_AVAILABLE: app.add_handler(CommandHandler("chart", chart_command))
    app.add_handler(CommandHandler("block", block_command))
    app.add_handler(CommandHandler("unblock", unblock_command))
    app.add_handler(CommandHandler("test_quota", test_quota_job))
    app.add_handler(CommandHandler("test_speed", test_speed_command))
    app.add_handler(CommandHandler("monitoring", monitoring_command))
    app.add_handler(CommandHandler("active_wg", active_wg_command))

    # Jobs
    jq.run_repeating(system_alert_job, interval=CHECK_INTERVAL_SECONDS, first=10)
    jq.run_repeating(traffic_snapshot_job, interval=600, first=30)
    jq.run_daily(daily_report_job, time=dt_time(hour=21, minute=0, tzinfo=TZ_MOSCOW))
    
    # Channel Jobs
    jq.run_repeating(live_dashboard_job, interval=300, first=10)
    jq.run_daily(weekly_speedtest_job, time=dt_time(hour=15, minute=0, tzinfo=TZ_MOSCOW), days=(6,))
    jq.run_monthly(monthly_public_report_job, when=dt_time(hour=12, minute=0, tzinfo=TZ_MOSCOW), day=1)
    jq.run_daily(payment_reminder_job, time=dt_time(hour=12, minute=0, tzinfo=TZ_MOSCOW))
    jq.run_daily(cleanup_old_data_job, time=dt_time(hour=4, minute=0, tzinfo=TZ_MOSCOW))

    logger.info("Bot v3.0 Started")
    app.run_polling()

if __name__ == "__main__":
    main()
