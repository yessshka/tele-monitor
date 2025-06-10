#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import re
import subprocess
import time
from datetime import timedelta

import psutil
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes

# --- НАСТРОЙКИ ---
load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")

# Словарь для сопоставления IP-адресов с именами клиентов
PEER_NAMES = {
    "10.66.66.2": "Client1",
    "10.66.66.3": "Client2",
    "10.66.66.4": "Client3",
# etc.
}

# Пороги для оповещений
CPU_THRESHOLD = 80.0  # в процентах
MEM_THRESHOLD = 80.0  # в процентах
NET_THRESHOLD_MBPS = 500.0 # в мегабитах/сек (суммарно upload + download)

# Интервал проверки для отправки алертов (в секундах)
CHECK_INTERVAL_SECONDS = 60

# --- КОНФИГУРАЦИЯ ЛОГИРОВАНИЯ ---
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# --- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ДЛЯ ОТСЛЕЖИВАНИЯ СОСТОЯНИЯ ---
# Используется для предотвращения спама одинаковыми алертами
alert_states = {
    "cpu": False,
    "mem": False,
    "net": False,
}
# Используется для расчета скорости сети
net_io_history = {
    "last_check_time": time.time(),
    "last_bytes_sent": 0,
    "last_bytes_recv": 0,
}

# --- ОСНОВНЫЕ ФУНКЦИИ ---

def get_system_metrics():
    """Собирает метрики CPU, RAM и сети."""
    cpu_usage = psutil.cpu_percent(interval=1)
    mem_info = psutil.virtual_memory()
    mem_usage = mem_info.percent
    
    # Расчет скорости сети
    global net_io_history
    current_time = time.time()
    # Инициализация при первом запуске
    if net_io_history["last_bytes_sent"] == 0:
        net_counters = psutil.net_io_counters()
        net_io_history["last_bytes_sent"] = net_counters.bytes_sent
        net_io_history["last_bytes_recv"] = net_counters.bytes_recv
        net_io_history["last_check_time"] = current_time
        # При первом запуске скорость равна 0
        net_upload_mbps, net_download_mbps = 0.0, 0.0
    else:
        time_delta = current_time - net_io_history["last_check_time"]
        current_net_counters = psutil.net_io_counters()
        
        bytes_sent_delta = current_net_counters.bytes_sent - net_io_history["last_bytes_sent"]
        bytes_recv_delta = current_net_counters.bytes_recv - net_io_history["last_bytes_recv"]
        
        # Конвертация в Мбит/с
        net_upload_mbps = (bytes_sent_delta * 8) / (time_delta * 1_000_000) if time_delta > 0 else 0
        net_download_mbps = (bytes_recv_delta * 8) / (time_delta * 1_000_000) if time_delta > 0 else 0
        
        # Обновление истории
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

def get_wg_peers():
    """
    Выполняет команду 'wg show' и возвращает ее вывод.
    ВАЖНО: для выполнения этой команды могут потребоваться права суперпользователя (sudo).
    """
    try:
        # Используем sudo, так как wg show требует повышенных прав
        result = subprocess.run(
            ["sudo", "wg", "show"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10
        )
        return result.stdout.strip()
    except FileNotFoundError:
        return "Ошибка: команда 'wg' не найдена. Убедитесь, что Wireguard установлен."
    except subprocess.CalledProcessError as e:
        logger.error(f"Ошибка выполнения 'wg show': {e.stderr}")
        return f"Ошибка выполнения команды 'wg show'.\nВозможно, у пользователя нет прав sudo?\n\n{e.stderr}"
    except subprocess.TimeoutExpired:
        return "Ошибка: команда 'wg show' выполнялась слишком долго."
    except Exception as e:
        logger.error(f"Неизвестная ошибка при вызове 'wg show': {e}")
        return f"Произошла неизвестная ошибка: {e}"

async def send_telegram_message(context: ContextTypes.DEFAULT_TYPE, message: str):
    """Отправляет сообщение в заданный чат."""
    try:
        await context.bot.send_message(
            chat_id=CHAT_ID, text=message, parse_mode=ParseMode.HTML
        )
    except Exception as e:
        logger.error(f"Не удалось отправить сообщение в Telegram: {e}")

# --- ОБРАБОТЧИКИ КОМАНД ---

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Отправляет приветственное сообщение при команде /start."""
    user = update.effective_user
    await update.message.reply_html(
        f"Привет, {user.mention_html()}!\n"
        "Я бот для мониторинга сервера Wireguard.\n\n"
        "Доступные команды:\n"
        "/monitoring - Показать текущую загрузку системы.\n"
        "/active_wg - Показать активных пиров Wireguard."
    )

async def monitoring_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Отправляет текущие метрики системы по запросу."""
    metrics = get_system_metrics()
    uptime_seconds = time.time() - psutil.boot_time()
    uptime_string = str(timedelta(seconds=int(uptime_seconds)))
    
    message = (
        "<b>📊 Текущее состояние системы</b>\n\n"
        f"🖥️ <b>CPU:</b> {metrics['cpu']:.2f} %\n"
        f"🧠 <b>Memory:</b> {metrics['mem']:.2f} %\n"
        f"🔼 <b>Upload:</b> {metrics['upload_mbps']:.2f} Мбит/с\n"
        f"🔽 <b>Download:</b> {metrics['download_mbps']:.2f} Мбит/с\n\n"
        f"⏱️ <b>Uptime:</b> {uptime_string}"
    )
    await update.message.reply_html(message)

async def active_wg_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Отправляет список активных пиров Wireguard с именами клиентов."""
    await update.message.reply_text("Получаю список пиров... Это может занять несколько секунд.")
    peers_info_raw = get_wg_peers()
    
    peers_info_processed = peers_info_raw

    # Проверяем, что команда выполнилась успешно, прежде чем обрабатывать вывод
    if "Ошибка" not in peers_info_raw and peers_info_raw:
        processed_lines = []
        for line in peers_info_raw.splitlines():
            # Ищем IP-адреса в строке
            found_ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            
            name_to_add = ""
            for ip in found_ips:
                if ip in PEER_NAMES:
                    # Если нашли IP из нашего словаря, запоминаем имя
                    name_to_add = f"  <b>({PEER_NAMES[ip]})</b>"
                    break # Достаточно одного совпадения
            
            # Добавляем имя к строке, если оно было найдено
            processed_lines.append(line + name_to_add)
            
        peers_info_processed = "\n".join(processed_lines)
    elif not peers_info_raw:
        peers_info_processed = "Пиры не найдены или интерфейс неактивен."
    
    message = f"<b>🛡️ Активные пиры Wireguard:</b>\n\n<pre>{peers_info_processed}</pre>"
    await update.message.reply_html(message)

# --- ФОНОВАЯ ЗАДАЧА ДЛЯ АЛЕРТОВ ---

async def check_alerts(context: ContextTypes.DEFAULT_TYPE):
    """Периодически проверяет метрики и отправляет алерты при превышении порогов."""
    global alert_states
    metrics = get_system_metrics()
    
    alerts_to_send = []

    # Проверка CPU
    if metrics["cpu"] > CPU_THRESHOLD and not alert_states["cpu"]:
        alerts_to_send.append(f"🚨 <b>Внимание: Высокая загрузка CPU!</b>\n   Текущее значение: {metrics['cpu']:.2f}% (Порог: {CPU_THRESHOLD}%)")
        alert_states["cpu"] = True
    elif metrics["cpu"] < CPU_THRESHOLD and alert_states["cpu"]:
        alerts_to_send.append(f"✅ <b>Норма: Загрузка CPU снизилась.</b>\n   Текущее значение: {metrics['cpu']:.2f}%")
        alert_states["cpu"] = False

    # Проверка Memory
    if metrics["mem"] > MEM_THRESHOLD and not alert_states["mem"]:
        alerts_to_send.append(f"🚨 <b>Внимание: Высокое использование памяти!</b>\n   Текущее значение: {metrics['mem']:.2f}% (Порог: {MEM_THRESHOLD}%)")
        alert_states["mem"] = True
    elif metrics["mem"] < MEM_THRESHOLD and alert_states["mem"]:
        alerts_to_send.append(f"✅ <b>Норма: Использование памяти снизилось.</b>\n   Текущее значение: {metrics['mem']:.2f}%")
        alert_states["mem"] = False
        
    # Проверка Network
    total_net = metrics["total_mbps"]
    if total_net > NET_THRESHOLD_MBPS and not alert_states["net"]:
        alerts_to_send.append(f"🚨 <b>Внимание: Высокая сетевая активность!</b>\n   Текущая скорость: {total_net:.2f} Мбит/с (Порог: {NET_THRESHOLD_MBPS} Мбит/с)")
        alert_states["net"] = True
    elif total_net < NET_THRESHOLD_MBPS and alert_states["net"]:
        alerts_to_send.append(f"✅ <b>Норма: Сетевая активность снизилась.</b>\n   Текущая скорость: {total_net:.2f} Мбит/с")
        alert_states["net"] = False

    if alerts_to_send:
        message = "\n\n".join(alerts_to_send)
        await send_telegram_message(context, message)

# --- ЗАПУСК БОТА ---

def main():
    """Основная функция для запуска бота."""
    if not BOT_TOKEN or CHAT_ID:
        logger.error("Пожалуйста, укажите BOT_TOKEN и CHAT_ID в .env")
        return

    application = Application.builder().token(BOT_TOKEN).build()
    
    # Добавляем обработчики команд
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("monitoring", monitoring_command))
    application.add_handler(CommandHandler("active_wg", active_wg_command))
    
    # Добавляем фоновую задачу для проверки алертов
    job_queue = application.job_queue
    job_queue.run_repeating(check_alerts, interval=CHECK_INTERVAL_SECONDS, first=10)
    
    logger.info("Бот запущен...")
    application.run_polling()

if __name__ == "__main__":
    main()
