# 🛡️ Telegram Бот для мониторинга WireGuard VPN

Простой бот на Python для мониторинга состояния сервера с WireGuard: загрузка CPU, память, сетевой трафик, список активных пиров.

## 📋 Функции

- Проверка загрузки CPU, памяти и скорости сети
- Получение списка активных пиров WireGuard
- Telegram-оповещения при превышении порогов
- systemd-сервис для автозапуска

## 🚀 Установка

```bash
git clone https://github.com/yourusername/tele-monitor.git
cd tele-monitor
python3 -m venv bot
source bot/bin/activate
pip install -r requirements.txt
