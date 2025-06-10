# 🛡️ Telegram Бот для мониторинга WireGuard VPN

Простой бот на Python для мониторинга состояния сервера с WireGuard: загрузка CPU, память, сетевой трафик, список активных пиров.

## 📋 Функции

- Проверка загрузки CPU, памяти и скорости сети
- Получение списка активных пиров WireGuard
- Telegram-оповещения при превышении порогов
- systemd-сервис для автозапуска

## 🚀 Установка

```bash
git clone https://github.com/yessshka/tele-monitor.git
cd tele-monitor
python3 -m venv bot
source bot/bin/activate
pip install -r requirements.txt
```

## Создайте .env:
```dotenv
BOT_TOKEN=ваш_токен
CHAT_ID=ваш_чат_id
```

## ⚙️ Автозапуск через systemd
```bash
sudo cp wg_bot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wg_bot
```

## 🧪 Команды бота
/start        Приветствие и справка
/monitoring	  Текущие метрики CPU, RAM, сеть
/active_wg	  Список активных VPN-клиентов

## 📦 Зависимости
python-telegram-bot
psutil
python-dotenv
