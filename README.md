# 🛡️ Telegram Бот для мониторинга WireGuard VPN

Уже не самый простой бот на Python для мониторинга, сбора статистики и управления сервером WireGuard. Бот собирает данные о трафике в базу данных SQLite, позволяет строить графики и управлять пирами.

## 📋 Функции

Бот предоставляет функционал для пользователей и администраторов:

- Проверка загрузки CPU, памяти и скорости сети
- Получение списка активных пиров WireGuard (с возможностью добавления никнеймов пирам в main.py, блокировкой пиров)
- Telegram-оповещения при превышении порогов, в том числе количества трафика
- systemd-сервис для автозапуска и др.

### 🧪 Команды для всех (при добавлении бота в общий чат и создании "подписочного" функционала:
```
/start              Показать стартовое меню
/monitoring         Показать текущую нагрузку на сервер (CPU, RAM, Net)
/active_wg          Показать полный "красивый" список пиров из wg show
/online             Показать только тех пиров, кто сейчас в сети (был handshake < 3 мин)
/chart <имя_пира>   Прислать график потребления трафика пиром за последние 7 дней
```

<img width="1000" height="600" alt="image" src="https://github.com/user-attachments/assets/36571e01-466a-42e1-be30-f5aaa0d54883" />

### 🧪 Админ-команды:
```
/test_quota        Принудительно запустить генерацию ежедневного отчета
/block <имя_пира>  Немедленно заблокировать пира (удаляет из сессии)
/unblock           Разблокировать всех, перезапустив интерфейс WireGuard
```

### Фоновые задачи (автоматические):
```
Сбор статистики:   каждые 10 минут сохраняет снэпшот трафика (RX/TX) всех пиров в базу SQLite.
Ежедневный отчет:  в 21:00* (МСК) присылает админу сводку: топ пользователей за день и общий трафик за месяц.
Контроль квот:     во время отчета проверяет месячный трафик пиров по квотам и присылает алерт админу в случае превышения.
Напоминания:       5-го* числа каждого месяца присылает напоминание об оплате.
Авто-очистка:      в 04:00* (МСК) удаляет из БД записи старше 90 дней и выполняет VACUUM для сжатия файла базы.
```

*Даты и время можно поменять в файле main.py в главной функции (точке входа).

## 🚀 Установка

###1. Клонирование репозитория (или просто скачайте ZIP-архив и загрузите файлы на сервер)

```bash
git clone https://github.com/yessshka/tele-monitor-v2.0.git
cd tele-monitor
```
###2. Создание виртуального окружения

```bash
python3 -m venv bot
source bot/bin/activate
```
###3. Установка зависимостей

```bash
pip install --upgrade pip
pip install -r requirements.txt
```
###4. Настройка конфигурации (секреты)

Скопируйте пример .env:
```bash
cp .env.example .env
```
Пример содержания:
```dotenv
#Токен от @BotFather
BOT_TOKEN="123456:ABC-DEF123456"

#Ваш Telegram User ID (для получения отчетов и админ-команд)
ADMIN_CHAT_ID="123456789"

#Имя вашего WireGuard интерфейса
WG_INTERFACE="wg0"
```
###5. Настройка конфигурации (пиры)

Откройте файл main.py (например, nano main.py) и найдите секцию --- КОНФИГУРАЦИЯ ---.

Вам нужно отредактировать два словаря:

- PEER_NAMES: Заполните этот словарь вашими IP-адресами и именами пиров.
- PEER_QUOTAS: Заполните квоты трафика (в ГБ) для каждого пира.

###6. Настройка sudo

Боту нужны права sudo для выполнения команд wg и systemctl, но без запроса пароля.
Откройте файл sudoers для редактирования:
```bash
sudo visudo
```

Перейдите в самый конец файла и добавьте строки. ВНИМАТЕЛЬНО замените user на ваше имя пользователя (от имени которого будет запускаться бот).
```bash
# Разрешаем пользователю user выполнять команды wg и systemctl без пароля
user ALL=(ALL) NOPASSWD: /usr/bin/wg
user ALL=(ALL) NOPASSWD: /bin/systemctl restart wg-quick@wg0.service
```

Путь к systemctl может быть /usr/bin/systemctl — проверьте через which systemctl.

###7. Запуск

Можно запустить напрямую для теста:
```bash
python3 main.py
```

## ⚙️ Автозапуск через systemd (надо актуализировать путь в wg_bot.service)

###Создайте файл сервиса:
```bash
sudo nano /etc/systemd/system/wg_bot.service
```
###Вставьте в него эту конфигурацию, заменив user и пути на ваши:
```bash
[Unit]
Description=Tele-Monitor Bot
After=network.target

[Service]
User=user
Group=user
WorkingDirectory=/home/user/tele-monitor
ExecStart=/home/user/tele-monitor/bot/bin/python /home/user/tele-monitor/main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```
###Включите и запустите сервис:
```bash
sudo systemctl enable wg_bot.service
sudo systemctl start wg_bot.service
```
###Проверьте статус:
```bash
systemctl status wg_bot.service
```

## 📦 Зависимости
```
python-telegram-bot
psutil
pytz
matplotlib
python-dotenv
```
