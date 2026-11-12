# Политика конфиденциальности AnyPC

Редакция от 12 ноября 2026 г.

AnyPC — программа удалённого доступа с открытым исходным кодом (https://github.com/LoginByCall/AnyPC). Здесь описано, какие данные проходят через серверы проекта, что хранится на вашем компьютере и чего AnyPC не делает. Всё сказанное можно проверить по исходному коду.

## Коротко

- Нет учётных записей, рекламы, cookies и телеметрии. Серверы считают только суммарные числа за сутки — без ID и IP-адресов (см. «Статистика»). Мы не продаём и не передаём данные.
- Экран, ввод, буфер обмена и файлы идут между компьютерами в зашифрованном виде (WebRTC: DTLS/SRTP). Серверы проекта не могут их прочитать.
- Пароль по сети не передаётся: вход проверяется протоколом CPace, и ни пароль, ни его хэш не отправляются ни серверам, ни другому компьютеру.

## Серверы проекта

Проект держит серверы сигнализации (hk.anypc.org — Гонконг, ru.anypc.org — Москва) и ретрансляторы TURN (те же серверы и us.anypc.org). DNS — Cloudflare, только DNS: трафик через Cloudflare не проходит.

**Сигнализация** нужна, чтобы два компьютера нашли друг друга.
- Хранится бессрочно: ID компьютера и его открытый ключ (файл соответствия «ID → ключ»). Больше ничего: ни IP-адресов, ни времени, ни имён.
- Только в памяти, пока открыто соединение: само соединение и счётчик новых ID по IP-адресу (не больше 20 в час — защита от злоупотреблений; сбрасывается через час).
- Только в памяти, до конца суток (UTC): хэши ID компьютеров, побывавших в сети за сутки, с солью, которая каждые сутки меняется, — чтобы посчитать, сколько их было, не считая один компьютер дважды.
- Проходит транзитом и не сохраняется: служебные сообщения для установки соединения — сетевые адреса компьютеров (кандидаты ICE), выбранный ретранслятор, задержки, открытый ключ клиента, режимы «Турбо» и «Только просмотр».
- Журнала запросов сервер не ведёт.

**Статистика.** Сервер раз в сутки записывает суммарные числа: сколько разных компьютеров было в сети и сколько одновременно, сколько из них на какой ОС и версии программы, сколько новых ID и запросов подключения (по этапам), сколько клиентов открыто в программе и сколько в браузере, сколько раз открыт сайт и веб-клиент и скачан каждый файл. ID, IP-адресов, имён и времени отдельных событий в ней нет. Она нужна, чтобы видеть нагрузку и понимать, что развивать.

**Ретранслятор TURN** используется, только если компьютеры не смогли соединиться напрямую. Он пересылает зашифрованный поток и видит IP-адреса и порты сторон, объём и время трафика и временное имя пользователя, в котором есть ID компьютера (пароль TURN действует 24 часа). Содержимое сессии ему недоступно.

**Журналы серверов.** Отдельного журнала с IP-адресами мы не ведём. Системные журналы серверов (служба TURN, ошибки установки TLS-соединения) могут содержать IP-адреса и время подключений. Они хранятся по умолчаниям операционной системы, не анализируются и никому не передаются.

**Сайт** www.anypc.org не использует cookies, счётчики в браузере и сторонние ресурсы (шрифты, CDN); открытия страницы и загрузки сервер учитывает только в суточных суммах. Выбранный язык хранится в вашем браузере. Страница загрузки запрашивает у серверов проекта номера версий и контрольные суммы файлов.

## Что программа делает сама

- Держит соединение с серверами сигнализации, пока запущена (или с вашим узлом, если он задан), и при подключении сообщает им ОС и версию программы — для статистики. Веб-клиент сообщает, открыт он в программе или в браузере.
- Проверяет обновления при запуске и раз в 12 часов: запрашивает файл VERSION с hk.anypc.org и ru.anypc.org. Версию программы, ID и другие сведения запрос не передаёт. Это происходит и при работе только через свой узел.
- Версия для Windows при первом запуске скачивает FFmpeg с GitHub (GyanD/codexffmpeg) или gyan.dev. На эти запросы распространяются правила GitHub и gyan.dev.
- Больше никуда не обращается и ничего разработчикам не отправляет.

## Что хранится на вашем компьютере

Эти данные не покидают компьютер.
- Настройки (`config.json`, Windows: `%APPDATA%\AnyPC`, Linux: `~/.config/AnyPC`, macOS: `~/Library/Application Support/AnyPC`): ID, закрытый ключ компьютера, хэш пароля (Argon2id, сам пароль не хранится), адрес своего узла, ключи доверенных клиентов (до 20), отпечатки ключей компьютеров, к которым вы подключались, секрет второго фактора (TOTP) этого компьютера — открытым текстом, и, если вы отметили «Запомнить пароль», пароли удалённых компьютеров — открытым текстом.
- Журнал (`anypc.log`, Windows: `%LOCALAPPDATA%\AnyPC`, Linux: `~/.cache/AnyPC`, macOS: `~/Library/Caches/AnyPC`): события сессий с ID клиентов, неудачные попытки входа, тип соединения (без IP-адресов), имена, размеры и контрольные суммы принятых и отправленных файлов. Журнал можно удалить в любой момент.
- Принятые файлы — в папке «Загрузки».

**В браузере** (веб-клиент, localStorage): до 8 последних ID, отпечатки ключей удалённых компьютеров, ключ клиента для каждого компьютера, настройки «Турбо», ретранслятора и подсказок. Пароль хранится только в памяти открытой вкладки, а если отмечено «Запомнить пароль» — в localStorage открытым текстом (снимите галочку, чтобы удалить). На сервер из этого уходит лишь открытый ключ клиента (для входа без повторной блокировки) — закрытая часть остаётся в браузере.

## Свой узел

Если вы используете свой узел (сервер), сигнализация и ретрансляция идут через него, и данными на нём распоряжается его владелец. Узел ведёт такую же суточную статистику у себя (файл `stats.jsonl` рядом с `hosts.json`) и никуда её не отправляет. Серверы проекта при этом используются только для проверки обновлений (и для загрузки FFmpeg на Windows — с GitHub/gyan.dev).

## Сторонние сервисы

- GitHub — исходный код, выпуски, тикеты. Тикеты публичны: не публикуйте в них пароли, ID и личные данные.
- Let's Encrypt — сертификаты для доменов серверов (получает только имена доменов).
- Cloudflare — DNS.

## Ваши права и связь

Учётных записей нет, поэтому серверы проекта не хранят о вас ничего, кроме ID компьютера и его открытого ключа. Чтобы удалить эту запись, напишите нам и укажите ID. Вопросы и запросы: https://github.com/LoginByCall/AnyPC/issues. Уязвимости — приватно: https://github.com/LoginByCall/AnyPC/security/advisories/new.

Об изменениях политики сообщается в этом файле и на странице www.anypc.org/privacy.html. Дата редакции указана вверху.

---

# AnyPC Privacy Policy

Effective November 12, 2026.

AnyPC is open-source remote access software (https://github.com/LoginByCall/AnyPC). This policy describes what passes through the project's servers, what is stored on your computer, and what AnyPC does not do. Everything here can be checked against the source code.

## In short

- No accounts, ads, cookies or telemetry. The servers count only daily totals, with no IDs or IP addresses (see “Statistics”). We do not sell or share data.
- Screen, input, clipboard and files travel between the computers encrypted (WebRTC: DTLS/SRTP). The project's servers cannot read them.
- The password is never sent over the network: login is verified with the CPace protocol, and neither the password nor its hash goes to the servers or to the other computer.

## Project servers

The project runs signaling servers (hk.anypc.org — Hong Kong, ru.anypc.org — Moscow) and TURN relays (the same servers plus us.anypc.org). DNS is Cloudflare, DNS only: no traffic goes through Cloudflare.

**Signaling** lets two computers find each other.
- Stored indefinitely: the computer ID and its public key (an "ID → key" mapping file). Nothing else: no IP addresses, times or names.
- In memory only, while connected: the connection itself and a per-IP counter of new IDs (at most 20 per hour, abuse protection; resets after an hour).
- In memory only, until the end of the day (UTC): hashes of the IDs of computers that were online that day, with a salt that changes daily, to count them without counting one computer twice.
- Passed through, not stored: connection setup messages — network addresses of the computers (ICE candidates), chosen relay, latencies, the client's public key, Turbo and View-only modes.
- The server keeps no request log.

**Statistics.** Once a day the server records totals: how many different computers were online and how many at once, how many of them run which OS and app version, how many new IDs and connection requests (by stage), how many clients were opened in the app and how many in a browser, how many times the website and web client were opened and each file was downloaded. It contains no IDs, IP addresses, names or times of individual events. It shows the load and helps decide what to develop.

**The TURN relay** is used only when the computers cannot connect directly. It forwards the encrypted stream and sees the IP addresses and ports of both sides, traffic volume and timing, and a temporary username containing the computer ID (TURN credentials are valid for 24 hours). It cannot access the session content.

**Server logs.** We keep no dedicated log of IP addresses. The servers' system logs (the TURN service, TLS handshake errors) may contain IP addresses and connection times. They are kept per operating-system defaults, are not analyzed and are not shared.

**The website** www.anypc.org uses no cookies, in-browser counters or third-party resources (fonts, CDNs); page views and downloads are counted by the server only as daily totals. The chosen language is stored in your browser. The download section asks the project's servers for version numbers and file checksums.

## What the app does on its own

- Keeps a connection to the signaling servers while running (or to your own node, if set) and, when connecting, tells them its OS and app version, for statistics. The web client tells whether it is opened in the app or in a browser.
- Checks for updates at launch and every 12 hours by fetching a VERSION file from hk.anypc.org and ru.anypc.org. The request carries no app version, ID or other data. This also happens when you use only your own node.
- On first launch, the Windows version downloads FFmpeg from GitHub (GyanD/codexffmpeg) or gyan.dev; those requests are subject to GitHub's and gyan.dev's policies.
- It contacts nothing else and sends nothing to the developers.

## What is stored on your computer

This data does not leave your computer.
- Settings (`config.json`; Windows: `%APPDATA%\AnyPC`, Linux: `~/.config/AnyPC`, macOS: `~/Library/Application Support/AnyPC`): ID, the computer's private key, the password hash (Argon2id; the password itself is not stored), your node address, trusted client keys (up to 20), key fingerprints of computers you connected to, this computer's second-factor (TOTP) secret in plain text and, if you ticked “Remember password”, the passwords of remote computers in plain text.
- Log (`anypc.log`; Windows: `%LOCALAPPDATA%\AnyPC`, Linux: `~/.cache/AnyPC`, macOS: `~/Library/Caches/AnyPC`): session events with client IDs, failed login attempts, connection type (no IP addresses), names, sizes and checksums of received and sent files. You can delete it at any time.
- Received files go to your Downloads folder.

**In the browser** (web client, localStorage): up to 8 recent IDs, key fingerprints of remote computers, a client key per computer, Turbo, relay and tips settings. The password is kept only in the memory of the open tab, or, if “Remember password” is ticked, in localStorage in plain text (untick it to delete). Of this, only the client's public key is sent (so that repeated logins are not locked out); the private part stays in the browser.

## Your own node

If you use your own node (server), signaling and relaying go through it, and its owner controls the data on it. The node keeps the same daily statistics locally (`stats.jsonl` next to `hosts.json`) and sends it nowhere. The project's servers are then used only for update checks (and, on Windows, FFmpeg comes from GitHub/gyan.dev).

## Third-party services

- GitHub — source code, releases, issues. Issues are public: do not post passwords, IDs or personal data there.
- Let's Encrypt — certificates for the servers' domains (receives domain names only).
- Cloudflare — DNS.

## Your rights and contact

There are no accounts, so the project's servers store nothing about you except a computer ID and its public key. To have that record deleted, contact us with the ID. Questions and requests: https://github.com/LoginByCall/AnyPC/issues. Vulnerabilities — privately: https://github.com/LoginByCall/AnyPC/security/advisories/new.

Changes to this policy are published in this file and at www.anypc.org/privacy.html; the effective date is shown at the top.
