# Безопасность / Security

AnyPC даёт удалённое управление компьютером, поэтому об уязвимостях просим сообщать **приватно**, а не в открытых тикетах:
**Security → Report a vulnerability** (https://github.com/LoginByCall/AnyPC/security/advisories/new).

AnyPC gives remote control of a computer, so please report vulnerabilities **privately**, not in public issues:
**Security → Report a vulnerability** (link above).

Поддерживается последняя версия / Only the latest release is supported. Подпись выпусков — `SHA256SUMS.sig`, открытый ключ — в README.

Вход без подтверждения защищён вторым фактором TOTP (код из приложения-аутентификатора после пароля); файл настроек
хоста содержит оба фактора (хэш пароля и секрет TOTP), поэтому TOTP защищает от утечки пароля, но не от кражи этого файла.
«Моё пространство»: каждый ПК пространства хранит общий список ПК со всеми общими секретами (хэш пароля, секрет TOTP);
сессия, вошедшая паролем и кодом владельца, получает этот список целиком. Кража одного ПК пространства — повод
исключить его и сменить пароль. / "My space": every member PC stores the shared member list with the shared secrets;
a session logged in with the owner's password and code receives it.
Login without confirmation is protected by a TOTP second factor; the host's settings file holds both factors (password
hash and TOTP secret), so TOTP protects against a leaked password, not against theft of that file.

«Моё пространство»: после «Работаю тут» (пароль и код) ключ хоста ПК «я тут» на срок пропуска — единственный фактор
входа на все ПК пространства. Пропуск снимается блокировкой экрана и выходом на том ПК, через 12 ч и перезапуском цели.
"My space": after "Work here" (password and code), the host key of the "I'm here" PC is, for the pass lifetime, the only
login factor for every PC of the space. The pass ends on screen lock or quit on that PC, after 12 h, or on target restart.
«Снять» — одно сообщение через хаб, подписанное ключом ПК «я тут» (ID цели, время, nonce), без соединения: поток
посторонних его не вытесняет. Цели старых версий снимаются по-старому, отдельным соединением, — там посторонний, знающий
ID цели, может потоком подключений задерживать «снять» (пропуск живёт до 12 ч или перезапуска цели). Хаб видит момент
«снять» (блокировку или выход на ПК «я тут»), ID цели и ключ ПК «я тут» (хабу он и так известен — это ключ, под которым
тот ПК в сети) и может выборочно «снять» не пропускать. Часы ПК «я тут» и цели должны расходиться не больше 5 мин,
иначе цель «снять» отклоняет.
"Off" is a single message via the hub, signed by the "I'm here" PC key (target ID, time, nonce), with no connection: a
stranger's flood cannot push it out. Targets of older versions get "off" the old way, over a separate connection, where
a stranger who knows the target ID can delay it with a flood of connections (the pass then lives up to 12 h or until the
target restarts). The hub sees when "off" is sent (lock or quit on the "I'm here" PC), the target ID and the "I'm here"
PC key (already known to the hub as that PC's host key) and can drop it selectively. The clocks of the two PCs must agree
within 5 minutes, otherwise the target rejects "off".
