# Безопасность / Security

AnyPC даёт удалённое управление компьютером, поэтому об уязвимостях просим сообщать **приватно**, а не в открытых тикетах:
**Security → Report a vulnerability** (https://github.com/LoginByCall/AnyPC/security/advisories/new).

AnyPC gives remote control of a computer, so please report vulnerabilities **privately**, not in public issues:
**Security → Report a vulnerability** (link above).

Поддерживается последняя версия / Only the latest release is supported. Подпись выпусков — `SHA256SUMS.sig`, открытый ключ — в README.

Вход без подтверждения защищён вторым фактором TOTP (код из приложения-аутентификатора после пароля); файл настроек
хоста содержит оба фактора (хэш пароля и секрет TOTP), поэтому TOTP защищает от утечки пароля, но не от кражи этого файла.
Login without confirmation is protected by a TOTP second factor; the host's settings file holds both factors (password
hash and TOTP secret), so TOTP protects against a leaked password, not against theft of that file.

«Моё пространство»: после «Работаю тут» (пароль и код) ключ хоста ПК «я тут» на срок пропуска — единственный фактор
входа на все ПК пространства. Пропуск снимается блокировкой экрана и выходом на том ПК, через 12 ч и перезапуском цели.
"My space": after "Work here" (password and code), the host key of the "I'm here" PC is, for the pass lifetime, the only
login factor for every PC of the space. The pass ends on screen lock or quit on that PC, after 12 h, or on target restart.
Ограничения: посторонний, знающий ID цели, может потоком подключений задерживать «снять» — пропуск тогда живёт до 12 ч
или перезапуска цели; хаб видит момент «снять» (блокировку или выход на ПК «я тут») и может выборочно его не пропускать.
Limits: a stranger who knows the target ID can delay "off" with a flood of connections — the pass then lives up to 12 h
or until the target restarts; the hub sees when "off" is sent (lock or quit on the "I'm here" PC) and can drop it selectively.
