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
