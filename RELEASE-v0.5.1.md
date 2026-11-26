## AnyPC v0.5.1

**Исправление системной авторизации / System authorization fix**
- Linux: если служба polkit отсутствует, авторизация настроек теперь использует `sudo -A -v` со стандартным `SUDO_ASKPASS` через zenity вместо немедленной ошибки без окна. / On Linux without polkit, settings authorization now falls back to `sudo -A -v` with the standard zenity `SUDO_ASKPASS` prompt instead of failing without a dialog.
- View Only и выключение Allow control / Allow space выполняются без пароля; включение по-прежнему требует системную авторизацию. / View Only and turning Allow control / Allow space off no longer require a password; enabling still requires system authorization.
- Отдельный пароль AnyPC для настроек и ключевая фраза не нужны. TOTP остаётся только для входа каждого пользователя My space. / No separate AnyPC settings password or key phrase. TOTP remains only for signing in each My space user.
