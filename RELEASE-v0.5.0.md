## AnyPC v0.5.0

**Системная авторизация настроек / System authorization for settings**
- Изменение доступа, пользователей, TOTP, одноразового кода, own server и состава пространства требует подтверждения операционной системой. / Changing access, users, TOTP, the one-time code, own server and space membership requires operating-system authorization.
- Windows: CredUI; Linux: polkit; macOS: LocalAuthentication. Отдельного пароля AnyPC для настроек и ключевой фразы для них нет. TOTP остаётся обязательным только для входа каждого постоянного пользователя My space. / No separate AnyPC settings password or key phrase. TOTP remains mandatory only for each permanent My space user signing in.

**Выключение сети при Allow control / Network shutdown with Allow control**
- При выключенном Allow control AnyPC останавливает сигнализацию и фоновую синхронизацию пространства и не повторяет подключения. При включении сеть запускается заново. / With Allow control off, AnyPC stops signaling and background space sync and does not retry connections. Turning it on restarts networking.
- Статус показывает выключенный профиль, а не ошибку сервера. / The status reports the disabled profile, not a server error.

**Подключение и настройки / Connection and settings**
- Шестизначный код всегда выбирает one-time вход, даже если сохранено имя учётной записи: достаточно ID + Code. / A six-digit code always selects one-time access, even with a saved account name: ID + Code is enough.
- Options переименованы в Extended options и получили явный индикатор раскрытия; Computer ID остался в основной форме. / Options is now Extended options with a clear expand indicator; Computer ID stays in the main form.
- В Settings сразу видны Own server и Allow space. / Own server and Allow space are shown immediately in Settings.
- Значок настроек — явная шестерёнка. / The settings icon is now a recognizable gear.
- Удалён блок Who can send here without a code. / Removed the Who can send here without a code block.
