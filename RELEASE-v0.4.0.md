## AnyPC v0.4.0

**Два независимых профиля доступа / Two independent access profiles**
- **«Моё пространство» / “My space”:** постоянный доступ включается отдельным переключателем «Allow space». / Permanent access has its own “Allow space” switch.
- **Одноразовый доступ / One-time access:** «Allow control» и «View Only» работают независимо от постоянного профиля. / “Allow control” and “View Only” work independently of the permanent profile.

**Постоянный доступ / Permanent access**
- Экран «Permanent access to this computer»: добавление и редактирование инициаторов с именем, паролем, обязательным TOTP и правами «Full control» / «View only». / Add and edit initiators with a name, password, mandatory TOTP and Full control / View only rights.
- Добавление пользователя, смена прав и «Allow space» не требуют ввода TOTP владельца. / Adding users, changing rights and toggling “Allow space” do not require the owner’s TOTP.
- Учётные записи без TOTP сохраняются, но не принимают вход до настройки второго фактора. / Accounts without TOTP are preserved but cannot sign in until the second factor is configured.

**Одноразовый доступ / One-time access**
- Для подключения достаточно ID и кода: подтверждение на управляемом ПК и TOTP больше не требуются. / ID + code is enough: no confirmation on the controlled PC and no TOTP.
- Код меняется после сессии и по кнопке «New code». / The code rotates after a session and with “New code”.
- «View Only» ограничивает только одноразовые сессии и не меняет права постоянных пользователей. / “View Only” restricts only one-time sessions and does not change permanent users’ rights.

**Совместимость / Compatibility**
- Обновите оба ПК. Одноразовый вход старого клиента на новый хост сохраняется; для постоянного входа по паролю и вступления в пространство нужен v0.4.0 на обеих сторонах. / Update both PCs. Old clients can still use one-time access to a new host; permanent password sign-in and joining a space require v0.4.0 on both sides.
- Прежний режим постоянного доступа при обновлении сохраняется через «Allow space». / The previous permanent-access mode is migrated to “Allow space”.
