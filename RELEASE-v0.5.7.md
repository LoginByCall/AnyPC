## AnyPC v0.5.7

**Пространство без лишних секретов / Space without extra secrets**
- Системный пароль ОС запрашивается один раз при входе в настройки и больше не появляется при каждом действии или опросе состояния. / The OS password is requested once when entering Settings and is not requested again for each action or status poll.
- Пользователь хоста создаёт пространство и управляет им без ввода фразы, пароля пространства и TOTP. / The host creates and manages a space without entering a phrase, space password or TOTP.
- Инициатор вступает по ID хоста и созданным для него постоянным логину, паролю и его собственному TOTP. / An Initiator joins using the host ID and their dedicated permanent login, password and their own TOTP.
- Хост сам подписывает добавление Инициатора после проверки именной записи: фраза, поручитель и окно «Пустить?» не нужны, ключ владельца остаётся на хосте. / The host signs Initiator membership after validating the named account: no phrase, guarantor or admission window is needed, and the owner key stays on the host.
- Для пространств прежних версий предусмотрена одноразовая проверка и локальное сохранение фразы; дальнейшие действия снова не требуют её ввода. / Spaces from previous versions support one-time phrase verification and local storage; subsequent actions do not require entering it again.

**Исправление авторизации / Authorization fix**
- Устранено повторное появление системных окон пароля при опросе `spaceOp`. / Fixed repeated system password prompts during `spaceOp` polling.
- Параллельный вход в настройки вызывает только одно системное окно; выход из настроек сбрасывает разрешение. / Concurrent Settings entry opens only one system prompt; leaving Settings clears the authorization grant.
- Переходы между главным экраном, настройками и вкладками выполняются по очереди без потери действий трея. / Navigation between Home, Settings and PC tabs is queued so tray actions are not dropped.

**Проверка / Verification**
- Регрессионные тесты повторных опросов, однократной авторизации и вступления по именной записи без фразы. / Regression tests for repeated polling, one-time authorization and named-account joining without a phrase.
