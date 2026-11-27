## AnyPC v0.5.6

**Space без пароля и TOTP / Space without password or TOTP**
- Создание Space выполняется одним действием после системной авторизации: фраза сохраняется в `Downloads/AnyPC-space-<ID>.txt` с правами `0600`, путь показывается пользователю. / Create a space in one action after system authorization: the phrase is saved to `Downloads/AnyPC-space-<ID>.txt` with `0600` permissions and the path is shown.
- Другой ПК вступает по ID и фразе — пароль и authenticator не нужны. «Я тут» и выход из Space также работают после системной авторизации без скрытых учётных данных. / Another PC joins with its ID and the phrase—no password or authenticator. “I’m here” and leaving the space also work after system authorization without hidden credentials.
- Из трея «Я тут» переводит фокус на кнопку, а не на удалённое поле пароля. / The tray “I’m here” action now focuses the button instead of the removed password field.

**Интерфейс и соединение / UI and connectivity**
- Расширенные параметры подключения раскрыты по умолчанию. / Extended connection options are open by default.
- Ожидание polkit/D-Bus перед запасным запросом пароля ограничено 1,5 с. / Polkit/D-Bus waiting before the fallback password prompt is capped at 1.5 seconds.
- В журнал добавлены адреса и типы выбранных ICE-кандидатов для диагностики P2P и relay/VPN. / Selected ICE candidate addresses and types are logged to diagnose P2P versus relay/VPN paths.
- Тестовый Chrome завершается вместе с `go test`; старые процессы и профили удалены. / Test Chrome now exits with `go test`; stale processes and profiles were removed.

**Проверка / Verification**
- Полные наборы Space, phrase-only e2e, browser `TestBrowserSpace`, `TestBrowserMain`, `TestBrowserHome`, `TestBrowserHostOTP` и `TestBrowserTrayJS`, CSP, переводы и Windows-компиляция. / Full Space suites, phrase-only e2e, browser and tray scenarios, CSP, translations, and Windows test compilation.
