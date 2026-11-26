## AnyPC v0.5.3

**Создание пространства / Space creation**
- «Создать пространство» больше не требует заранее задавать пароль этого ПК и код authenticator. На новом ПК поле пароля можно оставить пустым: после системной авторизации AnyPC сам создаёт учётные данные владельца. / “Create a space” no longer requires setting a PC password and authenticator code first. On a new PC, leave the password empty: after system authorization AnyPC creates the owner credentials automatically.
- Фраза пространства и QR authenticator показываются один раз на одном шаге: второй ПК можно добавить сразу, не восстанавливая скрытый секрет. При отмене или завершении мастера они удаляются из окна. / The space phrase and authenticator QR appear together once, so a second PC can join immediately. Both are removed from the window when the wizard is completed or cancelled.
- Обновлён CSP-хэш интерфейса; добавлены browser-проверки создания пространства без пароля и TOTP. / Updated the UI CSP hash and added browser coverage for space creation without a password or TOTP.

**Проверка / Verification**
- Все тесты пространства Go, полные browser-сценарии `TestBrowserSpace` и `TestBrowserSpaceCreate`, `TestBrowserTrayJS`, CSP и проверка семи языков. / All Go space tests, full `TestBrowserSpace` and `TestBrowserSpaceCreate` browser scenarios, `TestBrowserTrayJS`, CSP validation, and all seven languages checked.
