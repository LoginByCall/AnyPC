## AnyPC v0.5.7

**Исправление авторизации / Authorization fix**
- Устранено повторное появление системных окон пароля при опросе состояния Space: read-only вызов `spaceOp` больше не требует авторизации. / Fixed repeated system password prompts while polling Space status: the read-only `spaceOp` call no longer requires authorization.
- Изменяющие настройки и состав Space операции по-прежнему защищены системной авторизацией. / Operations that change settings or Space membership still require system authorization.

**Проверка / Verification**
- Добавлен регрессионный тест повторных опросов состояния без авторизации. / Added a regression test for repeated status polling without authorization.
