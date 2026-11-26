## AnyPC v0.5.2

**Сборка / Build**
- libvpx теперь линкуется только статически из `third_party/libvpx` для каждой целевой архитектуры: Linux amd64, Windows amd64, macOS amd64 и macOS arm64. / libvpx is now linked statically from `third_party/libvpx` for each target: Linux amd64, Windows amd64, macOS amd64 and macOS arm64.
- Это устраняет зависимость приложения от системной `libvpx.12.dylib` на macOS. / This removes the app’s dependency on the system `libvpx.12.dylib` on macOS.
- Остальные изменения v0.5.1: fallback системной авторизации через sudo при отсутствии polkit, View Only и выключение профилей без пароля. / v0.5.1 changes included: sudo fallback when polkit is unavailable, View Only and disabling profiles without a password.
