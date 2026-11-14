package main

// Разбор сообщений окна детектора блокировки Windows (lock_windows.go) — без ограничения сборки: чистая функция,
// тест идёт и на Linux (lock_wts_test.go).

// winuser.h, wtsapi32.h
const (
	wmTimer, wmWTSSessionChange, wmPowerBroadcast = 0x113, 0x2b1, 0x218
	pbtAPMSuspend                                 = 0x4
	wtsConsoleDisconnect, wtsRemoteDisconnect     = 0x2, 0x4
	wtsSessionLogoff, wtsSessionLock              = 0x6, 0x7
)

// lockMsg — сообщение окна (msg, wParam) означает блокировку. Разблокировка, вход, подключение, пробуждение — нет.
func lockMsg(msg, wp uintptr) bool {
	switch msg {
	case wmWTSSessionChange:
		return wp == wtsSessionLock || wp == wtsConsoleDisconnect || wp == wtsRemoteDisconnect || wp == wtsSessionLogoff
	case wmPowerBroadcast:
		return wp == pbtAPMSuspend
	}
	return false
}
