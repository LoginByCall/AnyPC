package main

import "testing"

// TestLockMsg — какие сообщения окна детектора — блокировка (lock_wts.go, lock_windows.go): блокировка, уход сеанса с консоли,
// отключение RDP, выход, сон — да; разблокировка, вход, подключение, пробуждение и чужие сообщения — нет.
func TestLockMsg(t *testing.T) {
	for _, c := range []struct {
		name    string
		msg, wp uintptr
		lock    bool
	}{
		{"WTS_SESSION_LOCK", wmWTSSessionChange, 0x7, true},
		{"WTS_CONSOLE_DISCONNECT", wmWTSSessionChange, 0x2, true},
		{"WTS_REMOTE_DISCONNECT", wmWTSSessionChange, 0x4, true},
		{"WTS_SESSION_LOGOFF", wmWTSSessionChange, 0x6, true},
		{"PBT_APMSUSPEND", wmPowerBroadcast, 0x4, true},
		{"WTS_CONSOLE_CONNECT", wmWTSSessionChange, 0x1, false},
		{"WTS_REMOTE_CONNECT", wmWTSSessionChange, 0x3, false},
		{"WTS_SESSION_LOGON", wmWTSSessionChange, 0x5, false},
		{"WTS_SESSION_UNLOCK", wmWTSSessionChange, 0x8, false},
		{"WTS_SESSION_REMOTE_CONTROL", wmWTSSessionChange, 0x9, false},
		{"WTS_SESSION_CREATE", wmWTSSessionChange, 0xa, false},
		{"PBT_APMRESUMESUSPEND", wmPowerBroadcast, 0x7, false},
		{"PBT_APMRESUMEAUTOMATIC", wmPowerBroadcast, 0x12, false},
		{"PBT_POWERSETTINGCHANGE", wmPowerBroadcast, 0x8013, false},
		{"WM_TIMER с wParam 7", wmTimer, 0x7, false},
		{"WM_SETTINGCHANGE", 0x1a, 0x7, false},
	} {
		if got := lockMsg(c.msg, c.wp); got != c.lock {
			t.Errorf("%s (%#x, %#x): блокировка %v, ждали %v", c.name, c.msg, c.wp, got, c.lock)
		}
	}
	if wmWTSSessionChange != 0x2b1 || wmPowerBroadcast != 0x218 { // winuser.h
		t.Error("номера сообщений не по winuser.h")
	}
}
