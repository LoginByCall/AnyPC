package main

import (
	"testing"
	"time"
)

// TestLockAct — что окно детектора Windows делает с сообщением (lock_wts.go, lock_windows.go). Номера — литералами
// из winuser.h / wtsapi32.h, не константами пакета: опечатка в константе не пройдёт.
func TestLockAct(t *testing.T) {
	for _, c := range []struct {
		name    string
		msg, wp uintptr
		reg     bool
		act     lockAction
	}{
		{"WTS_SESSION_LOCK", 0x2b1, 0x7, true, actLock},
		{"WTS_CONSOLE_DISCONNECT", 0x2b1, 0x2, true, actLock},
		{"WTS_REMOTE_DISCONNECT", 0x2b1, 0x4, true, actLock},
		{"PBT_APMSUSPEND", 0x218, 0x4, true, actLock},
		{"WM_ENDSESSION TRUE", 0x16, 1, true, actEnd},
		{"WM_ENDSESSION TRUE до регистрации", 0x16, 1, false, actEnd},
		{"WM_ENDSESSION FALSE (выключение отменено)", 0x16, 0, true, actPass},
		{"WM_QUERYENDSESSION", 0x11, 0, true, actPass},
		{"WM_TIMER повтора до регистрации", 0x113, 1, false, actRetry},
		{"WM_TIMER после регистрации", 0x113, 1, true, actPass},
		{"WM_TIMER чужой", 0x113, 2, false, actPass},
		{"WTS_SESSION_LOGOFF (раньше пришёл WM_ENDSESSION)", 0x2b1, 0x6, true, actPass},
		{"WTS_CONSOLE_CONNECT", 0x2b1, 0x1, true, actPass},
		{"WTS_REMOTE_CONNECT", 0x2b1, 0x3, true, actPass},
		{"WTS_SESSION_LOGON", 0x2b1, 0x5, true, actPass},
		{"WTS_SESSION_UNLOCK", 0x2b1, 0x8, true, actPass},
		{"WTS_SESSION_REMOTE_CONTROL", 0x2b1, 0x9, true, actPass},
		{"WTS_SESSION_CREATE", 0x2b1, 0xa, true, actPass},
		{"PBT_APMRESUMESUSPEND", 0x218, 0x7, true, actPass},
		{"PBT_APMRESUMEAUTOMATIC", 0x218, 0x12, true, actPass},
		{"PBT_POWERSETTINGCHANGE", 0x218, 0x8013, true, actPass},
		{"WM_TIMER с wParam 7", 0x113, 0x7, true, actPass},
		{"WM_SETTINGCHANGE", 0x1a, 0x7, true, actPass},
		{"WM_DESTROY", 0x2, 0, true, actPass},
	} {
		if got := lockAct(c.msg, c.wp, c.reg); got != c.act {
			t.Errorf("%s (%#x, %#x, reg %v): %d, ждали %d", c.name, c.msg, c.wp, c.reg, got, c.act)
		}
	}
}

// TestLockRegPolicy — регистрация WTS: успех — жив, без таймера; отказ — не жив, повтор через текущую паузу, следующая
// вдвое больше до lockRetryMax.
func TestLockRegPolicy(t *testing.T) {
	if alive, timer, _ := regPolicy(true, lockRetry); !alive || timer != 0 {
		t.Errorf("успех: alive %v, таймер %v", alive, timer)
	}
	wait := lockRetry
	for i := 0; i < 12; i++ {
		alive, timer, next := regPolicy(false, wait)
		if alive {
			t.Fatal("отказ регистрации — alive(true)")
		}
		if timer != wait || next != min(2*wait, lockRetryMax) || timer <= 0 {
			t.Fatalf("шаг %d: таймер %v, следующая %v при паузе %v", i, timer, next, wait)
		}
		wait = next
	}
	if wait != lockRetryMax || lockRetryMax != 5*time.Minute {
		t.Errorf("пауза не дошла до предела: %v", wait)
	}
}

// TestLockSession — сеанс 0 (служба) — не отслеживать; сеанс пользователя или сбой ProcessIdToSessionId — пробовать.
func TestLockSession(t *testing.T) {
	if sessionOK(1, 0) {
		t.Error("сеанс 0 принят")
	}
	if !sessionOK(1, 2) || !sessionOK(0, 0) {
		t.Error("сеанс пользователя или неизвестный отвергнут")
	}
}
