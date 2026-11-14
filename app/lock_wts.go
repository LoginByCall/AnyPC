package main

// Решения детектора блокировки Windows (lock_windows.go) — без ограничения сборки: чистые функции, тест идёт и на
// Linux (lock_wts_test.go). Поток, окно и вызовы API — в lock_windows.go.

import "time"

// winuser.h, wtsapi32.h
const (
	wmTimer, wmWTSSessionChange, wmPowerBroadcast = 0x113, 0x2b1, 0x218
	wmEndSession                                  = 0x16
	pbtAPMSuspend                                 = 0x4
	wtsConsoleDisconnect, wtsRemoteDisconnect     = 0x2, 0x4
	wtsSessionLock                                = 0x7
	lockTimerID                                   = 1
)

// lockAction — что окно детектора делает с сообщением.
type lockAction int

const (
	actPass  lockAction = iota // DefWindowProc
	actLock                    // on(): блокировка (снятие в фоне)
	actEnd                     // сеанс кончается (выключение, перезагрузка, выход): снять синхронно, потом вернуть 0
	actRetry                   // таймер повтора регистрации
)

// lockAct — решение по сообщению (msg, wParam); reg — подписка на события сеанса уже есть.
// Блокировка: WTS_SESSION_LOCK, WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT, PBT_APMSUSPEND. Разблокировка, вход,
// подключение, пробуждение — нет. WTS_SESSION_LOGOFF не нужен: выход из сеанса приходит раньше как WM_ENDSESSION
// (а фоновое снятие по нему опустошило бы список до синхронного — синхронное вернулось бы сразу).
func lockAct(msg, wp uintptr, reg bool) lockAction {
	switch msg {
	case wmWTSSessionChange:
		if wp == wtsSessionLock || wp == wtsConsoleDisconnect || wp == wtsRemoteDisconnect {
			return actLock
		}
	case wmPowerBroadcast:
		if wp == pbtAPMSuspend {
			return actLock
		}
	case wmEndSession: // wParam TRUE — сеанс действительно кончается; FALSE — выключение отменено
		if wp != 0 {
			return actEnd
		}
	case wmTimer:
		if wp == lockTimerID && !reg {
			return actRetry
		}
	}
	return actPass
}

// regPolicy — итог попытки WTSRegisterSessionNotification: alive — подписка есть; timer — через сколько повторить
// (0 — не нужно); next — пауза следующего повтора (растёт вдвое до lockRetryMax).
func regPolicy(ok bool, wait time.Duration) (alive bool, timer, next time.Duration) {
	if ok {
		return true, 0, wait
	}
	return false, wait, min(2*wait, lockRetryMax)
}

// sessionOK — процесс в сеансе пользователя: ProcessIdToSessionId (r ≠ 0 — успех) дал не 0. Сеанс 0 (служба)
// рабочего стола пользователя не видит; узнать не вышло — пробуем (регистрация скажет сама).
func sessionOK(r uintptr, sid uint32) bool { return r == 0 || sid != 0 }
