package main

// Решения детектора блокировки Windows (lock_windows.go) — без ограничения сборки: чистые функции, тест идёт и на
// Linux (lock_wts_test.go). Поток, окно и вызовы API — в lock_windows.go.

import "time"

// winuser.h, wtsapi32.h
const (
	wmTimer, wmWTSSessionChange, wmPowerBroadcast = 0x113, 0x2b1, 0x218
	wmEndSession, wmDestroyLock                   = 0x16, 0x2
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

// wtsDetector — склейка окна детектора Windows без вызовов API (они — функции из lock_windows.go): регистрация с
// повтором, alive только по итогу регистрации, синхронное снятие при конце сеанса. Трогается только из потока окна.
type wtsDetector struct {
	register   func() (bool, error) // WTSRegisterSessionNotification
	setTimer   func(time.Duration)  // SetTimer(lockTimerID)
	killTimer  func()
	unregister func() // WTSUnRegisterSessionNotification
	on, end    func() // блокировка (снятие в фоне); конец сеанса (снятие синхронно, до возврата)
	alive      func(string, bool)
	logf       func(string, ...any)
	reg        bool
	wait       time.Duration
}

// tryReg — попытка регистрации: alive(итог) — после ответа системы; отказ — таймер повтора.
func (d *wtsDetector) tryReg() {
	r, err := d.register()
	ok, timer, next := regPolicy(r, d.wait)
	d.reg, d.wait = ok, next
	if timer > 0 {
		d.logf("блокировка экрана: WTSRegisterSessionNotification: %v — повтор через %v", err, timer)
		d.setTimer(timer)
	} else {
		d.killTimer()
		d.logf("блокировка экрана: отслеживается (WTS)")
	}
	d.alive("wts", ok)
}

// handle — сообщение окна; true — обработано (окно вернёт 0), false — DefWindowProc. Конец сеанса — end() до
// возврата: после него процесс убивают.
func (d *wtsDetector) handle(msg, wp uintptr) bool {
	switch lockAct(msg, wp, d.reg) {
	case actLock:
		d.logf("блокировка экрана (сообщение %#x, %d)", msg, wp)
		d.on()
		return false // WM_POWERBROADCAST: DefWindowProc вернёт TRUE
	case actEnd:
		d.logf("блокировка экрана: сеанс кончается (WM_ENDSESSION) — снимаю пропуска")
		d.end()
		return true
	case actRetry:
		d.tryReg()
		return true
	}
	if msg == wmDestroyLock {
		if d.reg {
			d.unregister()
			d.reg = false
		}
		return true
	}
	return false
}
