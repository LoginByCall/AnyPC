// Блокировка экрана мастера на Windows (Э3, UI-REDESIGN.md, решение владельца 5): по ней мастер снимает выданные
// пропуска. Без cgo, как значок (tray_windows.go): скрытое окно верхнего уровня со своим циклом сообщений на
// закреплённом потоке, WTSRegisterSessionNotification(NOTIFY_FOR_THIS_SESSION). Решения — чистые функции lock_wts.go.
// Блокировка (снятие в фоне, on()) — любое из:
//   - WM_WTSSESSION_CHANGE / WTS_SESSION_LOCK — Win+L, по таймауту, перед сном с паролем при пробуждении;
//   - WTS_CONSOLE_DISCONNECT — сеанс ушёл с консоли (быстрая смена пользователя, вход в этот сеанс по RDP): к экрану
//     его вернёт только пароль Windows, перед ПК мастера владельца больше нет;
//   - WTS_REMOTE_DISCONNECT — мастер сам сеанс RDP и клиент отключился: сеанс живёт без зрителя, вернуться — с паролем;
//   - WM_POWERBROADCAST / PBT_APMSUSPEND — сон (как PrepareForSleep на Linux; сообщение — только окнам верхнего уровня).
//
// Выключение, перезагрузка, выход из сеанса — WM_ENDSESSION(TRUE): после возврата из обработчика процесс убивают,
// w.Run() в main не вернётся — снимаем синхронно здесь (lockEnd, ≤ lockEndWait).
// Ложное снятие лишь просит ввести код снова. Сеанс 0 (служба) рабочего стола пользователя не видит — alive(false),
// «Работаю тут» честно отказывает (errNoLockDetector). Регистрация не удалась (службы удалённых рабочих столов ещё не
// запущены — RPC_S_INVALID_BINDING, документация WTSRegisterSessionNotification) — alive(false) и повтор по таймеру.
package main

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	wtsapi32      = syscall.NewLazyDLL("wtsapi32.dll")
	pWTSReg       = wtsapi32.NewProc("WTSRegisterSessionNotification")
	pWTSUnreg     = wtsapi32.NewProc("WTSUnRegisterSessionNotification")
	pSessionID    = syscall.NewLazyDLL("kernel32.dll").NewProc("ProcessIdToSessionId")
	pSetTimer     = user32.NewProc("SetTimer")
	pKillTimer    = user32.NewProc("KillTimer")
	lockClass, _  = syscall.UTF16PtrFromString("AnyPCLock")
	lockClassOnce sync.Once
	lockClassErr  error
	winLockGuard  lockGuard
)

// lockEndWait — сколько WM_ENDSESSION ждёт снятия пропусков (система убивает «висящее» приложение через ~5 с).
var lockEndWait = 3 * time.Second

// lockEnd — снять пропуска мастера синхронно, пока сеанс кончается (тест подменяет).
var lockEnd = func() {
	ctx, cancel := context.WithTimeout(context.Background(), lockEndWait)
	passes.offAll(ctx)
	cancel()
}

func init() { startLock = runLock }

// lockWin — состояние детектора; трогается только из потока его окна. Один детектор на процесс (winLockGuard).
var lockWin struct {
	on    func()
	alive func(string, bool)
	reg   bool
	wait  time.Duration
}

// runLock — startLock на Windows: до конца ctx; alive("wts", …) — подписка на события сеанса есть или нет.
func runLock(ctx context.Context, on func(), alive func(string, bool)) {
	if !winLockGuard.take() {
		log.Print("блокировка экрана (wts): детектор уже запущен — второй не нужен")
		alive("wts", false)
		return
	}
	defer winLockGuard.drop()
	var sid uint32
	if r, _, _ := pSessionID.Call(uintptr(syscall.Getpid()), uintptr(unsafe.Pointer(&sid))); !sessionOK(r, sid) {
		log.Print("блокировка экрана: сеанс 0 (служба) — рабочего стола пользователя не видно, не отслеживается")
		alive("wts", false)
		return
	}
	runtime.LockOSThread() // окно принадлежит потоку (поток умрёт с горутиной)
	lockWin.on, lockWin.alive, lockWin.reg, lockWin.wait = on, alive, false, lockRetry
	defer func() { lockWin.on = nil }()
	h, err := createLockWin()
	if err != nil {
		log.Printf("блокировка экрана: %v — не отслеживается", err)
		alive("wts", false)
		return
	}
	stop := context.AfterFunc(ctx, func() { pPostMsg.Call(h, wmClose, 0, 0) })
	defer stop()
	lockReg(h)
	msgLoop()
	alive("wts", false)
	if ctx.Err() == nil { // окно пропало само — снять, как при потере шины на Linux
		log.Print("блокировка экрана: окно детектора закрылось — считаю блокировкой")
		on()
	}
}

func createLockWin() (uintptr, error) {
	inst, _, _ := pModuleHandle.Call(0)
	lockClassOnce.Do(func() { // у NewCallback конечный запас — один раз
		wc := wndClassEx{wndProc: syscall.NewCallback(lockProc), instance: inst, className: lockClass}
		wc.size = uint32(unsafe.Sizeof(wc))
		if r, _, e := pRegClass.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
			lockClassErr = fmt.Errorf("RegisterClassEx: %v", e)
		}
	})
	if lockClassErr != nil {
		return 0, lockClassErr
	}
	// скрытое окно верхнего уровня, не HWND_MESSAGE: WM_POWERBROADCAST и WM_ENDSESSION рассылаются только таким
	h, _, e := pCreateWindow.Call(0, uintptr(unsafe.Pointer(lockClass)), uintptr(unsafe.Pointer(lockClass)), 0, 0, 0, 0, 0, 0, 0, inst, 0)
	if h == 0 {
		return 0, fmt.Errorf("CreateWindowEx: %v", e)
	}
	return h, nil
}

// lockReg — подписаться на события сеанса; не вышло — alive(false) и повтор таймером (regPolicy).
func lockReg(h uintptr) {
	r, _, e := pWTSReg.Call(h, 0) // NOTIFY_FOR_THIS_SESSION
	ok, timer, next := regPolicy(r != 0, lockWin.wait)
	lockWin.reg, lockWin.wait = ok, next
	if timer > 0 {
		log.Printf("блокировка экрана: WTSRegisterSessionNotification: %v — повтор через %v", e, timer)
		pSetTimer.Call(h, lockTimerID, uintptr(timer/time.Millisecond), 0)
	} else {
		pKillTimer.Call(h, lockTimerID)
		log.Print("блокировка экрана: отслеживается (WTS)")
	}
	lockWin.alive("wts", ok)
}

func lockProc(h, msg, wp, lp uintptr) uintptr {
	if lockWin.on != nil {
		switch lockAct(msg, wp, lockWin.reg) {
		case actLock:
			log.Printf("блокировка экрана (сообщение %#x, %d)", msg, wp)
			lockWin.on()
		case actEnd:
			log.Printf("блокировка экрана: сеанс кончается (WM_ENDSESSION, %#x) — снимаю пропуска", lp)
			lockEnd()
			return 0
		case actRetry:
			lockReg(h)
			return 0
		}
	}
	if msg == wmDestroy {
		if lockWin.reg {
			pWTSUnreg.Call(h)
			lockWin.reg = false
		}
		pPostQuit.Call(0)
		return 0
	}
	r, _, _ := pDefWndProc.Call(h, msg, wp, lp) // WM_POWERBROADCAST: TRUE
	return r
}
