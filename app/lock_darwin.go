package main

// Блокировка экрана мастера на Маке (Э3, UI-REDESIGN.md, решение владельца 5): по ней мастер снимает выданные
// пропуска. Наблюдатели (lock_darwin.m, таблица anypcLockObs) — на главном потоке, в общем run loop AppKit
// ([NSApp run], window_darwin.go): его запускает uiStart и в режиме «окно в браузере» (ANYPC_MACWIN не задан) —
// значок в строке меню или сам детектор. uiStart = false, только когда в консоль никто не вошёл
// (CGSessionCopyCurrentDictionary = NULL: служба вне сеанса пользователя, Мак на экране входа); ssh при пользователе,
// вошедшем в консоль, — true. Тогда alive(false): «Работаю тут» честно отказывает. Ход — lockRun (lock_run.go).
// Проверка на настоящем сеансе — go test -tags lockprobe ./app -run MacLock (lock_probe_darwin*.go).

/*
void anypcLockOn(void);
void anypcLockOff(void);
*/
import "C"

import (
	"context"
	"log"
	"sync/atomic"
)

func init() { startLock = macLock }

var (
	lockOn       atomic.Pointer[func()] // для goLocked
	macLockGuard lockGuard              // наблюдатель один на процесс (lockObj)
)

// macLock — startLock на Маке: до конца ctx; alive("nsdnc", …) — наблюдатели стоят или нет.
func macLock(ctx context.Context, on func(), alive func(string, bool)) {
	lockRun(ctx, "nsdnc", &macLockGuard, uiStart,
		func() { lockOn.Store(&on); C.anypcLockOn() },  // ждёт главный поток: наблюдатели стоят до alive(true)
		func() { C.anypcLockOff(); lockOn.Store(nil) }, // ждёт главный поток: сняты до alive(false)
		alive)
}

//export goLocked
func goLocked(name *C.char) {
	log.Printf("блокировка экрана (%s)", C.GoString(name))
	if f := lockOn.Load(); f != nil {
		(*f)() // главный поток: on() не ждёт (main_unix.go — go offAll)
	}
}
