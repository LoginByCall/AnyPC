package main

// Блокировка экрана мастера на Маке (Э3, UI-REDESIGN.md, решение владельца 5): по ней мастер снимает выданные
// пропуска. Наблюдатели (lock_darwin.m) — на главном потоке, в общем run loop AppKit ([NSApp run], window_darwin.go):
// его запускает uiStart и в режиме «окно в браузере» (ANYPC_MACWIN не задан) — значок в строке меню или сам детектор.
// Нет графического сеанса (ssh без входа в Aqua, служба вне сеанса) — alive(false): «Работаю тут» честно отказывает.

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

var lockOn atomic.Pointer[func()] // для goLocked: один детектор на процесс

// macLock — startLock на Маке: до конца ctx; alive("nsdnc", …) — наблюдатели стоят или нет.
func macLock(ctx context.Context, on func(), alive func(string, bool)) {
	if !uiStart() {
		log.Print("блокировка экрана: нет графического сеанса — не отслеживается")
		alive("nsdnc", false)
		return
	}
	lockOn.Store(&on)
	C.anypcLockOn() // ждёт главный поток: наблюдатели стоят до alive(true)
	alive("nsdnc", true)
	log.Print("блокировка экрана: отслеживается (NSDistributedNotificationCenter)")
	<-ctx.Done()
	C.anypcLockOff()
	alive("nsdnc", false)
}

//export goLocked
func goLocked(name *C.char) {
	log.Printf("блокировка экрана (%s)", C.GoString(name))
	if f := lockOn.Load(); f != nil {
		(*f)() // главный поток: on() не ждёт (main_unix.go — go offAll)
	}
}
