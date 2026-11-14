package main

// Блокировка экрана мастера на Маке (Э3, UI-REDESIGN.md, решение владельца 5): по ней мастер снимает выданные
// пропуска. Наблюдатели (lock_darwin.m, таблица lockObs) — на главном потоке, в общем run loop AppKit
// ([NSApp run], window_darwin.go): его запускает uiStart и в режиме «окно в браузере» (ANYPC_MACWIN не задан) —
// значок в строке меню или сам детектор. uiStart = false, только когда в консоль никто не вошёл
// (CGSessionCopyCurrentDictionary = NULL: служба вне сеанса пользователя, Мак на экране входа); ssh при пользователе,
// вошедшем в консоль, — true. Тогда alive(false): «Работаю тут» честно отказывает. Ход — lockRun (lock_run.go).

/*
#include <stdlib.h>
void anypcLockOn(void);
void anypcLockOff(void);
char *anypcLockNames(void);
void anypcLockPostLocal(const char *name);
void anypcLockSuspend(int on);
*/
import "C"

import (
	"context"
	"log"
	"sync/atomic"
	"unsafe"
)

func init() { startLock = macLock }

var (
	lockOn       atomic.Pointer[func()] // для goLocked
	macLockGuard lockGuard              // наблюдатель один на процесс (lockObs)
)

// macLock — startLock на Маке: до конца ctx; alive("nsdnc", …) — наблюдатели стоят или нет.
func macLock(ctx context.Context, on func(), alive func(string, bool)) {
	lockRun(ctx, "nsdnc", &macLockGuard, uiStart,
		func() { lockOn.Store(&on); C.anypcLockOn() },  // ждёт главный поток: наблюдатели стоят до alive(true)
		func() { C.anypcLockOff(); lockOn.Store(nil) }, // ждёт главный поток: сняты до alive(false)
		alive)
}

// lockNames — таблица наблюдателей из lock_darwin.m строками «центр имя поведение» (для теста).
func lockNames() string {
	p := C.anypcLockNames()
	defer C.free(unsafe.Pointer(p))
	return C.GoString(p)
}

// lockPostLocal — уведомление name в центр NSWorkspace этого процесса (только тест: систему не трогает).
func lockPostLocal(name string) {
	c := C.CString(name)
	defer C.free(unsafe.Pointer(c))
	C.anypcLockPostLocal(c)
}

// lockSuspend — приостановка распределённых уведомлений процессу, как у неактивного приложения (только тест).
func lockSuspend(on bool) {
	v := C.int(0)
	if on {
		v = 1
	}
	C.anypcLockSuspend(v)
}

//export goLocked
func goLocked(name *C.char) {
	log.Printf("блокировка экрана (%s)", C.GoString(name))
	if f := lockOn.Load(); f != nil {
		(*f)() // главный поток: on() не ждёт (main_unix.go — go offAll)
	}
}
