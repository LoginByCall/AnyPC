//go:build lockprobe

package main

// Проба детектора блокировки Мака (lock_probe_darwin.m) — только с тегом lockprobe: go test -tags lockprobe ./app -run MacLock

/*
#include <stdlib.h>
char *anypcLockProbeNames(void);
int anypcLockProbeHits(void);
void anypcLockProbePost(const char *name);
void anypcLockProbeSuspend(int on);
*/
import "C"

import "unsafe"

// lockNames — таблица наблюдателей строками «центр имя поведение, переданное при подписке».
func lockNames() string {
	p := C.anypcLockProbeNames()
	defer C.free(unsafe.Pointer(p))
	return C.GoString(p)
}

// lockHits — сколько раз сработал наблюдатель (без оглядки на lockOn).
func lockHits() int { return int(C.anypcLockProbeHits()) }

// lockPostLocal — уведомление name в центр NSWorkspace этого процесса.
func lockPostLocal(name string) {
	c := C.CString(name)
	defer C.free(unsafe.Pointer(c))
	C.anypcLockProbePost(c)
}

// lockSuspend — приостановка распределённых уведомлений процессу, как у неактивного приложения.
func lockSuspend(on bool) {
	v := C.int(0)
	if on {
		v = 1
	}
	C.anypcLockProbeSuspend(v)
}
