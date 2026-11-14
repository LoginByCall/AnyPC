package main

// Основа — PoC приёмки Ч5 (acc_lock_windows_test.go). Только на Windows: настоящее окно и регистрация WTS; события
// сеанса шлёт сам тест (SendMessage своему окну) — система не трогается.

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

// TestLockWinLive — alive(true) после регистрации; WTS_SESSION_LOCK — on(); WM_ENDSESSION(TRUE) — синхронное снятие
// (lockEnd) до возврата из обработчика, WM_ENDSESSION(FALSE) — нет; второй runLock при живом — alive(false); конец
// ctx — alive(false) без on().
func TestLockWinLive(t *testing.T) {
	var ends atomic.Int32
	defer func(f func()) { lockEnd = f }(lockEnd)
	lockEnd = func() { ends.Add(1) } // зовётся в потоке окна, до возврата SendMessage
	locked, alive, done := make(chan struct{}, 8), make(chan bool, 8), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		defer close(done)
		runLock(ctx, func() { locked <- struct{}{} }, func(_ string, ok bool) { alive <- ok })
	}()
	select {
	case ok := <-alive:
		if !ok {
			t.Skip("WTS не зарегистрирован (сеанс 0?)")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("нет alive")
	}
	h, _, _ := user32.NewProc("FindWindowW").Call(uintptr(unsafe.Pointer(lockClass)), 0)
	if h == 0 {
		t.Fatal("окно детектора не найдено")
	}
	send := user32.NewProc("SendMessageW")
	got := func() bool {
		select {
		case <-locked:
			return true
		case <-time.After(500 * time.Millisecond):
			return false
		}
	}
	send.Call(h, wmWTSSessionChange, wtsSessionLock, 0)
	if !got() {
		t.Error("WTS_SESSION_LOCK: on() не вызван")
	}
	send.Call(h, 0x16, 0, 0) // WM_ENDSESSION FALSE: выключение отменено
	if ends.Load() != 0 {
		t.Error("WM_ENDSESSION(FALSE) снял пропуска")
	}
	send.Call(h, 0x11, 0, 0)          // WM_QUERYENDSESSION
	send.Call(h, 0x16, 1, 0x80000000) // WM_ENDSESSION TRUE, ENDSESSION_LOGOFF
	if n := ends.Load(); n != 1 {
		t.Errorf("WM_ENDSESSION(TRUE): синхронных снятий %d, ждали 1", n)
	}
	second := make(chan bool, 1)
	runLock(context.Background(), func() {}, func(_ string, ok bool) { second <- ok })
	if <-second {
		t.Error("второй runLock при живом первом — alive(true)")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runLock не вышел по ctx")
	}
	if ok := <-alive; ok {
		t.Error("конец ctx без alive(false)")
	}
	if got() {
		t.Error("конец ctx вызвал on()")
	}
}
