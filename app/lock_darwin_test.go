package main

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// postDist — распределённое уведомление name из другого процесса (osascript, JXA), как его шлёт loginwindow.
func postDist(t *testing.T, name string) {
	t.Helper()
	js := "ObjC.import('Foundation'); $.NSDistributedNotificationCenter.defaultCenter." +
		"postNotificationNameObjectUserInfoDeliverImmediately('" + name + "', $(), $(), true)"
	if out, err := exec.Command("osascript", "-l", "JavaScript", "-e", js).CombinedOutput(); err != nil {
		t.Fatalf("osascript: %v %s", err, out)
	}
}

// TestMacLockLive — детектор на настоящем сеансе без своего окна (как «окно в браузере»): alive после подписки,
// чужое уведомление — не блокировка, com.apple.screenIsLocked из другого процесса — блокировка, конец ctx — alive(false).
// Шлёт в сеанс пользователя настоящее com.apple.screenIsLocked (экран не блокируется, но его видят все наблюдатели
// сеанса) — только по запросу: ANYPC_LOCK_LIVE=1 go test ./app -run MacLockLive -v
func TestMacLockLive(t *testing.T) {
	if os.Getenv("ANYPC_LOCK_LIVE") == "" {
		t.Skip("ANYPC_LOCK_LIVE не задан")
	}
	if !uiStart() {
		t.Skip("нет графического сеанса")
	}
	locked, alive := make(chan struct{}, 4), make(chan bool, 4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		macLock(ctx, func() { locked <- struct{}{} }, func(src string, ok bool) {
			if src != "nsdnc" {
				t.Errorf("источник %q", src)
			}
			alive <- ok
		})
	}()
	if !<-alive {
		t.Fatal("alive(false) при графическом сеансе")
	}
	postDist(t, "org.anypc.test.notlock")
	select {
	case <-locked:
		t.Fatal("чужое уведомление — блокировка")
	case <-time.After(time.Second):
	}
	start := time.Now()
	postDist(t, "com.apple.screenIsLocked")
	select {
	case <-locked:
		t.Logf("com.apple.screenIsLocked дошло за %v", time.Since(start))
	case <-time.After(5 * time.Second):
		t.Fatal("com.apple.screenIsLocked не дошло за 5 с")
	}
	cancel()
	<-done
	if <-alive {
		t.Error("конец ctx без alive(false)")
	}
}
