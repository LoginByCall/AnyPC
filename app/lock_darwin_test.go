package main

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// postDist — распределённое уведомление name из другого процесса (osascript, JXA), как его шлёт loginwindow;
// imm — отправитель просит доставку и приостановленным (deliverImmediately).
func postDist(t *testing.T, name string, imm bool) {
	t.Helper()
	b := "false"
	if imm {
		b = "true"
	}
	js := "ObjC.import('Foundation'); $.NSDistributedNotificationCenter.defaultCenter." +
		"postNotificationNameObjectUserInfoDeliverImmediately('" + name + "', $(), $(), " + b + ")"
	if out, err := exec.Command("osascript", "-l", "JavaScript", "-e", js).CombinedOutput(); err != nil {
		t.Fatalf("osascript: %v %s", err, out)
	}
}

// TestMacLockNames — таблица наблюдателей (lock_darwin.m): все три источника, распределённый — с DeliverImmediately,
// имена NSWorkspace совпадают с системными константами.
func TestMacLockNames(t *testing.T) {
	want := "dist com.apple.screenIsLocked immediate\n" +
		"ws NSWorkspaceWillSleepNotification -\n" +
		"ws NSWorkspaceSessionDidResignActiveNotification -\n"
	if got := lockNames(); got != want {
		t.Errorf("наблюдатели:\n%s\nждали:\n%s", got, want)
	}
}

// TestMacLockLive — детектор на настоящем сеансе без своего окна (как «окно в браузере»): alive после подписки;
// чужое уведомление — не блокировка; com.apple.screenIsLocked из другого процесса — блокировка, и при приостановке
// уведомлений процессу (как у неактивного приложения) без deliverImmediately у отправителя; сон и уход сеанса
// (центр NSWorkspace этого процесса) — блокировка; второй одновременный детектор — alive(false); конец ctx —
// alive(false), наблюдатели сняты. Шлёт в сеанс пользователя настоящее com.apple.screenIsLocked (экран не
// блокируется, но его видят все наблюдатели сеанса) — только по запросу: ANYPC_LOCK_LIVE=1 go test ./app -run MacLock -v
func TestMacLockLive(t *testing.T) {
	if os.Getenv("ANYPC_LOCK_LIVE") == "" {
		t.Skip("ANYPC_LOCK_LIVE не задан")
	}
	if !uiStart() {
		t.Skip("нет графического сеанса")
	}
	locked, alive := make(chan struct{}, 8), make(chan bool, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
	got := func(d time.Duration) bool {
		select {
		case <-locked:
			return true
		case <-time.After(d):
			return false
		}
	}
	postDist(t, "org.anypc.test.notlock", true)
	if got(time.Second) {
		t.Fatal("чужое уведомление — блокировка")
	}
	start := time.Now()
	postDist(t, "com.apple.screenIsLocked", false)
	if !got(5 * time.Second) {
		t.Fatal("com.apple.screenIsLocked не дошло за 5 с")
	}
	t.Logf("com.apple.screenIsLocked дошло за %v", time.Since(start))
	lockSuspend(true)
	postDist(t, "com.apple.screenIsLocked", false)
	ok := got(5 * time.Second)
	lockSuspend(false)
	if !ok {
		t.Error("приостановлено (неактивное приложение): com.apple.screenIsLocked не дошло — нет DeliverImmediately")
	}
	for _, n := range []string{"NSWorkspaceWillSleepNotification", "NSWorkspaceSessionDidResignActiveNotification"} {
		lockPostLocal(n)
		if !got(2 * time.Second) {
			t.Errorf("%s: не блокировка", n)
		}
	}
	second := make(chan bool, 1)
	macLock(context.Background(), func() {}, func(_ string, ok bool) { second <- ok })
	if <-second {
		t.Error("второй детектор при живом первом — alive(true)")
	}
	cancel()
	<-done
	if <-alive {
		t.Error("конец ctx без alive(false)")
	}
	lockPostLocal("NSWorkspaceWillSleepNotification")
	postDist(t, "com.apple.screenIsLocked", true)
	if got(2 * time.Second) {
		t.Error("после конца ctx наблюдатели не сняты")
	}
}
