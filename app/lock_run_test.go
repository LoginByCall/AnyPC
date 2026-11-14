package main

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

type lockTrace struct {
	mu sync.Mutex
	ev []string
}

func (r *lockTrace) add(s string) { r.mu.Lock(); r.ev = append(r.ev, s); r.mu.Unlock() }
func (r *lockTrace) get() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ev...)
}

func (r *lockTrace) run(ctx context.Context, g *lockGuard, ready bool, tag string) {
	lockRun(ctx, "nsdnc", g, func() bool { r.add(tag + "ready"); return ready },
		func() { r.add(tag + "sub") }, func() { r.add(tag + "unsub") },
		func(src string, ok bool) { r.add(fmt.Sprintf("%salive %s %v", tag, src, ok)) })
}

func waitTrace(t *testing.T, r *lockTrace, n int) []string {
	t.Helper()
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if ev := r.get(); len(ev) >= n {
			return ev
		}
	}
	t.Fatalf("событий %v, ждали %d", r.get(), n)
	return nil
}

// TestLockRun — порядок детектора Мака (lock_run.go): подписка до alive(true), отписка до alive(false); нет
// графического сеанса — alive(false) без подписки.
func TestLockRun(t *testing.T) {
	var g lockGuard
	r := &lockTrace{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.run(ctx, &g, true, ""); close(done) }()
	if ev, want := waitTrace(t, r, 3), []string{"ready", "sub", "alive nsdnc true"}; !reflect.DeepEqual(ev, want) {
		t.Fatalf("старт: %v, ждали %v", ev, want)
	}
	cancel()
	<-done
	if ev, want := r.get()[3:], []string{"unsub", "alive nsdnc false"}; !reflect.DeepEqual(ev, want) {
		t.Errorf("конец ctx: %v, ждали %v", ev, want)
	}

	r = &lockTrace{}
	r.run(context.Background(), &g, false, "") // ctx не кончится: без сеанса lockRun обязан вернуться сам
	if ev, want := r.get(), []string{"ready", "alive nsdnc false"}; !reflect.DeepEqual(ev, want) {
		t.Errorf("без сеанса: %v, ждали %v", ev, want)
	}
}

// TestLockDouble — второй одновременный детектор (общий наблюдатель или окно) — alive(false) без подписки; первый
// при этом жив; после конца первого снова можно (страж снят, в т.ч. после отказа «нет сеанса»).
func TestLockDouble(t *testing.T) {
	var g lockGuard
	r := &lockTrace{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.run(ctx, &g, true, "1:"); close(done) }()
	waitTrace(t, r, 3)
	r.run(context.Background(), &g, true, "2:")
	if ev, want := r.get()[3:], []string{"2:alive nsdnc false"}; !reflect.DeepEqual(ev, want) {
		t.Errorf("второй при живом первом: %v, ждали %v", ev, want)
	}
	cancel()
	<-done
	r = &lockTrace{}
	r.run(context.Background(), &g, false, "3:")
	ctx, cancel = context.WithCancel(context.Background())
	go func() { r.run(ctx, &g, true, "4:") }()
	if ev := waitTrace(t, r, 5); ev[4] != "4:alive nsdnc true" {
		t.Errorf("после первого: %v", ev)
	}
	cancel()
}
