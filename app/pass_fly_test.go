package main

// Основа — PoC приёмки Ч5, круг 3 (acc2_offall_test.go): синхронный offAll (WM_ENDSESSION, выход) не возвращается,
// пока «снять» фонового offAll (блокировка) ещё в пути. Без p.bg.Wait(): ждёт сам offAll.

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"anypc/agent"
	"anypc/totp"
)

// flyMaster — мастер с одним выданным пропуском; off — «снять» (passOffFn).
func flyMaster(t *testing.T, off func(context.Context, agent.PassDial) error) *passMaster {
	t.Helper()
	sec := totp.NewSecret()
	c, _, _ := passSpace(t, sec, "200000001")
	oldOpen, oldOff := passOpenFn, passOffFn
	t.Cleanup(func() { passOpenFn, passOffFn = oldOpen, oldOff })
	passOpenFn = func(context.Context, agent.PassDial) ([]byte, error) { return nil, nil }
	passOffFn = off
	p := testMaster(c)
	code, _ := totp.Code(sec, time.Now())
	if _, err := p.workHere(context.Background(), spacePass, code); err != nil {
		t.Fatal(err)
	}
	return p
}

func waitStarted(n *atomic.Int32) {
	for n.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
}

// TestPassLockThenEnd — Win+L (фоновый offAll), сразу выключение (WM_ENDSESSION: синхронный offAll): синхронный
// возвращается не раньше, чем «снять» дошло.
func TestPassLockThenEnd(t *testing.T) {
	var started, done atomic.Int32
	p := flyMaster(t, func(context.Context, agent.PassDial) error {
		started.Add(1)
		time.Sleep(400 * time.Millisecond)
		done.Add(1)
		return nil
	})
	go p.offAll(context.Background())
	waitStarted(&started)
	quit, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	p.offAll(quit)
	if done.Load() == 0 {
		t.Error("синхронное снятие вернулось, пока «снять» в пути: пропуск остался бы на цели")
	}
	if started.Load() != 1 {
		t.Errorf("«снять» послано %d раз, ждали 1 (дошедшее не повторять)", started.Load())
	}
}

// TestPassLockThenQuit — фоновый offAll в пути, его ctx отменён (выход), offAll выхода перенимает неудачное «снять».
func TestPassLockThenQuit(t *testing.T) {
	var started, done atomic.Int32
	p := flyMaster(t, func(ctx context.Context, _ agent.PassDial) error {
		started.Add(1)
		select {
		case <-ctx.Done():
			time.Sleep(50 * time.Millisecond) // сеть отпускает вызов не мгновенно
			return ctx.Err()
		case <-time.After(400 * time.Millisecond):
			done.Add(1)
			return nil
		}
	})
	app, stop := context.WithCancel(context.Background())
	go p.offAll(app)
	waitStarted(&started)
	stop()
	quit, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	p.offAll(quit)
	if done.Load() == 0 {
		t.Errorf("выход: «снять» начато %d, дошло 0 — процесс завершается с живым пропуском на цели", started.Load())
	}
}

// TestPassFlyBounded — летящее «снять» висит дольше ctx синхронного offAll: тот возвращается по своему ctx.
func TestPassFlyBounded(t *testing.T) {
	var started atomic.Int32
	release := make(chan struct{})
	p := flyMaster(t, func(context.Context, agent.PassDial) error {
		started.Add(1)
		<-release
		return nil
	})
	defer close(release)
	go p.offAll(context.Background())
	waitStarted(&started)
	quit, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	begin := time.Now()
	p.offAll(quit)
	if d := time.Since(begin); d > 2*time.Second {
		t.Errorf("синхронный offAll ждал %v при ctx 200 мс", d)
	}
}
