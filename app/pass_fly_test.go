package main

// Основа — PoC приёмки Ч5, круги 3–4 (acc2_offall_test.go, acc3_race_test.go): синхронный offAll (WM_ENDSESSION, выход) не возвращается,
// пока «снять» фонового offAll (блокировка) ещё в пути. Без p.bg.Wait(): ждёт сам offAll.

import (
	"context"
	"errors"
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

// flyIdle — после всех offAll в p.flying никого нет (иначе следующий синхронный offAll ждал бы до конца ctx).
func flyIdle(t *testing.T, p *passMaster) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.flying) != 0 {
		t.Errorf("p.flying после доставки: %d", len(p.flying))
	}
}

// TestPassThreeParty — блокировка даёт два события (два фоновых offAll: A летит, C ждёт A), затем выход (B, синхронный,
// тоже ждёт A). «Снять» A не дошло: кто бы из C и B ни взял retry первым, B возвращается не раньше доставки.
func TestPassThreeParty(t *testing.T) {
	for i := range 20 {
		var calls, done atomic.Int32
		p := flyMaster(t, func(context.Context, agent.PassDial) error {
			n := calls.Add(1)
			time.Sleep(60 * time.Millisecond)
			if n == 1 {
				return errors.New("нет ответа") // A: хаб не ответил
			}
			done.Add(1)
			return nil
		})
		bg := context.WithoutCancel(context.Background())
		fin := make(chan struct{}, 2)
		go func() { p.offAll(bg); fin <- struct{}{} }() // A
		waitStarted(&calls)
		go func() { p.offAll(bg); fin <- struct{}{} }() // C
		time.Sleep(10 * time.Millisecond)
		quit, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		p.offAll(quit) // B
		cancel()
		if done.Load() == 0 {
			t.Fatalf("круг %d: синхронный offAll вернулся, пока «снять» в пути (попыток %d, дошло 0)", i, calls.Load())
		}
		<-fin
		<-fin
		if n := calls.Load(); n != 2 {
			t.Errorf("круг %d: «снять» послано %d раз, ждали 2 (неудача и одна доставка)", i, n)
		}
		flyIdle(t, p)
	}
}

// TestPassRetryOnce — неудачное «снять» уходит в retry; следующий offAll берёт его и доставляет; третий не шлёт
// ничего (retry обнулён, p.flying пуст).
func TestPassRetryOnce(t *testing.T) {
	var calls atomic.Int32
	p := flyMaster(t, func(context.Context, agent.PassDial) error {
		if calls.Add(1) == 1 {
			return errors.New("нет ответа")
		}
		return nil
	})
	gone, stop := context.WithCancel(context.Background())
	stop() // повтор в фоне сразу кончается: цель остаётся в retry
	p.offAll(gone)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	p.offAll(ctx)
	if n := calls.Load(); n != 2 {
		t.Fatalf("после второго offAll попыток %d, ждали 2", n)
	}
	p.offAll(ctx)
	if n := calls.Load(); n != 2 {
		t.Errorf("третий offAll послал «снять» ещё раз (попыток %d): retry не обнулён", n)
	}
	flyIdle(t, p)
}
