package agent

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anypc/pake"
)

// TestCodeRotate — REQ-S-23: вход одноразовым кодом и «Разрешить»; после сессии хост просит новый код (CodeUsed) —
// старый уже не входит; блокировка перебора записи по умолчанию — тоже новый код, а неудачи ниже порога и чужие
// имена — нет.
func TestCodeRotate(t *testing.T) {
	var mu sync.Mutex
	code, kdf := "111111", pake.KDF("111111", salt)
	var used, asked atomic.Int32
	e2eAgent = func(a *Agent) {
		a.Secret = func(u string) ([]byte, []byte, bool) {
			mu.Lock()
			defer mu.Unlock()
			if u != "" {
				return nil, nil, false
			}
			return salt, kdf, false
		}
		a.Unattended = func() bool { return false }
		a.Confirm = func(string, string) Answer { asked.Add(1); return Allow }
		a.CodeUsed = func() {
			mu.Lock()
			code, kdf = "222222", pake.KDF("222222", salt)
			mu.Unlock()
			used.Add(1)
		}
	}
	defer e2eReset()
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
	e2eGood = "111111"
	e2e(t, local(t), "123456789", false, ff, "111111")
	for i := 0; used.Load() == 0 && i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	mu.Lock()
	now := code
	mu.Unlock()
	if asked.Load() != 1 || used.Load() != 1 || now != "222222" {
		t.Fatalf("после сессии: окно %d, смена кода %d", asked.Load(), used.Load())
	}
	e2eGood = "222222"
	e2e(t, local(t), "123456789", false, ff, "111111") // старый код — отказ
	if used.Load() != 1 {
		t.Fatalf("неверный код сменил код: %d", used.Load())
	}

	a := newAgent("", "123456789", nil)
	var n atomic.Int32
	a.CodeUsed = func() { n.Add(1) }
	for range 4 {
		a.authResult("c1", "", false)
		a.authResult("c1", "ivan", false)
	}
	time.Sleep(100 * time.Millisecond)
	if n.Load() != 0 {
		t.Fatalf("до блокировки код сменён %d раз", n.Load())
	}
	a.authResult("c1", "", false) // 5-я неудача записи по умолчанию — блокировка
	for i := 0; n.Load() == 0 && i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if n.Load() != 1 {
		t.Fatalf("блокировка: код сменён %d раз", n.Load())
	}
}

// TestAskLoop — «Разрешить» не раньше AskDelay: согласие раньше — окно снова, позже — засчитано; отказ — сразу;
// всего не дольше AskTimeout.
func TestAskLoop(t *testing.T) {
	d, sp, to := AskDelay, askSpawn, AskTimeout
	defer func() { AskDelay, askSpawn = d, sp }()
	AskDelay, askSpawn = 150*time.Millisecond, 50*time.Millisecond
	shows := 0
	early := func(wait time.Duration, a Answer) func(time.Duration, bool) Answer {
		return func(left time.Duration, _ bool) Answer {
			shows++
			if left > to {
				t.Errorf("окно дольше AskTimeout: %v", left)
			}
			if shows == 1 {
				return a // сразу
			}
			time.Sleep(wait)
			return a
		}
	}
	if a := askLoop(early(300*time.Millisecond, Allow)); a != Allow || shows != 2 {
		t.Fatalf("раннее «Разрешить»: %v, окон %d", a, shows)
	}
	shows = 0
	if a := askLoop(early(300*time.Millisecond, ViewOnly)); a != ViewOnly || shows != 2 {
		t.Fatalf("ранний «Только просмотр»: %v, окон %d", a, shows)
	}
	shows = 0
	if a := askLoop(early(0, Deny)); a != Deny || shows != 1 {
		t.Fatalf("отказ: %v, окон %d", a, shows)
	}
	t0 := time.Now()
	AskDelay = time.Hour // согласие всегда «раньше» — до конца AskTimeout и отказ
	if a := askLoop(func(left time.Duration, _ bool) Answer { time.Sleep(min(left, 5*time.Second)); return Allow }); a != Deny || time.Since(t0) > to+time.Second {
		t.Fatalf("без засчитанного согласия: %v за %v", a, time.Since(t0))
	}
}

// TestAskLoopFromFirst — регрессия (канбан 2026-11-13, «окно запроса всплывает снова и снова»): задержка считается от
// ПЕРВОГО окна. Раньше отсчёт начинался заново в каждом окне, и щелчок через 120 мс в каждом окне давал бесконечный повтор.
// Повторное окно получает again=true (пояснение сверху), первое — false.
func TestAskLoopFromFirst(t *testing.T) {
	d, sp := AskDelay, askSpawn
	defer func() { AskDelay, askSpawn = d, sp }()
	AskDelay, askSpawn = 150*time.Millisecond, 50*time.Millisecond // порог 200 мс
	var flags []bool
	a := askLoop(func(left time.Duration, again bool) Answer {
		flags = append(flags, again)
		time.Sleep(120 * time.Millisecond) // каждое окно — раньше порога, вместе — позже
		return Allow
	})
	if a != Allow || len(flags) != 2 || flags[0] || !flags[1] {
		t.Fatalf("ожидалось «Разрешить» со 2-го окна (again=false,true), получено %v, окна %v", a, flags)
	}
	if s := againText("T", "ru", false, true); !strings.HasPrefix(s, "⚠ ") || !strings.HasSuffix(s, "\n\nT") {
		t.Fatalf("пояснение повтора: %q", s)
	}
	if againText("T", "ru", true, false) != "T" {
		t.Fatal("первое окно — без пояснения")
	}
}

// TestDropPending — приёмка otc Д3: код сменили, пока вход ждал «Разрешить», — вход закрыт (его CPace построен на
// старом коде), «Разрешить» после этого не впускает.
func TestDropPending(t *testing.T) {
	var ag *Agent
	e2eAgent = func(a *Agent) {
		ag = a
		a.Unattended = func() bool { return false }
		a.Confirm = func(string, string) Answer { ag.DropPending(); time.Sleep(200 * time.Millisecond); return Allow }
	}
	defer e2eReset()
	e2eGood = "-" // ждём отказ
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
}
