package agent

import (
	"sync/atomic"
	"testing"
	"time"
)

// Регрессия повторной приёмки otc (Д3): DropPending закрывает вход, ещё не приславший «b» (старый код), и не трогает вошедшую сессию.
func TestDropPendingAuthed(t *testing.T) {
	var ag *Agent
	var dropped, authedAlive atomic.Bool
	var asked atomic.Int32
	e2eAgent = func(a *Agent) {
		ag = a
		a.Unattended = func() bool { return false }
		a.Confirm = func(string, string) Answer { asked.Add(1); return Allow }
	}
	e2eSeen = func(m authMsg) {
		if m.T == "a" && !dropped.Swap(true) { // вход открыт, «a» получено, «b» ещё не ушло — код сменили
			ag.mu.Lock()
			n := len(ag.pend)
			ag.mu.Unlock()
			ag.DropPending()
			t.Logf("незавершённых входов в момент смены кода: %d", n)
		}
	}
	defer e2eReset()
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
	e2eGood = "-" // ждём отказ: соединение закрыто до проверки пароля
	e2e(t, local(t), "123456789", false, ff, "secret123")
	t.Logf("вход, открытый до смены кода: окно «Разрешить» показано %d раз", asked.Load())
	if asked.Load() != 0 {
		t.Error("незавершённый вход пережил смену кода")
	}
	// вошедшая сессия смену кода переживает
	e2eSeen, e2eGood = nil, ""
	e2eInput = func(t *testing.T, a *Agent) {
		a.DropPending()
		time.Sleep(400 * time.Millisecond)
		a.mu.Lock()
		authedAlive.Store(a.sess != nil && a.sess.authed.Load() && !a.sess.gone.Load())
		a.mu.Unlock()
	}
	e2e(t, local(t), "123456789", false, ff, "secret123")
	t.Logf("вошедшая сессия после DropPending жива: %v", authedAlive.Load())
	if !authedAlive.Load() {
		t.Error("DropPending разорвал вошедшую сессию")
	}
}
