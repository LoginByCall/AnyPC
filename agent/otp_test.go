package agent

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anypc/totp"
)

// otpHost — второй фактор хоста как в app/config.go: секрет (пусто — не настроен) и шаг последнего принятого кода.
type otpHost struct {
	mu     sync.Mutex
	secret string
	last   int64
}

func (o *otpHost) check(code string) (set, ok bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.secret == "" {
		return false, false
	}
	step, ok := totp.Check(o.secret, code, time.Now(), o.last)
	if ok {
		o.last = step
	}
	return true, ok
}

// lock — счётчик неудач и блокировка хоста.
func lock(a *Agent) (int, time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fails, time.Until(a.lockUntil)
}

func (o *otpHost) code() string { c, _ := totp.Code(o.secret, time.Now()); return c }

// TestOTP — вход без подтверждения с TOTP (PLAN.md): верный код — вход; повтор того же кода — отказ;
// неверный — отказ и общий с паролем счётчик перебора (верный пароль его не сбрасывает); без кода — нет входа.
func TestOTP(t *testing.T) {
	o := &otpHost{secret: totp.NewSecret()}
	var ag *Agent
	var asks atomic.Int32
	e2eAgent = func(a *Agent) { ag = a; a.OTP = o.check }
	e2eSeen = func(m authMsg) {
		if m.T == "otp" {
			asks.Add(1)
		}
	}
	defer func() { e2eAgent, e2eSeen, e2eOTP, e2eFail, authWait = nil, nil, nil, false, 20*time.Second }()
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})

	var used string
	e2eOTP = func(int) string { used = o.code(); return used }
	e2e(t, local(t), "123456789", false, ff, "secret123")
	if asks.Load() != 1 {
		t.Fatalf("код спрошен %d раз", asks.Load())
	}

	e2eFail = true
	e2eOTP = func(int) string { // повтор принятого кода (тот же шаг) — отказ и новый запрос; после 5 — блокировка
		return used
	}
	asks.Store(0)
	e2e(t, local(t), "123456789", false, ff, "secret123")
	if f, l := lock(ag); asks.Load() != 5 || f != 5 || l < 50*time.Second {
		t.Fatalf("повтор кода: запросов %d, неудач %d, блокировка %v", asks.Load(), f, l)
	}

	e2eAgent = func(a *Agent) { ag = a; a.OTP = o.check; a.fails = 4 }
	e2eOTP = func(int) string { c := []byte(o.code()); c[0] = '0' + (c[0]-'0'+1)%10; return string(c) }
	asks.Store(0)
	e2e(t, local(t), "123456789", false, ff, "secret123") // верный пароль не сбросил 4 неудачи: первый неверный код — блокировка
	if f, l := lock(ag); asks.Load() != 1 || f != 5 || l < 50*time.Second {
		t.Fatalf("неверный код: запросов %d, неудач %d, блокировка %v", asks.Load(), f, l)
	}

	e2eAgent = func(a *Agent) { ag = a; a.OTP = o.check }
	authWait = time.Second
	e2eOTP = func(int) string { return "" } // клиент молчит — хост закрывает сессию сам
	t0 := time.Now()
	e2e(t, local(t), "123456789", false, ff, "secret123")
	if d := time.Since(t0); d > 8*time.Second {
		t.Fatalf("без кода сессия жила %v", d)
	}
}

// TestOTPConfirm — с окном «Разрешить» код не спрашивается, даже если TOTP настроен.
func TestOTPConfirm(t *testing.T) {
	o := &otpHost{secret: totp.NewSecret()}
	var asks atomic.Int32
	e2eAgent = func(a *Agent) {
		a.OTP = o.check
		a.Unattended = func() bool { return false }
		a.Confirm = func(string, string) Answer { return Allow }
	}
	e2eSeen = func(m authMsg) {
		if m.T == "otp" {
			asks.Add(1)
		}
	}
	defer func() { e2eAgent, e2eSeen = nil, nil }()
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
	if asks.Load() != 0 {
		t.Fatal("с подтверждением спрошен код TOTP")
	}
}

// TestOTPUpgrade — хост обновлён с выключенным подтверждением, TOTP нет: паролем без человека не пускает —
// спрашивает «Разрешить» (клиенту — причина nootp), «Отклонить» — отказ; после настройки TOTP — снова сам, по коду.
// Без окна (Confirm == nil) такой хост отказывает.
func TestOTPUpgrade(t *testing.T) {
	o := &otpHost{}
	answer := Deny
	var asked, nootp, otpAsked atomic.Bool
	e2eAgent = func(a *Agent) {
		a.OTP = o.check
		a.Unattended = func() bool { return true }
		a.Confirm = func(string, string) Answer { asked.Store(true); return answer }
	}
	e2eSeen = func(m authMsg) {
		nootp.Store(nootp.Load() || m.T == "ask" && m.NoOTP)
		otpAsked.Store(otpAsked.Load() || m.T == "otp")
	}
	defer func() { e2eAgent, e2eSeen, e2eOTP, e2eDeny, e2eFail = nil, nil, nil, false, false }()
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
	e2eDeny = true
	e2e(t, local(t), "123456789", false, ff, "secret123")
	if !asked.Load() || !nootp.Load() || otpAsked.Load() {
		t.Fatalf("без TOTP: окно %v, причина клиенту %v, код %v", asked.Load(), nootp.Load(), otpAsked.Load())
	}
	e2eDeny, answer = false, Allow
	e2e(t, local(t), "123456789", false, ff, "secret123")

	o.secret = totp.NewSecret() // настроили TOTP — без окна, по коду
	asked.Store(false)
	e2eOTP = func(int) string { return o.code() }
	e2e(t, local(t), "123456789", false, ff, "secret123")
	if asked.Load() || !otpAsked.Load() {
		t.Fatalf("после настройки TOTP: окно %v, код %v", asked.Load(), otpAsked.Load())
	}

	o.secret = ""
	e2eAgent = func(a *Agent) { a.OTP = o.check } // Confirm == nil: спросить некого
	e2eFail = true
	e2e(t, local(t), "123456789", false, ff, "secret123")
}
