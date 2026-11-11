package agent

import (
	"bytes"
	"encoding/base64"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anypc/pake"
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
	defer func() {
		e2eAgent, e2eSeen, e2eOTP, e2eFail = nil, nil, nil, false
		otpWait90.Store(int64(90 * time.Second))
	}()
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
	otpWait90.Store(int64(time.Second))
	var denied atomic.Bool
	e2eSeen = func(m authMsg) { denied.Store(denied.Load() || m.T == "denied") }
	e2eOTP = func(int) string { return "" } // клиент молчит — хост отказывает сам
	t0 := time.Now()
	e2e(t, local(t), "123456789", false, ff, "secret123")
	if d := time.Since(t0); d > 8*time.Second || !denied.Load() {
		t.Fatalf("без кода: сессия жила %v, отказ %v", d, denied.Load())
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

// TestHostViewOnly — «Только показ экрана» на хосте: клиент просит полный доступ, а сессия — только просмотр
// (view в "ok", ввод не доходит), и «Разрешить» в окне тоже даёт только просмотр; без галочки — как раньше.
func TestHostViewOnly(t *testing.T) {
	var on atomic.Bool
	var gotView atomic.Bool
	var held atomic.Int32
	e2eAgent = func(a *Agent) {
		a.ViewOnly = on.Load
		a.Unattended = func() bool { return false }
		a.Confirm = func(string, string) Answer { return Allow }
	}
	e2eSeen = func(m authMsg) {
		if m.T == "ok" {
			gotView.Store(m.View)
		}
	}
	e2eInput = func(t *testing.T, a *Agent) { // клиент нажал ControlLeft: дошло — клавиша числится зажатой
		a.mu.Lock()
		s := a.sess
		a.mu.Unlock()
		s.keys.mu.Lock()
		held.Store(int32(len(s.keys.keys)))
		s.keys.mu.Unlock()
	}
	defer func() { e2eAgent, e2eSeen, e2eInput = nil, nil, nil }()
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
	on.Store(true)
	e2e(t, local(t), "123456789", false, ff, "secret123")
	if !gotView.Load() || held.Load() != 0 {
		t.Fatalf("только показ: view=%v, зажато клавиш %d", gotView.Load(), held.Load())
	}
	on.Store(false)
	e2e(t, local(t), "123456789", false, ff, "secret123")
	if gotView.Load() || held.Load() != 1 {
		t.Fatalf("без галочки: view=%v, зажато клавиш %d", gotView.Load(), held.Load())
	}
}

// TestOTPTrustedLock — У3 с TOTP: хост заблокирован чужим перебором паролей, а владелец с закреплённым ключом,
// верным паролем и верным кодом входит; неверные коды от кого угодно — одна лестница (и в общий счётчик): с ключом
// и без вор получает 5 кодов, не больше; на шаге кода блокировка действует и на верный код.
func TestOTPTrustedLock(t *testing.T) {
	k, _ := pake.ClientSignB64(e2eSeed(), "", "", "")
	pub, _ := base64.StdEncoding.DecodeString(k["pub"])
	o := &otpHost{secret: totp.NewSecret()}
	var ag *Agent
	var asks atomic.Int32
	trusted := func(a *Agent) {
		ag = a
		a.OTP = o.check
		a.fails, a.lockUntil = 9, time.Now().Add(time.Hour)
		a.Trusted = func(p []byte) bool { return bytes.Equal(p, pub) }
	}
	e2eSeen = func(m authMsg) {
		if m.T == "otp" {
			asks.Add(1)
		}
	}
	defer func() { e2eAgent, e2eSeen, e2eOTP, e2eFail, e2eKey = nil, nil, nil, false, "" }()
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
	e2eAgent, e2eKey = trusted, "ok"
	e2eOTP = func(int) string { return o.code() }
	e2e(t, local(t), "123456789", false, ff, "secret123")
	if f, _ := lock(ag); f != 9 {
		t.Fatalf("вход владельца сбросил общий счётчик: %d", f)
	}

	e2eFail = true
	e2eOTP = func(int) string { c := []byte(o.code()); c[0] = '0' + (c[0]-'0'+1)%10; return string(c) }
	asks.Store(0)
	e2e(t, local(t), "123456789", false, ff, "secret123")
	ag.mu.Lock()
	of, ol, f := ag.otpFails, time.Until(ag.otpLock), ag.fails
	ag.mu.Unlock()
	if asks.Load() != 5 || of != 5 || ol < 50*time.Second || f != 14 {
		t.Fatalf("неверные коды ключа: запросов %d, своих неудач %d (блокировка %v), общих %d", asks.Load(), of, ol, f)
	}

	fresh := func() string { o.mu.Lock(); o.last = 0; o.mu.Unlock(); return o.code() } // код не повтор: отказ — только от блокировки
	e2eAgent = func(a *Agent) { trusted(a); a.otpLock = time.Now().Add(time.Hour) }
	e2eOTP = func(int) string { return fresh() }
	e2e(t, local(t), "123456789", false, ff, "secret123") // своя блокировка ключа — отказ и верному коду

	e2eAgent = func(a *Agent) { trusted(a); a.otpFails = 4 } // 4 неверных кода уже ввели без ключа — ключ получает один
	e2eOTP = func(int) string { c := []byte(fresh()); c[0] = '0' + (c[0]-'0'+1)%10; return string(c) }
	asks.Store(0)
	e2e(t, local(t), "123456789", false, ff, "secret123")
	ag.mu.Lock()
	of, ol = ag.otpFails, time.Until(ag.otpLock)
	ag.mu.Unlock()
	if asks.Load() != 1 || of != 5 || ol < 50*time.Second {
		t.Fatalf("одна лестница кодов: запросов %d, неудач %d, блокировка %v", asks.Load(), of, ol)
	}

	e2eKey = ""
	e2eAgent = func(a *Agent) { ag = a; a.OTP = o.check; a.otpLock = time.Now().Add(time.Hour) } // лестница кодов — и для чужих
	e2eOTP = func(int) string { return fresh() }
	e2e(t, local(t), "123456789", false, ff, "secret123")

	e2eAgent = func(a *Agent) { ag = a; a.OTP = o.check }
	e2eOTP = func(int) string { // чужой перебор запер хост, пока человек вводит код
		ag.mu.Lock()
		ag.lockUntil = time.Now().Add(time.Hour)
		ag.mu.Unlock()
		return fresh()
	}
	e2e(t, local(t), "123456789", false, ff, "secret123")
}

// TestViewOnlyDrop — регрессия (приёмка Д4): «Только показ экрана» включили во время сессии с полным доступом —
// она разорвана; сессию «только просмотр» включение не рвёт.
func TestViewOnlyDrop(t *testing.T) {
	var on atomic.Bool
	var gone atomic.Bool
	e2eAgent = func(a *Agent) { a.ViewOnly = on.Load }
	e2eInput = func(t *testing.T, a *Agent) {
		on.Store(true) // хозяин поставил галочку
		a.DisconnectFull()
		for range 30 {
			a.mu.Lock()
			s := a.sess
			a.mu.Unlock()
			if s == nil {
				gone.Store(true)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		gone.Store(false)
	}
	defer func() { e2eAgent, e2eInput = nil, nil }()
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
	e2e(t, local(t), "123456789", false, ff, "secret123")
	if !gone.Load() {
		t.Fatal("сессия с полным доступом не разорвана")
	}
	e2e(t, local(t), "123456789", false, ff, "secret123") // галочка уже стоит: сессия — просмотр, её не рвать
	if gone.Load() {
		t.Fatal("сессия «только просмотр» разорвана")
	}
}

// TestOTPLateCode — код пришёл сразу после срока: хост его уже не проверяет — "denied" без «ok» следом.
func TestOTPLateCode(t *testing.T) {
	o := &otpHost{secret: totp.NewSecret()}
	var seen sync.Map
	e2eAgent = func(a *Agent) { a.OTP = o.check }
	e2eSeen = func(m authMsg) { seen.Store(m.T, true) }
	e2eOTP = func(int) string { time.Sleep(1200 * time.Millisecond); return o.code() } // срок — 1 с
	otpWait90.Store(int64(time.Second))
	e2eFail = true
	defer func() {
		e2eAgent, e2eSeen, e2eOTP, e2eFail = nil, nil, nil, false
		otpWait90.Store(int64(90 * time.Second))
	}()
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
	time.Sleep(300 * time.Millisecond)
	if _, ok := seen.Load("ok"); ok {
		t.Fatal("код после срока принят: «ok» после «denied»")
	}
	if _, ok := seen.Load("denied"); !ok {
		t.Fatal("нет отказа по сроку")
	}
}
