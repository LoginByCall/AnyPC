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

	"github.com/pion/webrtc/v4"
)

// otpHost — второй фактор хоста как в app/config.go: секрет (пусто — не настроен) и шаг последнего принятого кода.
type otpHost struct {
	mu     sync.Mutex
	secret string
	last   int64
}

func (o *otpHost) check(_, code string) (set, ok bool) {
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

// nlock — счётчик неудач и блокировка имени записи (REQ-S-22).
func nlock(a *Agent, user string) (int, time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n := a.names[user]; n != nil {
		return n.fails, time.Until(n.until)
	}
	return 0, -1
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
	if f, l := nlock(ag, ""); asks.Load() != 5 || f != 5 || l < 50*time.Second {
		t.Fatalf("повтор кода: запросов %d, неудач %d, блокировка %v", asks.Load(), f, l)
	}

	e2eAgent = func(a *Agent) {
		ag = a
		a.OTP = o.check
		a.names = map[string]*nameLock{"": {fails: 4, at: time.Now()}}
	}
	e2eOTP = func(int) string { c := []byte(o.code()); c[0] = '0' + (c[0]-'0'+1)%10; return string(c) }
	asks.Store(0)
	e2e(t, local(t), "123456789", false, ff, "secret123") // верный пароль не сбросил 4 неудачи: первый неверный код — блокировка
	if f, l := nlock(ag, ""); asks.Load() != 1 || f != 5 || l < 50*time.Second {
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
		a.Trusted = func(p []byte, _ string) bool { return bytes.Equal(p, pub) }
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
	of, ol, f := ag.names[""].otpFails, time.Until(ag.names[""].otpUntil), ag.fails
	ag.mu.Unlock()
	if asks.Load() != 5 || of != 5 || ol < 50*time.Second || f != 14 {
		t.Fatalf("неверные коды ключа: запросов %d, своих неудач %d (блокировка %v), общих %d", asks.Load(), of, ol, f)
	}

	fresh := func() string { o.mu.Lock(); o.last = 0; o.mu.Unlock(); return o.code() } // код не повтор: отказ — только от блокировки
	e2eAgent = func(a *Agent) { trusted(a); a.names = map[string]*nameLock{"": {otpUntil: time.Now().Add(time.Hour)}} }
	e2eOTP = func(int) string { return fresh() }
	e2e(t, local(t), "123456789", false, ff, "secret123") // своя блокировка ключа — отказ и верному коду

	e2eAgent = func(a *Agent) { trusted(a); a.names = map[string]*nameLock{"": {otpFails: 4, at: time.Now()}} } // 4 неверных кода уже ввели без ключа — ключ получает один
	e2eOTP = func(int) string { c := []byte(fresh()); c[0] = '0' + (c[0]-'0'+1)%10; return string(c) }
	asks.Store(0)
	e2e(t, local(t), "123456789", false, ff, "secret123")
	ag.mu.Lock()
	of, ol = ag.names[""].otpFails, time.Until(ag.names[""].otpUntil)
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

// TestViewOnlyLive — регрессия ToDo 2026-11-12 (Ubuntu → Win): «Только показ экрана» во время сессии рвал её, а
// выключение управления не возвращало. Теперь: включили — та же сессия в просмотре (ввод не принимается), клиенту
// {"t":"mode","view":true}; выключили — управление вернулось. Сессия, вошедшая при галочке, после выключения —
// с управлением; клиент, сам выбравший просмотр, и запись «просмотр» остаются просмотром.
func TestViewOnlyLive(t *testing.T) {
	var on atomic.Bool
	var ag *Agent
	e2eAgent = func(a *Agent) { ag = a; a.ViewOnly = on.Load }
	defer func() { e2eAgent, e2eCtl = nil, nil }()
	sess := func() *session { ag.mu.Lock(); defer ag.mu.Unlock(); return ag.sess }
	mode := func(t *testing.T, msgs chan ctlMsg) {
		t.Helper()
		for end := time.After(3 * time.Second); ; {
			select {
			case m := <-msgs:
				if m.T == "mode" {
					return
				}
			case <-end:
				t.Fatal("клиенту не пришёл mode")
			}
		}
	}
	flip := func(t *testing.T, msgs chan ctlMsg, v bool) {
		t.Helper()
		s := sess()
		on.Store(v)
		ag.ViewOnlyChanged(v)
		mode(t, msgs)
		if sess() != s || s.control() == v {
			t.Fatalf("галочка %v: сессия %p→%p, управление %v", v, s, sess(), s.control())
		}
		ag.ViewOnlyChanged(v) // опрос раз в 2 с повторяет — ничего не меняет
		if s.control() == v {
			t.Fatalf("повтор %v сменил режим", v)
		}
	}
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
	e2eCtl = func(t *testing.T, _ *webrtc.DataChannel, msgs chan ctlMsg) {
		flip(t, msgs, true)
		flip(t, msgs, false)
	}
	e2e(t, local(t), "123456789", false, ff, "secret123")

	on.Store(true) // галочка уже стоит при входе
	e2eCtl = func(t *testing.T, _ *webrtc.DataChannel, msgs chan ctlMsg) {
		if sess().control() {
			t.Fatal("вошла с управлением при галочке")
		}
		flip(t, msgs, false)
	}
	e2e(t, local(t), "123456789", false, ff, "secret123")

	on.Store(true) // клиент сам выбрал просмотр, пока стояла галочка, — выключение не даёт управления
	e2eCtl = func(t *testing.T, dc *webrtc.DataChannel, msgs chan ctlMsg) {
		s := sess()
		s.byAsk.Store(true)
		ag.ConfirmControl = func(string, string) bool { return false }
		dc.SendText(`{"t":"mode","view":true}`)
		mode(t, msgs)
		on.Store(false)
		ag.ViewOnlyChanged(false)
		if s.control() {
			t.Fatal("просмотр по выбору клиента сменился на управление")
		}
	}
	e2e(t, local(t), "123456789", false, ff, "secret123")
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

// TestViewOnlyPending — регрессия (приёмка Б1): опрос «Только показ экрана» (ViewOnlyChanged раз в 2 с) не рвёт
// сессию, ещё не вошедшую — на шаге кода и при открытом окне «Разрешить»; после кода и «Разрешить» она входит
// просмотром. Галочка, включённая между проверкой в accept и authed, тоже даёт просмотр.
func TestViewOnlyPending(t *testing.T) {
	o := &otpHost{secret: totp.NewSecret()}
	var gotView atomic.Bool
	var ag *Agent
	e2eSeen = func(m authMsg) {
		if m.T == "ok" {
			gotView.Store(m.View)
		}
	}
	defer func() { e2eAgent, e2eSeen, e2eOTP = nil, nil, nil }()
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
	yes := func() bool { return true }

	e2eAgent = func(a *Agent) { ag = a; a.OTP = o.check; a.ViewOnly = yes }
	e2eOTP = func(int) string { ag.ViewOnlyChanged(true); time.Sleep(300 * time.Millisecond); return o.code() } // опрос на шаге кода
	e2e(t, local(t), "123456789", false, ff, "secret123")
	if !gotView.Load() {
		t.Fatal("шаг кода: сессия вошла не просмотром")
	}

	e2eOTP = nil
	e2eAgent = func(a *Agent) {
		ag = a
		a.ViewOnly = yes
		a.Unattended = func() bool { return false }
		a.Confirm = func(string, string) Answer {
			ag.ViewOnlyChanged(true)
			time.Sleep(300 * time.Millisecond)
			return Allow
		} // опрос при открытом окне
	}
	gotView.Store(false)
	e2e(t, local(t), "123456789", false, ff, "secret123")
	if !gotView.Load() {
		t.Fatal("окно «Разрешить»: сессия вошла не просмотром")
	}

	var calls atomic.Int32 // галочку включили сразу после первой проверки в accept
	e2eAgent = func(a *Agent) { a.ViewOnly = func() bool { return calls.Add(1) > 1 } }
	gotView.Store(false)
	e2e(t, local(t), "123456789", false, ff, "secret123")
	if !gotView.Load() {
		t.Fatal("галочка между проверкой и входом: полный доступ")
	}
}
