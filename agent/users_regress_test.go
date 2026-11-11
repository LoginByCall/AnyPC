package agent

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anypc/pake"
	"anypc/totp"
)

// Регрессии приёмки учётных записей (PoC приёмщика, scratchpad/acc-poc).

// TestAccEvict — Д2: мусорные имена и свои входы между ними не стирают счёт настоящего имени (имена с неудачами не
// вытесняются, сверх maxNames — общий счётчик), а свой вход не обнуляет общий по хосту — хост запирается.
func TestAccEvict(t *testing.T) {
	a := newAgent("", "123456789", nil)
	for range 4 {
		a.authResult("c1", "admin", false)
	}
	for i := range maxNames + 50 {
		a.authResult("c1", "guest", true) // свой верный вход (запись «просмотр») перед каждой неудачей
		a.authResult("c1", fmt.Sprint("junk", i), false)
	}
	a.mu.Lock()
	n, locked := len(a.names), time.Now().Before(a.lockUntil)
	a.mu.Unlock()
	if f, _ := nlock(a, "admin"); f != 4 || !locked || n > maxNames+1 {
		t.Fatalf("счёт admin %d (ждали 4), хост заперт %v, имён %d", f, locked, n)
	}
	// запертое имя с истёкшей блокировкой: по лестнице — 1 попытка и 32 мин
	a2 := newAgent("", "123456789", nil)
	a2.names = map[string]*nameLock{"admin": {fails: 9, until: time.Now().Add(-time.Second)}}
	for i := range maxNames {
		a2.authResult("c1", "guest", true)
		a2.authResult("c1", fmt.Sprint("junk", i), false)
	}
	a2.mu.Lock()
	a2.lockUntil = time.Time{} // общий не мешает: проверяем лестницу имени
	a2.mu.Unlock()
	free := 0
	for !a2.pwLocked("admin", time.Now()) && free < 50 {
		a2.authResult("c1", "admin", false)
		free++
	}
	if f, l := nlock(a2, "admin"); free != 1 || f != 10 || l < 31*time.Minute {
		t.Fatalf("после мусорных имён: попыток %d, счёт %d, блокировка %v (ждали 1, 10, 32 мин)", free, f, l)
	}
	// сверх maxNames новые имена делят один счётчик: перебор их не бесконечен
	free = 0
	for !a2.pwLocked("fresh0", time.Now()) && free < 50 {
		a2.authResult("c1", fmt.Sprint("fresh", free), false)
		free++
	}
	if free > 5 {
		t.Fatalf("новые имена сверх maxNames: %d попыток без блокировки", free)
	}
}

// TestAccOTPReset — Д1: лестница кодов TOTP — у каждой записи своя, верный код другой записи её не сбрасывает: вор с
// паролем и закреплённым ключом ivan и своей записью olga получает 5 кодов ivan, а не бесконечно.
func TestAccOTPReset(t *testing.T) {
	k, _ := pake.ClientSignB64(e2eSeed(), "", "", "")
	pub, _ := base64.StdEncoding.DecodeString(k["pub"])
	ivan, olga := &otpHost{secret: totp.NewSecret()}, &otpHost{secret: totp.NewSecret()}
	us := map[string]testUser{"": {pass: "secret123", otp: &otpHost{secret: totp.NewSecret()}}, "ivan": {pass: "ivan-pass1", otp: ivan}, "olga": {pass: "olga-pass1", view: true, otp: olga}}
	hosts := usersHost(us)
	var prev *Agent
	e2eAgent = func(a *Agent) {
		hosts(a)
		a.Trusted = func(p []byte, u string) bool { return bytes.Equal(p, pub) && (u == "ivan" || u == AnyUser) }
		if prev != nil { // один и тот же хост между подключениями: счётчики переносим
			prev.mu.Lock()
			a.fails, a.lockUntil, a.failAt, a.names, a.otpFails, a.otpLock, a.otpAt = prev.fails, prev.lockUntil, prev.failAt, prev.names, prev.otpFails, prev.otpLock, prev.otpAt
			prev.mu.Unlock()
		}
		prev = a
	}
	var wrong, locked atomic.Int32
	e2eSeen = func(m authMsg) {
		if m.T == "locked" {
			locked.Add(1)
		}
	}
	defer func() { e2eReset(); otpWait90.Store(int64(90 * time.Second)) }()
	otpWait90.Store(int64(time.Second))
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
	for range 3 {
		e2eUser, e2eGood, e2eKey, e2eFail = "ivan", "ivan-pass1", "ok", true // 4 неверных кода и молчок
		e2eOTP = func(n int) string {
			if n > 4 {
				return ""
			}
			wrong.Add(1)
			c := []byte(ivan.code())
			c[0] = '0' + (c[0]-'0'+1)%10
			return string(c)
		}
		e2e(t, local(t), "123456789", false, ff, "ivan-pass1")
		e2eUser, e2eGood, e2eKey, e2eFail = "olga", "olga-pass1", "", false // своей записью с верным кодом
		e2eOTP = func(int) string { olga.mu.Lock(); olga.last = 0; olga.mu.Unlock(); return olga.code() }
		e2e(t, local(t), "123456789", false, ff, "olga-pass1")
	}
	prev.mu.Lock()
	of, ol := prev.names["ivan"].otpFails, time.Until(prev.names["ivan"].otpUntil)
	prev.mu.Unlock()
	if of != 5 || ol < 30*time.Second || locked.Load() < 2 { // коды после блокировки хост не проверяет; блокировка 1 мин, под -race прогон долгий
		t.Fatalf("проверено неверных кодов ivan %d (ждали 5), блокировка %v, locked %d из %d отправленных", of, ol, locked.Load(), wrong.Load())
	}
}

// TestAccAnyUser — Д6: имя "*" от клиента — обычное имя, не AnyUser: ключ другой записи не закреплён, блокировка
// имени действует; имя с управляющим символом (как AnyUser) хост не принимает — вход на соединении кончен.
func TestAccAnyUser(t *testing.T) {
	k, _ := pake.ClientSignB64(e2eSeed(), "", "", "")
	pub, _ := base64.StdEncoding.DecodeString(k["pub"])
	hosts := usersHost(accounts)
	var mu sync.Mutex
	var got string
	var asked []string
	e2eAgent = func(a *Agent) {
		hosts(a)
		a.names = map[string]*nameLock{"*": {fails: 5, until: time.Now().Add(time.Hour)}}
		a.Trusted = func(p []byte, u string) bool {
			mu.Lock()
			asked = append(asked, u)
			mu.Unlock()
			return bytes.Equal(p, pub) && (u == "olga" || u == AnyUser)
		}
	}
	e2eSeen = func(m authMsg) {
		if m.T == "locked" || m.T == "fail" || m.T == "ok" || m.T == "a" && m.User != "" {
			mu.Lock()
			got += m.T + ";"
			mu.Unlock()
		}
	}
	defer e2eReset()
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
	e2eUser, e2eGood, e2eKey = "*", "-", "ok"
	e2e(t, local(t), "123456789", false, ff, "whatever1")
	mu.Lock()
	if got != "a;locked;" || !slices.Contains(asked, "*") {
		t.Fatalf("имя *: ответы %q, Trusted спрошен с %q", got, asked)
	}
	got = ""
	mu.Unlock()
	t0 := time.Now()
	e2eUser = AnyUser
	e2e(t, local(t), "123456789", false, ff, "whatever1")
	mu.Lock()
	defer mu.Unlock()
	if got != "" || time.Since(t0) > 10*time.Second {
		t.Fatalf("имя AnyUser: ответы %q за %v (ждали разрыв без ответа)", got, time.Since(t0))
	}
}

// TestUserOnce — выжившая мутация: хост принимает одно "a" с именем на соединение; второе — разрыв, без ответа на "b".
func TestUserOnce(t *testing.T) {
	var got atomic.Value
	hosts := usersHost(accounts)
	e2eAgent = hosts
	e2eSeen = func(m authMsg) {
		if m.T == "ok" || m.T == "fail" {
			got.Store(m.T)
		}
	}
	e2eTwice = true
	defer func() { e2eReset(); e2eTwice = false }()
	t0 := time.Now()
	e2eUser, e2eGood = "ivan", "-" // ждём отказ: пароль верный, но имя названо дважды
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "ivan-pass1")
	if g, _ := got.Load().(string); g != "" || time.Since(t0) > 10*time.Second {
		t.Fatalf("второе имя: ответ %q за %v", g, time.Since(t0))
	}
}

// wind — «прошло d»: все отметки времени счётчиков хоста и имён сдвигаются в прошлое.
func wind(a *Agent, d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lockUntil, a.failAt, a.otpLock, a.otpAt = a.lockUntil.Add(-d), a.failAt.Add(-d), a.otpLock.Add(-d), a.otpAt.Add(-d)
	for _, n := range a.names {
		n.until, n.otpUntil, n.at = n.until.Add(-d), n.otpUntil.Add(-d), n.at.Add(-d)
	}
}

// TestRe2HostCounter — повторная приёмка: общий счётчик без сброса успехом не запирает хост навсегда: 19 неудач в час
// не запирают вовсе (счёт забывается через час тишины), после атаки и часа тишины одна опечатка не запирает.
func TestRe2HostCounter(t *testing.T) {
	a := newAgent("", "123456789", nil)
	for h := range 48 {
		for i := range 19 {
			a.authResult("c1", fmt.Sprint("j", h, "-", i%3), false)
		}
		if a.mu.Lock(); time.Now().Before(a.lockUntil) {
			a.mu.Unlock()
			t.Fatalf("час %d: хост заперт", h)
		}
		a.mu.Unlock()
		wind(a, hostForget+time.Second)
	}
	b := newAgent("", "123456789", nil)
	for i := range 26 { // посторонний ждёт конца каждой блокировки
		b.mu.Lock()
		d := time.Until(b.lockUntil)
		b.mu.Unlock()
		if d > 0 {
			wind(b, d+time.Second)
		}
		b.authResult("c1", fmt.Sprint("j", i), false)
	}
	b.mu.Lock()
	d, f := time.Until(b.lockUntil), b.fails
	b.mu.Unlock()
	if f != 26 || d < 59*time.Minute {
		t.Fatalf("26 неудач: счёт %d, блокировка %v", f, d)
	}
	wind(b, d+hostForget+time.Second)
	b.authResult("c3", "ivan", false)
	if b.mu.Lock(); b.fails != 1 || time.Now().Before(b.lockUntil) {
		t.Errorf("после часа тишины опечатка: счёт %d, заперт %v", b.fails, time.Now().Before(b.lockUntil))
	}
	b.mu.Unlock()
}

// TestRe2Others — Н1: таблица имён, заполненная мусором, не вечна: после суток тишины строки забываются, опечатка
// настоящей записи идёт в свою строку, и опечатки разных людей за месяцы друг друга не запирают.
func TestRe2Others(t *testing.T) {
	a := newAgent("", "123456789", nil)
	for i := 0; len(a.names) < maxNames; i++ { // посторонний: по 19 мусорных имён в час, без блокировки
		if i > 0 && i%19 == 0 {
			wind(a, hostForget+time.Second)
		}
		a.authResult("c1", fmt.Sprint("junk", i), false)
	}
	a.authResult("c1", "overflow", false)
	if a.mu.Lock(); a.names[othersKey] == nil || a.names["overflow"] != nil {
		a.mu.Unlock()
		t.Fatal("сверх таблицы — не в общий счётчик")
	}
	a.mu.Unlock()
	wind(a, nameForget+2*time.Hour) // сутки тишины
	a.authResult("c2", "ivan", false)
	a.mu.Lock()
	own, others, n := a.names["ivan"] != nil, a.names[othersKey], len(a.names)
	a.mu.Unlock()
	if !own || others != nil || n != 1 {
		t.Fatalf("после суток тишины: своя строка ivan %v, «прочие» %v, имён %d", own, others, n)
	}
	for _, u := range []string{"olga", "petr", "anna", "oleg", "olga", "olga", "olga", "olga", "olga", "olga"} { // опечатки раз в месяц
		wind(a, 30*24*time.Hour)
		a.authResult("c3", u, false)
	}
	if now := time.Now(); a.pwLocked("ivan", now) || a.pwLocked("", now) || a.pwLocked("olga", now) {
		t.Fatal("опечатки разных людей за месяцы запирают других")
	}
	// запертое имя сутками тишины не забывается раньше конца блокировки
	c := newAgent("", "123456789", nil)
	c.names = map[string]*nameLock{"admin": {fails: 30, until: time.Now().Add(time.Hour), at: time.Now().Add(-48 * time.Hour)}}
	if !c.pwLocked("admin", time.Now()) {
		t.Fatal("запертое имя забыто до конца блокировки")
	}
}

// TestRe2InsiderOTPLock — Н2: запись «просмотр» со своим TOTP неверными кодами запирает шаг кода чужим (общая
// лестница по хосту), но не владельцу с закреплённым ключом: у него — только лестница кодов своей записи.
func TestRe2InsiderOTPLock(t *testing.T) {
	k, _ := pake.ClientSignB64(e2eSeed(), "", "", "")
	pub, _ := base64.StdEncoding.DecodeString(k["pub"])
	ivan, olga := &otpHost{secret: totp.NewSecret()}, &otpHost{secret: totp.NewSecret()}
	us := map[string]testUser{"": {pass: "secret123", otp: &otpHost{secret: totp.NewSecret()}}, "ivan": {pass: "ivan-pass1", otp: ivan}, "olga": {pass: "olga-pass1", view: true, otp: olga}}
	hosts := usersHost(us)
	var prev *Agent
	e2eAgent = func(a *Agent) {
		hosts(a)
		a.Trusted = func(p []byte, u string) bool { return bytes.Equal(p, pub) && (u == "ivan" || u == AnyUser) }
		if prev != nil {
			prev.mu.Lock()
			a.fails, a.lockUntil, a.failAt, a.names, a.otpFails, a.otpLock, a.otpAt = prev.fails, prev.lockUntil, prev.failAt, prev.names, prev.otpFails, prev.otpLock, prev.otpAt
			prev.mu.Unlock()
		}
		prev = a
	}
	var last atomic.Value
	e2eSeen = func(m authMsg) {
		if m.T == "locked" || m.T == "ok" || m.T == "fail" || m.T == "denied" {
			last.Store(m.T)
		}
	}
	defer e2eReset()
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
	fresh := func(o *otpHost) string { o.mu.Lock(); o.last = 0; o.mu.Unlock(); return o.code() }
	for i := range 5 { // olga: 4 неверных кода и верный — своя лестница сбрасывается; 20-й неверный код запирает её
		e2eUser, e2eGood, e2eKey, e2eFail = "olga", "olga-pass1", "", i == 4
		e2eOTP = func(n int) string {
			c := []byte(fresh(olga))
			if n <= 4 {
				c[0] = '0' + (c[0]-'0'+1)%10
			}
			return string(c)
		}
		e2e(t, local(t), "123456789", false, ff, "olga-pass1")
	}
	if prev.mu.Lock(); !time.Now().Before(prev.otpLock) {
		prev.mu.Unlock()
		t.Fatal("общая лестница кодов не заперла чужих")
	}
	prev.mu.Unlock()
	e2eUser, e2eGood, e2eKey, e2eFail = "ivan", "ivan-pass1", "ok", false // владелец с ключом, верным паролем и кодом
	e2eOTP = func(int) string { return fresh(ivan) }
	e2e(t, local(t), "123456789", false, ff, "ivan-pass1")
	if last.Load() != "ok" {
		t.Fatalf("ivan с закреплённым ключом: %v", last.Load())
	}
}

// TestRe2RevokedDuringLogin — Н3: запись удалили или сменили ей пароль, пока её вход ждал «Разрешить» (на Windows
// опроса настроек нет) — accept отказывает; права сузили — вход только просмотром.
func TestRe2RevokedDuringLogin(t *testing.T) {
	var change atomic.Int32 // 1 — удалена, 2 — новая соль, 3 — права «просмотр»
	var now atomic.Bool     // правка уже случилась (окно «Разрешить» открыто)
	var view atomic.Bool
	hosts := usersHost(accounts)
	e2eAgent = func(a *Agent) {
		hosts(a)
		sec := a.Secret
		a.Secret = func(n string) ([]byte, []byte, bool) {
			s, k, v := sec(n)
			if n == "ivan" && now.Load() {
				switch change.Load() {
				case 1:
					return nil, nil, false
				case 2:
					s = []byte("another-salt-123")
				case 3:
					v = true
				}
			}
			return s, k, v
		}
		a.Unattended = func() bool { return false }
		a.Confirm = func(string, string) Answer { now.Store(true); return Allow }
	}
	e2eSeen = func(m authMsg) {
		if m.T == "ok" {
			view.Store(m.View)
		}
	}
	defer e2eReset()
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
	for _, c := range []struct {
		change int32
		good   string
	}{{1, "-"}, {2, "-"}, {3, "ivan-pass1"}} {
		change.Store(c.change)
		now.Store(false)
		e2eUser, e2eGood = "ivan", c.good
		e2e(t, local(t), "123456789", false, ff, "ivan-pass1")
		if c.change == 3 && !view.Load() {
			t.Fatal("права сузили во время входа — вход не только просмотром")
		}
	}
}
