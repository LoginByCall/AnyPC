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
