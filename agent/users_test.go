package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anypc/pake"
	"anypc/totp"
)

// testUser — учётная запись хоста как в app/config.go (REQ-S-20): пароль, права «просмотр», свой TOTP.
type testUser struct {
	pass string
	view bool
	otp  *otpHost
}

// usersHost — записи по имени (UserKey); "" — по умолчанию. KDF считается один раз: Argon2 64 МБ.
func usersHost(us map[string]testUser) func(*Agent) {
	kdf, otp := map[string][]byte{}, false
	for n, u := range us {
		kdf[n] = pake.KDF(u.pass, userSalt(n))
		otp = otp || u.otp != nil
	}
	return func(a *Agent) {
		a.Secret = func(n string) ([]byte, []byte, bool) {
			u, ok := us[n]
			if !ok {
				return nil, nil, false
			}
			return userSalt(n), kdf[n], u.view
		}
		if !otp { // TOTP нет вовсе — вход без подтверждения как раньше (иначе без секрета — «Разрешить»)
			return
		}
		a.OTP = func(n, code string) (bool, bool) {
			if u := us[n]; u.otp != nil {
				return u.otp.check(n, code)
			}
			return false, false
		}
	}
}

func userSalt(n string) []byte { return []byte((n + "-salt-0123456789")[:16]) }

var accounts = map[string]testUser{"": {pass: "secret123"}, "ivan": {pass: "ivan-pass1"}, "olga": {pass: "olga-pass1", view: true}}

// e2eReset — вернуть общие крючки e2e.
func e2eReset() {
	e2eAgent, e2eSeen, e2eInput, e2eOTP, e2eUser, e2eGood, e2eKey, e2eFail, e2eDeny = nil, nil, nil, nil, "", "", "", false, false
}

// sessHeld — после входа: подпись клиента (плашка, журнал) и сколько клавиш зажато (ввод дошёл).
func sessHeld(label *atomic.Value, held *atomic.Int32) func(*testing.T, *Agent) {
	return func(t *testing.T, a *Agent) {
		a.mu.Lock()
		s := a.sess
		a.mu.Unlock()
		_, text := plaqueText("ru", s.label(), s.plaque())
		label.Store(text)
		s.keys.mu.Lock()
		held.Store(int32(len(s.keys.keys)))
		s.keys.mu.Unlock()
	}
}

// TestUsers — REQ-S-20, F-24: каждая запись входит своим паролем (имя без регистра и пробелов), чужой пароль к имени —
// отказ; старый клиент без имени — запись по умолчанию; права «просмотр» — view в "ok", ввод не доходит; имя — на
// плашке, ключ клиента закрепляется за своей записью.
func TestUsers(t *testing.T) {
	var label atomic.Value
	var held atomic.Int32
	var view atomic.Bool
	var pinned atomic.Value
	hosts := usersHost(accounts)
	e2eAgent = func(a *Agent) { hosts(a); a.Trust = func(_ []byte, u string) { pinned.Store(u) } }
	e2eSeen = func(m authMsg) {
		if m.T == "ok" {
			view.Store(m.View)
		}
	}
	e2eInput = sessHeld(&label, &held)
	defer e2eReset()
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})

	e2e(t, local(t), "123456789", false, ff, "secret123") // старый клиент
	if l, _ := label.Load().(string); strings.Contains(l, "·") || held.Load() != 1 || view.Load() {
		t.Fatalf("по умолчанию: плашка %q, зажато %d, view %v", l, held.Load(), view.Load())
	}

	e2eUser, e2eGood, e2eKey = " Ivan", "ivan-pass1", "ok"
	e2e(t, local(t), "123456789", false, ff, "ivan-pass1")
	if l, _ := label.Load().(string); !strings.Contains(l, "· ivan") || held.Load() != 1 || view.Load() {
		t.Fatalf("ivan: плашка %q, зажато %d, view %v", l, held.Load(), view.Load())
	}
	if u, _ := pinned.Load().(string); u != "ivan" {
		t.Fatalf("ключ закреплён за %q", u)
	}
	e2eKey = ""
	e2e(t, local(t), "123456789", false, ff, "secret123") // пароль записи по умолчанию к имени ivan — отказ
	e2e(t, local(t), "123456789", false, ff, "olga-pass1")

	e2eUser, e2eGood = "olga", "olga-pass1"
	e2e(t, local(t), "123456789", false, ff, "olga-pass1")
	if l, _ := label.Load().(string); !strings.Contains(l, "· olga") || held.Load() != 0 || !view.Load() {
		t.Fatalf("olga (просмотр): плашка %q, зажато %d, view %v", l, held.Load(), view.Load())
	}
}

// TestUserUnknown — REQ-S-21: на несуществующее имя хост отвечает тем же "a": соль 16 байт, детерминированная
// (HMAC-SHA256(ключ хоста, имя)[:16], без регистра), msg той же длины; дальше — "fail", как на неверный пароль.
func TestUserUnknown(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(nil)
	var mu sync.Mutex
	var as [][2][]byte // соль и msg из ответа на имя
	var res []string
	hosts := usersHost(accounts)
	e2eAgent = func(a *Agent) { hosts(a); a.Key = key }
	e2eSeen = func(m authMsg) {
		mu.Lock()
		defer mu.Unlock()
		if m.T == "a" && m.User != "" {
			as = append(as, [2][]byte{m.Salt, m.Msg})
		}
		if m.T == "fail" || m.T == "locked" {
			res = append(res, m.T)
		}
	}
	defer e2eReset()
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
	for _, u := range []string{"nobody", "NoBody ", "ivan"} {
		e2eUser, e2eGood = u, "-"
		e2e(t, local(t), "123456789", false, ff, "wrong-pass")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("nobody"))
	want := mac.Sum(nil)[:16]
	if len(as) != 3 || !bytes.Equal(as[0][0], want) || !bytes.Equal(as[1][0], want) || !bytes.Equal(as[2][0], userSalt("ivan")) {
		t.Fatalf("соли: %x, ждали %x", as, want)
	}
	if len(as[0][1]) != len(as[2][1]) || !slices.Equal(res, []string{"fail", "fail", "fail"}) {
		t.Fatalf("msg %d и %d байт, ответы %v", len(as[0][1]), len(as[2][1]), res)
	}
}

// TestUserTiming — REQ-S-21: ответ на несуществующее имя готовится столько же, сколько на существующее (медианы
// вперемешку; работа одна и та же — HMAC, rand и HostStart в обоих случаях).
func TestUserTiming(t *testing.T) {
	a := newAgent("", "123456789", nil)
	usersHost(accounts)(a)
	fp := "sha-256 AB:CD"
	var real, fake []time.Duration
	for range 41 {
		for _, u := range []string{"ivan", "nobody"} {
			t0 := time.Now()
			if _, _, _, _, err := a.userStart(u, fp, fp); err != nil {
				t.Fatal(err)
			}
			d := time.Since(t0)
			if u == "ivan" {
				real = append(real, d)
			} else {
				fake = append(fake, d)
			}
		}
	}
	slices.Sort(real)
	slices.Sort(fake)
	r, f := real[len(real)/2], fake[len(fake)/2]
	if f > 2*r || r > 2*f {
		t.Fatalf("медиана: есть имя %v, нет имени %v", r, f)
	}
	t.Logf("медиана: есть имя %v, нет имени %v", r, f)
}

// TestUserLocks — REQ-S-22 в канале auth: запертое имя отвечает "locked" и верному паролю (и несуществующее —
// так же, по ответу не отличить), другое имя входит; ключ, закреплённый за другой записью, блокировку не обходит,
// за своей — обходит (У3).
func TestUserLocks(t *testing.T) {
	var got atomic.Value
	var trustedFor atomic.Value
	hosts := usersHost(accounts)
	e2eAgent = func(a *Agent) {
		hosts(a)
		until := time.Now().Add(time.Hour)
		a.names = map[string]*nameLock{"ivan": {fails: 5, until: until}, "nobody": {fails: 5, until: until}}
		a.Trusted = func(_ []byte, u string) bool { w, _ := trustedFor.Load().(string); return u == w || u == AnyUser }
	}
	e2eSeen = func(m authMsg) {
		if m.T == "locked" || m.T == "fail" || m.T == "ok" {
			got.Store(m.T)
		}
	}
	defer e2eReset()
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
	trustedFor.Store("-")
	for _, c := range []struct{ user, pass, good, want string }{
		{"ivan", "ivan-pass1", "-", "locked"},
		{"nobody", "ivan-pass1", "-", "locked"},
		{"olga", "olga-pass1", "olga-pass1", "ok"},
		{"", "secret123", "secret123", "ok"},
	} {
		e2eUser, e2eGood = c.user, c.good
		e2e(t, local(t), "123456789", false, ff, c.pass)
		if g, _ := got.Load().(string); g != c.want {
			t.Fatalf("%q: ответ %q, ждали %q", c.user, g, c.want)
		}
	}
	e2eKey = "ok"
	trustedFor.Store("olga") // ключ olga не перебирает пароль ivan мимо блокировки
	e2eUser, e2eGood = "ivan", "-"
	e2e(t, local(t), "123456789", false, ff, "ivan-pass1")
	if g, _ := got.Load().(string); g != "locked" {
		t.Fatalf("ключ чужой записи: %q", g)
	}
	trustedFor.Store("ivan")
	e2eGood = "ivan-pass1"
	e2e(t, local(t), "123456789", false, ff, "ivan-pass1")
}

// TestUserOTP — у каждой записи свой TOTP: без подтверждения запись с TOTP входит своим кодом (код чужой записи —
// отказ, лестница кодов); запись без TOTP — через «Разрешить» с пометкой nootp, а без окна — отказ.
func TestUserOTP(t *testing.T) {
	ivan, def := &otpHost{secret: totp.NewSecret()}, &otpHost{secret: totp.NewSecret()}
	us := map[string]testUser{"": {pass: "secret123", otp: def}, "ivan": {pass: "ivan-pass1", otp: ivan}, "olga": {pass: "olga-pass1"}}
	hosts := usersHost(us)
	var asked, nootp atomic.Bool
	var confirm func(string, string) Answer
	e2eAgent = func(a *Agent) { hosts(a); a.Confirm = confirm; a.Unattended = func() bool { return true } }
	e2eSeen = func(m authMsg) {
		if m.T == "ask" {
			asked.Store(true)
			nootp.Store(m.NoOTP)
		}
	}
	defer e2eReset()
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
	e2eUser, e2eGood = "ivan", "ivan-pass1"
	e2eOTP = func(int) string { return ivan.code() }
	e2e(t, local(t), "123456789", false, ff, "ivan-pass1")

	e2eFail = true
	e2eOTP = func(int) string { return def.code() } // код записи по умолчанию к ivan
	e2e(t, local(t), "123456789", false, ff, "ivan-pass1")

	e2eUser, e2eGood, e2eOTP = "olga", "olga-pass1", nil // без TOTP и без окна — отказ
	e2e(t, local(t), "123456789", false, ff, "olga-pass1")
	if asked.Load() {
		t.Fatal("спросили некого")
	}
	e2eFail = false
	confirm = func(cid, _ string) Answer {
		if !strings.HasSuffix(cid, " · olga") {
			t.Errorf("окно «Разрешить» без имени: %q", cid)
		}
		return Allow
	}
	e2e(t, local(t), "123456789", false, ff, "olga-pass1")
	if !asked.Load() || !nootp.Load() {
		t.Fatalf("olga без TOTP: окно %v, nootp %v", asked.Load(), nootp.Load())
	}
}

// TestDropRevoked — приёмка Д4: запись вошедшей сессии удалили, сменили ей пароль или сузили права до «просмотр» —
// сессия рвётся; без перемен и у записи «просмотр», оставшейся «просмотр», — нет.
func TestDropRevoked(t *testing.T) {
	var mode, change atomic.Int32 // change: 0 как есть, 1 новая соль, 2 права «просмотр», 3 запись удалена
	var gone atomic.Bool
	hosts := usersHost(accounts)
	e2eAgent = func(a *Agent) {
		hosts(a)
		sec := a.Secret
		a.Secret = func(n string) ([]byte, []byte, bool) {
			s, k, v := sec(n)
			if n == "ivan" {
				switch mode.Load() {
				case 1:
					s = []byte("another-salt-123")
				case 2:
					v = true
				case 3:
					return nil, nil, false
				}
			}
			return s, k, v
		}
	}
	e2eInput = func(t *testing.T, a *Agent) {
		mode.Store(change.Load())
		defer mode.Store(0)
		a.DropRevoked()
		for range 20 {
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
	defer e2eReset()
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
	for _, c := range []struct {
		user, pass string
		change     int32
		gone       bool
	}{{"ivan", "ivan-pass1", 0, false}, {"ivan", "ivan-pass1", 1, true}, {"ivan", "ivan-pass1", 2, true}, {"ivan", "ivan-pass1", 3, true}, {"olga", "olga-pass1", 0, false}} {
		change.Store(c.change)
		e2eUser, e2eGood = c.user, c.pass
		e2e(t, local(t), "123456789", false, ff, c.pass)
		if gone.Load() != c.gone {
			t.Fatalf("%s, правка %d: разорвана %v", c.user, c.change, gone.Load())
		}
	}
}
