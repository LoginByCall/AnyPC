package agent

import (
	"bytes"
	"encoding/base64"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anypc/pake"
	"anypc/totp"
)

// keyStore — списки входа без пароля по записям, как account.KeyLogin в app/config.go (REQ-S-24).
type keyStore struct {
	mu   sync.Mutex
	keys map[string][][]byte
}

func (k *keyStore) has(pub []byte, user string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	for u, l := range k.keys {
		if (user == AnyUser || u == user) && slices.ContainsFunc(l, func(p []byte) bool { return bytes.Equal(p, pub) }) {
			return true
		}
	}
	return false
}

func (k *keyStore) add(pub []byte, user string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !slices.ContainsFunc(k.keys[user], func(p []byte) bool { return bytes.Equal(p, pub) }) {
		k.keys[user] = append(k.keys[user], bytes.Clone(pub))
	}
}

func (k *keyStore) set(user string, pubs ...[]byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys = map[string][][]byte{}
	if len(pubs) > 0 {
		k.keys[user] = pubs
	}
}

// TestKeyLogin — REQ-S-24: вход паролем с «Доверять» кладёт ключ во вход без пароля этой записи; дальше — ключ без
// пароля и верный TOTP; ключ не из списка, другой записи или отозванный — "nokey" и неудача в счётчике; запись без
// TOTP и режим «Спрашивать» — по ключу нельзя (и окна нет); неверные коды после ключа — та же лестница кодов записи.
func TestKeyLogin(t *testing.T) {
	k, _ := pake.ClientSignB64(e2eSeed(), "", "", "")
	pub, _ := base64.StdEncoding.DecodeString(k["pub"])
	ivan, def := &otpHost{secret: totp.NewSecret()}, &otpHost{secret: totp.NewSecret()}
	us := map[string]testUser{"": {pass: "secret123", otp: def}, "ivan": {pass: "ivan-pass1", otp: ivan}, "olga": {pass: "olga-pass1"}}
	hosts := usersHost(us)
	ks := &keyStore{}
	ks.set("")
	var ag *Agent
	var asked, okKey, otpConf, okConf, nokey atomic.Bool
	var asks atomic.Int32
	unattended, hostLocked := true, false
	e2eAgent = func(a *Agent) {
		ag = a
		hosts(a)
		a.KeyLogin, a.KeyTrust = ks.has, ks.add
		a.Unattended = func() bool { return unattended }
		a.Confirm = func(string, string) Answer { asked.Store(true); return Allow }
		if hostLocked { // хост заперт чужим перебором: ключ своей записи блокировку паролей не смотрит (У3)
			a.fails, a.lockUntil = 25, time.Now().Add(time.Hour)
		}
	}
	e2eSeen = func(m authMsg) {
		switch m.T {
		case "ok":
			okKey.Store(m.Key)
			okConf.Store(len(m.Conf) > 0)
		case "otp":
			asks.Add(1)
			otpConf.Store(len(m.Conf) > 0)
		case "nokey":
			nokey.Store(true)
		}
	}
	reset := func() {
		asked.Store(false)
		okKey.Store(false)
		otpConf.Store(false)
		okConf.Store(false)
		nokey.Store(false)
		asks.Store(0)
	}
	defer e2eReset()
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
	e2eKey, e2eUser, e2eGood = "ok", "ivan", "ivan-pass1"
	e2eOTP = func(int) string { ivan.mu.Lock(); ivan.last = 0; ivan.mu.Unlock(); return ivan.code() }

	// до «Доверять» ключа нет в списке: "nokey", неудача засчитана записи
	e2eByKey, e2eFail = true, true
	e2e(t, local(t), "123456789", false, ff, "ivan-pass1")
	if f, _ := nlock(ag, "ivan"); f != 1 || !nokey.Load() || asks.Load() != 0 {
		t.Fatalf("ключа нет в списке: неудач записи %d, nokey %v, запросов кода %d", f, nokey.Load(), asks.Load())
	}

	// пароль + «Доверять» + код — ключ во входе без пароля записи ivan, "ok" с key
	e2eByKey, e2eFail, e2eTrust = false, false, true
	reset()
	e2e(t, local(t), "123456789", false, ff, "ivan-pass1")
	if !ks.has(pub, "ivan") || ks.has(pub, "") || !okKey.Load() || !okConf.Load() {
		t.Fatalf("после «Доверять»: у ivan %v, у записи по умолчанию %v, key в ok %v, conf %v", ks.has(pub, "ivan"), ks.has(pub, ""), okKey.Load(), okConf.Load())
	}

	// ключ без пароля + верный код — сессия; CPace не было: ни в "otp", ни в "ok" conf нет
	e2eTrust, e2eByKey, hostLocked = false, true, true
	reset()
	e2e(t, local(t), "123456789", false, ff, "ivan-pass1")
	if asks.Load() != 1 || otpConf.Load() || okConf.Load() || !okKey.Load() {
		t.Fatalf("по ключу: запросов кода %d, conf в otp %v, conf в ok %v, key в ok %v", asks.Load(), otpConf.Load(), okConf.Load(), okKey.Load())
	}
	if f, _ := lock(ag); f != 25 {
		t.Fatalf("вход по ключу сбросил общий счётчик: %d", f)
	}

	// неверные коды после ключа — лестница кодов записи: 5 запросов, блокировка
	e2eFail = true
	e2eOTP = func(int) string { c := []byte(ivan.code()); c[0] = '0' + (c[0]-'0'+1)%10; return string(c) }
	reset()
	e2e(t, local(t), "123456789", false, ff, "ivan-pass1")
	ag.mu.Lock()
	of, ol := ag.names["ivan"].otpFails, time.Until(ag.names["ivan"].otpUntil)
	ag.mu.Unlock()
	if asks.Load() != 5 || of != 5 || ol < 50*time.Second {
		t.Fatalf("неверные коды по ключу: запросов %d, неудач %d, блокировка %v", asks.Load(), of, ol)
	}

	// тот же ключ к другой записи, отозванный, запись без TOTP, режим «Спрашивать» — "nokey", кода и окна нет
	hostLocked = false
	for _, c := range []struct {
		name, user string
		keys       string // за какой записью ключ; "-" — ни за какой
		unattended bool
		counted    bool // неудача засчитана записи
	}{
		{"другая запись", "", "ivan", true, true},
		{"отозван", "ivan", "-", true, true},
		{"без TOTP", "olga", "olga", true, false},
		{"Спрашивать", "ivan", "ivan", false, false},
	} {
		if c.keys == "-" {
			ks.set("")
		} else {
			ks.set(c.keys, pub)
		}
		unattended, e2eUser = c.unattended, c.user
		reset()
		e2e(t, local(t), "123456789", false, ff, "ivan-pass1")
		f, _ := nlock(ag, c.user)
		if !nokey.Load() || asks.Load() != 0 || asked.Load() || (f == 1) != c.counted {
			t.Fatalf("%s: nokey %v, запросов кода %d, окно %v, неудач %d", c.name, nokey.Load(), asks.Load(), asked.Load(), f)
		}
	}

	// «Доверять» у записи без TOTP (вход через «Разрешить») ключ не добавляет: по нему всё равно не войти
	ks.set("")
	unattended, e2eByKey, e2eTrust, e2eFail, e2eUser, e2eGood, e2eOTP = true, false, true, false, "olga", "olga-pass1", nil
	reset()
	e2e(t, local(t), "123456789", false, ff, "olga-pass1")
	if ks.has(pub, "olga") || okKey.Load() || !asked.Load() {
		t.Fatalf("olga без TOTP: ключ добавлен %v, key в ok %v, окно %v", ks.has(pub, "olga"), okKey.Load(), asked.Load())
	}
}

// TestKeyLoginBadSig — заявка ключа из списка без верной подписи над DTLS-отпечатками — "nokey" и неудача.
func TestKeyLoginBadSig(t *testing.T) {
	k, _ := pake.ClientSignB64(e2eSeed(), "", "", "")
	pub, _ := base64.StdEncoding.DecodeString(k["pub"])
	ivan := &otpHost{secret: totp.NewSecret()}
	hosts := usersHost(map[string]testUser{"": {pass: "secret123"}, "ivan": {pass: "ivan-pass1", otp: ivan}})
	ks := &keyStore{}
	ks.set("ivan", pub)
	var ag *Agent
	e2eAgent = func(a *Agent) {
		ag = a
		hosts(a)
		a.KeyLogin, a.KeyTrust = ks.has, ks.add
		a.Unattended = func() bool { return true }
	}
	defer e2eReset()
	e2eKey, e2eByKey, e2eFail, e2eUser = "bad", true, true, "ivan"
	e2eOTP = func(int) string { return ivan.code() }
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "")
	if f, _ := nlock(ag, "ivan"); f != 1 {
		t.Fatalf("неверная подпись ключа: неудач %d", f)
	}
}

// TestKeyLoginRevoke — отзыв ключа во время сессии этим ключом рвёт её (DropRevoked); без отзыва — нет; сессию
// паролем отзыв её ключа не рвёт.
func TestKeyLoginRevoke(t *testing.T) {
	k, _ := pake.ClientSignB64(e2eSeed(), "", "", "")
	pub, _ := base64.StdEncoding.DecodeString(k["pub"])
	ivan := &otpHost{secret: totp.NewSecret()}
	hosts := usersHost(map[string]testUser{"": {pass: "secret123"}, "ivan": {pass: "ivan-pass1", otp: ivan}})
	ks := &keyStore{}
	var revoke, gone atomic.Bool
	e2eAgent = func(a *Agent) {
		hosts(a)
		a.KeyLogin, a.KeyTrust = ks.has, ks.add
		a.Unattended = func() bool { return true }
	}
	e2eInput = func(t *testing.T, a *Agent) {
		if revoke.Load() {
			ks.set("")
		}
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
	e2eKey, e2eUser, e2eGood = "ok", "ivan", "ivan-pass1"
	e2eOTP = func(int) string { ivan.mu.Lock(); ivan.last = 0; ivan.mu.Unlock(); return ivan.code() }
	for _, c := range []struct {
		byKey, revoke, gone bool
	}{{true, false, false}, {true, true, true}, {false, true, false}} {
		ks.set("ivan", pub)
		e2eByKey = c.byKey
		revoke.Store(c.revoke)
		e2e(t, local(t), "123456789", false, ff, "ivan-pass1")
		if gone.Load() != c.gone {
			t.Fatalf("по ключу %v, отзыв %v: разорвана %v", c.byKey, c.revoke, gone.Load())
		}
	}
}
