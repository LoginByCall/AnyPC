package agent

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anypc/pake"
	"anypc/totp"

	"github.com/pion/webrtc/v4"
)

// trustSend — e2e-клиент шлёт в ctl сырые сообщения и собирает ответы "trust".
func trustSend(t *testing.T, dc *webrtc.DataChannel, raw ...string) []trustMsg {
	t.Helper()
	var got []trustMsg
	recv := make(chan trustMsg, 8)
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		var tm trustMsg
		if json.Unmarshal(m.Data, &tm) == nil && tm.T == "trust" {
			recv <- tm
		}
	})
	for _, s := range raw {
		dc.SendText(s)
		select {
		case m := <-recv:
			got = append(got, m)
		case <-time.After(5 * time.Second):
			t.Fatalf("нет ответа на %s", s)
		}
	}
	return got
}

// TestTrustCtl — Ч7б (решение B): ctl "trust" в вошедшей сессии кладёт доказанный в "b" ключ во вход без пароля
// записи тем же KeyTrust (с солью — режим добавления, пределы — у владельца списка), один раз за сессию; "ok"
// объявляет trust только такой сессии. Отказы: вход ключом, пропуском, через «Разрешить» (код разовой помощи),
// запись без TOTP, ключ не доказан или подписан над другим соединением, cpub не тот, trust уже был в "b", второй
// trust, «Спрашивать» включили во время сессии, ключ исключён из пространства, ключ не добавился, хост без входа
// по ключу. Дальше добавленным ключом входят без пароля.
func TestTrustCtl(t *testing.T) {
	k, _ := pake.ClientSignB64(e2eSeed(), "", "", "")
	pub, _ := base64.StdEncoding.DecodeString(k["pub"])
	opub, _, _ := ed25519.GenerateKey(nil)
	other := base64.StdEncoding.EncodeToString(opub)
	ivan, def := &otpHost{secret: totp.NewSecret()}, &otpHost{secret: totp.NewSecret()}
	hosts := usersHost(map[string]testUser{"": {pass: "secret123", otp: def}, "ivan": {pass: "ivan-pass1", otp: ivan}, "olga": {pass: "olga-pass1"}})
	fresh := func(o *otpHost) func(int) string {
		return func(int) string { o.mu.Lock(); o.last = 0; o.mu.Unlock(); return o.code() }
	}
	defer func() { e2eReset(); e2eCtl, e2eNoVideo, e2ePass = nil, false, false }()
	e2eNoVideo = true

	type tc struct {
		name     string
		user     string // запись; пароль — по ней
		key      string // e2eKey
		byKey    bool   // вход ключом
		pass     bool   // вход по пропуску
		trust    bool   // trust в "b"
		ask      bool   // «Спрашивать» (вход через «Разрешить»)
		has      bool   // ключ уже во входе без пароля записи
		noKeys   bool   // хост без входа по ключу (KeyLogin == nil)
		mid      func() // перед ctl: смена условий во время сессии
		send     []string
		okTrust  bool     // trust в "ok"
		want     []string // "ok" или why по порядку
		added    int      // вызовов KeyTrust с солью
		keyAfter bool     // ключ во входе записи после
	}
	var (
		mu       sync.Mutex
		adds     int
		addSalt  []byte
		refuse   atomic.Bool // KeyTrust не добавляет (пароль сменили, список не принял)
		gone     atomic.Bool // KeyGone: ключ исключён из пространства
		unatt    atomic.Bool
		okTrust  atomic.Bool
		ks       = &keyStore{}
		fpWant   = pake.KeyFingerprint(pub)
		trust    = `{"t":"trust"}`
		trustOth = `{"t":"trust","cpub":"` + other + `"}`
		trustOwn = `{"t":"trust","cpub":"` + k["pub"] + `"}`
	)
	cases := []tc{
		{name: "пароль и код", user: "ivan", key: e2eSeed(), send: []string{trustOth, trustOwn, trust}, okTrust: true, want: []string{"key", "ok", "again"}, added: 1, keyAfter: true},
		{name: "дальше ключом", user: "ivan", key: e2eSeed(), byKey: true, has: true, send: []string{trust}, want: []string{"rights"}, keyAfter: true},
		{name: "пропуск", key: e2eSeed(), byKey: true, pass: true, send: []string{trust}, want: []string{"rights"}},
		{name: "Разрешить", user: "ivan", key: e2eSeed(), ask: true, send: []string{trust}, want: []string{"rights"}},
		{name: "без TOTP", user: "olga", key: e2eSeed(), send: []string{trust}, want: []string{"rights"}},
		{name: "без ключа", user: "ivan", send: []string{trust}, want: []string{"key"}},
		{name: "ключ другого соединения", user: "ivan", key: "otherpw", send: []string{trust, trustOwn}, want: []string{"key", "key"}},
		{name: "trust в b", user: "ivan", key: e2eSeed(), trust: true, send: []string{trust}, want: []string{"again"}, added: 1, keyAfter: true},
		{name: "Спрашивать во время", user: "ivan", key: e2eSeed(), mid: func() { unatt.Store(false); ks.mu.Lock(); ks.ask = true; ks.mu.Unlock() }, okTrust: true, send: []string{trust, trust}, want: []string{"ask", "again"}},
		{name: "исключён", user: "ivan", key: e2eSeed(), mid: func() { gone.Store(true) }, okTrust: true, send: []string{trust}, want: []string{"gone"}},
		{name: "не добавился", user: "ivan", key: e2eSeed(), mid: func() { refuse.Store(true) }, okTrust: true, send: []string{trust}, want: []string{"gone"}, added: 1},
		{name: "ключ у другой записи", user: "ivan", key: e2eSeed(), mid: func() { refuse.Store(true); ks.mu.Lock(); ks.keys[""] = [][]byte{pub}; ks.mu.Unlock() }, okTrust: true, send: []string{trust}, want: []string{"gone"}, added: 1},
		{name: "вход ключом выключен после KeyTrust", user: "ivan", key: e2eSeed(), mid: func() { ks.mu.Lock(); ks.ask = true; ks.mu.Unlock() }, okTrust: true, send: []string{trust}, want: []string{"gone"}, added: 1, keyAfter: true},
		{name: "хост без ключей", user: "ivan", key: e2eSeed(), noKeys: true, send: []string{trust}, want: []string{"rights"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mu.Lock()
			adds, addSalt = 0, nil
			mu.Unlock()
			refuse.Store(false)
			gone.Store(false)
			unatt.Store(!c.ask)
			okTrust.Store(false)
			ks.set(c.user)
			if c.has {
				ks.set(c.user, pub)
			}
			ks.ask = false
			e2eAgent = func(a *Agent) {
				hosts(a)
				a.Unattended = unatt.Load
				a.Confirm = func(string, string) Answer { return Allow }
				a.KeyGone = func(p []byte) bool { return gone.Load() && bytes.Equal(p, pub) }
				if !c.noKeys {
					a.KeyLogin = ks.login
					a.KeyTrust = func(p []byte, u string, salt []byte) {
						if salt != nil {
							mu.Lock()
							adds++
							addSalt = bytes.Clone(salt)
							mu.Unlock()
						}
						if !refuse.Load() {
							ks.add(p, u, salt)
						}
					}
				}
				if c.pass { // Э3: пропуск этого ключа на записи владельца уже выдан
					now := time.Now()
					a.passes = map[string]passEntry{string(pub): {exp: now.Add(time.Hour), wall: now.Add(time.Hour).Round(0), salt: userSalt(""), id: []byte("pid")}}
					a.SpaceMember = func(_, p []byte) bool { return bytes.Equal(p, pub) }
				}
			}
			e2eSeen = func(m authMsg) {
				if m.T == "ok" {
					okTrust.Store(m.Trust)
				}
			}
			e2eUser, e2eKey, e2eByKey, e2ePass, e2eTrust = c.user, c.key, c.byKey, c.pass, c.trust
			pw, o := "secret123", def
			switch c.user {
			case "ivan":
				pw, o = "ivan-pass1", ivan
			case "olga":
				pw, o = "olga-pass1", nil
			}
			e2eGood, e2eOTP = pw, nil
			if o != nil && !c.pass {
				e2eOTP = fresh(o)
			}
			var got []trustMsg
			e2eCtl = func(t *testing.T, dc *webrtc.DataChannel, _ chan ctlMsg) {
				if c.mid != nil {
					c.mid()
				}
				got = trustSend(t, dc, c.send...)
			}
			e2e(t, local(t), "123456789", false, nil, pw)
			if okTrust.Load() != c.okTrust {
				t.Errorf("trust в ok %v, ждали %v", okTrust.Load(), c.okTrust)
			}
			if len(got) != len(c.want) {
				t.Fatalf("ответов %d: %+v", len(got), got)
			}
			for i, w := range c.want {
				g := got[i]
				if w == "ok" {
					if !g.OK || g.Why != "" || g.FP != fpWant {
						t.Errorf("ответ %d: %+v, ждали ok с отпечатком %s", i, g, fpWant)
					}
				} else if g.OK || g.Why != w || g.FP != "" {
					t.Errorf("ответ %d: %+v, ждали отказ %q", i, g, w)
				}
			}
			mu.Lock()
			n, salt := adds, addSalt
			mu.Unlock()
			if n != c.added || n > 0 && !bytes.Equal(salt, userSalt(c.user)) {
				t.Errorf("KeyTrust с солью: %d раз (соль %q), ждали %d", n, salt, c.added)
			}
			if in := ks.in(pub, c.user); in != c.keyAfter {
				t.Errorf("ключ во входе записи %q: %v, ждали %v", c.user, in, c.keyAfter)
			}
		})
	}
}

// TestTrustCtlLog — журнал хоста: «Добавить» в сессии пишет отпечаток добавленного ключа; пароль и код — нет.
func TestTrustCtlLog(t *testing.T) {
	var logs syncBuf
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	ivan := &otpHost{secret: totp.NewSecret()}
	hosts := usersHost(map[string]testUser{"": {pass: "secret123"}, "ivan": {pass: "ivan-pass1", otp: ivan}})
	ks := &keyStore{}
	ks.set("ivan")
	defer func() { e2eReset(); e2eCtl, e2eNoVideo = nil, false }()
	e2eNoVideo = true
	e2eAgent = func(a *Agent) {
		hosts(a)
		a.Unattended = func() bool { return true }
		a.KeyLogin, a.KeyTrust = ks.login, ks.add
	}
	e2eUser, e2eGood, e2eKey = "ivan", "ivan-pass1", e2eSeed()
	e2eOTP = func(int) string { return ivan.code() }
	var got []trustMsg
	e2eCtl = func(t *testing.T, dc *webrtc.DataChannel, _ chan ctlMsg) { got = trustSend(t, dc, `{"t":"trust"}`) }
	e2e(t, local(t), "123456789", false, nil, "ivan-pass1")
	if len(got) != 1 || !got[0].OK {
		t.Fatalf("ответ %+v", got)
	}
	if l := logs.String(); !strings.Contains(l, "ключ "+got[0].FP[:9]+" во входе без пароля") || strings.Contains(l, "ivan-pass1") || strings.Contains(l, ivan.secret) {
		t.Errorf("журнал:\n%s", l)
	}
}

// TestTrustCtlMore — сценарии приёмки Ч7б: пароль сменили и TOTP сняли во время сессии; «Только показ экрана» и
// запись «просмотр» trust не запрещают (как в "b"); cpub "" — не тот ключ, null — как без поля; журнал — только
// отказы после «одного на сессию» (поток отказов до него журнал не засоряет).
func TestTrustCtlMore(t *testing.T) {
	k, _ := pake.ClientSignB64(e2eSeed(), "", "", "")
	pub, _ := base64.StdEncoding.DecodeString(k["pub"])
	ivan := &otpHost{secret: totp.NewSecret()}
	hosts := usersHost(map[string]testUser{"": {pass: "secret123", otp: &otpHost{secret: totp.NewSecret()}}, "ivan": {pass: "ivan-pass1", otp: ivan, view: true}})
	defer func() { e2eReset(); e2eCtl, e2eNoVideo = nil, false }()
	e2eNoVideo = true
	var pwChanged, noTOTP, viewOnly atomic.Bool
	ks := &keyStore{}
	many, manyW := make([]string, 300), make([]string, 300)
	for i := range many {
		many[i], manyW[i] = `{"t":"trust","cpub":"AAAA"}`, "key"
	}
	for _, c := range []struct {
		name string
		mid  func()
		send []string
		want []string
		in   bool
		logs int // строк журнала «отказ (»
	}{
		{name: "пароль сменили", mid: func() { pwChanged.Store(true) }, send: []string{`{"t":"trust"}`, `{"t":"trust"}`}, want: []string{"gone", "again"}, logs: 1},
		{name: "TOTP сняли", mid: func() { noTOTP.Store(true) }, send: []string{`{"t":"trust"}`}, want: []string{"ask"}, logs: 1},
		{name: "Только показ экрана и запись просмотр", mid: func() { viewOnly.Store(true) }, send: []string{`{"t":"trust"}`}, want: []string{"ok"}, in: true},
		{name: "cpub пустой, null", send: []string{`{"t":"trust","cpub":""}`, `{"t":"trust","cpub":null}`}, want: []string{"key", "ok"}, in: true},
		{name: "поток отказов", send: many, want: manyW},
	} {
		t.Run(c.name, func(t *testing.T) {
			pwChanged.Store(false)
			noTOTP.Store(false)
			viewOnly.Store(false)
			ks.set("ivan")
			var logs syncBuf
			log.SetOutput(&logs)
			defer log.SetOutput(os.Stderr)
			e2eAgent = func(a *Agent) {
				hosts(a)
				sec := a.Secret
				a.Secret = func(n string) ([]byte, []byte, bool) {
					s, h, v := sec(n)
					if pwChanged.Load() {
						s = []byte("another-salt-012")
					}
					return s, h, v
				}
				otp := a.OTP
				a.OTP = func(n, code string) (bool, bool) {
					if noTOTP.Load() {
						return false, false
					}
					return otp(n, code)
				}
				a.ViewOnly = viewOnly.Load
				a.Unattended = func() bool { return true }
				a.Confirm = func(string, string) Answer { return Allow }
				a.KeyLogin, a.KeyTrust = ks.login, ks.add
			}
			e2eUser, e2eGood, e2eKey = "ivan", "ivan-pass1", e2eSeed()
			e2eOTP = func(int) string { ivan.mu.Lock(); ivan.last = 0; ivan.mu.Unlock(); return ivan.code() }
			var got []trustMsg
			e2eCtl = func(t *testing.T, dc *webrtc.DataChannel, _ chan ctlMsg) {
				if c.mid != nil {
					c.mid()
				}
				got = trustSend(t, dc, c.send...)
			}
			e2e(t, local(t), "123456789", false, nil, "ivan-pass1")
			if len(got) != len(c.want) {
				t.Fatalf("ответов %d: %+v", len(got), got)
			}
			for i, w := range c.want {
				if g := got[i]; w == "ok" && !g.OK || w != "ok" && (g.OK || g.Why != w) {
					t.Errorf("ответ %d: %+v, ждали %q", i, g, w)
				}
			}
			if in := ks.in(pub, "ivan"); in != c.in {
				t.Errorf("ключ во входе: %v, ждали %v", in, c.in)
			}
			if ks.in(pub, "") {
				t.Error("ключ попал в запись по умолчанию")
			}
			if n := strings.Count(logs.String(), "отказ ("); n != c.logs {
				t.Errorf("строк журнала об отказе %d, ждали %d", n, c.logs)
			}
		})
	}
}
