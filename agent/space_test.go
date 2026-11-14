package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anypc/pake"
	"anypc/totp"

	"github.com/pion/webrtc/v4"
)

// spaceRig — ПК пространства P для тестов Э2: запись по умолчанию secret123 с TOTP, гость «guest» со своим TOTP,
// состав — непрозрачные байты (разбор — app/space.go). Захвата нет: вступлению видео не нужно.
type spaceRig struct {
	a            *Agent
	owner, guest *otpHost
	ask          atomic.Bool // режим «Спрашивать»: вход через «Разрешить», без кода
	mu           sync.Mutex
	m            []byte
	joined       []byte
	joinPub      ed25519.PublicKey
}

var guestSalt = []byte("fedcba9876543210")

// newSpaceRig — настроить хост a как P.
func newSpaceRig(a *Agent) *spaceRig {
	r := &spaceRig{a: a, owner: &otpHost{secret: totp.NewSecret()}, guest: &otpHost{secret: totp.NewSecret()}, m: []byte("M-SECRET-MARK-1")}
	gsec, osec := pake.KDF("guestpass123", guestSalt), pake.KDF("secret123", salt)
	a.Secret = func(u string) ([]byte, []byte, bool) {
		switch u {
		case "":
			return salt, osec, false
		case "guest":
			return guestSalt, gsec, false
		}
		return nil, nil, false
	}
	a.OTP = func(u, code string) (bool, bool) {
		if u == "guest" {
			return r.guest.check(u, code)
		}
		return r.owner.check(u, code)
	}
	a.Unattended = func() bool { return !r.ask.Load() }
	a.Confirm = func(string, string) Answer { return Allow }
	a.Capture = func(context.Context, Cap) (*exec.Cmd, error) {
		return nil, errors.New("тест: без захвата")
	}
	a.SpaceGet = func(s []byte) []byte {
		r.mu.Lock()
		defer r.mu.Unlock()
		if !bytes.Equal(s, salt) {
			return nil
		}
		return bytes.Clone(r.m)
	}
	a.SpaceJoin = func(s, m []byte, pub ed25519.PublicKey) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if !bytes.Equal(s, salt) || bytes.Contains(m, []byte("reject")) {
			return errors.New("тест: не принят")
		}
		r.joined, r.joinPub = bytes.Clone(m), bytes.Clone(pub)
		return nil
	}
	return r
}

// spaceHost — P в сети на хабе url (opt — правка до запуска); ждать регистрации.
func spaceHost(t *testing.T, url, id string, opt ...func(*spaceRig)) *spaceRig {
	r := newSpaceRig(newAgent(url, id, nil))
	for _, f := range opt {
		f(r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	on := make(chan bool, 4)
	r.a.OnState = func(o bool, _ string) {
		select {
		case on <- o:
		default:
		}
	}
	go r.a.Run(ctx)
	select {
	case <-on:
	case <-time.After(5 * time.Second):
		t.Fatal("P не зарегистрировался")
	}
	return r
}

// syncBuf — журнал для проверки: пишут горутины pion и хоста, читает тест.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) { b.mu.Lock(); defer b.mu.Unlock(); return b.b.Write(p) }
func (b *syncBuf) String() string              { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }

// TestSpaceJoin — Э2, вступление по сети: N входит на P паролем и кодом записи по умолчанию, получает M, отдаёт
// подписанный M; P принимает его с ключом, которым N доказал себя в "b". Секреты (M) не в журнале.
func TestSpaceJoin(t *testing.T) {
	var logs syncBuf
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	url := local(t)
	var leaked atomic.Int32 // С5: ключ клиента в connect (его видит хаб) — хост спросил бы о нём с AnyUser
	r := spaceHost(t, url, "123456789", func(r *spaceRig) {
		r.a.Trusted = func(_ []byte, u string) bool {
			if u == AnyUser {
				leaked.Add(1)
			}
			return false
		}
		r.a.KeyLogin = func(_ []byte, u string) (bool, bool) {
			if u == AnyUser {
				leaked.Add(1)
			}
			return false, false
		}
	})
	_, nkey, _ := ed25519.GenerateKey(nil)
	var gotHost ed25519.PublicKey
	out, err := SpaceJoin(context.Background(), SpaceDial{Server: url, ID: "123456789", Key: nkey, Password: "secret123", Code: r.owner.code(),
		Sign: func(m []byte, hp ed25519.PublicKey) ([]byte, error) {
			if !bytes.Equal(m, r.m) {
				t.Errorf("пришёл не тот M: %q", m)
			}
			gotHost = hp
			return append(bytes.Clone(m), "+N"...), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotHost, r.a.Key.Public().(ed25519.PublicKey)) {
		t.Error("ключ хоста P в Sign — не его")
	}
	r.mu.Lock()
	joined, jp := r.joined, r.joinPub
	r.mu.Unlock()
	if string(out) != "M-SECRET-MARK-1+N" || !bytes.Equal(joined, out) {
		t.Errorf("P принял %q, N получил %q", joined, out)
	}
	if !bytes.Equal(jp, nkey.Public().(ed25519.PublicKey)) {
		t.Error("ключ нового ПК в SpaceJoin — не тот, которым он вошёл")
	}
	if leaked.Load() != 0 {
		t.Error("ключ клиента ушёл в connect (виден хабу)")
	}
	for _, s := range []string{"M-SECRET-MARK", base64.StdEncoding.EncodeToString(r.m), r.owner.secret} {
		if strings.Contains(logs.String(), s) {
			t.Errorf("в журнале секрет %q", s)
		}
	}
	if !strings.Contains(logs.String(), "вступил в пространство") {
		t.Error("вступление не в журнале")
	}
}

// TestSpaceJoinRefused — неверный код и пароль (M не отдаётся), «Спрашивать» (вход через «Разрешить»), отказ P
// принять M.
func TestSpaceJoinRefused(t *testing.T) {
	url := local(t)
	r := spaceHost(t, url, "123456789")
	_, nkey, _ := ed25519.GenerateKey(nil)
	signed := false
	d := SpaceDial{Server: url, ID: "123456789", Key: nkey, Password: "secret123", Code: "000000",
		Sign: func(m []byte, _ ed25519.PublicKey) ([]byte, error) {
			signed = true
			return append(bytes.Clone(m), '+'), nil
		}}
	if r.owner.code() == "000000" {
		d.Code = "111111"
	}
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceAuth) {
		t.Errorf("неверный код: %v", err)
	}
	d.Code, d.Password = r.owner.code(), "wrong-pass"
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceAuth) {
		t.Errorf("неверный пароль: %v", err)
	}
	if signed {
		t.Error("M отдан без входа")
	}
	d.Password = "secret123"
	r.ask.Store(true)
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceAsk) || signed {
		t.Errorf("«Спрашивать»: %v (подписан %v)", err, signed)
	}
	r.ask.Store(false)
	r.mu.Lock()
	r.m = []byte("reject")
	r.mu.Unlock()
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceRefused) || !signed { // код ещё не входил
		t.Errorf("P не принял M: %v (подписан %v)", err, signed)
	}
}

// TestSpaceOldHost — хост без пространства (SpaceGet == nil, как v0.1.27): клиент вступления узнаёт это по "a" и
// пароля не отдаёт (CPace не начинается — неудачи у хоста нет).
func TestSpaceOldHost(t *testing.T) {
	url := local(t)
	r := spaceHost(t, url, "123456789", func(r *spaceRig) { r.a.SpaceGet, r.a.SpaceJoin = nil, nil })
	_, nkey, _ := ed25519.GenerateKey(nil)
	_, err := SpaceJoin(context.Background(), SpaceDial{Server: url, ID: "123456789", Key: nkey, Password: "secret123", Code: r.owner.code(),
		Sign: func(m []byte, _ ed25519.PublicKey) ([]byte, error) { return m, nil }})
	if !errors.Is(err, ErrSpaceOld) {
		t.Errorf("старый хост: %v", err)
	}
	if f, _ := lock(r.a); f != 0 {
		t.Errorf("неудач у хоста %d", f)
	}
}

// spaceCtl — e2e-клиент (как браузер) шлёт в ctl сырые "sp" и собирает ответы.
func spaceCtl(t *testing.T, dc *webrtc.DataChannel, msgs chan ctlMsg, raw ...string) []spMsg {
	t.Helper()
	var got []spMsg
	recv := make(chan spMsg, 8)
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		var sm spMsg
		if json.Unmarshal(m.Data, &sm) == nil && sm.T == "sp" {
			recv <- sm
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

// TestSpaceCtlRights — ctl "sp": гость со своим кодом, вход «Разрешить» (разовый код) и вход без кода — "rights";
// владелец с кодом без доказанного ключа — M отдаётся, вступление — "key"; с ключом — одно вступление на сессию.
func TestSpaceCtlRights(t *testing.T) {
	var r *spaceRig
	e2eNoVideo = true
	defer func() {
		e2eAgent, e2eCtl, e2eNoVideo, e2eOTP, e2eUser, e2eGood, e2eKey = nil, nil, false, nil, "", "", ""
	}()
	type step struct {
		name      string
		user, key string
		ask, code bool
		viewOnly  bool // «Только показ экрана» на хосте
		send      []string
		want      []spMsg
	}
	join := `{"t":"sp","m":"` + base64.StdEncoding.EncodeToString([]byte("M+N")) + `"}`
	for _, c := range []step{
		{name: "гость", user: "guest", code: true, send: []string{`{"t":"sp"}`, join}, want: []spMsg{{T: "sp", Err: "rights"}, {T: "sp", Err: "rights"}}},
		{name: "разрешить", ask: true, send: []string{`{"t":"sp"}`}, want: []spMsg{{T: "sp", Err: "rights"}}},
		{name: "без ключа", code: true, send: []string{`{"t":"sp"}`, join}, want: []spMsg{{T: "sp", M: []byte("M-SECRET-MARK-1")}, {T: "sp", Err: "key"}}},
		{name: "с ключом", code: true, key: e2eSeed(), send: []string{join, join}, want: []spMsg{{T: "sp", OK: true}, {T: "sp", Err: "again"}}},
		{name: "только показ", code: true, key: e2eSeed(), viewOnly: true, send: []string{`{"t":"sp"}`, join}, want: []spMsg{{T: "sp", Err: "rights"}, {T: "sp", Err: "rights"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e2eAgent = func(a *Agent) {
				r = newSpaceRig(a)
				r.ask.Store(c.ask)
				if c.viewOnly {
					a.ViewOnly = func() bool { return true }
				}
			}
			e2eUser, e2eGood, e2eKey, e2eOTP = c.user, "", c.key, nil
			pass := "secret123"
			if c.user != "" {
				pass, e2eGood = "guestpass123", "guestpass123"
			}
			if c.code {
				e2eOTP = func(int) string {
					if c.user != "" {
						return r.guest.code()
					}
					return r.owner.code()
				}
			}
			e2eCtl = func(t *testing.T, dc *webrtc.DataChannel, msgs chan ctlMsg) {
				got := spaceCtl(t, dc, msgs, c.send...)
				for i := range c.want {
					if got[i].Err != c.want[i].Err || got[i].OK != c.want[i].OK || !bytes.Equal(got[i].M, c.want[i].M) {
						t.Errorf("%s: ответ %d %+v, ждали %+v", c.name, i, got[i], c.want[i])
					}
				}
			}
			e2e(t, local(t), "123456789", false, nil, pass) // свой хаб: у общего — лимит connect с адреса
		})
	}
}

// TestSpaceOldClient — клиент без "sp" (браузер, v0.1.27) на хосте с пространством входит и получает видео, как раньше.
func TestSpaceOldClient(t *testing.T) {
	o := &otpHost{secret: totp.NewSecret()}
	e2eAgent = func(a *Agent) {
		a.OTP, a.SpaceGet = o.check, func([]byte) []byte { return []byte("M") }
		a.SpaceJoin = func([]byte, []byte, ed25519.PublicKey) error {
			t.Error("вступление без запроса")
			return nil
		}
	}
	e2eOTP = func(int) string { return o.code() }
	defer func() { e2eAgent, e2eOTP = nil, nil }()
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
}

// TestSpaceKnownHost — С8: ключ P не тот, что запомнен на этом ПК (Known), — отказ до отправки кода (код на P не
// израсходован); тот же — вступление идёт.
func TestSpaceKnownHost(t *testing.T) {
	url := local(t)
	r := spaceHost(t, url, "123456789")
	_, nkey, _ := ed25519.GenerateKey(nil)
	d := SpaceDial{Server: url, ID: "123456789", Key: nkey, Password: "secret123", Code: r.owner.code(),
		Known: pake.KeyFingerprint(bytes.Repeat([]byte{9}, 32)),
		Sign:  func(m []byte, _ ed25519.PublicKey) ([]byte, error) { return append(bytes.Clone(m), '+'), nil }}
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceHostKey) {
		t.Fatalf("чужой ключ P: %v", err)
	}
	r.owner.mu.Lock()
	used := r.owner.last != 0
	r.owner.mu.Unlock()
	if used {
		t.Error("код отдан P с незапомненным ключом")
	}
	d.Known = pake.KeyFingerprint(r.a.Key.Public().(ed25519.PublicKey))
	if _, err := SpaceJoin(context.Background(), d); err != nil {
		t.Fatal(err)
	}
}

// TestSpaceAlready — С1: Sign вернул тот же M (этот ПК уже в составе P) — P ничего не шлётся, вступление успешно.
func TestSpaceAlready(t *testing.T) {
	url := local(t)
	r := spaceHost(t, url, "123456789")
	_, nkey, _ := ed25519.GenerateKey(nil)
	out, err := SpaceJoin(context.Background(), SpaceDial{Server: url, ID: "123456789", Key: nkey, Password: "secret123", Code: r.owner.code(),
		Sign: func(m []byte, _ ed25519.PublicKey) ([]byte, error) { return m, nil }})
	r.mu.Lock()
	joined := r.joined
	r.mu.Unlock()
	if err != nil || string(out) != "M-SECRET-MARK-1" || joined != nil {
		t.Fatalf("уже в составе: %q %v, P получил %q", out, err, joined)
	}
}
