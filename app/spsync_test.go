package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"anypc/agent"
	"anypc/hub"
	"anypc/pake"
	"anypc/totp"
)

// Э4: сверка состава между членами по настоящей сети (хаб в памяти, agent/spsync.go) — ПК = config + agent.

func syncHub(t *testing.T) string {
	srv := httptest.NewServer(&hub.Hub{})
	t.Cleanup(srv.Close)
	oldR, oldM := spaceSyncRetry, spaceSyncRetryMax
	spaceSyncRetry, spaceSyncRetryMax = 50*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { spaceSyncRetry, spaceSyncRetryMax = oldR, oldM })
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

// syncPC — ПК на хабе url: хост с паролем и кодом записи по умолчанию, вступлением (Э2) и сверкой (Э4); old — хост
// старой версии (без сверки). stop — выключить ПК (хост уходит с хаба, повторы рассылки кончаются).
type syncPC struct {
	c    *config
	stop func()
}

func syncNode(t *testing.T, url string, c *config, old bool) *syncPC {
	t.Helper()
	c.mu.Lock()
	c.Server = url
	c.save()
	c.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	syn := &spaceSyncer{cfg: c, ctx: ctx}
	c.syn = syn
	a := &agent.Agent{Server: url, ID: c.id(), Secret: c.secret, Key: c.key(), OTP: c.otp,
		Unattended: func() bool { return !c.confirm() }, SpaceGet: c.spaceGet, SpaceJoin: c.spaceJoin, SpaceMember: c.spaceMember, LoginShut: c.loginShut,
		Capture: func(context.Context, agent.Cap) (*exec.Cmd, error) {
			return nil, errors.New("тест: без захвата")
		}}
	if !old {
		a.SpaceSync = c
	}
	on := make(chan bool, 8)
	a.OnState = func(o bool, _ string) {
		if o {
			select {
			case on <- o:
			default:
			}
		}
	}
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	select {
	case <-on:
	case <-time.After(10 * time.Second):
		t.Fatal("ПК не зарегистрировался")
	}
	p := &syncPC{c: c}
	p.stop = func() { cancel(); <-done; syn.bg.Wait() }
	t.Cleanup(p.stop)
	return p
}

// syncSpace — пространство на cs[0] с членами cs и ещё ключами extra; M — на всех (запись по умолчанию — из M).
func syncSpace(t *testing.T, extra int, cs ...*config) (string, []ed25519.PublicKey) {
	t.Helper()
	ph := spaceMake(t, cs[0])
	m := spaceOf(cs[0])
	var err error
	for _, c := range cs[1:] {
		if m, err = spaceAdd(m, ph, c.id(), cfgPub(c)); err != nil {
			t.Fatal(err)
		}
	}
	var keys []ed25519.PublicKey
	for range extra {
		pub, _, _ := ed25519.GenerateKey(nil)
		if m, err = spaceAdd(m, ph, "9"+hub.RandDigits(8), pub); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, pub)
	}
	for _, c := range cs {
		spaceReset(t, c, m)
	}
	return ph, keys
}

func spaceOf(c *config) *space {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	return c.spaceLocked()
}

func sameSpaceBytes(a, b *config) bool {
	a.mu.Lock()
	a.reload()
	x := bytes.Clone(a.Space)
	a.mu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reload()
	return bytes.Equal(x, b.Space)
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	for end := time.Now().Add(20 * time.Second); !f(); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal(what)
		}
	}
}

func states(rs []spaceResult) map[string]string {
	m := map[string]string{}
	for _, r := range rs {
		m[r.ID] = r.State
	}
	return m
}

// spaceLogin — вход на ПК c паролем pw и кодом записи по умолчанию по сети (Э2: сессия паролем и кодом отдаёт M).
func spaceLogin(url string, c *config, pw string) error {
	m := spaceOf(c)
	code, _ := totp.Code(m.TOTP, time.Now())
	_, key, _ := ed25519.GenerateKey(nil)
	_, err := agent.SpaceJoin(context.Background(), agent.SpaceDial{Server: url, ID: c.id(), Key: key, Password: pw, Code: code,
		Sign: func(b []byte, _ ed25519.PublicKey, _ ...[]byte) ([]byte, error) { return b, nil }})
	return err
}

// TestSpaceSyncChain — три ПК: исключение и смена пароля на A доходят до B сразу; C был выключен и при запуске
// догоняет две смены входа одной последней M (цепочка не нужна: побеждает сильнейший вход); вход на C новым паролем
// работает, старым — нет.
func TestSpaceSyncChain(t *testing.T) {
	url := syncHub(t)
	sec := totp.NewSecret()
	ca, cb, cc := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, keys := syncSpace(t, 1, ca, cb, cc)
	a, b := syncNode(t, url, ca, false), syncNode(t, url, cb, false)
	_ = b
	ctx := context.Background()

	rs, err := a.c.syn.spaceExclude(ctx, ph, keys[0], "") // исключение — новый секрет кода (смена входа 1)
	if err != nil {
		t.Fatal(err)
	}
	if st := states(rs); st[cb.id()] != "ok" || st[cc.id()] != "offline" || len(st) != 2 {
		t.Fatalf("рассылка исключения: %v", st)
	}
	if _, err := a.c.syn.spaceChangeLogin(ctx, ph, "new-pass-22", false); err != nil { // смена входа 2
		t.Fatal(err)
	}
	ma := spaceOf(ca)
	if ma.LGen != 3 || !sameSpaceBytes(ca, cb) {
		t.Fatalf("B не получил правки: lgen %d", ma.LGen)
	}
	if spaceOf(cb).member(keys[0]) || !spaceOf(cb).gone(keys[0]) {
		t.Error("на B исключённый — член")
	}
	if err := spaceLogin(url, cb, spacePass); !errors.Is(err, agent.ErrSpaceAuth) {
		t.Errorf("старый пароль на B: %v", err)
	}
	if err := spaceLogin(url, cb, "new-pass-22"); err != nil {
		t.Errorf("новый пароль на B: %v", err)
	}

	c := syncNode(t, url, cc, false) // C включили: сверка при запуске
	rs = c.c.syn.spread(ctx, true)
	if st := states(rs); st[ca.id()] != "ok" && st[cb.id()] != "ok" {
		t.Fatalf("C: %v", st)
	}
	eventually(t, "C не догнал A", func() bool { return sameSpaceBytes(ca, cc) })
	cc.mu.Lock()
	heads := len(cc.SpaceHeads)
	u := cc.Users[0]
	cc.mu.Unlock()
	if heads != 0 {
		t.Errorf("C: лишних верхушек %d", heads)
	}
	if !bytes.Equal(pake.KDF("new-pass-22", u.Salt), u.Hash) || u.TOTP != ma.TOTP || u.TOTP == sec {
		t.Error("C: вход записи по умолчанию — не из M")
	}
	if err := spaceLogin(url, cc, spacePass); !errors.Is(err, agent.ErrSpaceAuth) {
		t.Errorf("старый пароль на C: %v", err)
	}
	if err := spaceLogin(url, cc, "new-pass-22"); err != nil {
		t.Errorf("новый пароль на C: %v", err)
	}
	salt, _, _ := cc.secret("")
	if !cc.spaceMember(salt, cfgPub(ca)) {
		t.Error("C: пропуск A не выдаётся")
	}
}

// TestSpaceSyncConcurrent — две правки от одной эпохи (на A смена пароля, на B исключение, без сети): после сверки
// у обоих одно объединение (исключённый не член, вход — исключения по развилке), расколов и флагов нет, пропуска
// выдаются, правки фразой — можно и сводят верхушки к одной.
func TestSpaceSyncConcurrent(t *testing.T) {
	url := syncHub(t)
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, keys := syncSpace(t, 1, ca, cb)
	m := spaceOf(ca)
	na, err := spaceSetLogin(m, ph, "pass-of-a-1", "")
	if err != nil {
		t.Fatal(err)
	}
	nb, err := spaceRemove(m, ph, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.spaceEdit(spSnap(ca), na); err != nil {
		t.Fatal(err)
	}
	if _, err := cb.spaceEdit(spSnap(cb), nb); err != nil {
		t.Fatal(err)
	}
	a, b := syncNode(t, url, ca, false), syncNode(t, url, cb, false)
	if st := states(b.c.syn.spread(context.Background(), false)); st[ca.id()] != "ok" {
		t.Fatalf("сверка: %v", st)
	}
	if !bytes.Equal(spSnap(ca), spSnap(cb)) {
		t.Fatal("верхушки разошлись")
	}
	for _, p := range []*syncPC{a, b} {
		v := spaceOf(p.c)
		if v.member(keys[0]) || !v.gone(keys[0]) || !sameLogin(v, nb) || v.Compromised {
			t.Fatalf("объединение: %v", v)
		}
		salt, _, _ := p.c.secret("")
		other := cfgPub(ca)
		if p == a {
			other = cfgPub(cb)
		}
		if !p.c.spaceMember(salt, other) {
			t.Error("пропуска нет после сверки")
		}
	}
	if err := spaceLogin(url, ca, spacePass); err != nil { // смена пароля на A проиграла исключению (правило развилки)
		t.Errorf("пароль победившего входа на A: %v", err)
	}
	if _, err := a.c.syn.spaceChangeLogin(context.Background(), ph, "pass-again-1", false); err != nil {
		t.Fatalf("правка после встречных правок: %v", err)
	}
	eventually(t, "правка не свела верхушки", func() bool {
		return bytes.Equal(spSnap(ca), spSnap(cb)) && len(spaceHeadsOf(ca)) == 1
	})
}

// TestSpaceLocalLogin — С6: на члене пространства пароль, код и «Спрашивать» записи по умолчанию — только правкой M;
// гостевые записи — как прежде.
func TestSpaceLocalLogin(t *testing.T) {
	sec := totp.NewSecret()
	c := spaceCfg(t, spacePass, sec)
	spaceMake(t, c)
	sec2 := totp.NewSecret()
	code, _ := totp.Code(sec2, time.Now())
	for name, err := range map[string]error{
		"пароль":     c.setPassword("other-pass-1"),
		"Спрашивать": c.setConfirm(true),
		"новый TOTP": c.otpEnable(sec2, code, ""),
		"--user ''":  c.setAccount("", "other-pass-1", ""),
		"гость":      c.setUser("bob", "guest-pass-1", "view"),
	} {
		if want := name != "гость"; errors.Is(err, errSpaceVia) != want {
			t.Errorf("%s: %v", name, err)
		}
	}
	salt, _, _ := c.secret("")
	if c.spaceGet(salt) == nil {
		t.Error("пространство выключилось")
	}
}

// TestSpaceJoinStale — N вступает через отставший P (у A уже новый код): P сверяется с A до выдачи M — N вступает в
// текущий состав, у всех трёх он один, раскола нет, пропуска на N выдаются (сверен с A).
func TestSpaceJoinStale(t *testing.T) {
	url := syncHub(t)
	sec := totp.NewSecret()
	ca, cp, cn := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec), spaceCfg(t, "n-own-pass-1", totp.NewSecret())
	ph, _ := syncSpace(t, 0, ca, cp)
	m1, err := spaceSetLogin(spaceOf(ca), ph, "", totp.NewSecret()) // у A — новый код; P о нём не знает
	if err != nil {
		t.Fatal(err)
	}
	raw := spSnap(ca)
	if _, err := ca.spaceEdit(raw, m1); err != nil {
		t.Fatal(err)
	}
	syncNode(t, url, ca, false)
	syncNode(t, url, cp, false)
	n := syncNode(t, url, cn, false)
	withSpaceNet(t, agent.SpaceJoin)
	ch, err := cn.spaceEnter(context.Background(), cp.id(), spacePass, spaceCode(cp, sec), ph)
	if err != nil {
		t.Fatal(err)
	}
	if !ch.Fresh {
		t.Errorf("вступление через старый P: %v", ch)
	}
	mn := spaceOf(cn)
	if mn.TOTP != m1.TOTP || !mn.member(cfgPub(cn)) || len(mn.Members) != 3 {
		t.Errorf("состав N не текущий: %v", mn)
	}
	eventually(t, "A и P не получили состав с N", func() bool { return sameSpaceBytes(cn, ca) && sameSpaceBytes(cn, cp) })
	for _, c := range []*config{ca, cp, n.c} {
		if h := spaceHeadsOf(c); len(h) != 1 {
			t.Errorf("верхушек %d", len(h))
		}
	}
	salt, _, _ := cn.secret("")
	if !cn.spaceMember(salt, cfgPub(ca)) {
		t.Error("N: пропуск A не выдаётся после сверки")
	}
}

// TestSpaceSyncBadID — С4: новый член заявил в M ID чужого ПК; рассылка P видит под этим ID другой ключ — итог
// "badid" для окна, но состояние не меняется (ответ "notme" не подписан, его может подставить хаб): ни флагов в
// настройках, ни отказа в пропуске. Старый хост (без сверки) — итог "old", без повторов.
func TestSpaceSyncBadID(t *testing.T) {
	url := syncHub(t)
	sec := totp.NewSecret()
	cp, cx, cold := spaceCfg(t, spacePass, sec), spaceCfg(t, "x-own-pass-1", totp.NewSecret()), spaceCfg(t, spacePass, sec)
	ph, _ := syncSpace(t, 0, cp, cold)
	p := syncNode(t, url, cp, false)
	syncNode(t, url, cx, false)
	syncNode(t, url, cold, true)
	npub, _, _ := ed25519.GenerateKey(nil)
	in, err := spaceAdd(spaceOf(cp), ph, cx.id(), npub) // N подписал себя под ID X
	if err != nil {
		t.Fatal(err)
	}
	b, _ := in.marshal()
	salt, _, _ := cp.secret("")
	if err := cp.spaceJoin(salt, b, npub); err != nil {
		t.Fatal(err)
	}
	before := spConf(cp)
	if st := states(p.c.syn.spread(context.Background(), true)); st[cx.id()] != "badid" || st[cold.id()] != "old" {
		t.Fatalf("рассылка: %v", st)
	}
	if spConf(cp) != before {
		t.Error("неподписанный notme изменил настройки")
	}
	if !cp.spaceMember(salt, npub) || !cp.spaceMember(salt, cfgPub(cold)) {
		t.Error("пропуск члену не выдаётся")
	}
	p.c.syn.mu.Lock()
	_, oldRetry := p.c.syn.retry[cold.id()]
	_, badRetry := p.c.syn.retry[cx.id()]
	p.c.syn.mu.Unlock()
	if oldRetry || !badRetry {
		t.Errorf("повтор: старому хосту %v (нужно нет), badid %v (нужно да)", oldRetry, badRetry)
	}
}
