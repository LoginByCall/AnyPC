package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"anypc/agent"
	"anypc/pake"
	"anypc/totp"
)

const spacePass = "owner-pass-1"

// spaceCfg — ПК с паролем spacePass и TOTP записи по умолчанию (вход без подтверждения); секрет TOTP — sec.
func spaceCfg(t *testing.T, pass, sec string) *config {
	t.Helper()
	c, err := loadConfig(filepath.Join(t.TempDir(), "AnyPC", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.setPassword(pass); err != nil {
		t.Fatal(err)
	}
	code, _ := totp.Code(sec, time.Now())
	if err := c.otpEnable(sec, code, ""); err != nil {
		t.Fatal(err)
	}
	return c
}

// spaceCode — код TOTP для входа на p: шаг последнего принятого кода сброшен (код из spaceCfg — тот же шаг).
func spaceCode(p *config, sec string) string {
	p.mu.Lock()
	p.Users[0].TOTPStep = 0
	p.save()
	p.mu.Unlock()
	code, _ := totp.Code(sec, time.Now())
	return code
}

func cfgPub(c *config) ed25519.PublicKey { return c.key().Public().(ed25519.PublicKey) }

// spaceNet — вместо сети (agent.SpaceJoin): P отвечает тем, что отдал бы agent по ctl "sp" сессии записи по
// умолчанию, вошедшей паролем и кодом (spaceGet с её солью), и принимает M с ключом клиента (spaceJoin). Сеть и
// права сессии — agent/space_test.go.
func spaceNet(p *config, give func([]byte) []byte) func(context.Context, agent.SpaceDial) ([]byte, error) {
	return func(_ context.Context, d agent.SpaceDial) ([]byte, error) {
		if d.ID != p.id() {
			return nil, agent.ErrSpaceOffline
		}
		salt, hash, _ := p.secret("")
		if !bytes.Equal(pake.KDF(d.Password, salt), hash) {
			return nil, agent.ErrSpaceAuth
		}
		if set, ok := p.otp("", d.Code); !set || !ok {
			return nil, agent.ErrSpaceAuth
		}
		m := p.spaceGet(salt)
		if m == nil {
			return nil, fmt.Errorf("%w: none", agent.ErrSpaceRefused)
		}
		if give != nil {
			m = give(m)
		}
		out, err := d.Sign(m, cfgPub(p))
		if err != nil {
			return nil, err
		}
		if err := p.spaceJoin(out, d.Key.Public().(ed25519.PublicKey)); err != nil {
			return nil, fmt.Errorf("%w: bad (%v)", agent.ErrSpaceRefused, err)
		}
		return out, nil
	}
}

func withSpaceNet(t *testing.T, f func(context.Context, agent.SpaceDial) ([]byte, error)) {
	old := spaceDial
	spaceDial = f
	t.Cleanup(func() { spaceDial = old })
}

// TestSpaceCreateStore — создание на P и хранение: в файле только байты marshal (никаких полей состава), после
// перезапуска — тот же состав; повторно создать нельзя; без TOTP («Спрашивать») — нельзя; чужой пароль — нельзя.
func TestSpaceCreateStore(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	if !errors.Is(p.spaceCreate("wrong-pass-1"), errSpacePassword) {
		t.Fatal("пространство создано чужим паролем")
	}
	if err := p.spaceCreate(spacePass); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(p.spaceCreate(spacePass), errSpaceIn) {
		t.Error("второе пространство поверх первого")
	}
	raw, _ := os.ReadFile(p.path)
	for _, k := range []string{`"SID"`, `"OPub"`, `"Members"`, `"PHash"`, `"TOTP"`} {
		if bytes.Contains(raw, []byte(k)) {
			t.Errorf("в файле поле состава %s", k)
		}
	}
	p.mu.Lock()
	m := p.spaceLocked()
	b := bytes.Clone(p.Space)
	p.mu.Unlock()
	if m == nil || m.Epoch != 1 || len(m.Members) != 1 || m.Members[0].ID != p.id() || !bytes.Equal(m.Members[0].Pub, cfgPub(p)) || m.TOTP != sec {
		t.Fatalf("состав: %v", m)
	}
	if !bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(b))) {
		t.Error("в файле нет записи состава")
	}
	q, err := loadConfig(p.path) // перезапуск
	if err != nil {
		t.Fatal(err)
	}
	q.mu.Lock()
	m2 := q.spaceLocked()
	q.mu.Unlock()
	if m2 == nil || !bytes.Equal(m2.signBytes(), m.signBytes()) {
		t.Fatal("после перезапуска состав другой")
	}
	q.mu.Lock()
	q.Space[len(q.Space)-1] ^= 1 // подпись испорчена (правка файла руками) — состава нет, а не чужой состав
	q.save()
	q.mu.Unlock()
	if q.spaceGet(m.PSalt) != nil {
		t.Error("испорченный состав отдан")
	}

	c := spaceCfg(t, spacePass, totp.NewSecret())
	if err := c.setConfirm(true); err != nil {
		t.Fatal(err)
	}
	if c.spaceCreate(spacePass) == nil {
		t.Error("пространство в режиме «Спрашивать»")
	}
}

// TestSpaceGetGate — P отдаёт M только записи по умолчанию, которая и есть запись владельца из M.
func TestSpaceGetGate(t *testing.T) {
	p := spaceCfg(t, spacePass, totp.NewSecret())
	if err := p.spaceCreate(spacePass); err != nil {
		t.Fatal(err)
	}
	salt, _, _ := p.secret("")
	if p.spaceGet(salt) == nil {
		t.Fatal("M не отдан владельцу")
	}
	if p.spaceGet(bytes.Repeat([]byte{1}, 16)) != nil {
		t.Error("M отдан по чужой соли")
	}
	if err := p.setPassword("new-pass-123"); err != nil { // пароль сменили (не пароль пространства)
		t.Fatal(err)
	}
	salt, _, _ = p.secret("")
	if p.spaceGet(salt) != nil {
		t.Error("M отдан записи с другим паролем")
	}
}

// TestSpaceEnter — Э2, вступление N через P: составы совпадают (эпоха 2, оба ПК), на N запись по умолчанию —
// запись владельца из M (тот же пароль и секрет кода), вход без подтверждения; код, вошедший на P, на N — повтор.
// Секреты не в журнале.
func TestSpaceEnter(t *testing.T) {
	var logs syncLog
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	if err := p.spaceCreate(spacePass); err != nil {
		t.Fatal(err)
	}
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	n.setUser("гость", "guest-pass-1", "view")
	withSpaceNet(t, spaceNet(p, nil))
	code := spaceCode(p, sec)
	if err := n.spaceEnter(context.Background(), p.id(), spacePass, code); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	pm, pb := p.spaceLocked(), bytes.Clone(p.Space)
	pu := p.Users[0]
	p.mu.Unlock()
	n.mu.Lock()
	nm, nb := n.spaceLocked(), bytes.Clone(n.Space)
	nu := n.Users[0]
	guests := len(n.Users)
	n.mu.Unlock()
	if pm == nil || nm == nil || !bytes.Equal(pb, nb) || nm.Epoch != 2 || len(nm.Members) != 2 || !nm.member(cfgPub(n)) || !nm.member(cfgPub(p)) {
		t.Fatalf("составы: P %v, N %v", pm, nm)
	}
	if !bytes.Equal(nu.Salt, pu.Salt) || !bytes.Equal(nu.Hash, pu.Hash) || nu.TOTP != sec || nu.Trusted != nil || nu.KeyLogin != nil {
		t.Error("запись по умолчанию на N — не запись владельца")
	}
	if n.confirm() || n.codeMode() || guests != 2 {
		t.Errorf("N: подтверждение %v, «Спрашивать» %v, записей %d", n.confirm(), n.codeMode(), guests)
	}
	if salt, hash, _ := n.secret(""); !bytes.Equal(pake.KDF(spacePass, salt), hash) {
		t.Error("на N не войти паролем владельца")
	}
	if _, ok := n.otp("", code); ok {
		t.Error("код, вошедший на P, на N принят повторно")
	}
	if !errors.Is(n.spaceEnter(context.Background(), p.id(), spacePass, code), errSpaceIn) {
		t.Error("второе вступление")
	}
	for _, s := range []string{sec, hex.EncodeToString(pu.Hash), base64.StdEncoding.EncodeToString(pu.Hash), base64.StdEncoding.EncodeToString(pb)} {
		if strings.Contains(logs.String(), s) {
			t.Errorf("в журнале секрет %.12s…", s)
		}
	}
	if s := fmt.Sprintf("%v %+v %#v", nm, nm, nm); strings.Contains(s, sec) {
		t.Error("печать состава выдала секрет")
	}
}

// TestSpaceEnterForeign — Н1: N не верит M, чей opub не выведен из введённого пароля (чужое пространство; подделка
// с хэшем пароля владельца, но своим ключом), и M, где P не числится с ключом, которым он вошёл. P и N без изменений.
func TestSpaceEnterForeign(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	if err := p.spaceCreate(spacePass); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	real := p.spaceLocked()
	p.mu.Unlock()
	// подделка: запись владельца как в настоящем M (psalt/phash/TOTP), ключ владельца — из пароля злоумышленника
	evil, err := spaceNew("evil-pass-12", real.PSalt, pake.KDF("evil-pass-12", real.PSalt), real.TOTP, p.id(), cfgPub(p))
	if err != nil {
		t.Fatal(err)
	}
	evil.PHash = real.PHash // хэш пароля владельца, подпись — своим ключом
	evil.Sig = nil
	if err := evil.sign("evil-pass-12"); err != nil {
		t.Fatal(err)
	}
	eb, _ := evil.marshal()
	other := spaceCfg(t, spacePass, totp.NewSecret()) // другое пространство того же пароля: свой osalt — свой opub
	if err := other.spaceCreate(spacePass); err != nil {
		t.Fatal(err)
	}
	other.mu.Lock()
	ob := bytes.Clone(other.Space)
	other.mu.Unlock()
	for name, c := range map[string]struct {
		m   []byte
		why string
	}{
		"подделка opub":  {eb, "ключ владельца из пароля не совпал"},
		"P не в составе": {ob, "не числится"}, // opub верный для пароля, но P там нет
	} {
		t.Run(name, func(t *testing.T) {
			n := spaceCfg(t, "n-local-pass", totp.NewSecret())
			withSpaceNet(t, spaceNet(p, func([]byte) []byte { return c.m }))
			err := n.spaceEnter(context.Background(), p.id(), spacePass, spaceCode(p, sec))
			if err == nil || errors.Is(err, agent.ErrSpaceAuth) || !strings.Contains(err.Error(), c.why) {
				t.Fatalf("чужой состав: %v", err)
			}
			n.mu.Lock()
			nIn := len(n.Space) > 0
			n.mu.Unlock()
			p.mu.Lock()
			pm := p.spaceLocked()
			p.mu.Unlock()
			if nIn || pm.Epoch != 1 {
				t.Errorf("N в пространстве %v, эпоха P %d", nIn, pm.Epoch)
			}
		})
	}
	if spaceOwnerCheck(evil, spacePass) == nil {
		t.Error("Н1: подделка прошла сверку opub")
	}
}

// TestSpaceJoinStrict — P принимает только «текущий + ровно этот ПК»: не тот ключ, два ПК, скачок эпохи, другой
// секрет кода, M без подписи владельца — отказ.
func TestSpaceJoinStrict(t *testing.T) {
	p := spaceCfg(t, spacePass, totp.NewSecret())
	if err := p.spaceCreate(spacePass); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	cur := p.spaceLocked()
	p.mu.Unlock()
	_, k1, _ := ed25519.GenerateKey(nil)
	_, k2, _ := ed25519.GenerateKey(nil)
	pub1, pub2 := k1.Public().(ed25519.PublicKey), k2.Public().(ed25519.PublicKey)
	add := func(m *space, id string, pub ed25519.PublicKey) *space {
		n, err := spaceAdd(m, spacePass, id, pub)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	b := func(m *space) []byte { x, _ := m.marshal(); return x }
	one := add(cur, "111111111", pub1)
	two := add(one, "222222222", pub2)
	edit := func(m *space, f func(*space)) *space { // правка с подписью паролем владельца
		n, err := spaceParse(b(m))
		if err != nil {
			t.Fatal(err)
		}
		f(n)
		if err := n.sign(spacePass); err != nil {
			t.Fatal(err)
		}
		return n
	}
	jump := edit(one, func(m *space) { m.Epoch = 5 })
	newTOTP := edit(one, func(m *space) { m.TOTP = totp.NewSecret() })
	forged := b(one)
	forged[len(forged)-1] ^= 1
	for name, c := range map[string]struct {
		m   []byte
		pub ed25519.PublicKey
	}{
		"чужой ключ": {b(one), pub2},
		"два ПК":     {b(two), pub1},
		"скачок":     {b(jump), pub1},
		"новый код":  {b(newTOTP), pub1},
		"подпись":    {forged, pub1},
		"тот же":     {b(cur), cfgPub(p)},
		"мусор":      {[]byte("M"), pub1},
	} {
		if p.spaceJoin(c.m, c.pub) == nil {
			t.Errorf("%s: принят", name)
		}
	}
	if err := p.spaceJoin(b(one), pub1); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	got := p.spaceLocked()
	p.mu.Unlock()
	if got.Epoch != 2 || !got.member(pub1) {
		t.Errorf("состав P: %v", got)
	}
}

// syncLog — журнал теста (пишут горутины).
type syncLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *syncLog) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *syncLog) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }
