package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"anypc/agent"
	"anypc/totp"
)

// passSpace — мастер в пространстве (пароль spacePass, секрет sec) с ещё тремя членами ids; ключи членов — keys.
func passSpace(t *testing.T, sec string, ids ...string) (*config, map[string]ed25519.PublicKey) {
	t.Helper()
	c := spaceCfg(t, spacePass, sec)
	if err := c.spaceCreate(spacePass); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	m := c.spaceLocked()
	c.mu.Unlock()
	keys := map[string]ed25519.PublicKey{}
	for _, id := range ids {
		pub, _, _ := ed25519.GenerateKey(nil)
		n, err := spaceAdd(m, spacePass, id, pub)
		if err != nil {
			t.Fatal(err)
		}
		m, keys[id] = n, pub
	}
	setSpace(t, c, m)
	return c, keys
}

func setSpace(t *testing.T, c *config, m *space) {
	t.Helper()
	b, err := m.marshal()
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.Space, c.Users[0].TOTP = b, m.TOTP
	err = c.save()
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
}

type passCall struct {
	id, pw, code string
	host, key    ed25519.PublicKey
}

// TestPassWorkHere — «Работаю тут»: пароль и код сверяются на мастере (неверные в сеть не уходят), все остальные
// члены M открываются с ключами из M; итог по каждой; «снять» уходит только туда, где пропуск мог быть выдан.
func TestPassWorkHere(t *testing.T) {
	var logs syncLog
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	sec := totp.NewSecret()
	c, keys := passSpace(t, sec, "200000001", "200000002", "200000003", "200000004")
	var mu sync.Mutex
	var opens, offs []passCall
	oldOpen, oldOff := passOpenFn, passOffFn
	defer func() { passOpenFn, passOffFn = oldOpen, oldOff }()
	passOpenFn = func(_ context.Context, d agent.PassDial) error {
		mu.Lock()
		opens = append(opens, passCall{d.ID, d.Password, d.Code, d.HostPub, d.Key.Public().(ed25519.PublicKey)})
		mu.Unlock()
		return map[string]error{"200000002": agent.ErrSpaceOffline, "200000003": agent.ErrSpaceAuth,
			"200000004": errors.New("пространство: нет ответа")}[d.ID]
	}
	offFail := true
	passOffFn = func(_ context.Context, d agent.PassDial) error {
		mu.Lock()
		defer mu.Unlock()
		offs = append(offs, passCall{id: d.ID, pw: d.Password, code: d.Code, host: d.HostPub, key: d.Key.Public().(ed25519.PublicKey)})
		if offFail && d.ID == "200000004" {
			return agent.ErrSpaceOffline
		}
		return nil
	}
	p := &passMaster{cfg: c}
	code, _ := totp.Code(sec, time.Now())
	bad := "000000"
	if code == bad {
		bad = "111111"
	}
	for _, x := range []struct {
		pw, code string
		want     error
	}{{"wrong-pass-1", code, errSpacePassword}, {spacePass, bad, errPassCode}} {
		if _, err := p.workHere(context.Background(), x.pw, x.code); !errors.Is(err, x.want) {
			t.Errorf("%s/%s: %v, ждали %v", x.pw, x.code, err, x.want)
		}
	}
	if len(opens) != 0 {
		t.Fatal("неверные пароль или код ушли в сеть")
	}
	rs, err := p.workHere(context.Background(), spacePass, code)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rs {
		got[r.ID] = r.State
	}
	want := map[string]string{"200000001": "ok", "200000002": "offline", "200000003": "refused", "200000004": "refused"}
	if len(got) != len(want) {
		t.Errorf("итог %v, ждали %v (сам мастер — не цель)", got, want)
	}
	for id, s := range want {
		if got[id] != s {
			t.Errorf("%s: %q, ждали %q", id, got[id], s)
		}
	}
	for _, o := range opens {
		if o.pw != spacePass || o.code != code || !bytes.Equal(o.host, keys[o.id]) || !bytes.Equal(o.key, cfgPub(c)) {
			t.Errorf("вход на %s: не те пароль, код или ключи", o.id)
		}
	}
	if p.hold == nil {
		t.Fatal("нет hold")
	}
	if _, _, ok := p.hold.get(); ok {
		t.Error("пароль и код не затёрты после «Работаю тут»")
	}

	p.offAll(context.Background()) // 1 — выдан, 4 — ответ не дошёл (мог быть выдан): оба; 4 не снят — остаётся
	ids := func() []string {
		mu.Lock()
		defer mu.Unlock()
		var l []string
		for _, o := range offs {
			l = append(l, o.id)
			if o.pw != "" || o.code != "" || !bytes.Equal(o.host, keys[o.id]) {
				t.Errorf("«снять» на %s: с паролем или кодом либо не тот ключ цели", o.id)
			}
		}
		offs = nil
		return l
	}
	if l := ids(); len(l) != 2 || !strings.Contains(strings.Join(l, ","), "200000001") || !strings.Contains(strings.Join(l, ","), "200000004") {
		t.Errorf("«снять» ушло на %v", l)
	}
	offFail = false
	p.offAll(context.Background())
	if l := ids(); len(l) != 1 || l[0] != "200000004" {
		t.Errorf("повтор «снять»: %v", l)
	}
	p.offAll(context.Background())
	if l := ids(); len(l) != 0 {
		t.Errorf("снятые сняты снова: %v", l)
	}
	if strings.Contains(logs.String(), spacePass) || strings.Contains(logs.String(), sec) {
		t.Error("пароль или секрет в журнале")
	}
	if !strings.Contains(logs.String(), "200000001 ok") {
		t.Error("итог «Работаю тут» не в журнале")
	}
	c2 := spaceCfg(t, spacePass, sec) // не в пространстве
	if _, err := (&passMaster{cfg: c2}).workHere(context.Background(), spacePass, code); !errors.Is(err, errSpaceNotIn) {
		t.Errorf("не в пространстве: %v", err)
	}
}

// TestPassHoldWipe — пароль и код на мастере затираются по сроку passHoldFor, даже если цель не ответила.
func TestPassHoldWipe(t *testing.T) {
	sec := totp.NewSecret()
	c, _ := passSpace(t, sec, "200000001")
	old, oldFor := passOpenFn, passHoldFor
	defer func() { passOpenFn, passHoldFor = old, oldFor }()
	passHoldFor = 300 * time.Millisecond
	p := &passMaster{cfg: c}
	held := make(chan bool, 1)
	passOpenFn = func(ctx context.Context, d agent.PassDial) error {
		_, _, ok := p.hold.get()
		held <- ok
		<-ctx.Done() // цель молчит
		time.Sleep(200 * time.Millisecond)
		return ctx.Err()
	}
	code, _ := totp.Code(sec, time.Now())
	start := time.Now()
	go p.workHere(context.Background(), spacePass, code)
	if !<-held {
		t.Fatal("во время входа пароля и кода нет")
	}
	for time.Since(start) < 2*time.Second {
		if _, _, ok := p.hold.get(); !ok {
			if d := time.Since(start); d < passHoldFor {
				t.Errorf("затёрты раньше срока: %v", d)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("пароль и код не затёрты за срок")
}

// TestPassMember — SpaceMember на цели: член M — да; сам этот ПК, чужой ключ, исключённый, чужая соль,
// «Спрашивать» — нет.
func TestPassMember(t *testing.T) {
	sec := totp.NewSecret()
	c, keys := passSpace(t, sec, "200000001", "200000002")
	salt, _, _ := c.secret("")
	other, _, _ := ed25519.GenerateKey(nil)
	for _, x := range []struct {
		name string
		pub  []byte
		salt []byte
		want bool
	}{
		{"член", keys["200000001"], salt, true},
		{"сам", cfgPub(c), salt, false},
		{"чужой", other, salt, false},
		{"чужая соль", keys["200000001"], []byte("0123456789abcdeX"), false},
	} {
		if got := c.spaceMember(x.salt, x.pub); got != x.want {
			t.Errorf("%s: %v", x.name, got)
		}
	}
	c.mu.Lock()
	m := c.spaceLocked()
	c.mu.Unlock()
	n, err := spaceRemove(m, spacePass, keys["200000002"])
	if err != nil {
		t.Fatal(err)
	}
	setSpace(t, c, n)
	if c.spaceMember(salt, keys["200000002"]) || !c.spaceMember(salt, keys["200000001"]) {
		t.Error("исключённый — член, или член — нет")
	}
	if err := c.setConfirm(true); err != nil {
		t.Fatal(err)
	}
	if c.spaceMember(salt, keys["200000001"]) {
		t.Error("«Спрашивать» — член")
	}
}
