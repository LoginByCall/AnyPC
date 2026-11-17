package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anypc/agent"
	"anypc/hub"
	"anypc/pake"
	"anypc/totp"
)

// Э4 + решение 10 A: правила сверки без сети (обмен — как agent/spsync.go, регрессии приёмки Э4).

func spRaw(c *config) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	return bytes.Clone(c.Space)
}

// spSnap — снимок верхушек (для spaceEdit и сравнения двух ПК).
func spSnap(c *config) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	return c.spaceSnapLocked()
}

// spaceHeadsOf — сохранённые верхушки ПК.
func spaceHeadsOf(c *config) []*space {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	h, _ := c.spaceStoredLocked()
	return h
}

// spConf — настройки ПК одной строкой (сравнить «ничего не изменилось»).
func spConf(c *config) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	b, _ := json.Marshal(c)
	return string(b)
}

// spaceReset — на c ровно состав m (одна верхушка), запись по умолчанию — вход из m.
func spaceReset(t *testing.T, c *config, m *space) {
	t.Helper()
	b, err := m.marshal()
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Space, c.SpaceHeads = b, nil
	u := &c.Users[0]
	u.Salt, u.Hash, u.TOTP, u.Trusted, u.KeyLogin = bytes.Clone(m.PSalt), bytes.Clone(m.PHash), m.TOTP, nil, nil
	if err := c.save(); err != nil {
		t.Fatal(err)
	}
}

// spSync — обмен сверки cli → host без сети, как agent/spsync.go; true — главные верхушки сошлись.
func spSync(cli, host *config) bool {
	mc := cli.SyncGate(cfgPub(host), nil)
	if mc == nil || !host.SyncKey(cfgPub(cli)) {
		return false
	}
	cur := host.SyncGate(cfgPub(cli), mc)
	if cur == nil {
		return false
	}
	mine := cli.SyncApply(cur, host.SyncRecs(mc))
	return bytes.Equal(host.SyncApply(mine, cli.SyncRecs(cur)), mine)
}

func spSet(t *testing.T, c *config, ms ...*space) {
	t.Helper()
	for _, n := range ms {
		if _, err := c.spaceEdit(spSnap(c), n); err != nil {
			t.Fatal(err)
		}
	}
}

// fakeNet — spaceSyncFn без сети: ответ по ID; calls — сколько раз звали.
func fakeNet(t *testing.T, f func(d agent.SyncDial) ([]byte, error)) *atomic.Int32 {
	var n atomic.Int32
	old := spaceSyncFn
	spaceSyncFn = func(_ context.Context, d agent.SyncDial) ([]byte, error) { n.Add(1); return f(d) }
	t.Cleanup(func() { spaceSyncFn = old })
	return &n
}

func spSyncer(t *testing.T, c *config) *spaceSyncer {
	oldR, oldM, oldF := spaceSyncRetry, spaceSyncRetryMax, spaceSyncRetryFor
	spaceSyncRetry, spaceSyncRetryMax = 20*time.Millisecond, 40*time.Millisecond
	t.Cleanup(func() { spaceSyncRetry, spaceSyncRetryMax, spaceSyncRetryFor = oldR, oldM, oldF })
	ctx, cancel := context.WithCancel(context.Background())
	s := &spaceSyncer{cfg: c, ctx: ctx}
	c.syn = s
	t.Cleanup(func() { cancel(); s.bg.Wait() }) // до возврата переменных выше (Cleanup — в обратном порядке)
	return s
}

// TestSpaceConcurrentEdits — правки фразой на A и на P, не знавших друг о друге (A: +W и новый код; P: +N): после
// сверки в любую сторону у обоих одно объединение (W и N — члены, вход — A); повтор старой M ничего не меняет;
// исключение W с A доходит до P, и W, повторяя старые M, не возвращается.
func TestSpaceConcurrentEdits(t *testing.T) {
	sec := totp.NewSecret()
	ca, cp, cn := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, _ := syncSpace(t, 0, ca, cp)
	m1 := spaceOf(ca)
	wpub, _, _ := ed25519.GenerateKey(nil)
	m2, _ := spaceAdd(m1, ph, "9"+hub.RandDigits(8), wpub)
	m3, err := spaceSetLogin(m2, ph, "", totp.NewSecret()) // эпоха 3, вход 2
	if err != nil {
		t.Fatal(err)
	}
	spSet(t, ca, m2, m3)
	mn, _ := spaceAdd(m1, ph, cn.id(), cfgPub(cn)) // на P: +N
	spSet(t, cp, mn)
	if !spSync(cp, ca) || !bytes.Equal(spSnap(ca), spSnap(cp)) {
		t.Fatal("не сошлись")
	}
	for _, c := range []*config{ca, cp} {
		v := spaceOf(c)
		if !v.member(wpub) || !v.member(cfgPub(cn)) || !sameLogin(v, m3) || v.Compromised || len(spaceHeadsOf(c)) != 2 {
			t.Fatalf("объединение: %v", v)
		}
	}
	snap := spSnap(ca)
	for _, old := range []*space{m1, m2, mn} {
		b, _ := old.marshal()
		ca.SyncApply(b, nil)
	}
	if !bytes.Equal(snap, spSnap(ca)) {
		t.Error("повтор старых M изменил состояние")
	}
	fakeNet(t, func(agent.SyncDial) ([]byte, error) { return nil, agent.ErrSpaceOffline })
	spSyncer(t, ca)
	if _, err := ca.syn.spaceExclude(context.Background(), ph, wpub, ""); err != nil {
		t.Fatalf("исключение: %v", err)
	}
	if h := spaceHeadsOf(ca); len(h) != 1 || !h[0].member(cfgPub(cn)) || !h[0].gone(wpub) {
		t.Fatalf("правка не свела верхушки: %d", len(h))
	}
	if !spSync(cp, ca) {
		t.Fatal("P не догнал")
	}
	for _, old := range []*space{m2, m3} { // W повторяет M, где он член
		b, _ := old.marshal()
		cp.SyncApply(b, nil)
	}
	salt, _, _ := cp.secret("")
	if v := spaceOf(cp); v.member(wpub) || !v.gone(wpub) || cp.SyncKey(wpub) || cp.spaceMember(salt, wpub) {
		t.Error("исключённый вернулся")
	}
}

// TestSpaceCatchUp — замечание приёмки Э4 (space_behind): ПК, пропустивший две смены входа (исключение, затем
// пароль), догоняет одной последней M: исключённый сразу не член, вход записи по умолчанию — новый (старый пароль
// больше не действует), пропуска выдаются — флага «отстал» нет.
func TestSpaceCatchUp(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, keys := syncSpace(t, 1, ca, cb)
	x1, _ := spaceRemove(spaceOf(ca), ph, keys[0])
	x2, err := spaceSetLogin(x1, ph, "new-pass-123", "")
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := x2.marshal()
	cb.SyncApply(b2, nil)
	salt, hash, _ := cb.secret("")
	v := spaceOf(cb)
	if v.member(keys[0]) || !bytes.Equal(salt, x2.PSalt) || !bytes.Equal(hash, x2.PHash) || !sameLogin(v, x2) {
		t.Fatalf("не догнал: %v", v)
	}
	if !cb.spaceMember(salt, cfgPub(ca)) || cb.spaceMember(salt, keys[0]) {
		t.Error("пропуск: члену нет или исключённому да")
	}
}

// TestSpaceSyncGateRules — кому отдаётся M: член объединения (не исключённый ни в одной известной M, не сам); peer —
// подлинный M того же пространства; иначе — нет. SyncKey — то же по ключу. Член чужой ветви, ещё не принятой здесь,
// — нет; после приёма его M — да.
func TestSpaceSyncGateRules(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, keys := syncSpace(t, 2, ca, cb)
	m := spaceOf(ca)
	gone, _ := spaceRemove(m, ph, keys[1])
	spSet(t, ca, gone)
	mb, _ := m.marshal()
	npub, _, _ := ed25519.GenerateKey(nil)
	branch, _ := spaceAdd(m, ph, "9"+hub.RandDigits(8), npub) // ветвь, где keys[1] — ещё член
	bb, _ := branch.marshal()
	foreign := spaceCfg(t, spacePass, sec)
	fph := spaceMake(t, foreign)
	fm, _ := spaceAdd(spaceOf(foreign), fph, "9"+hub.RandDigits(8), npub)
	fb, _ := fm.marshal()
	for _, x := range []struct {
		name string
		pub  ed25519.PublicKey
		peer []byte
		want bool
	}{
		{"член", cfgPub(cb), nil, true},
		{"член с M", keys[0], mb, true},
		{"исключённый", keys[1], nil, false},
		{"исключённый со своим старым M", keys[1], mb, false},
		{"исключённый, член в M ветви", keys[1], bb, false},
		{"сам", cfgPub(ca), nil, false},
		{"член ветви, не принятой здесь", npub, bb, false},
		{"не член без M", npub, nil, false},
		{"чужое пространство", cfgPub(cb), fb, false},
		{"испорченный M", cfgPub(cb), mb[:len(mb)-1], false},
	} {
		if got := ca.SyncGate(x.pub, x.peer) != nil; got != x.want {
			t.Errorf("SyncGate %s: %v", x.name, got)
		}
	}
	if !ca.SyncKey(cfgPub(cb)) || ca.SyncKey(keys[1]) || ca.SyncKey(cfgPub(ca)) || ca.SyncKey(npub) {
		t.Error("SyncKey: член, исключённый, сам, чужой")
	}
	ca.SyncApply(bb, nil) // ветвь принята: её новый член — член, её «член» keys[1] — по-прежнему исключён
	if !ca.SyncKey(npub) || ca.SyncKey(keys[1]) || ca.SyncGate(keys[1], bb) != nil {
		t.Error("SyncKey после приёма ветви")
	}
	if got := ca.SyncRecs(nil); len(got) != 1 {
		t.Errorf("SyncRecs: %d верхушек сверх главной", len(got))
	}
}

// TestSpaceCompromised — исключения на двух ПК, не знавших друг о друге: секрет каждого нового кода видел ПК,
// исключённый на другом. После сверки — «скомпрометирован»: пропусков, выдачи M, вступлений и «Работаю тут» нет,
// правка без нового кода — отказ; новый код фразой снимает состояние на обоих.
func TestSpaceCompromised(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, keys := syncSpace(t, 2, ca, cb)
	m := spaceOf(ca)
	xa, _ := spaceRemove(m, ph, keys[0])
	xb, _ := spaceRemove(m, ph, keys[1])
	spSet(t, ca, xa)
	spSet(t, cb, xb)
	if spaceOf(ca).Compromised {
		t.Fatal("одно исключение — уже скомпрометирован")
	}
	if !spSync(cb, ca) {
		t.Fatal("не сошлись")
	}
	fakeNet(t, func(agent.SyncDial) ([]byte, error) { return nil, agent.ErrSpaceOffline })
	spSyncer(t, ca)
	for _, c := range []*config{ca, cb} {
		salt, _, _ := c.secret("")
		other := cfgPub(cb)
		if c == cb {
			other = cfgPub(ca)
		}
		if v := spaceOf(c); !v.Compromised || len(v.Members) != 2 {
			t.Fatalf("не скомпрометирован: %v", v)
		}
		if c.spaceMember(salt, other) || c.spaceGet(salt) != nil {
			t.Error("пропуск или выдача M при скомпрометированном входе")
		}
	}
	npub, _, _ := ed25519.GenerateKey(nil)
	top, _ := spaceParse(spRaw(ca))
	in, _ := spaceAdd(top, ph, "9"+hub.RandDigits(8), npub)
	ib, _ := in.marshal()
	salt, _, _ := ca.secret("")
	if err := ca.spaceJoin(salt, ib, npub, ""); !errors.Is(err, errSpaceNotIn) {
		t.Errorf("вступление при скомпрометированном входе: %v", err)
	}
	p := testMaster(ca)
	code, _ := totp.Code(spaceOf(ca).TOTP, time.Now())
	if _, err := p.workHere(context.Background(), spacePass, code); !errors.Is(err, errSpaceCompromised) {
		t.Errorf("«Работаю тут»: %v", err)
	}
	if _, err := ca.syn.edit(context.Background(), func(m *space) (*space, error) { return spaceSetLogin(m, ph, "other-pass-12", "") }); !errors.Is(err, errSpaceCompromised) {
		t.Errorf("правка без нового кода: %v", err)
	}
	if _, err := ca.syn.spaceChangeLogin(context.Background(), ph, "", false); err != nil { // новый код — сам
		t.Fatal(err)
	}
	if !spSync(cb, ca) {
		t.Fatal("не сошлись после нового кода")
	}
	for _, c := range []*config{ca, cb} {
		salt, _, _ := c.secret("")
		other := cfgPub(cb)
		if c == cb {
			other = cfgPub(ca)
		}
		if v := spaceOf(c); v.Compromised || v.TOTP == xa.TOTP || v.TOTP == xb.TOTP || !c.spaceMember(salt, other) {
			t.Errorf("новый код не снял состояние: %v", v)
		}
	}
}

// TestSpaceWaitRules — space_wait: пока он есть, пропусков нет; снимает только подтверждение (подписанный M хоста,
// равный своему) от члена, кроме ПК вступления; «differs» и подделка подтверждения — нет. Неподписанные "badid" и
// "clock" состояние решений не меняют ("clock" — только SpaceClock для окна), повтор идёт; "old" — повтора нет;
// повтор ограничен spaceSyncRetryFor.
func TestSpaceWaitRules(t *testing.T) {
	sec := totp.NewSecret()
	ca, cp, cn := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, _ := syncSpace(t, 0, cn, cp, ca)
	cn.mu.Lock()
	cn.SpaceWait = cp.id()
	cn.save()
	cn.mu.Unlock()
	var mu sync.Mutex
	answer := map[string]func() ([]byte, error){}
	set := func(id string, f func() ([]byte, error)) { mu.Lock(); answer[id] = f; mu.Unlock() }
	mine := func() ([]byte, error) { return spRaw(cn), nil }
	var acalls atomic.Int32
	fakeNet(t, func(d agent.SyncDial) ([]byte, error) {
		if d.ID == ca.id() {
			acalls.Add(1)
		}
		mu.Lock()
		f := answer[d.ID]
		mu.Unlock()
		return f()
	})
	s := spSyncer(t, cn)
	salt, _, _ := cn.secret("")
	if cn.spaceMember(salt, cfgPub(ca)) {
		t.Error("пропуск при space_wait")
	}
	set(cp.id(), mine)
	set(ca.id(), func() ([]byte, error) { b := spRaw(cn); b[len(b)-1] ^= 1; return b, nil }) // подпись испорчена
	st := states(s.spread(context.Background(), false))
	if st[cp.id()] != "ok" || st[ca.id()] != "differs" || cn.spaceFreshNow() {
		t.Errorf("снял не тот: %v, сверен %v", st, cn.spaceFreshNow())
	}
	other, err := spaceSetLogin(spaceOf(cn), ph, "", totp.NewSecret()) // подлинный, но не свой M — тоже не «ok»
	if err != nil {
		t.Fatal(err)
	}
	ob, _ := other.marshal()
	set(ca.id(), func() ([]byte, error) { return bytes.Clone(ob), nil })
	if st := states(s.spread(context.Background(), false)); st[ca.id()] != "differs" || cn.spaceFreshNow() {
		t.Errorf("чужой подлинный M: %v, сверен %v", st, cn.spaceFreshNow())
	}
	set(ca.id(), func() ([]byte, error) { return nil, agent.ErrSpaceIDKey })
	before := spConf(cn)
	s.spread(context.Background(), true)
	if spConf(cn) != before {
		t.Error("неподписанный badid изменил настройки")
	}
	n := acalls.Load()
	eventually(t, "повтор после badid", func() bool { return acalls.Load() >= n+2 }) // повторяет, пока не подтвердят
	set(ca.id(), func() ([]byte, error) { return nil, agent.ErrSpaceSkew })
	eventually(t, "часы не отмечены", func() bool {
		cn.mu.Lock()
		defer cn.mu.Unlock()
		return len(cn.SpaceClock) == 1 && cn.SpaceClock[0] == ca.id()
	})
	if cn.spaceFreshNow() {
		t.Error("часы сняли space_wait")
	}
	n = acalls.Load()
	set(ca.id(), mine) // ПК подтвердил — повтор снимает и часы, и space_wait
	eventually(t, "повтор рассылки не снял флаги", func() bool {
		cn.mu.Lock()
		defer cn.mu.Unlock()
		return len(cn.SpaceClock) == 0 && cn.SpaceWait == ""
	})
	if acalls.Load() <= n {
		t.Error("повтора не было")
	}
	salt, _, _ = cn.secret("")
	if !cn.spaceMember(salt, cfgPub(ca)) {
		t.Error("пропуска нет после подтверждения")
	}
	time.Sleep(100 * time.Millisecond) // повтор кончился на "ok"
	// старый хост: повтора нет
	set(ca.id(), func() ([]byte, error) { return nil, agent.ErrSpaceOld })
	n = acalls.Load()
	s.spread(context.Background(), true)
	time.Sleep(150 * time.Millisecond)
	if got := acalls.Load(); got != n+1 {
		t.Errorf("старому хосту — %d вызовов, ждали 1", got-n)
	}
	// повтор ограничен по времени
	spaceSyncRetryFor = 100 * time.Millisecond
	set(ca.id(), func() ([]byte, error) { return nil, agent.ErrSpaceOffline })
	s.spread(context.Background(), true)
	time.Sleep(300 * time.Millisecond)
	n = acalls.Load()
	time.Sleep(200 * time.Millisecond)
	if acalls.Load() != n {
		t.Error("повтор не кончился за spaceSyncRetryFor")
	}
}

// TestSpaceEnterWait — после вступления при других членах space_wait ставится (без сети сверки — остаётся).
func TestSpaceEnterWait(t *testing.T) {
	sec := totp.NewSecret()
	cp, ca, cn := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec), spaceCfg(t, "n-own-pass-1", totp.NewSecret())
	ph, _ := syncSpace(t, 0, cp, ca)
	withSpaceNet(t, spaceNet(cp, nil))
	ch, err := cn.spaceEnter(context.Background(), cp.id(), spacePass, spaceCode(cp, sec), ph)
	if err != nil {
		t.Fatal(err)
	}
	cn.mu.Lock()
	w := cn.SpaceWait
	cn.mu.Unlock()
	salt, _, _ := cn.secret("")
	if ch.Fresh || w != cp.id() || cn.spaceMember(salt, cfgPub(ca)) {
		t.Errorf("space_wait после вступления: %q, сверен %v", w, ch.Fresh)
	}
}

// TestSpaceEnterAlone — вступление в пространство из одного P: сверять не с кем — space_wait не ставится, пропуск P
// выдаётся сразу (выживший мутант приёмки 2P-Set, ветка «других членов нет»).
func TestSpaceEnterAlone(t *testing.T) {
	sec := totp.NewSecret()
	cp, cn := spaceCfg(t, spacePass, sec), spaceCfg(t, "n-own-pass-1", totp.NewSecret())
	ph, _ := syncSpace(t, 0, cp)
	withSpaceNet(t, spaceNet(cp, nil))
	ch, err := cn.spaceEnter(context.Background(), cp.id(), spacePass, spaceCode(cp, sec), ph)
	if err != nil {
		t.Fatal(err)
	}
	cn.mu.Lock()
	w := cn.SpaceWait
	cn.mu.Unlock()
	salt, _, _ := cn.secret("")
	if !ch.Fresh || w != "" || !cn.spaceMember(salt, cfgPub(cp)) {
		t.Errorf("вступление к одному P: space_wait %q, сверен %v", w, ch.Fresh)
	}
}

// TestSpaceEditSyncFirst — правка фразой сперва сверяется (spaceSyncer.edit): исключение, сделанное на B и не
// дошедшее до A, входит в правку A — её M уже без исключённого (выживший мутант приёмки 2P-Set).
func TestSpaceEditSyncFirst(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, keys := syncSpace(t, 1, ca, cb)
	x, err := spaceRemove(spaceOf(cb), ph, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	spSet(t, cb, x)
	xb, _ := x.marshal()
	fakeNet(t, func(d agent.SyncDial) ([]byte, error) {
		if d.ID != cb.id() {
			return nil, agent.ErrSpaceOffline
		}
		return d.S.SyncApply(xb, nil), nil
	})
	spSyncer(t, ca)
	if _, err := ca.syn.spaceChangeLogin(context.Background(), ph, "", true); err != nil {
		t.Fatal(err)
	}
	h := spaceHeadsOf(ca)
	if len(h) != 1 || !h[0].gone(keys[0]) || h[0].LEx != 1 || h[0].LGen != x.LGen+1 || h[0].TOTP == x.TOTP || h[0].Compromised {
		t.Fatalf("правка не от свежего объединения: верхушек %d, %v", len(h), h[0])
	}
}

// TestSpaceApplyLogin — принятая смена входа: запись по умолчанию — из объединения, её Trusted/KeyLogin сброшены,
// гость не тронут, сессии со старым паролем рвутся (spaceChanged); цепочка правок не копится (одна верхушка).
func TestSpaceApplyLogin(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, _ := syncSpace(t, 0, ca, cb)
	if err := cb.setUser("bob", "guest-pass-1", "view"); err != nil {
		t.Fatal(err)
	}
	cb.mu.Lock()
	cb.Users[0].Trusted, cb.Users[0].KeyLogin = [][]byte{{1}}, []loginKey{{Pub: []byte{2}}}
	cb.user("bob").Trusted = [][]byte{{3}}
	cb.save()
	cb.mu.Unlock()
	var drops atomic.Int32
	old := spaceChanged
	spaceChanged = func() { drops.Add(1) }
	t.Cleanup(func() { spaceChanged = old })
	n, _ := spaceSetLogin(spaceOf(ca), ph, "new-pass-123", "")
	spSet(t, ca, n)
	drops.Store(0) // правка на A — свой spaceChanged; нужен вызов от сверки на B
	if !spSync(cb, ca) {
		t.Fatal("не сошлись")
	}
	cb.mu.Lock()
	u, g := cb.Users[0], *cb.user("bob")
	cb.mu.Unlock()
	if u.Trusted != nil || u.KeyLogin != nil || len(g.Trusted) != 1 || !bytes.Equal(u.Salt, n.PSalt) {
		t.Errorf("запись по умолчанию: trusted %v keylogin %v; гость %v", u.Trusted, u.KeyLogin, g.Trusted)
	}
	if drops.Load() == 0 {
		t.Error("spaceChanged не позван")
	}
	m := spaceOf(ca)
	for range 4 {
		m, _ = spaceSetLogin(m, ph, "", totp.NewSecret())
		spSet(t, ca, m)
	}
	if h := spaceHeadsOf(ca); len(h) != 1 {
		t.Errorf("верхушек: %d", len(h))
	}
}

// TestSpaceLeaveSelf — выйти из пространства: пароль и верный код записи по умолчанию (код погашен — повтором не
// войти); верхушки и флаги — вон, запись по умолчанию — с тем же паролем и кодом, пропусков нет; после — смена пароля
// снова можно. Исключить себя с этого же ПК — нельзя.
func TestSpaceLeaveSelf(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, _ := syncSpace(t, 0, ca, cb)
	spSyncer(t, cb)
	if _, err := cb.syn.spaceExclude(context.Background(), ph, cfgPub(cb), ""); !errors.Is(err, errSpaceSelf) {
		t.Errorf("исключить себя: %v", err)
	}
	m := spaceOf(cb)
	cb.mu.Lock()
	cb.Users[0].TOTPStep = 0 // код из spaceCfg — тот же шаг
	cb.save()
	cb.mu.Unlock()
	code := func() string { c, _ := totp.Code(m.TOTP, time.Now()); return c }
	if err := cb.spaceLeave("wrong-pass-1", code()); !errors.Is(err, errSpacePassword) {
		t.Errorf("чужой пароль: %v", err)
	}
	if err := cb.spaceLeave(spacePass, "000000"); !errors.Is(err, errPassCode) && code() != "000000" {
		t.Errorf("чужой код: %v", err)
	}
	cb.mu.Lock()
	cb.SpaceHeads, cb.SpaceClock = [][]byte{{1}}, []string{"x"} // SpaceWait — пароль и код стираются (TestSpaceLeaveWait)
	cb.save()
	cb.mu.Unlock()
	c := code()
	if err := cb.spaceLeave(spacePass, c); err != nil {
		t.Fatal(err)
	}
	cb.mu.Lock()
	left := cb.Space == nil && cb.SpaceHeads == nil && cb.SpaceWait == "" && cb.SpaceClock == nil
	u := cb.Users[0]
	cb.mu.Unlock()
	salt, _, _ := cb.secret("")
	if !left || !bytes.Equal(u.Salt, m.PSalt) || u.TOTP != m.TOTP || cb.spaceMember(salt, cfgPub(ca)) {
		t.Error("выход: состав или флаги остались, или запись по умолчанию сменилась")
	}
	if _, ok := totp.Check(u.TOTP, c, time.Now(), u.TOTPStep); ok { // l3: код выхода погашен
		t.Error("код выхода можно повторить")
	}
	if err := cb.setPassword("own-pass-123"); err != nil {
		t.Errorf("после выхода пароль не меняется: %v", err)
	}
	if err := cb.spaceLeave(spacePass, code()); !errors.Is(err, errSpaceNotIn) {
		t.Errorf("второй выход: %v", err)
	}
}

// TestSpaceWorkHereSync — w1 приёмки Э4: «Работаю тут» сперва сверяется — свежий состав (исключённый, новый код)
// принимается до открытия целей: старый код уже не годен, исключённый не открывается.
func TestSpaceWorkHereSync(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, keys := syncSpace(t, 1, ca, cb)
	x, err := spaceRemove(spaceOf(cb), ph, keys[0]) // на B — исключение (новый код); A о нём не знает
	if err != nil {
		t.Fatal(err)
	}
	spSet(t, cb, x)
	xb, _ := x.marshal()
	fakeNet(t, func(d agent.SyncDial) ([]byte, error) {
		if d.ID != cb.id() {
			return nil, agent.ErrSpaceOffline
		}
		return d.S.SyncApply(xb, nil), nil // B отдал своё — A принял
	})
	spSyncer(t, ca)
	var mu sync.Mutex
	var opened []string
	oldOpen := passOpenFn
	t.Cleanup(func() { passOpenFn = oldOpen })
	passOpenFn = func(_ context.Context, d agent.PassDial) ([]byte, error) {
		mu.Lock()
		opened = append(opened, d.ID)
		mu.Unlock()
		return nil, nil
	}
	p := testMaster(ca)
	old, _ := totp.Code(sec, time.Now())
	if nw, _ := totp.Code(x.TOTP, time.Now()); nw == old {
		t.Skip("коды совпали")
	}
	if _, err := p.workHere(context.Background(), spacePass, old); !errors.Is(err, errPassCode) {
		t.Fatalf("старый код после сверки: %v", err)
	}
	nw, _ := totp.Code(x.TOTP, time.Now())
	if _, err := p.workHere(context.Background(), spacePass, nw); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(opened) != 1 || opened[0] != cb.id() {
		t.Errorf("открыты %v, ждали только B", opened)
	}
}

// TestSpaceLoginForkLost — замечание приёмки (раскол/отставание): B сменил пароль и код, не зная об исключении на A
// (больше исключений — вход сильнее, хоть lgen у B больше). После сверки вход B — вход A: свой пароль B не действует
// ни для записи по умолчанию, ни для «Работаю тут»; пропусков по старой соли нет; верхушка одна — исключение.
func TestSpaceLoginForkLost(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, keys := syncSpace(t, 1, ca, cb)
	m := spaceOf(ca)
	x, err := spaceRemoveLogin(m, ph, keys[0], "a-wins-pass-1") // A: lex 1, lgen 2
	if err != nil {
		t.Fatal(err)
	}
	spSet(t, ca, x)
	b1, err := spaceSetLogin(m, ph, "b-loses-pass", "") // B: lex 0, lgen 2
	if err != nil {
		t.Fatal(err)
	}
	b2, err := spaceSetLogin(b1, ph, "", totp.NewSecret()) // B: lex 0, lgen 3
	if err != nil {
		t.Fatal(err)
	}
	spSet(t, cb, b1, b2)
	oldSalt, oldHash, _ := cb.secret("")
	if !bytes.Equal(oldHash, pake.KDF("b-loses-pass", oldSalt)) {
		t.Fatal("до сверки на B не свой пароль")
	}
	if !spSync(cb, ca) {
		t.Fatal("не сошлись")
	}
	salt, hash, _ := cb.secret("")
	if !bytes.Equal(salt, x.PSalt) || !bytes.Equal(hash, x.PHash) || bytes.Equal(hash, pake.KDF("b-loses-pass", salt)) {
		t.Fatal("вход B после проигрыша развилки — не вход A")
	}
	if h := spaceHeadsOf(cb); len(h) != 1 || !sameLogin(h[0], x) || spaceOf(cb).Compromised {
		t.Fatalf("верхушки B: %d", len(h))
	}
	if cb.spaceMember(oldSalt, cfgPub(ca)) || !cb.spaceMember(salt, cfgPub(ca)) {
		t.Error("пропуск: по старой соли да или по новой нет")
	}
	fakeNet(t, func(agent.SyncDial) ([]byte, error) { return nil, agent.ErrSpaceOffline })
	spSyncer(t, cb)
	oldOpen := passOpenFn
	t.Cleanup(func() { passOpenFn = oldOpen })
	passOpenFn = func(context.Context, agent.PassDial) ([]byte, error) { return nil, nil }
	p := testMaster(cb)
	code, _ := totp.Code(x.TOTP, time.Now())
	if _, err := p.workHere(context.Background(), "b-loses-pass", code); !errors.Is(err, errSpacePassword) {
		t.Errorf("«Работаю тут» паролем проигравшей ветви: %v", err)
	}
	if _, err := p.workHere(context.Background(), "a-wins-pass-1", code); err != nil {
		t.Errorf("«Работаю тут» паролем победившего входа: %v", err)
	}
}

// TestSpaceEditStale — правка от устаревшего снимка (состояние сменилось за время Argon2 фразы) — errSpaceChange,
// ничего не записано. Мутант e3 приёмки 2P-Set.
func TestSpaceEditStale(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, _ := syncSpace(t, 0, ca, cb)
	snap := spSnap(ca)
	n, err := spaceSetLogin(spaceOf(ca), ph, "", totp.NewSecret())
	if err != nil {
		t.Fatal(err)
	}
	wpub, _, _ := ed25519.GenerateKey(nil)
	w, _ := spaceAdd(spaceOf(ca), ph, "9"+hub.RandDigits(8), wpub)
	wb, _ := w.marshal()
	ca.SyncApply(wb, nil) // пришло во время правки
	before := spConf(ca)
	if _, err := ca.spaceEdit(snap, n); !errors.Is(err, errSpaceChange) {
		t.Errorf("правка от старого снимка: %v", err)
	}
	if spConf(ca) != before {
		t.Error("правка от старого снимка записана")
	}
}

// TestSpaceForward — принятое новое уходит дальше остальным членам (кроме себя), повтор того же — нет. Мутант a3.
func TestSpaceForward(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb, cc := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, _ := syncSpace(t, 0, ca, cb, cc)
	var toC atomic.Int32
	fakeNet(t, func(d agent.SyncDial) ([]byte, error) {
		if d.ID == cc.id() {
			toC.Add(1)
		}
		return spRaw(ca), nil // подтверждение: повтор кончается
	})
	spSyncer(t, ca)
	n, err := spaceSetLogin(spaceOf(cb), ph, "", totp.NewSecret()) // правка на B
	if err != nil {
		t.Fatal(err)
	}
	nb, _ := n.marshal()
	ca.SyncApply(nb, nil)
	eventually(t, "принятое не ушло C", func() bool { return toC.Load() >= 1 })
	time.Sleep(100 * time.Millisecond)
	k := toC.Load()
	ca.SyncApply(nb, nil)
	time.Sleep(150 * time.Millisecond)
	if toC.Load() != k {
		t.Error("повтор того же M разослан снова")
	}
}

// TestSpaceCompromisedUnionMember — Б1 приёмки 2P-Set (сценарий приёмщика zz_acc3/zz_acc4): на A исключён Y (вход
// L); на B, не знающем об этом, добавлен X; A↔B и B→X сверились — у X секрет L, хотя X нет ни в одной M с входом L.
// D (видел X, но не L) исключает украденный X; его вход проигрывает L — по хэшу (равные lex и lgen) или по lgen
// (ещё одна смена кода на A). Итог на всех: X исключён, вход скомпрометирован, пропусков нет; новый код фразой
// снимает это.
func TestSpaceCompromisedUnionMember(t *testing.T) {
	for _, more := range []bool{false, true} {
		t.Run(fmt.Sprintf("lgen+%v", more), func(t *testing.T) {
			sec := totp.NewSecret()
			ca, cb, cd, cx := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
			ph, keys := syncSpace(t, 1, ca, cb, cd) // члены A, B, D и Y
			base := spaceOf(ca)
			hT, err := spaceRemove(base, ph, keys[0]) // на A: исключён Y, вход L (lex 1, lgen 2)
			if err != nil {
				t.Fatal(err)
			}
			spSet(t, ca, hT)
			if more { // ещё одна смена кода на A: lgen 3 — L побеждает всегда
				if hT, err = spaceSetLogin(hT, ph, "", totp.NewSecret()); err != nil {
					t.Fatal(err)
				}
				spSet(t, ca, hT)
			}
			hX, err := spaceAdd(base, ph, cx.id(), cfgPub(cx)) // на B (не знает hT): добавлен X
			if err != nil {
				t.Fatal(err)
			}
			spSet(t, cb, hX)
			hxb, _ := hX.marshal()
			if err := cd.spaceSync(hxb, nil); err != nil { // D получил hX и ушёл из сети
				t.Fatal(err)
			}
			spaceReset(t, cx, hX)
			if !spSync(ca, cb) || !spSync(cb, cx) { // A↔B, затем B→X: X — член объединения
				t.Fatal("не сошлись")
			}
			if spaceOf(cx).TOTP != hT.TOTP || spaceOf(ca).Compromised {
				t.Fatal("X не получил секрет входа L или L уже скомпрометирован")
			}
			for { // на D (не видел hT; A и B недоступны): исключение украденного X, вход которого проигрывает L
				hR, err := spaceRemove(spaceOf(cd), ph, cfgPub(cx))
				if err != nil {
					t.Fatal(err)
				}
				if spaceLoginCmp(hT, hR) > 0 {
					spSet(t, cd, hR)
					break
				}
			}
			if !spSync(cd, ca) || !spSync(cb, ca) || !spSync(cd, cb) {
				t.Fatal("не сошлись после исключения")
			}
			for name, c := range map[string]*config{"A": ca, "B": cb, "D": cd} {
				v := spaceOf(c)
				salt, _, _ := c.secret("")
				if !v.gone(cfgPub(cx)) || !v.Compromised || !sameLogin(v, hT) || c.spaceMember(salt, cfgPub(cb)) || c.spaceMember(salt, cfgPub(ca)) {
					t.Errorf("lgen+%v, %s: X исключён %v, скомпрометирован %v, вход L %v", more, name, v.gone(cfgPub(cx)), v.Compromised, sameLogin(v, hT))
				}
			}
			fakeNet(t, func(agent.SyncDial) ([]byte, error) { return nil, agent.ErrSpaceOffline })
			spSyncer(t, cd)
			if _, err := cd.syn.spaceChangeLogin(context.Background(), ph, "", false); err != nil { // новый код — сам
				t.Fatal(err)
			}
			if !spSync(cd, ca) || !spSync(cb, ca) {
				t.Fatal("не сошлись после нового кода")
			}
			for name, c := range map[string]*config{"A": ca, "B": cb, "D": cd} {
				v := spaceOf(c)
				salt, _, _ := c.secret("")
				if v.Compromised || v.TOTP == hT.TOTP || !c.spaceMember(salt, cfgPub(cd)) && c != cd {
					t.Errorf("lgen+%v, %s: новый код не снял состояние: %v", more, name, v)
				}
			}
		})
	}
}

// TestSpaceHeadsOver — неблокирующее 1 приёмки 2P-Set: верхушек больше spaceMaxHeads даже после поглощения
// перекрытых — правка не принята, но не молча: SpaceOver с причиной, пропусков, выдачи M и «Работаю тут» нет. Правка
// фразой здесь сводит верхушки к одной и снимает SpaceOver; непринятое исключение, присланное снова, принимается —
// исключённый не член (исключение не потеряно).
func TestSpaceHeadsOver(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, keys := syncSpace(t, 1, ca, cb)
	base := spaceOf(ca)
	var adds [][]byte
	for range spaceMaxHeads {
		pub, _, _ := ed25519.GenerateKey(nil)
		m, err := spaceAdd(base, ph, "9"+hub.RandDigits(8), pub) // параллельные добавления: ни одно не перекрыто
		if err != nil {
			t.Fatal(err)
		}
		b, _ := m.marshal()
		adds = append(adds, b)
	}
	ca.SyncApply(adds[0], adds[1:])
	if h := spaceHeadsOf(ca); len(h) != spaceMaxHeads {
		t.Fatalf("верхушек %d", len(h))
	}
	x, err := spaceRemove(base, ph, keys[0]) // семнадцатая — исключение
	if err != nil {
		t.Fatal(err)
	}
	xb, _ := x.marshal()
	stored := spRaw(ca)
	if err := ca.spaceSync(xb, nil); !errors.Is(err, errSpaceHeads) {
		t.Fatalf("сверх предела: %v", err)
	}
	ca.mu.Lock()
	over, pend := ca.SpaceOver, len(ca.SpacePend)
	ca.mu.Unlock()
	salt, _, _ := ca.secret("")
	if !bytes.Equal(stored, spRaw(ca)) || len(spaceHeadsOf(ca)) != spaceMaxHeads || pend != 1 || over == "" ||
		ca.spaceMember(salt, cfgPub(cb)) || ca.spaceGet(salt) != nil {
		t.Fatalf("переполнение: верхушек %d, непринятых %d, причина %q, пропуск или выдача M есть", len(spaceHeadsOf(ca)), pend, over)
	}
	if v := spaceOf(ca); !v.gone(keys[0]) || !sameLogin(v, x) { // непринятое исключение уже в составе для решений
		t.Fatalf("непринятая M не в составе: %v", v)
	}
	ca.mu.Lock()
	tw := ca.Users[0].TOTP
	ca.mu.Unlock()
	if tw != x.TOTP { // вход непринятой (сильнее) — уже в записи по умолчанию: старый код не действует
		t.Fatal("запись по умолчанию не перешла на вход непринятой M")
	}
	fakeNet(t, func(agent.SyncDial) ([]byte, error) { return nil, agent.ErrSpaceOffline })
	spSyncer(t, ca)
	code, _ := totp.Code(spaceOf(ca).TOTP, time.Now())
	if _, err := testMaster(ca).workHere(context.Background(), spacePass, code); !errors.Is(err, errSpaceHeads) {
		t.Errorf("«Работаю тут» при переполнении: %v", err)
	}
	if _, err := ca.syn.spaceChangeLogin(context.Background(), ph, "", true); err != nil {
		t.Fatal(err)
	}
	ca.mu.Lock()
	over = ca.SpaceOver
	ca.mu.Unlock()
	salt, _, _ = ca.secret("")
	if h := spaceHeadsOf(ca); len(h) != 1 || over != "" || !ca.spaceMember(salt, cfgPub(cb)) {
		t.Fatalf("правка фразой: верхушек %d, причина %q", len(h), over)
	}
	if err := ca.spaceSync(xb, nil); err != nil { // владелец непринятой M прислал её снова
		t.Fatal(err)
	}
	salt, _, _ = ca.secret("")
	if v := spaceOf(ca); !v.gone(keys[0]) || v.member(keys[0]) || ca.spaceMember(salt, keys[0]) || v.LEx != 1 || v.Compromised {
		t.Errorf("исключение потеряно: %v", v) // правка — от состава с непринятым исключением: lex 1, чиста
	}
}

// TestSpaceHeadCorrupt — неблокирующее 3: испорченная неглавная верхушка — закрыто: состава нет (пропусков нет,
// исключённый не становится членом, «скомпрометирован» не снимается молча), приёма нет.
func TestSpaceHeadCorrupt(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, keys := syncSpace(t, 2, ca, cb)
	m := spaceOf(ca)
	xa, _ := spaceRemove(m, ph, keys[0])
	xb, _ := spaceRemove(m, ph, keys[1]) // встречные исключения: две верхушки, скомпрометирован
	spSet(t, ca, xa)
	b, _ := xb.marshal()
	ca.SyncApply(b, nil)
	if v := spaceOf(ca); len(spaceHeadsOf(ca)) != 2 || !v.Compromised {
		t.Fatalf("сценарий: %v", v)
	}
	ca.mu.Lock()
	ca.SpaceHeads[0][len(ca.SpaceHeads[0])-1] ^= 1 // подпись неглавной верхушки испорчена
	ca.save()
	ca.mu.Unlock()
	salt, _, _ := ca.secret("")
	if v := spaceOf(ca); v != nil || ca.spaceMember(salt, cfgPub(cb)) || ca.SyncGate(cfgPub(cb), nil) != nil {
		t.Errorf("испорченная верхушка пропущена: %v", v)
	}
	if tg := ca.loginTag("", nil); tg == nil || !bytes.Equal(tg, ca.loginTag("", nil)) { // не рвать сессии циклом
		t.Error("метка испорченного состояния не постоянна")
	}
	fakeNet(t, func(agent.SyncDial) ([]byte, error) { return nil, agent.ErrSpaceOffline })
	spSyncer(t, ca)
	if _, err := ca.syn.spaceChangeLogin(context.Background(), ph, "", true); !errors.Is(err, errSpaceDamaged) {
		t.Errorf("правка при испорченной записи: %v", err)
	}
	n, _ := spaceSetLogin(xa, ph, "", totp.NewSecret())
	nb, _ := n.marshal()
	if err := ca.spaceSync(nb, nil); err == nil {
		t.Error("приём при испорченной верхушке")
	}
}

// TestSpaceLoginTag — неблокирующее 6: метка входа для agent.LoginTag. Та же, пока вход и исключённые те же; смена
// кода без смены пароля и исключение, проигравшее развилку (вход тот же), — новая (и spaceChanged зовётся); ПК
// клиента исключён — каждый раз новая; гость и ПК вне пространства — nil.
func TestSpaceLoginTag(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb, cn := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	if tg := cn.loginTag("", nil); tg == nil || !bytes.Equal(tg, cn.loginTag("", cfgPub(ca))) {
		t.Error("вне пространства: метки нет или зависит от ключа клиента")
	}
	ph, keys := syncSpace(t, 2, ca, cb)
	if err := ca.setUser("bob", "guest-pass-1", "view"); err != nil {
		t.Fatal(err)
	}
	t0 := ca.loginTag("", nil)
	if k := ca.loginTag("", cfgPub(cb)); t0 == nil || k == nil || !bytes.Equal(t0, ca.loginTag("", nil)) ||
		!bytes.Equal(k, ca.loginTag("", cfgPub(cb))) || ca.loginTag("bob", nil) != nil {
		t.Fatal("метка записи по умолчанию или гостя")
	}
	var calls atomic.Int32
	old := spaceChanged
	spaceChanged = func() { calls.Add(1) }
	t.Cleanup(func() { spaceChanged = old })
	base := spaceOf(ca)
	n1, _ := spaceRemove(base, ph, keys[1])             // на A: исключён keys[1] (lex 1, lgen 2)
	n, _ := spaceSetLogin(n1, ph, "", totp.NewSecret()) // и ещё раз только код (lgen 3)
	b1, _ := n1.marshal()
	ca.SyncApply(b1, nil)
	t0 = ca.loginTag("", nil)
	nb, _ := n.marshal()
	ca.SyncApply(nb, nil)
	t1 := ca.loginTag("", nil)
	if bytes.Equal(t0, t1) || calls.Load() == 0 {
		t.Fatal("смена кода без смены пароля — метка та же")
	}
	x, _ := spaceRemove(base, ph, keys[0]) // на B, не знавшем о правках A: lex 1, lgen 2 — проигрывает n
	if spaceLoginCmp(n, x) <= 0 {
		t.Fatal("сценарий: исключение B не проиграло")
	}
	calls.Store(0)
	k1 := ca.loginTag("", cfgPub(cb))
	xb, _ := x.marshal()
	ca.SyncApply(xb, nil)
	if v := spaceOf(ca); !v.gone(keys[0]) || !sameLogin(v, n) || bytes.Equal(t1, ca.loginTag("", nil)) || calls.Load() == 0 {
		t.Fatalf("исключение без смены входа — метка клиента без ключа та же или spaceChanged нет: %v", v)
	}
	if !bytes.Equal(k1, ca.loginTag("", cfgPub(cb))) { // 3а приёмки: чужое исключение сессию с ключом не рвёт
		t.Error("исключение чужого ПК без смены входа сменило метку клиента с ключом")
	}
	if !ca.keyGone(keys[0]) || ca.keyGone(cfgPub(cb)) || ca.keyGone(keys[1]) == false { // keys[1] исключён в n1
		t.Error("keyGone: исключённый не исключён или член исключён")
	}
	on := true
	ca.mu.Lock()
	ca.Confirm = &on // 3в: «Спрашивать» (правкой файла) — вход одноразовым кодом, не входом пространства
	ca.save()
	ca.mu.Unlock()
	if !ca.codeMode() || ca.loginTag("", nil) != nil {
		t.Error("«Спрашивать»: метка входа пространства")
	}
}

// TestSpaceHeadsOverSync — неблокирующее 2 приёмки круга 2: SpaceOver снимает и правка, пришедшая сверкой, если она
// свела верхушки (их снова меньше spaceMaxHeads).
func TestSpaceHeadsOverSync(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, _ := syncSpace(t, 0, ca, cb)
	base := spaceOf(ca)
	var all []*space
	for range spaceMaxHeads + 1 {
		pub, _, _ := ed25519.GenerateKey(nil)
		m, err := spaceAdd(base, ph, "9"+hub.RandDigits(8), pub)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, m)
	}
	var bs [][]byte
	for _, m := range all[:spaceMaxHeads] {
		b, _ := m.marshal()
		bs = append(bs, b)
	}
	ca.SyncApply(bs[0], bs[1:])
	last, _ := all[spaceMaxHeads].marshal()
	if err := ca.spaceSync(last, nil); !errors.Is(err, errSpaceHeads) {
		t.Fatalf("сверх предела: %v", err)
	}
	if disk, err := loadConfig(ca.path); err != nil || len(disk.SpacePend) != 1 || disk.SpaceOver == "" { // и на диске
		t.Fatalf("непринятая (вход тот же) не сохранена: %v", err)
	}
	v := spaceView(all) // правка на B от объединения всех семнадцати (там они — все верхушки)
	n, err := spaceSetLogin(v, ph, "", totp.NewSecret())
	if err != nil {
		t.Fatal(err)
	}
	nb, _ := n.marshal()
	if err := ca.spaceSync(nb, nil); err != nil {
		t.Fatal(err)
	}
	ca.mu.Lock()
	over := ca.SpaceOver
	ca.mu.Unlock()
	salt, _, _ := ca.secret("")
	if h := spaceHeadsOf(ca); len(h) != 1 || over != "" || !ca.spaceMember(salt, cfgPub(cb)) {
		t.Errorf("сводящая правка сверкой: верхушек %d, причина %q", len(h), over)
	}
}

// TestSpaceOverFlap — приёмка круга 3 (zz_acc7): 10 своих верхушек, пачка из 7 (с исключением) — отказ; пустая
// сверка с другим членом SpaceOver не снимает: непринятые не приняты, пропусков нет, исключённый не член. Сводящая
// правка сверкой принимает непринятые — снимает. Ровно spaceMaxHeads верхушек — не переполнение.
func TestSpaceOverFlap(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, keys := syncSpace(t, 1, ca, cb)
	base := spaceOf(ca)
	var adds [][]byte
	var all []*space
	for range spaceMaxHeads {
		pub, _, _ := ed25519.GenerateKey(nil)
		m, err := spaceAdd(base, ph, "9"+hub.RandDigits(8), pub)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := m.marshal()
		adds, all = append(adds, b), append(all, m)
	}
	x, _ := spaceRemove(base, ph, keys[0])
	xb, _ := x.marshal()
	ca.SyncApply(adds[0], adds[1:10])                                       // 10 своих верхушек
	if err := ca.spaceSync(xb, adds[10:]); !errors.Is(err, errSpaceHeads) { // исключение + 6 добавлений = 17
		t.Fatalf("пачка сверх предела: %v", err)
	}
	over := func() string { ca.mu.Lock(); defer ca.mu.Unlock(); ca.reload(); return ca.SpaceOver }
	ca.SyncApply(adds[0], nil) // пустая сверка с другим членом
	salt, _, _ := ca.secret("")
	if v := spaceOf(ca); over() == "" || v.member(keys[0]) || ca.spaceMember(salt, cfgPub(cb)) || ca.spaceMember(salt, keys[0]) {
		t.Fatalf("пустая сверка сняла переполнение: причина %q, исключённый член %v", over(), v.member(keys[0]))
	}
	flip := func() {
		ca.mu.Lock()
		p := ca.SpacePend[0]
		p[len(p)-1] ^= 1
		ca.save()
		ca.mu.Unlock()
	}
	flip() // испорченная непринятая — тоже закрыто (исключённый не вернётся)
	if !ca.spaceDamaged() {
		t.Error("испорченная непринятая M пропущена")
	}
	flip()
	hs, err := spaceHeadsAll(append(all, x))
	if err != nil {
		t.Fatal(err)
	}
	n, err := spaceSetLogin(spaceView(hs), ph, "", totp.NewSecret()) // сводящая правка на P1: от объединения
	if err != nil {
		t.Fatal(err)
	}
	nb, _ := n.marshal()
	if err := ca.spaceSync(nb, nil); err != nil {
		t.Fatal(err)
	}
	salt, _, _ = ca.secret("")
	if v := spaceOf(ca); over() != "" || len(spaceHeadsOf(ca)) != 1 || !v.gone(keys[0]) || !ca.spaceMember(salt, cfgPub(cb)) {
		t.Errorf("сводящая правка: причина %q, верхушек %d", over(), len(spaceHeadsOf(ca)))
	}
	// граница: ровно spaceMaxHeads — принято
	cc := spaceCfg(t, spacePass, sec)
	spaceReset(t, cc, base)
	if err := cc.spaceSync(adds[0], adds[1:spaceMaxHeads]); err != nil || len(spaceHeadsOf(cc)) != spaceMaxHeads {
		t.Errorf("ровно %d верхушек: %v, %d", spaceMaxHeads, err, len(spaceHeadsOf(cc)))
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.SpaceOver != "" || cc.SpacePend != nil {
		t.Error("ровно предел — переполнение")
	}
}

// TestSpaceRejoinTag — приёмка круга 3 (zz_acc6): выход, в пространстве сменили только код, вступление снова — соль
// та же, но метка входа другая (сессия, открытая вне пространства старым кодом, рвётся), и spaceChanged позван.
// Создание пространства тем же паролем и кодом метку не меняет.
func TestSpaceRejoinTag(t *testing.T) {
	sec := totp.NewSecret()
	ca, cc := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	before := ca.loginTag("", nil)
	var calls atomic.Int32
	old := spaceChanged
	spaceChanged = func() { calls.Add(1) }
	t.Cleanup(func() { spaceChanged = old })
	ph := spaceMake(t, ca)
	if !bytes.Equal(before, ca.loginTag("", nil)) || calls.Load() == 0 {
		t.Fatal("создание тем же паролем и кодом сменило метку или spaceChanged нет")
	}
	m, _ := spaceAdd(spaceOf(ca), ph, cc.id(), cfgPub(cc))
	spSet(t, ca, m)
	spaceReset(t, cc, m)
	code, _ := totp.Code(sec, time.Now())
	cc.mu.Lock()
	cc.Users[0].TOTPStep = 0
	cc.save()
	cc.mu.Unlock()
	if err := cc.spaceLeave(spacePass, code); err != nil {
		t.Fatal(err)
	}
	salt0, _, _ := cc.secret("")
	tagOut := cc.loginTag("", nil)
	n, err := spaceSetLogin(spaceOf(ca), ph, "", totp.NewSecret()) // в пространстве сменили только код
	if err != nil {
		t.Fatal(err)
	}
	spSet(t, ca, n)
	withSpaceNet(t, spaceNet(ca, nil))
	calls.Store(0)
	if _, err := cc.spaceEnter(context.Background(), ca.id(), spacePass, spaceCode(ca, n.TOTP), ph); err != nil {
		t.Fatal(err)
	}
	salt1, _, _ := cc.secret("")
	if !bytes.Equal(salt0, salt1) || tagOut == nil || bytes.Equal(tagOut, cc.loginTag("", nil)) || calls.Load() == 0 {
		t.Errorf("вступление с другим кодом: соль та же %v, метка сменилась %v, spaceChanged %d", bytes.Equal(salt0, salt1), !bytes.Equal(tagOut, cc.loginTag("", nil)), calls.Load())
	}
}

// TestSpaceTagStranger — приёмка круга 3 (п. 3): доказанный ключ не члена — как сессия без ключа: исключение без
// смены входа меняет его метку; у члена — нет.
func TestSpaceTagStranger(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, keys := syncSpace(t, 2, ca, cb)
	base := spaceOf(ca)
	n1, _ := spaceRemove(base, ph, keys[1])
	n, _ := spaceSetLogin(n1, ph, "", totp.NewSecret())
	spSet(t, ca, n1, n)
	stranger, _, _ := ed25519.GenerateKey(nil)
	m0, s0 := ca.loginTag("", cfgPub(cb)), ca.loginTag("", stranger)
	x, _ := spaceRemove(base, ph, keys[0]) // проигрывает развилку: вход тот же
	xb, _ := x.marshal()
	ca.SyncApply(xb, nil)
	if !bytes.Equal(m0, ca.loginTag("", cfgPub(cb))) || bytes.Equal(s0, ca.loginTag("", stranger)) {
		t.Error("метка: член должен остаться, посторонний ключ — смениться")
	}
}

// TestSpaceDamagedErrors — приёмка круга 3 (п. 4): при испорченной записи «Работаю тут», создание и вступление
// отвечают errSpaceDamaged, окно получает признак spaceDamaged.
func TestSpaceDamagedErrors(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, _ := syncSpace(t, 0, ca, cb)
	if ca.spaceDamaged() {
		t.Fatal("целая запись — испорчена")
	}
	ca.mu.Lock()
	ca.Space[len(ca.Space)-1] ^= 1
	ca.save()
	ca.mu.Unlock()
	if !ca.spaceDamaged() || hostInfo(ca, &agent.Agent{}, false, "", "")["spaceDamaged"] != true {
		t.Fatal("признак испорченной записи (и в состоянии окна)")
	}
	code, _ := totp.Code(sec, time.Now())
	if _, err := testMaster(ca).workHere(context.Background(), spacePass, code); !errors.Is(err, errSpaceDamaged) {
		t.Errorf("«Работаю тут»: %v", err)
	}
	if _, err := ca.spaceCreate(spacePass); !errors.Is(err, errSpaceDamaged) {
		t.Errorf("создание: %v", err)
	}
	if _, err := ca.spaceEnter(context.Background(), cb.id(), spacePass, code, ph); !errors.Is(err, errSpaceDamaged) {
		t.Errorf("вступление: %v", err)
	}
}

// TestSpaceKeyGone — решение владельца A: ключ ПК, исключённого в объединении, — keyGone и в режиме «Спрашивать»;
// член, посторонний ключ и ПК вне пространства — нет.
func TestSpaceKeyGone(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb, cn := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, keys := syncSpace(t, 1, ca, cb)
	x, _ := spaceRemove(spaceOf(ca), ph, keys[0])
	spSet(t, ca, x)
	stranger, _, _ := ed25519.GenerateKey(nil)
	on := true
	ca.mu.Lock()
	ca.Confirm = &on // «Спрашивать»
	ca.save()
	ca.mu.Unlock()
	if !ca.keyGone(keys[0]) || ca.keyGone(cfgPub(cb)) || ca.keyGone(stranger) || cn.keyGone(keys[0]) {
		t.Error("keyGone: исключённый, член, посторонний, вне пространства")
	}
}

// TestSpacePendJunk — приёмка круга 4 (zz_acc8): при переполнении в space_pend идёт только новое — повторы своих
// верхушек (пустые сверки) и уже непринятого не копятся; следующее исключение запоминается и действует.
func TestSpacePendJunk(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, keys := syncSpace(t, 2, ca, cb)
	base := spaceOf(ca)
	var adds [][]byte
	for range spaceMaxHeads {
		pub, _, _ := ed25519.GenerateKey(nil)
		m, err := spaceAdd(base, ph, "9"+hub.RandDigits(8), pub)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := m.marshal()
		adds = append(adds, b)
	}
	ca.SyncApply(adds[0], adds[1:])
	pend := func() int { ca.mu.Lock(); defer ca.mu.Unlock(); ca.reload(); return len(ca.SpacePend) }
	x1, _ := spaceRemove(base, ph, keys[0])
	x1b, _ := x1.marshal()
	if err := ca.spaceSync(x1b, nil); !errors.Is(err, errSpaceHeads) || pend() != 1 {
		t.Fatalf("17-я: %v, непринятых %d", err, pend())
	}
	for range 3 { // пустые сверки: те же 16 и то же исключение
		ca.spaceSync(adds[0], append(adds[1:], x1b))
	}
	if pend() != 1 {
		t.Fatalf("после пустых сверок непринятых %d, ждали 1", pend())
	}
	x2, _ := spaceRemove(base, ph, keys[1])
	x2b, _ := x2.marshal()
	ca.spaceSync(x2b, nil)
	if v := spaceOf(ca); pend() != 2 || !v.gone(keys[1]) || !ca.keyGone(keys[1]) {
		t.Errorf("второе исключение: непринятых %d, исключён %v", pend(), v.gone(keys[1]))
	}
}

// TestSpacePendLimit — space_pend не больше spaceMaxPend: сверх предела новое не запоминается (ПК и так закрыт).
func TestSpacePendLimit(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, _ := syncSpace(t, 0, ca, cb)
	base := spaceOf(ca)
	var adds [][]byte
	for range spaceMaxHeads + spaceMaxPend + 1 {
		pub, _, _ := ed25519.GenerateKey(nil)
		m, err := spaceAdd(base, ph, "9"+hub.RandDigits(8), pub)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := m.marshal()
		adds = append(adds, b)
	}
	ca.SyncApply(adds[0], adds[1:spaceMaxHeads])
	if err := ca.spaceSync(adds[spaceMaxHeads], adds[spaceMaxHeads+1:]); !errors.Is(err, errSpaceHeads) {
		t.Fatalf("сверх предела: %v", err)
	}
	ca.mu.Lock()
	n := len(ca.SpacePend)
	ca.mu.Unlock()
	if n != spaceMaxPend {
		t.Errorf("непринятых %d, предел %d", n, spaceMaxPend)
	}
}
