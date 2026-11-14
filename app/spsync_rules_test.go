package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anypc/agent"
	"anypc/hub"
	"anypc/totp"
)

// Э4: правила сверки без сети (обмен — как agent/spsync.go, регрессии приёмки Э4).

func spRaw(c *config) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	return bytes.Clone(c.Space)
}
func spFork(c *config) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	return len(c.SpaceFork) > 0
}

// spSync — обмен сверки cli → host без сети, как agent/spsync.go; true — составы сошлись.
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
		if _, err := c.spaceEdit(spRaw(c), n); err != nil {
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
	oldR, oldM := spaceSyncRetry, spaceSyncRetryMax
	spaceSyncRetry, spaceSyncRetryMax = 20*time.Millisecond, 40*time.Millisecond
	t.Cleanup(func() { spaceSyncRetry, spaceSyncRetryMax = oldR, oldM })
	ctx, cancel := context.WithCancel(context.Background())
	s := &spaceSyncer{cfg: c, ctx: ctx}
	c.syn = s
	t.Cleanup(func() { cancel(); s.bg.Wait() }) // до возврата переменных выше (Cleanup — в обратном порядке)
	return s
}

// TestSpaceFalseFork — предок слитого состава и запись цепочки основной ветви (Fork относительно него) не дают
// ложного раскола ни у текущего A, ни у отставшего P (решает только последняя запись); исключение с A проходит;
// повтор старой ветви после слияния раскола не ставит.
func TestSpaceFalseFork(t *testing.T) {
	sec := totp.NewSecret()
	ca, cp, cn := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, _ := syncSpace(t, 0, ca, cp)
	m1 := spaceOf(ca)
	wpub, _, _ := ed25519.GenerateKey(nil)
	m2, _ := spaceAdd(m1, ph, "9"+hub.RandDigits(8), wpub)
	m3, err := spaceSetLogin(m2, ph, "", totp.NewSecret()) // запись цепочки (lgen 2), эпоха 3
	if err != nil {
		t.Fatal(err)
	}
	spSet(t, ca, m2, m3)
	mn, _ := spaceAdd(m1, ph, cn.id(), cfgPub(cn)) // ветвь P: +N
	spSet(t, cp, mn)
	merged, err := spaceMerge(mn, m3, ph, "")
	if err != nil {
		t.Fatal(err)
	}
	mb, _ := merged.marshal()
	ca.SyncApply(mb, nil)
	if !bytes.Equal(spRaw(ca), mb) {
		t.Fatal("A не принял слитый")
	}
	if !spSync(cp, ca) || spFork(ca) || spFork(cp) || !bytes.Equal(spRaw(cp), mb) {
		t.Fatalf("ложный раскол: A %v, P %v, P текущий %v", spFork(ca), spFork(cp), bytes.Equal(spRaw(cp), mb))
	}
	fakeNet(t, func(agent.SyncDial) ([]byte, error) { return nil, agent.ErrSpaceOffline })
	spSyncer(t, ca)
	if _, err := ca.syn.spaceExclude(context.Background(), ph, wpub, ""); err != nil {
		t.Fatalf("исключение: %v", err)
	}
	mnb, _ := mn.marshal()
	ca.SyncApply(mnb, nil) // украденный член повторяет старую ветвь
	if spFork(ca) {
		t.Error("повтор предка ставит раскол")
	}
	// и наоборот: настоящий раскол последней записью — флаг
	other, _ := spaceSetLogin(mn, ph, "branch-pass-1", "")
	ob, _ := other.marshal()
	ca.SyncApply(ob, nil)
	if !spFork(ca) {
		t.Error("раскол последней записью не замечен")
	}
	// при расколе: смена входа — отказ, исключение — можно (украденный член не заблокирует своё исключение)
	if _, err := ca.syn.spaceChangeLogin(context.Background(), ph, "pass-again-1"); !errors.Is(err, errSpaceForked) {
		t.Errorf("смена входа при расколе: %v", err)
	}
	cpPub := cfgPub(cp)
	if _, err := ca.syn.spaceExclude(context.Background(), ph, cpPub, ""); err != nil {
		t.Errorf("исключение при расколе: %v", err)
	}
}

// TestSpaceGapBehind — состав новее через смену входа, которой нет в цепочке: не раскол, а «отстал» — пропусков нет
// (и исключённому в новом составе), сверка со всеми; полная цепочка снимает флаг.
func TestSpaceGapBehind(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, keys := syncSpace(t, 1, ca, cb)
	x1, _ := spaceRemove(spaceOf(ca), ph, keys[0])
	x2, err := spaceSetLogin(x1, ph, "new-pass-123", "")
	if err != nil {
		t.Fatal(err)
	}
	spSet(t, ca, x1, x2)
	calls := fakeNet(t, func(agent.SyncDial) ([]byte, error) { return nil, agent.ErrSpaceOffline })
	s := spSyncer(t, cb)
	b2, _ := x2.marshal()
	cb.SyncApply(b2, nil)
	salt, _, _ := cb.secret("")
	cb.mu.Lock()
	behind := cb.SpaceBehind
	cb.mu.Unlock()
	if spFork(cb) || behind != x2.Epoch {
		t.Errorf("пропуск в цепочке: раскол %v, отстал %d", spFork(cb), behind)
	}
	if cb.spaceMember(salt, keys[0]) || cb.spaceMember(salt, cfgPub(ca)) {
		t.Error("пропуск выдаётся отставшим ПК")
	}
	eventually(t, "отставший не сверяется со всеми", func() bool { return calls.Load() > 0 })
	_ = s
	if !spSync(cb, ca) {
		t.Fatal("полная цепочка не принята")
	}
	cb.mu.Lock()
	behind = cb.SpaceBehind
	cb.mu.Unlock()
	salt, _, _ = cb.secret("")
	if behind != 0 || !cb.spaceMember(salt, cfgPub(ca)) {
		t.Errorf("флаг «отстал» не снят: %d", behind)
	}
}

// TestSpaceSyncGateRules — кому отдаётся M: член (не исключённый, не сам), член ветви peer того же пространства, не
// исключённый здесь; чужое пространство и не член — нет. SyncKey — то же по ключу (с ветвью раскола).
func TestSpaceSyncGateRules(t *testing.T) {
	sec := totp.NewSecret()
	ca, cb := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	ph, keys := syncSpace(t, 2, ca, cb)
	m := spaceOf(ca)
	gone, _ := spaceRemove(m, ph, keys[1])
	spSet(t, ca, gone)
	mb, _ := m.marshal()
	npub, _, _ := ed25519.GenerateKey(nil)
	branch, _ := spaceAdd(m, ph, "9"+hub.RandDigits(8), npub)
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
		{"сам", cfgPub(ca), nil, false},
		{"член ветви", npub, bb, true},
		{"не член без M", npub, nil, false},
		{"не член своей ветви", npub, mb, false},
		{"чужое пространство", npub, fb, false},
	} {
		if got := ca.SyncGate(x.pub, x.peer) != nil; got != x.want {
			t.Errorf("SyncGate %s: %v", x.name, got)
		}
	}
	if !ca.SyncKey(cfgPub(cb)) || ca.SyncKey(keys[1]) || ca.SyncKey(cfgPub(ca)) || ca.SyncKey(npub) {
		t.Error("SyncKey: член, исключённый, сам, чужой")
	}
	ca.mu.Lock()
	ca.SpaceFork = bb // ветвь раскола, известная здесь
	ca.save()
	ca.mu.Unlock()
	if !ca.SyncKey(npub) {
		t.Error("SyncKey: член известной ветви раскола")
	}
	salt, _, _ := ca.secret("")
	if err := ca.spaceJoin(salt, bb, npub); !errors.Is(err, errSpaceNotIn) {
		t.Errorf("вступление при расколе: %v", err)
	}
}

// TestSpaceWaitRules — space_wait: пока он есть, пропусков нет; снимает только подтверждение (подписанный M хоста,
// равный своему) от члена, кроме ПК вступления; «differs» и подделка подтверждения — нет. Повтор рассылки идёт до
// подтверждения (и для badid: флаг С4 не залипает).
func TestSpaceWaitRules(t *testing.T) {
	sec := totp.NewSecret()
	ca, cp, cn := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec)
	syncSpace(t, 0, cn, cp, ca)
	cn.mu.Lock()
	cn.SpaceWait = cp.id()
	cn.save()
	cn.mu.Unlock()
	var mu sync.Mutex
	answer := map[string]func() ([]byte, error){}
	set := func(id string, f func() ([]byte, error)) { mu.Lock(); answer[id] = f; mu.Unlock() }
	mine := func() ([]byte, error) { return spRaw(cn), nil }
	calls := fakeNet(t, func(d agent.SyncDial) ([]byte, error) { mu.Lock(); f := answer[d.ID]; mu.Unlock(); return f() })
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
	set(ca.id(), func() ([]byte, error) { return nil, agent.ErrSpaceIDKey })
	s.spread(context.Background(), true)
	cn.mu.Lock()
	bad := len(cn.SpaceBadID)
	cn.mu.Unlock()
	if bad != 1 {
		t.Fatal("флаг С4 не поставлен")
	}
	n := calls.Load()
	eventually(t, "повтор после badid", func() bool { return calls.Load() >= n+2 }) // повторяет, пока не подтвердят
	n = calls.Load()
	set(ca.id(), mine) // ПК под этим ID доказал ключ и подтвердил — повтор снимает и С4, и space_wait
	eventually(t, "повтор рассылки не снял флаги", func() bool {
		cn.mu.Lock()
		defer cn.mu.Unlock()
		return len(cn.SpaceBadID) == 0 && cn.SpaceWait == ""
	})
	if calls.Load() <= n {
		t.Error("повтора не было")
	}
	salt, _, _ = cn.secret("")
	if !cn.spaceMember(salt, cfgPub(ca)) {
		t.Error("пропуска нет после подтверждения")
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

// TestSpaceApplyLogin — принятая смена входа: запись по умолчанию — из M, её Trusted/KeyLogin сброшены, гость не
// тронут, сессии со старым паролем рвутся (spaceChanged); цепочка — не больше spaceLogMax записей.
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
	for range spaceLogMax + 4 {
		m, _ = spaceSetLogin(m, ph, "", totp.NewSecret())
		spSet(t, ca, m)
	}
	ca.mu.Lock()
	l := len(ca.SpaceLog)
	ca.mu.Unlock()
	if l != spaceLogMax {
		t.Errorf("цепочка: %d записей", l)
	}
}

// TestSpaceLeaveSelf — выйти из пространства: пароль и верный код записи по умолчанию; M, цепочка и флаги — вон,
// запись по умолчанию — с тем же паролем и кодом, пропусков нет; после — смена пароля снова можно. Исключить себя
// с этого же ПК — нельзя.
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
	cb.SpaceFork, cb.SpaceWait, cb.SpaceLog = []byte{1}, "x", [][]byte{{1}}
	cb.save()
	cb.mu.Unlock()
	if err := cb.spaceLeave(spacePass, code()); err != nil {
		t.Fatal(err)
	}
	cb.mu.Lock()
	left := cb.Space == nil && cb.SpaceFork == nil && cb.SpaceWait == "" && cb.SpaceLog == nil
	u := cb.Users[0]
	cb.mu.Unlock()
	salt, _, _ := cb.secret("")
	if !left || !bytes.Equal(u.Salt, m.PSalt) || u.TOTP != m.TOTP || cb.spaceMember(salt, cfgPub(ca)) {
		t.Error("выход: состав или флаги остались, или запись по умолчанию сменилась")
	}
	if err := cb.setPassword("own-pass-123"); err != nil {
		t.Errorf("после выхода пароль не меняется: %v", err)
	}
	if err := cb.spaceLeave(spacePass, code()); !errors.Is(err, errSpaceNotIn) {
		t.Errorf("второй выход: %v", err)
	}
}
