package main

// Этап «окна пространства», Ч1 (UI-REDESIGN.md, решение 12 A): вступление в два шага, черновик создания, вход
// паролем на новом ПК закрыт до сверки с членом ≠ поручитель.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"testing"
	"time"

	"anypc/agent"
	"anypc/hub"
	"anypc/pake"
	"anypc/totp"
)

type enterRes struct {
	ch  spaceChanges
	err error
}

// enterAsk — spaceEnterAsk в горутине: превью — в канал, ответ — по ok.
func enterAsk(n, p *config, code, ph string) (chan spacePreview, chan bool, chan enterRes) {
	pv, ok, res := make(chan spacePreview, 1), make(chan bool), make(chan enterRes, 1)
	go func() {
		ch, err := n.spaceEnterAsk(context.Background(), p.id(), spacePass, code, ph, func(x spacePreview) { pv <- x }, ok)
		res <- enterRes{ch, err}
	}()
	return pv, ok, res
}

// within — значение из ch не дольше 10 с (поломка не вешает тест до общего таймаута).
func within[T any](t *testing.T, what string, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("нет за 10 с: %s", what)
	}
	var zero T
	return zero
}

// say — ответ окна не дольше 10 с (вступление могло уже кончиться без вопроса).
func say(t *testing.T, ok chan<- bool, v bool) {
	t.Helper()
	select {
	case ok <- v:
	case <-time.After(10 * time.Second):
		t.Fatal("ответ окна никто не ждёт")
	}
}

func spaceEpoch(c *config) uint32 {
	if m := spaceOf(c); m != nil {
		return uint32(m.Epoch)
	}
	return 0
}

// TestSpaceEnterAsk — состав показан до подписи, P до подтверждения нового M не получает; превью = итог
// (spaceChanges, кроме Fresh); члены — ID и отпечатки ключей из M P.
func TestSpaceEnterAsk(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	n.mu.Lock()
	n.Users[0].Trusted = [][]byte{[]byte("k1"), []byte("k2")}
	n.Users[0].KeyLogin = []loginKey{{}}
	yes := true
	n.Confirm = &yes // «Спрашивать» остаётся после вступления
	n.save()
	n.mu.Unlock()
	withSpaceNet(t, spaceNet(p, nil))
	pv, ok, res := enterAsk(n, p, spaceCode(p, sec), ph)
	var got spacePreview
	select {
	case got = <-pv:
	case r := <-res:
		t.Fatalf("без превью: %v", r.err)
	}
	time.Sleep(100 * time.Millisecond)
	if e := spaceEpoch(p); e != 1 || spaceOf(n) != nil {
		t.Fatalf("до подтверждения: эпоха P %d", e)
	}
	if !slices.Equal(got.Members, []spacePC{{ID: p.id(), FP: pake.KeyFingerprint(cfgPub(p))}}) {
		t.Errorf("члены в превью: %v", got.Members)
	}
	say(t, ok, true)
	r := within(t, "итог", res)
	if r.err != nil {
		t.Fatal(r.err)
	}
	want := r.ch
	want.Fresh = false
	if got.spaceChanges != want || !got.Password || !got.TOTP || got.Trusted != 2 || got.KeyLogin != 1 || !got.Ask || got.Already {
		t.Errorf("превью %v, итог %v", got.spaceChanges, r.ch)
	}
	if spaceEpoch(p) != 2 || !r.ch.Fresh { // других членов, кроме P, нет — сверять не с кем
		t.Errorf("после подтверждения: эпоха P %d, сверен %v", spaceEpoch(p), r.ch.Fresh)
	}
}

// TestSpaceEnterAskNo — отказ и срок подтверждения: ошибка вступления, P нового M не получил, N вне пространства.
func TestSpaceEnterAskNo(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	withSpaceNet(t, spaceNet(p, nil))
	pv, ok, res := enterAsk(n, p, spaceCode(p, sec), ph)
	within(t, "превью", pv)
	say(t, ok, false)
	if r := within(t, "итог", res); !errors.Is(r.err, errSpaceNo) {
		t.Errorf("отказ: %v", r.err)
	}
	old := spaceConfirmWait
	spaceConfirmWait = 200 * time.Millisecond
	t.Cleanup(func() { spaceConfirmWait = old })
	pv, _, res = enterAsk(n, p, spaceCode(p, sec), ph)
	within(t, "превью", pv)
	if r := within(t, "итог", res); !errors.Is(r.err, errSpaceSlow) {
		t.Errorf("срок: %v", r.err)
	}
	if spaceEpoch(p) != 1 || spaceOf(n) != nil {
		t.Errorf("после отказа: эпоха P %d, N в пространстве %v", spaceEpoch(p), spaceOf(n) != nil)
	}
}

// TestSpaceDraft — создание в два шага: до повторного ввода фразы Space пуст; неверная фраза (опечатка, чужая) —
// ошибка, Space пуст, черновик жив; отмена — Space пуст, черновика нет; «Спрашивать» — errSpaceLogin.
func TestSpaceDraft(t *testing.T) {
	p := spaceCfg(t, spacePass, totp.NewSecret())
	empty := func(what string) {
		t.Helper()
		p.mu.Lock()
		defer p.mu.Unlock()
		p.reload()
		if len(p.Space) > 0 {
			t.Fatalf("%s: Space не пуст", what)
		}
	}
	ph, err := p.spaceDraft(spacePass)
	if err != nil {
		t.Fatal(err)
	}
	empty("черновик")
	other := spaceMake(t, spaceCfg(t, spacePass, totp.NewSecret()))
	if err := p.spaceCreateOK(other); !errors.Is(err, errSpaceForeign) {
		t.Errorf("чужая фраза: %v", err)
	}
	empty("чужая фраза")
	if err := p.spaceCreateOK(ph + "x"); err == nil {
		t.Error("опечатка принята")
	}
	empty("опечатка")
	if err := p.spaceCreateOK(ph); err != nil {
		t.Fatal(err)
	}
	if m := spaceOf(p); m == nil || m.Epoch != 1 || spaceOwnerCheck(m, ph) != nil {
		t.Fatal("после верной фразы нет пространства")
	}

	q := spaceCfg(t, spacePass, totp.NewSecret())
	ph, err = q.spaceDraft(spacePass)
	if err != nil {
		t.Fatal(err)
	}
	q.spaceCreateNo()
	if err := q.spaceCreateOK(ph); !errors.Is(err, errSpaceDraft) || spaceOf(q) != nil {
		t.Errorf("после отмены: %v", err)
	}
	if err := q.setConfirm(true); err != nil {
		t.Fatal(err)
	}
	if _, err := q.spaceDraft(spacePass); !errors.Is(err, errSpaceLogin) {
		t.Errorf("«Спрашивать»: %v", err)
	}
}

// TestSpaceLoginShutCfg — loginShut: после вступления, пока другие члены не сверены, — вход паролем в запись по
// умолчанию закрыт; гости и «Спрашивать» (одноразовый код) — открыты; других членов нет — открыт.
func TestSpaceLoginShutCfg(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph, _ := syncSpace(t, 1, p) // ещё один член, не в сети: сверять есть с кем
	withSpaceNet(t, spaceNet(p, nil))
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	if n.loginShut("") {
		t.Fatal("закрыт до вступления")
	}
	if _, err := n.spaceEnter(context.Background(), p.id(), spacePass, spaceCode(p, sec), ph); err != nil {
		t.Fatal(err)
	}
	if !n.loginShut("") || n.loginShut("гость") {
		t.Errorf("после вступления: по умолчанию %v, гость %v", n.loginShut(""), n.loginShut("гость"))
	}
	k := spaceCfg(t, "k-local-pass", totp.NewSecret())
	if err := k.setConfirm(true); err != nil {
		t.Fatal(err)
	}
	if _, err := k.spaceEnter(context.Background(), p.id(), spacePass, spaceCode(p, sec), ph); err != nil {
		t.Fatal(err)
	}
	if k.loginShut("") {
		t.Error("«Спрашивать» закрыт")
	}
	if p.loginShut("") {
		t.Error("создатель закрыт")
	}
}

// TestSpaceEnterShut — по сети: N вступил через P, A не в сети — вход паролем на N закрыт; A в сети — сверка A с N
// проходит, после "ok" от A (не поручитель) вход открыт. Сверка при закрытом входе — agent TestSpaceSyncShut.
func TestSpaceEnterShut(t *testing.T) {
	url := syncHub(t)
	sec := totp.NewSecret()
	ca, cp, cn := spaceCfg(t, spacePass, sec), spaceCfg(t, spacePass, sec), spaceCfg(t, "n-own-pass-1", totp.NewSecret())
	ph, _ := syncSpace(t, 0, ca, cp)
	syncNode(t, url, cp, false)
	syncNode(t, url, cn, false)
	withSpaceNet(t, agent.SpaceJoin)
	ch, err := cn.spaceEnter(context.Background(), cp.id(), spacePass, spaceCode(cp, sec), ph)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Fresh || !cn.loginShut("") {
		t.Fatalf("A не в сети: %v, закрыт %v", ch, cn.loginShut(""))
	}
	spaceCode(cn, sec)
	if err := spaceLogin(url, cn, spacePass); !errors.Is(err, agent.ErrSpaceAuth) {
		t.Fatalf("вход паролем до сверки: %v", err)
	}
	syncNode(t, url, ca, false)
	var rs map[string]string
	eventually(t, "сверка A с N", func() bool { // первая сверка — с P: A узнаёт о N; дальше — и с N
		rs = states(ca.syn.spread(context.Background(), false))
		return rs[cn.id()] == "ok"
	})
	if !cn.spaceFresh(context.Background()) || cn.loginShut("") {
		t.Fatal("после сверки с A вход не открыт")
	}
	spaceCode(cn, sec)
	if err := spaceLogin(url, cn, spacePass); err != nil {
		t.Fatalf("вход паролем после сверки: %v", err)
	}
}

// TestSpaceLeaveNoTOTP — тупик FINDINGS Э5 («испорчено» + у записи по умолчанию нет TOTP), решение владельца B:
// особого пути нет — выход без кода отклоняется; лечение — в тексте errSpaceDamaged.
func TestSpaceLeaveNoTOTP(t *testing.T) {
	c := spaceCfg(t, spacePass, totp.NewSecret())
	spaceMake(t, c)
	c.mu.Lock() // правка файла: секрет кода стёрт, запись состава испорчена
	c.Users[0].TOTP = ""
	c.Space[len(c.Space)-1] ^= 1
	c.save()
	c.mu.Unlock()
	if !c.spaceDamaged() {
		t.Fatal("не «испорчено»")
	}
	if err := c.spaceLeave(spacePass, ""); !errors.Is(err, errPassCode) || !c.spaceDamaged() {
		t.Errorf("без TOTP без кода: %v", err)
	}
}

// headsOn — добавить на p параллельные верхушки hs (как после вступлений через разных поручителей).
func headsOn(t *testing.T, p *config, hs ...*space) {
	t.Helper()
	p.mu.Lock()
	_, _, err := p.spaceAddLocked(hs...)
	p.save()
	p.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
}

func topOf(t *testing.T, p *config) *space {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	m, err := spaceParse(p.Space)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func newPC(t *testing.T) (string, ed25519.PublicKey) {
	pub, _, _ := ed25519.GenerateKey(nil)
	return "9" + hub.RandDigits(8), pub
}

// TestSpaceEnterHeads — B1 приёмки Ч1: у P две параллельные верхушки; превью — объединение (все ПК), N подписывает
// M от объединения — она перекрывает обе верхушки: у N и P одна верхушка со всеми ПК.
func TestSpaceEnterHeads(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	top := topOf(t, p)
	var hs []*space
	for range 2 {
		id, pub := newPC(t)
		h, err := spaceAdd(top, ph, id, pub)
		if err != nil {
			t.Fatal(err)
		}
		hs = append(hs, h)
	}
	headsOn(t, p, hs...)
	union := spaceOf(p)
	if len(spaceHeadsOf(p)) != 2 || len(union.Members) != 3 {
		t.Fatalf("верхушек %d, членов %d", len(spaceHeadsOf(p)), len(union.Members))
	}
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	withSpaceNet(t, spaceNet(p, nil))
	pv, ok, res := enterAsk(n, p, spaceCode(p, sec), ph)
	got := within(t, "превью", pv)
	var want []spacePC
	for _, x := range union.Members {
		want = append(want, spacePC{ID: x.ID, FP: pake.KeyFingerprint(x.Pub)})
	}
	if !slices.Equal(got.Members, want) || len(got.Gone) != 0 {
		t.Errorf("превью %v, состав P %v", got.Members, want)
	}
	say(t, ok, true)
	if r := within(t, "итог", res); r.err != nil {
		t.Fatal(r.err)
	}
	for _, c := range []*config{p, n} {
		if h := spaceHeadsOf(c); len(h) != 1 || len(h[0].Members) != 4 || !h[0].member(cfgPub(n)) {
			t.Errorf("после вступления: верхушек %d", len(h))
		}
	}
	if !sameSpaceBytes(p, n) {
		t.Error("у P и N разные составы")
	}
}

// TestSpaceEnterGone — B1: X исключён в одной верхушке, а в другой (вступление N1, не видевшее исключения) — член;
// превью — объединение: X нет среди членов, он среди исключённых; у N X исключён.
func TestSpaceEnterGone(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	xid, xpub := newPC(t)
	m1, err := spaceAdd(topOf(t, p), ph, xid, xpub)
	if err != nil {
		t.Fatal(err)
	}
	id1, pub1 := newPC(t)
	hj, err := spaceAdd(m1, ph, id1, pub1)
	if err != nil {
		t.Fatal(err)
	}
	hex, err := spaceRemove(m1, ph, xpub)
	if err != nil {
		t.Fatal(err)
	}
	headsOn(t, p, m1, hj, hex)
	union := spaceOf(p)
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	withSpaceNet(t, spaceNet(p, nil))
	pv, ok, res := enterAsk(n, p, spaceCode(p, union.TOTP), ph)
	got := within(t, "превью", pv)
	if slices.ContainsFunc(got.Members, func(x spacePC) bool { return x.ID == xid }) || len(got.Members) != len(union.Members) ||
		!slices.Equal(got.Gone, []string{pake.KeyFingerprint(xpub)}) {
		t.Errorf("превью: члены %v, исключённые %v", got.Members, got.Gone)
	}
	say(t, ok, true)
	if r := within(t, "итог", res); r.err != nil {
		t.Fatal(r.err)
	}
	if m := spaceOf(n); m == nil || !m.gone(xpub) || m.member(xpub) || !m.member(pub1) {
		t.Errorf("у N: %v", m)
	}
}

// TestSpaceEnterBadHeads — в пачке P поддельная или чужая верхушка, или верхушек больше spaceMaxHeads: отказ до
// превью, P нового M не получил, N вне пространства.
func TestSpaceEnterBadHeads(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	top := topOf(t, p)
	main, _ := top.marshal()
	forged := bytes.Clone(main)
	forged[len(forged)-1] ^= 1
	foreign, _ := topOf(t, func() *config { q := spaceCfg(t, spacePass, sec); spaceMake(t, q); return q }()).marshal()
	var many [][]byte
	for range spaceMaxHeads + 1 { // главная (только P) перекрыта каждой — верхушек 17
		id, pub := newPC(t)
		h, err := spaceAdd(top, ph, id, pub)
		if err != nil {
			t.Fatal(err)
		}
		hb, _ := h.marshal()
		many = append(many, hb)
	}
	for name, rest := range map[string][][]byte{"поддельная": {forged}, "чужая": {foreign}, "больше 16": many} {
		n := spaceCfg(t, "n-local-pass", totp.NewSecret())
		previewed := false
		withSpaceNet(t, func(_ context.Context, d agent.SpaceDial) ([]byte, error) { return d.Sign(main, cfgPub(p), rest...) })
		yes := make(chan bool, 1)
		yes <- true
		_, err := n.spaceEnterAsk(context.Background(), p.id(), spacePass, "000000", ph, func(spacePreview) { previewed = true }, yes)
		if err == nil || previewed || spaceOf(n) != nil || spaceEpoch(p) != 1 {
			t.Errorf("%s: %v (превью %v)", name, err, previewed)
		}
	}
}

// TestSpaceEnterLate — M1: обмен оборвался раньше, чем Sign дошёл до окна: превью нет, Sign не подписывает.
func TestSpaceEnterLate(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	m, _ := topOf(t, p).marshal()
	signed := make(chan error, 1)
	start := make(chan struct{})
	withSpaceNet(t, func(_ context.Context, d agent.SpaceDial) ([]byte, error) {
		go func() { <-start; _, err := d.Sign(m, cfgPub(p)); signed <- err }() // как agent: Sign в своей горутине
		return nil, agent.ErrSpaceRefused                                      // P оборвал обмен (bye)
	})
	pv := make(chan spacePreview, 1)
	ok := make(chan bool, 1)
	ok <- true
	if _, err := n.spaceEnterAsk(context.Background(), p.id(), spacePass, "000000", ph, func(x spacePreview) { pv <- x }, ok); err == nil {
		t.Fatal("обрыв — без ошибки")
	}
	close(start)
	if err := within(t, "Sign", signed); !errors.Is(err, context.Canceled) {
		t.Errorf("Sign после конца: %v", err)
	}
	select {
	case <-pv:
		t.Error("превью после конца вступления")
	default:
	}
}

// TestSpaceEnterCancel — вступление отменено (окно закрыто), пока превью ждёт ответа: Sign выходит сразу, P пуст.
func TestSpaceEnterCancel(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	withSpaceNet(t, spaceNet(p, nil))
	ctx, cancel := context.WithCancel(context.Background())
	pv, res := make(chan spacePreview, 1), make(chan enterRes, 1)
	go func() {
		ch, err := n.spaceEnterAsk(ctx, p.id(), spacePass, spaceCode(p, sec), ph, func(x spacePreview) { pv <- x }, make(chan bool))
		res <- enterRes{ch, err}
	}()
	within(t, "превью", pv)
	cancel()
	if r := within(t, "итог", res); !errors.Is(r.err, context.Canceled) || spaceEpoch(p) != 1 {
		t.Errorf("отмена: %v, эпоха P %d", r.err, spaceEpoch(p))
	}
}

// TestSpaceEnterDrift — M2: пока владелец смотрит превью, у записи по умолчанию появились ключи: «да» — отказ
// errSpaceChange, P нового M не получил.
func TestSpaceEnterDrift(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	n := spaceCfg(t, spacePass, sec)
	withSpaceNet(t, spaceNet(p, nil))
	pv, ok, res := enterAsk(n, p, spaceCode(p, sec), ph)
	within(t, "превью", pv)
	n.mu.Lock()
	n.reload()
	n.Users[0].Trusted = [][]byte{[]byte("k1")}
	n.save()
	n.mu.Unlock()
	say(t, ok, true)
	if r := within(t, "итог", res); !errors.Is(r.err, errSpaceChange) || spaceEpoch(p) != 1 || spaceOf(n) != nil {
		t.Errorf("смена после превью: %v, эпоха P %d", r.err, spaceEpoch(p))
	}
}

// TestSpaceEnterDriftLate — запись по умолчанию сменилась уже после подписи (P принял M): применения нет
// (errSpaceChange); повтор — «уже в составе» по верхушкам P, без нового M.
func TestSpaceEnterDriftLate(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	n := spaceCfg(t, spacePass, sec)
	inner := spaceNet(p, nil)
	drift := true
	withSpaceNet(t, func(ctx context.Context, d agent.SpaceDial) ([]byte, error) {
		out, err := inner(ctx, d)
		if drift {
			n.mu.Lock()
			n.Users[0].Trusted = [][]byte{[]byte("k1")}
			n.save()
			n.mu.Unlock()
		}
		return out, err
	})
	if _, err := n.spaceEnter(context.Background(), p.id(), spacePass, spaceCode(p, sec), ph); !errors.Is(err, errSpaceChange) || spaceOf(n) != nil {
		t.Fatalf("смена после подписи: %v", err)
	}
	drift = false
	ch, err := n.spaceEnter(context.Background(), p.id(), spacePass, spaceCode(p, sec), ph)
	if err != nil || !ch.Already || ch.Trusted != 1 || spaceEpoch(p) != 2 || !sameSpaceBytes(p, n) {
		t.Errorf("повтор: %v %v, эпоха P %d", ch, err, spaceEpoch(p))
	}
}

// TestSpaceLeaveWait — M3: выход до сверки после вступления — пароль и код записи по умолчанию (из M поручителя)
// стёрты: вход — «Спрашивать» с новым одноразовым кодом с экрана, закрытия входа больше нет.
func TestSpaceLeaveWait(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph, _ := syncSpace(t, 1, p)
	withSpaceNet(t, spaceNet(p, nil))
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	if _, err := n.spaceEnter(context.Background(), p.id(), spacePass, spaceCode(p, sec), ph); err != nil {
		t.Fatal(err)
	}
	if !n.loginShut("") {
		t.Fatal("вход не закрыт")
	}
	n.mu.Lock()
	before := n.Code // код, лежавший в настройках до вступления (мог быть виден)
	n.mu.Unlock()
	if err := n.spaceLeave(spacePass, spaceCode(n, sec)); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	u := n.Users[0]
	n.mu.Unlock()
	if len(u.Hash) != 0 || u.TOTP != "" || !n.codeMode() || !n.confirm() || n.code() == "" || n.code() == before || n.loginShut("") || spaceOf(n) != nil {
		t.Errorf("после выхода при SpaceWait: хэш %d байт, TOTP %v, «Спрашивать» %v", len(u.Hash), u.TOTP != "", n.codeMode())
	}
}

// TestSpaceDraftRace — черновик отменён или заменён новым, пока шла сверка фразы: Space пуст.
func TestSpaceDraftRace(t *testing.T) {
	p := spaceCfg(t, spacePass, totp.NewSecret())
	for name, during := range map[string]func(){"отмена": p.spaceCreateNo, "новый черновик": func() { p.spaceDraft(spacePass) }} {
		ph, err := p.spaceDraft(spacePass)
		if err != nil {
			t.Fatal(err)
		}
		old := spaceCreateCheck
		spaceCreateCheck = func(m *space, phrase string) error { during(); return old(m, phrase) }
		err = p.spaceCreateOK(ph)
		spaceCreateCheck = old
		if !errors.Is(err, errSpaceDraft) || spaceOf(p) != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestSpaceAskOff — вступил со «Спрашивать»: окно (Ч3) снимает его через setConfirm(false) без мастера TOTP — код
// записи по умолчанию уже код пространства; включить «Спрашивать» в пространстве нельзя (errSpaceVia, С6).
func TestSpaceAskOff(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph, _ := syncSpace(t, 1, p)
	withSpaceNet(t, spaceNet(p, nil))
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	n.mu.Lock()
	yes := true
	n.Confirm = &yes
	n.save()
	n.mu.Unlock()
	if _, err := n.spaceEnter(context.Background(), p.id(), spacePass, spaceCode(p, sec), ph); err != nil {
		t.Fatal(err)
	}
	if !n.codeMode() {
		t.Fatal("«Спрашивать» не осталось после вступления")
	}
	if err := n.setConfirm(false); err != nil || n.codeMode() {
		t.Fatalf("снять «Спрашивать» в пространстве: %v, режим кода %v", err, n.codeMode())
	}
	if err := n.setConfirm(true); !errors.Is(err, errSpaceVia) || n.codeMode() {
		t.Errorf("включить «Спрашивать» в пространстве: %v, режим кода %v", err, n.codeMode())
	}
}

// TestSpaceEnterCompromised — P отдаёт подлинные верхушки со скомпрометированным входом (два встречных исключения
// без смены кода): отказ до превью.
func TestSpaceEnterCompromised(t *testing.T) {
	p := spaceCfg(t, spacePass, totp.NewSecret())
	ph := spaceMake(t, p)
	xid, xpub := newPC(t)
	m1, err := spaceAdd(topOf(t, p), ph, xid, xpub)
	if err != nil {
		t.Fatal(err)
	}
	yid, ypub := newPC(t)
	m2, err := spaceAdd(m1, ph, yid, ypub)
	if err != nil {
		t.Fatal(err)
	}
	var bs [][]byte
	for _, pub := range []ed25519.PublicKey{xpub, ypub} {
		ex, err := spaceRemove(m2, ph, pub)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := ex.marshal()
		bs = append(bs, b)
	}
	if u, _ := spaceJoin(spaceMust(t, bs[0]), spaceMust(t, bs[1])); u == nil || !u.Compromised {
		t.Fatal("объединение не скомпрометировано")
	}
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	withSpaceNet(t, func(_ context.Context, d agent.SpaceDial) ([]byte, error) { return d.Sign(bs[0], cfgPub(p), bs[1]) })
	previewed := false
	yes := make(chan bool, 1)
	yes <- true
	_, err = n.spaceEnterAsk(context.Background(), p.id(), spacePass, "000000", ph, func(spacePreview) { previewed = true }, yes)
	if !errors.Is(err, errSpaceCompromised) || previewed || spaceOf(n) != nil {
		t.Errorf("скомпрометирован: %v (превью %v)", err, previewed)
	}
}

func spaceMust(t *testing.T, b []byte) *space {
	t.Helper()
	m, err := spaceParse(b)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestSpaceEnterHalfHeads — полу-вступление при двух верхушках у P, N — только в неглавной: «уже в составе», N
// сохраняет все верхушки P — составы совпадают.
func TestSpaceEnterHalfHeads(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	top := topOf(t, p)
	xid, xpub := newPC(t)
	h1, err := spaceAdd(top, ph, xid, xpub)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := spaceAdd(top, ph, n.id(), cfgPub(n))
	if err != nil {
		t.Fatal(err)
	}
	headsOn(t, p, h1, h2)
	withSpaceNet(t, spaceNet(p, nil))
	ch, err := n.spaceEnter(context.Background(), p.id(), spacePass, spaceCode(p, sec), ph)
	pu, nu := spaceOf(p), spaceOf(n)
	if err != nil || !ch.Already || nu == nil || !bytes.Equal(pu.signBytes(), nu.signBytes()) || len(spaceHeadsOf(n)) != 2 {
		t.Errorf("полу-вступление при двух верхушках: %v %v", ch, err)
	}
}

// TestSpaceEnterCancelYes — вступление отменено, когда «да» уже лежит в ok: подписи нет, P пуст. Выбор select между
// готовыми ok и ctx.Done случаен — повторы ловят пропуск проверки ctx после «да».
func TestSpaceEnterCancelYes(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	withSpaceNet(t, spaceNet(p, nil))
	for i := range 12 {
		ctx, cancel := context.WithCancel(context.Background())
		yes := make(chan bool, 1)
		_, err := n.spaceEnterAsk(ctx, p.id(), spacePass, spaceCode(p, sec), ph, func(spacePreview) { yes <- true; cancel() }, yes)
		cancel()
		if !errors.Is(err, context.Canceled) || spaceEpoch(p) != 1 || spaceOf(n) != nil {
			t.Fatalf("попытка %d: %v, эпоха P %d", i, err, spaceEpoch(p))
		}
	}
}

// TestSpaceWaitGone — N ждёт сверки с Q (не в сети); Q исключили фразой, исключение дошло до N: кроме поручителя
// членов нет — SpaceWait снят, вход открыт (правило вступления; дефолт A вопроса владельцу). Пока Q — член, закрыт.
func TestSpaceWaitGone(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph, keys := syncSpace(t, 1, p)
	withSpaceNet(t, spaceNet(p, nil))
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	if _, err := n.spaceEnter(context.Background(), p.id(), spacePass, spaceCode(p, sec), ph); err != nil {
		t.Fatal(err)
	}
	if !n.loginShut("") {
		t.Fatal("вход не закрыт")
	}
	ex, err := spaceRemove(topOf(t, n), ph, keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.spaceEdit(spSnap(n), ex); err != nil {
		t.Fatal(err)
	}
	if n.loginShut("") || !n.spaceFreshNow() {
		t.Error("сверять не с кем, а вход закрыт")
	}
}
