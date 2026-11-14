package main

// Этап «окна пространства», Ч1 (UI-REDESIGN.md, решение 12 A): вступление в два шага, черновик создания, вход
// паролем на новом ПК закрыт до сверки с членом ≠ поручитель.

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"anypc/agent"
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
	if spaceEpoch(p) != 2 {
		t.Error("после подтверждения P не принял M")
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
