package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"anypc/agent"
	"anypc/pake"
	"anypc/totp"
)

// Ч12б — вступление без пароля (решение A') по настоящей сети: P — config с пространством, окно «Пустить?» —
// функция теста; N — config со своим паролем, вводит ID P, код пространства и фразу (пароль — пустой).

type admitLog struct {
	mu   sync.Mutex
	asks []agent.AdmitReq
}

func (l *admitLog) got() []agent.AdmitReq {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]agent.AdmitReq(nil), l.asks...)
}

func admitP(t *testing.T, url string, c *config, yes bool) *admitLog {
	l := &admitLog{}
	syncNode(t, url, c, false, func(a *agent.Agent) {
		a.SpaceOwner = c.spaceAdmitOwner
		a.SpaceAdmit = func(_ context.Context, q agent.AdmitReq) agent.AdmitResult {
			l.mu.Lock()
			l.asks = append(l.asks, q)
			l.mu.Unlock()
			if yes {
				return agent.AdmitYes
			}
			return agent.AdmitNo
		}
	})
	return l
}

// TestSpaceEnterNoPassword — happy-path: N вступает без пароля; в окне P — ID, имя и отпечаток ключа N; запись по
// умолчанию N — из M (пароль пространства, хотя его не вводили); неверная фраза (из словаря, чужая) — badphrase без
// окна; «Отклонить» — declined.
func TestSpaceEnterNoPassword(t *testing.T) {
	url := syncHub(t)
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	l := admitP(t, url, p, true)
	n := spaceCfg(t, "n-own-pass-1", totp.NewSecret())
	n.mu.Lock()
	n.Server = url
	n.save()
	n.mu.Unlock()

	other := spaceCfg(t, spacePass, sec) // фраза другого пространства: слова из словаря, ключ не тот
	foreign := spaceMake(t, other)
	if _, err := n.spaceEnter(context.Background(), p.id(), "", spaceCode(p, sec), foreign); spaceErrCode(err) != "badphrase" {
		t.Fatalf("чужая фраза: %v (%s)", err, spaceErrCode(err))
	}
	if len(l.got()) != 0 {
		t.Fatal("окно после неверной фразы")
	}
	ch, err := n.spaceEnter(context.Background(), p.id(), "", spaceCode(p, sec), ph)
	if err != nil {
		t.Fatal(err)
	}
	host, _ := os.Hostname()
	if a := l.got(); len(a) != 1 || a[0].ID != n.id() || a[0].FP != pake.KeyFingerprint(cfgPub(n)) || a[0].Name != host {
		t.Errorf("окно «Пустить?»: %+v (ждали %s, %s)", a, n.id(), host)
	}
	if !ch.Password {
		t.Error("пароль записи по умолчанию N не заменён паролем пространства")
	}
	m := spaceOf(n)
	if m == nil || !m.member(cfgPub(n)) || spaceLoginCheck(m, spacePass) != nil {
		t.Fatal("N не в составе или вход не из M")
	}
	salt, hash, _ := n.secret("")
	if !bytes.Equal(pake.KDF(spacePass, salt), hash) {
		t.Error("на N пароль пространства не действует")
	}
	if !spaceOf(p).member(cfgPub(n)) {
		t.Error("P не сохранил N")
	}
}

// TestSpaceEnterDeclined — «Отклонить» на P: N остаётся вне пространства (declined), P его не сохранил.
func TestSpaceEnterDeclined(t *testing.T) {
	url := syncHub(t)
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	admitP(t, url, p, false)
	n := spaceCfg(t, "n-own-pass-1", totp.NewSecret())
	n.mu.Lock()
	n.Server = url
	n.save()
	n.mu.Unlock()
	if _, err := n.spaceEnter(context.Background(), p.id(), "", spaceCode(p, sec), ph); spaceErrCode(err) != "declined:30" { // и пауза до нового окна (первая — 30 с)
		t.Errorf("«Отклонить»: %v (%s)", err, spaceErrCode(err))
	}
	if spaceOf(n) != nil || spaceOf(p).member(cfgPub(n)) {
		t.Error("после «Отклонить» N в составе")
	}
}

// TestSpaceAdmitOwner — SpaceOwner: соль и ключ владельца только для записи владельца; вне пространства — none.
func TestSpaceAdmitOwner(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	salt, _, _ := p.secret("")
	if _, _, why := p.spaceAdmitOwner(salt); why != "none" {
		t.Errorf("вне пространства: %q", why)
	}
	spaceMake(t, p)
	salt, _, _ = p.secret("")
	m := spaceOf(p)
	osalt, opub, why := p.spaceAdmitOwner(salt)
	if why != "" || !bytes.Equal(osalt, m.OSalt) || !bytes.Equal(opub, m.OPub) {
		t.Errorf("в пространстве: %q", why)
	}
	if _, _, why := p.spaceAdmitOwner(bytes.Repeat([]byte{7}, 16)); why != "none" {
		t.Errorf("чужая соль: %q", why)
	}
	p.mu.Lock()
	on := true
	p.Confirm = &on // правка файла старой версией: «Спрашивать» на члене
	p.save()
	p.mu.Unlock()
	if _, _, why := p.spaceAdmitOwner(salt); why != "ask" {
		t.Errorf("«Спрашивать»: %q", why)
	}
}

// TestSpaceJoinShownID — P принимает нового члена только под ID, показанным в окне «Пустить?».
func TestSpaceJoinShownID(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	salt, _, _ := p.secret("")
	_, nk, _ := ed25519.GenerateKey(nil)
	npub := nk.Public().(ed25519.PublicKey)
	n, err := spaceAdd(spaceOf(p), ph, "222333444", npub)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := n.marshal()
	if err := p.spaceJoin(salt, b, npub, "999888777"); err == nil {
		t.Fatal("принят под другим ID, чем в окне")
	}
	if err := p.spaceJoin(salt, b, npub, "222333444"); err != nil {
		t.Fatal(err)
	}
}

// TestSpaceJoinDomains — подпись состава M и доказательство фразы — разные домены одного ключа владельца: одно не
// сходит за другое.
func TestSpaceJoinDomains(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	m := spaceOf(p)
	key := spaceOwnerKey(ph, m.OSalt)
	_, cpub0, _ := ed25519.GenerateKey(nil)
	cpub := cpub0.Public().(ed25519.PublicKey)
	const fc, fh = "sha-256 AA:BB", "sha-256 CC:DD"
	stored, err := spaceParse(p.Space)
	if err != nil || stored.verify() != nil {
		t.Fatal("тест: состав P не читается")
	}
	if pake.SpaceJoinVerify(m.OPub, stored.Sig, p.id(), fc, fh, cpub) {
		t.Error("подпись состава сошла за доказательство фразы")
	}
	proof := pake.SpaceJoinSign(key, p.id(), fc, fh, cpub)
	if !pake.SpaceJoinVerify(m.OPub, proof, p.id(), fc, fh, cpub) {
		t.Fatal("доказательство тем же ключом не принято")
	}
	stored.Sig = proof
	if stored.verify() == nil {
		t.Error("доказательство фразы сошло за подпись состава")
	}
}

// TestSpaceJoinCodes — Ч12б: коды окна для новых отказов.
func TestSpaceJoinCodes(t *testing.T) {
	for err, want := range map[error]string{
		agent.ErrSpaceNeedPass: "needpw",
		fmt.Errorf("%w (%w)", agent.ErrSpaceBadCode, agent.ErrSpaceAuth):                                          "badcode",
		fmt.Errorf("%w (%w)", agent.ErrSpaceBadPhrase, agent.ErrSpaceAuth):                                        "badphrase",
		fmt.Errorf("%w (%w)", agent.ErrSpaceDeclined, agent.ErrSpaceRefused):                                      "declined",
		fmt.Errorf("%w (%w)", agent.ErrSpaceNoAnswer, agent.ErrSpaceRefused):                                      "noanswer",
		fmt.Errorf("%w (%w)", agent.ErrSpaceLater, agent.ErrSpaceRefused):                                         "later",
		fmt.Errorf("%w (%w)", agent.ErrSpaceNoWindow, agent.ErrSpaceRefused):                                      "nowin",
		agent.SpaceWaitError{Err: fmt.Errorf("%w (%w)", agent.ErrSpaceDeclined, agent.ErrSpaceRefused), Secs: 60}: "declined:60",
		fmt.Errorf("%w (%w)", agent.ErrSpaceJoinLocked, agent.ErrSpaceLockedThere):                                "joinlocked",
		fmt.Errorf("%w (%w)", agent.ErrSpaceSlowHere, agent.ErrSpaceRefused):                                      "late",
		fmt.Errorf("%w (%w)", agent.ErrSpaceViewOnlyThere, agent.ErrSpaceRefused):                                 "viewonly",
		fmt.Errorf("%w: none (%w)", agent.ErrSpaceNotThere, agent.ErrSpaceRefused):                                "nospace",
		fmt.Errorf("%w (%w: denied)", agent.ErrSpaceWaitThere, agent.ErrSpaceAuth):                                "waitthere",
		errors.New("x"): "other",
	} {
		if got := spaceErrCode(err); got != want {
			t.Errorf("%v: %s, ждали %s", err, got, want)
		}
	}
}

// TestSpaceOpAdmitLeft — стадия admit: окну — сколько ещё ждёт окно «Пустить?» на том ПК (с, вверх).
func TestSpaceOpAdmitLeft(t *testing.T) {
	now := time.Now()
	defer func(f func() time.Time) { spaceOpNow = f }(spaceOpNow)
	spaceOpNow = func() time.Time { return now }
	var r spaceOpRun
	in, out := make(chan struct{}), make(chan struct{})
	r.start("enter", func(ctx context.Context, _ func(spacePreview), _ <-chan bool) (any, error) {
		spaceStageOf(ctx)("admit")
		close(in)
		<-out
		return nil, nil
	})
	<-in
	if s := r.snap(false); s["stage"] != "admit" || s["left"] != 120 {
		t.Errorf("в начале: %v", s)
	}
	now = now.Add(30*time.Second + time.Millisecond)
	if s := r.snap(false); s["left"] != 90 {
		t.Errorf("через 30 с: %v", s)
	}
	now = now.Add(5 * time.Minute)
	if s := r.snap(false); s["left"] != 0 {
		t.Errorf("после срока: %v", s)
	}
	close(out)
	r.wg.Wait()
}
