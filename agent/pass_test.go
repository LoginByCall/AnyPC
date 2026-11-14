package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// passRig — цель T для тестов Э3: P из Э2 (spaceRig) и состав M — набор ключей членов.
type passRig struct {
	*spaceRig
	mmu     sync.Mutex
	members map[string]bool
	stop    context.CancelFunc
}

func (p *passRig) member(pub ed25519.PublicKey, on bool) {
	p.mmu.Lock()
	defer p.mmu.Unlock()
	p.members[string(pub)] = on
}

// passTarget — T в сети на хабе url с ключом хоста key (nil — новый): член M — mpub.
func passTarget(t *testing.T, url string, key ed25519.PrivateKey, mpub ed25519.PublicKey, opt ...func(*passRig)) *passRig {
	a := newAgent(url, "123456789", nil)
	if key != nil {
		a.Key = key
	}
	p := &passRig{spaceRig: newSpaceRig(a), members: map[string]bool{string(mpub): true}}
	a.SpaceMember = func(s, pub []byte) bool {
		p.mmu.Lock()
		defer p.mmu.Unlock()
		return bytes.Equal(s, salt) && p.members[string(pub)]
	}
	for _, f := range opt {
		f(p)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.stop = cancel
	t.Cleanup(cancel)
	on := make(chan bool, 4)
	a.OnState = func(o bool, _ string) {
		select {
		case on <- o:
		default:
		}
	}
	go a.Run(ctx)
	select {
	case <-on:
	case <-time.After(5 * time.Second):
		t.Fatal("T не зарегистрировался")
	}
	return p
}

// idle — сессии на T кончились (прошлый вход закрыт): следующий connect не получит «занят».
func idle(t *testing.T, a *Agent) {
	t.Helper()
	for range 100 {
		a.mu.Lock()
		free := a.sess == nil && len(a.pend) == 0 && a.starting == 0
		a.mu.Unlock()
		if free {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("сессия на T не кончилась")
}

func passDial(url string, p *passRig, mkey ed25519.PrivateKey) PassDial {
	return PassDial{Server: url, ID: "123456789", HostPub: p.a.Key.Public().(ed25519.PublicKey), Key: mkey, Password: "secret123", Code: p.owner.code()}
}

func codeUsed(o *otpHost) bool { o.mu.Lock(); defer o.mu.Unlock(); return o.last != 0 }

// TestPassIssue — «Работаю тут» на одной цели: пароль и код — пропуск; дальше вход по пропуску без пароля и кода
// (код второй раз не проверяется). Пароль и секрет кода — не в журнале.
func TestPassIssue(t *testing.T) {
	var logs syncBuf
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	url := local(t)
	_, mkey, _ := ed25519.GenerateKey(nil)
	p := passTarget(t, url, nil, mkey.Public().(ed25519.PublicKey))
	d := passDial(url, p, mkey)
	if err := PassOpen(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	p.owner.mu.Lock()
	step := p.owner.last
	p.owner.mu.Unlock()
	for range 2 {
		idle(t, p.a)
		if err := PassLogin(context.Background(), PassDial{Server: url, ID: d.ID, HostPub: d.HostPub, Key: mkey}); err != nil {
			t.Fatal(err)
		}
	}
	p.owner.mu.Lock()
	again := p.owner.last != step
	p.owner.mu.Unlock()
	if again {
		t.Error("вход по пропуску проверял код")
	}
	if f, _ := lock(p.a); f != 0 {
		t.Errorf("неудач у T %d", f)
	}
	for _, s := range []string{"secret123", p.owner.secret} {
		if strings.Contains(logs.String(), s) {
			t.Errorf("в журнале секрет %q", s)
		}
	}
	if !strings.Contains(logs.String(), "выдан пропуск") || !strings.Contains(logs.String(), "вход по пропуску") {
		t.Error("выдача и вход по пропуску — не в журнале")
	}
}

// TestPassRefused — пропуска не дают: ключ не член M, гость со своим кодом, «Спрашивать»; ключ хоста не тот, что
// в M, — код не отдаётся; старый хост — пароль не отдаётся. Неудач у T нет.
func TestPassRefused(t *testing.T) {
	url := local(t)
	_, mkey, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)
	p := passTarget(t, url, nil, other.Public().(ed25519.PublicKey)) // мастер — не член
	d := passDial(url, p, mkey)
	if err := PassOpen(context.Background(), d); !errors.Is(err, ErrPassNone) {
		t.Errorf("чужой ключ: %v", err)
	}
	idle(t, p.a)
	if err := PassLogin(context.Background(), d); !errors.Is(err, ErrPassNone) {
		t.Errorf("чужой ключ, вход по пропуску: %v", err)
	}
	if f, _ := lock(p.a); f != 0 {
		t.Errorf("неудач у T %d", f)
	}

	p.member(mkey.Public().(ed25519.PublicKey), true)
	g := d
	g.user, g.Password, g.Code = "guest", "guestpass123", p.guest.code()
	idle(t, p.a)
	if err := PassOpen(context.Background(), g); !errors.Is(err, ErrPassNone) {
		t.Errorf("гость: %v", err)
	}
	idle(t, p.a)
	if err := PassLogin(context.Background(), d); !errors.Is(err, ErrPassNone) {
		t.Errorf("гость получил пропуск: %v", err)
	}

	p.ask.Store(true)
	idle(t, p.a)
	if err := PassOpen(context.Background(), d); !errors.Is(err, ErrSpaceAsk) {
		t.Errorf("«Спрашивать»: %v", err)
	}
	p.ask.Store(false)

	q := passTarget(t, local(t), nil, mkey.Public().(ed25519.PublicKey))
	qd := passDial(q.a.Server, q, mkey)
	qd.HostPub = other.Public().(ed25519.PublicKey)
	if err := PassOpen(context.Background(), qd); !errors.Is(err, ErrSpaceHostKey) || codeUsed(q.owner) {
		t.Errorf("ключ T не из M: %v (код отдан %v)", err, codeUsed(q.owner))
	}

	o := passTarget(t, local(t), nil, mkey.Public().(ed25519.PublicKey), func(p *passRig) { p.a.SpaceMember = nil })
	if err := PassOpen(context.Background(), passDial(o.a.Server, o, mkey)); !errors.Is(err, ErrSpaceOld) {
		t.Errorf("старый хост: %v", err)
	}
	if f, _ := lock(o.a); f != 0 || codeUsed(o.owner) {
		t.Errorf("старый хост: неудач %d, код израсходован %v", f, codeUsed(o.owner))
	}
}

// TestPassEnd — пропуск не действует: «Спрашивать» на T, истёк срок (часы подменены), ключ исключён из M; «снять» —
// пропуска больше нет, вход не выполняется и неудачей не считается.
func TestPassEnd(t *testing.T) {
	url := local(t)
	_, mkey, _ := ed25519.GenerateKey(nil)
	mpub := mkey.Public().(ed25519.PublicKey)
	p := passTarget(t, url, nil, mpub)
	d := passDial(url, p, mkey)
	if err := PassOpen(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	login := func(why string, want error) {
		t.Helper()
		idle(t, p.a)
		if err := PassLogin(context.Background(), d); !errors.Is(err, want) && !(want == nil && err == nil) {
			t.Errorf("%s: %v, ждали %v", why, err, want)
		}
	}
	p.ask.Store(true)
	login("«Спрашивать»", ErrPassNone)
	p.ask.Store(false)
	login("снова «пароль + код»", nil)

	defer passSkew.Store(0)
	passSkew.Store(int64(PassTTL - time.Minute))
	login("за минуту до срока", nil)
	passSkew.Store(int64(PassTTL + time.Second))
	login("истёк", ErrPassNone)
	passSkew.Store(0)

	p.member(mpub, false)
	login("исключён из M", ErrPassNone)
	p.member(mpub, true)
	login("снова в M", nil)

	idle(t, p.a)
	if err := PassOff(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	login("снят", ErrPassNone)
	idle(t, p.a)
	if err := PassOff(context.Background(), d); err != nil { // снять уже снятый — тоже «off»
		t.Error(err)
	}
	if f, _ := lock(p.a); f != 0 {
		t.Errorf("неудач у T %d", f)
	}
}

// TestPassRestart — пропуск только в памяти: перезапуск T (тот же ключ, ID и состав) — пропуска нет.
func TestPassRestart(t *testing.T) {
	url := local(t)
	_, mkey, _ := ed25519.GenerateKey(nil)
	mpub := mkey.Public().(ed25519.PublicKey)
	p := passTarget(t, url, nil, mpub)
	d := passDial(url, p, mkey)
	if err := PassOpen(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	idle(t, p.a)
	p.stop()
	time.Sleep(200 * time.Millisecond) // хаб снимает старую регистрацию
	passTarget(t, url, p.a.Key, mpub)
	if err := PassLogin(context.Background(), d); !errors.Is(err, ErrPassNone) {
		t.Errorf("после перезапуска: %v", err)
	}
}

// TestPassRevoked — сессия, вошедшая по пропуску, отозвана, когда пропуск сняли или ключ исключили (DropRevoked).
func TestPassRevoked(t *testing.T) {
	a := newAgent("", "123456789", nil)
	in := true
	a.SpaceMember = func(s, _ []byte) bool { return in && bytes.Equal(s, salt) }
	_, mkey, _ := ed25519.GenerateKey(nil)
	pub := mkey.Public().(ed25519.PublicKey)
	s := &session{salt: salt, byPass: pub}
	if gone, _ := a.revoked(s); !gone {
		t.Error("без пропуска — не отозвана")
	}
	a.passGive(pub, salt)
	if gone, _ := a.revoked(s); gone {
		t.Error("с пропуском — отозвана")
	}
	in = false
	if gone, _ := a.revoked(s); !gone {
		t.Error("ключ не в M — не отозвана")
	}
	in = true
	a.passDrop(pub)
	if gone, _ := a.revoked(s); !gone {
		t.Error("пропуск снят — не отозвана")
	}
}

// TestPassWall — приёмка Э3: срок истёк по настенным часам (ПК спал: монотонные стояли) — пропуска нет.
func TestPassWall(t *testing.T) {
	a := newAgent("", "123456789", nil)
	a.SpaceMember = func(s, _ []byte) bool { return bytes.Equal(s, salt) }
	_, mkey, _ := ed25519.GenerateKey(nil)
	pub := mkey.Public().(ed25519.PublicKey)
	a.passGive(pub, salt)
	if !a.passValid(pub, salt) {
		t.Fatal("свежий пропуск не годен")
	}
	a.mu.Lock()
	e := a.passes[string(pub)]
	e.wall = time.Now().Round(0).Add(-time.Second) // настенные ушли за срок, монотонные — нет
	a.passes[string(pub)] = e
	a.mu.Unlock()
	if a.passValid(pub, salt) {
		t.Error("истёк по настенным часам — годен")
	}
}

// TestPassViewOnly — приёмка Э3: «Только показ экрана» на цели — пропуск не выдаётся и не действует.
func TestPassViewOnly(t *testing.T) {
	_, mkey, _ := ed25519.GenerateKey(nil)
	for _, before := range []bool{true, false} { // включён до выдачи; включили после
		url := local(t)
		var vo atomic.Bool
		p := passTarget(t, url, nil, mkey.Public().(ed25519.PublicKey), func(p *passRig) { p.a.ViewOnly = vo.Load })
		d := passDial(url, p, mkey)
		vo.Store(before)
		err := PassOpen(context.Background(), d)
		if before {
			if !errors.Is(err, ErrPassNone) {
				t.Errorf("выдача при «Только показ»: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		vo.Store(true)
		idle(t, p.a)
		if err := PassLogin(context.Background(), d); !errors.Is(err, ErrPassNone) {
			t.Errorf("вход по пропуску при «Только показ»: %v", err)
		}
	}
}

// TestPassOffLocked — приёмка Э3: хост заперт перебором паролей — «снять» доходит (это не вход); ответ «off»
// подписан ключом хоста: другой ключ в M — мастер не верит.
func TestPassOffLocked(t *testing.T) {
	url := local(t)
	_, mkey, _ := ed25519.GenerateKey(nil)
	p := passTarget(t, url, nil, mkey.Public().(ed25519.PublicKey))
	d := passDial(url, p, mkey)
	if err := PassOpen(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	idle(t, p.a)
	p.a.mu.Lock()
	p.a.lockUntil = time.Now().Add(time.Hour)
	p.a.mu.Unlock()
	bad := d
	_, other, _ := ed25519.GenerateKey(nil)
	bad.HostPub = other.Public().(ed25519.PublicKey)
	if err := PassOff(context.Background(), bad); !errors.Is(err, ErrSpaceHostKey) {
		t.Errorf("«off» с ключом не того хоста: %v", err)
	}
	if err := PassOff(context.Background(), d); err != nil {
		t.Errorf("«снять» при запертом хосте: %v", err)
	}
	if p.a.passValid(mkey.Public().(ed25519.PublicKey), salt) {
		t.Error("пропуск не снят")
	}
	if f, _ := lock(p.a); f != 0 {
		t.Errorf("неудач %d", f)
	}
}
