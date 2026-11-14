package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// rtClient — свой клиент: после первого "a" шлёт b(cpub, csig); ответы хоста — в got. Держит соединение до ctx.
func rtClient(ctx context.Context, url, id string, key ed25519.PrivateKey, b func(cpub, csig []byte) authMsg, got chan<- string) error {
	return hostDial(ctx, url, id, connectReq{View: true}, func(pc *webrtc.PeerConnection, finish func(error)) {
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			if dc.Label() != "auth" {
				return
			}
			first := true
			dc.OnMessage(func(msg webrtc.DataChannelMessage) {
				var am authMsg
				json.Unmarshal(msg.Data, &am)
				if am.T == "a" && first {
					first = false
					cpub, csig, _ := signB(key, id, pc)
					bb, _ := json.Marshal(b(cpub, csig))
					dc.SendText(string(bb))
					return
				}
				select {
				case got <- am.T:
				default:
				}
			})
		})
	})
}

func rtWait(t *testing.T, got <-chan string) string {
	t.Helper()
	select {
	case s := <-got:
		return s
	case <-time.After(20 * time.Second):
		t.Fatal("нет ответа хоста")
		return ""
	}
}

func rtAuthed(a *Agent) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sess != nil && a.sess.authed.Load()
}

// Приёмка Э3, проба 1: живая сессия на T (по пропуску) — «снять» не доходит (connect → busy); сессия живёт, пропуск жив.
func TestRTOffWhileSession(t *testing.T) {
	var logs syncBuf
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	url := local(t)
	_, mkey, _ := ed25519.GenerateKey(nil)
	mpub := mkey.Public().(ed25519.PublicKey)
	p := passTarget(t, url, nil, mpub)
	d := passDial(url, p, mkey)
	if err := PassOpen(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	idle(t, p.a)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan string, 4)
	go rtClient(ctx, url, d.ID, mkey, func(cpub, csig []byte) authMsg {
		return authMsg{T: "b", CPub: cpub, CSig: csig, Key: true, Pass: true}
	}, got)
	if r := rtWait(t, got); r != "ok" {
		t.Fatalf("вход по пропуску: %s", r)
	}
	time.Sleep(300 * time.Millisecond)
	if !rtAuthed(p.a) {
		t.Fatal("сессия по пропуску не вошла")
	}
	err := PassOff(context.Background(), d)
	t.Logf("PassOff при живой сессии: err=%v", err)
	time.Sleep(500 * time.Millisecond)
	t.Logf("сессия по пропуску жива после PassOff: %v; пропуск жив: %v", rtAuthed(p.a), p.a.passValid(mpub, salt))
	if err == nil && !rtAuthed(p.a) {
		t.Log("OK: снят и сессия разорвана")
	} else {
		t.Errorf("регрессия: «снять» не доставлено при занятой цели (err=%v), сессия жива=%v", err, rtAuthed(p.a))
	}
}

// Приёмка Э3, проба 2: посторонний держит 3 незавершённых входа — «снять» мастера не доходит.
func TestRTOffWhilePending(t *testing.T) {
	url := local(t)
	_, mkey, _ := ed25519.GenerateKey(nil)
	mpub := mkey.Public().(ed25519.PublicKey)
	p := passTarget(t, url, nil, mpub)
	d := passDial(url, p, mkey)
	if err := PassOpen(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	idle(t, p.a)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for range 3 { // молчуны: connect и тишина
		go hostDial(ctx, url, d.ID, connectReq{View: true}, func(pc *webrtc.PeerConnection, finish func(error)) {})
	}
	for range 100 {
		p.a.mu.Lock()
		n := len(p.a.pend) + p.a.starting
		p.a.mu.Unlock()
		if n >= 3 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	err := PassOff(context.Background(), d)
	t.Logf("PassOff при 3 незавершённых входах постороннего: err=%v; пропуск жив: %v", err, p.a.passValid(mpub, salt))
	if err != nil {
		t.Errorf("регрессия: посторонний (знает только ID) блокирует «снять»: %v", err)
	}
}

// Приёмка Э3, проба 3: срок истёк, опроса DropRevoked нет (как на Windows) — сессия по пропуску живёт дальше.
func TestRTExpireNoPoll(t *testing.T) {
	url := local(t)
	_, mkey, _ := ed25519.GenerateKey(nil)
	mpub := mkey.Public().(ed25519.PublicKey)
	p := passTarget(t, url, nil, mpub)
	d := passDial(url, p, mkey)
	if err := PassOpen(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	idle(t, p.a)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan string, 4)
	go rtClient(ctx, url, d.ID, mkey, func(cpub, csig []byte) authMsg {
		return authMsg{T: "b", CPub: cpub, CSig: csig, Key: true, Pass: true}
	}, got)
	if r := rtWait(t, got); r != "ok" {
		t.Fatalf("вход по пропуску: %s", r)
	}
	time.Sleep(300 * time.Millisecond)
	defer passSkew.Store(0)
	passSkew.Store(int64(PassTTL + time.Hour))
	time.Sleep(5 * time.Second)
	alive := rtAuthed(p.a)
	t.Logf("через 13 ч (часы сдвинуты), 5 с без опроса приложения: сессия жива=%v, пропуск жив=%v", alive, p.a.passValid(mpub, salt))
	if alive {
		t.Errorf("регрессия: агент сам сессию по истёкшему пропуску не рвёт — только опрос приложения (на Windows его нет)")
	}
	p.a.DropRevoked()
	time.Sleep(300 * time.Millisecond)
	t.Logf("после ручного DropRevoked: сессия жива=%v", rtAuthed(p.a))
}

// Приёмка Э3, проба 4: посторонний «снять» (свой ключ), «снять» с чужим cpub и подписью не этого соединения (replay),
// вход по пропуску с подписью не этого соединения — пропуск мастера цел; что в журнале и счётчике.
func TestRTOffStrangerReplay(t *testing.T) {
	var logs syncBuf
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	url := local(t)
	_, mkey, _ := ed25519.GenerateKey(nil)
	_, xkey, _ := ed25519.GenerateKey(nil)
	mpub := mkey.Public().(ed25519.PublicKey)
	p := passTarget(t, url, nil, mpub)
	d := passDial(url, p, mkey)
	if err := PassOpen(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	run := func(name string, key ed25519.PrivateKey, b func(cpub, csig []byte) authMsg) string {
		idle(t, p.a)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		got := make(chan string, 4)
		go rtClient(ctx, url, d.ID, key, b, got)
		r := rtWait(t, got)
		f, _ := lock(p.a)
		t.Logf("%s → %q; пропуск мастера жив=%v; неудач=%d", name, r, p.a.passValid(mpub, salt), f)
		return r
	}
	// подпись мастера из ДРУГОГО соединения (перехвачена злым хостом/хабом): снимаем её тут
	var oldSig []byte
	run("мастер, честный вход по пропуску (снимаем подпись)", mkey, func(cpub, csig []byte) authMsg {
		oldSig = bytes.Clone(csig)
		return authMsg{T: "b", CPub: cpub, CSig: csig, Key: true, Pass: true}
	})
	if r := run("посторонний ключ: off", xkey, func(cpub, csig []byte) authMsg {
		return authMsg{T: "b", CPub: cpub, CSig: csig, Key: true, Off: true}
	}); r != "off" {
		t.Logf("посторонний off: %s", r)
	}
	if !p.a.passValid(mpub, salt) {
		t.Error("регрессия: посторонний снял чужой пропуск")
	}
	run("replay: cpub мастера + старая подпись, off", xkey, func(_, _ []byte) authMsg {
		return authMsg{T: "b", CPub: mpub, CSig: oldSig, Key: true, Off: true}
	})
	if !p.a.passValid(mpub, salt) {
		t.Error("регрессия: replay подписи снял пропуск")
	}
	if r := run("replay: cpub мастера + старая подпись, вход по пропуску", xkey, func(_, _ []byte) authMsg {
		return authMsg{T: "b", CPub: mpub, CSig: oldSig, Key: true, Pass: true}
	}); r == "ok" {
		t.Error("регрессия: replay подписи вошёл по пропуску")
	}
	if r := run("cpub мастера без подписи, вход по пропуску", xkey, func(_, _ []byte) authMsg {
		return authMsg{T: "b", CPub: mpub, Key: true, Pass: true}
	}); r == "ok" {
		t.Error("регрессия: вход по пропуску без подписи")
	}
	for range 8 { // nopass без счёта: сколько угодно
		run("посторонний ключ: вход по пропуску", xkey, func(cpub, csig []byte) authMsg {
			return authMsg{T: "b", CPub: cpub, CSig: csig, Key: true, Pass: true}
		})
	}
	n := strings.Count(logs.String(), "снят")
	t.Logf("строк «пропуск … снят» в журнале: %d (реально пропусков снято: 0)", n)
}

// Приёмка Э3, проба 5: пропуск не привязан к записи владельца на момент выдачи: сменили пароль/пространство (новая соль), ключ
// член нового состава — старый пропуск действует.
func TestRTPassSurvivesNewSalt(t *testing.T) {
	a := newAgent("", "123456789", nil)
	_, mkey, _ := ed25519.GenerateKey(nil)
	pub := mkey.Public().(ed25519.PublicKey)
	cur := salt
	a.SpaceMember = func(s, _ []byte) bool { return bytes.Equal(s, cur) }
	a.passGive(pub, salt) // выдан при старой записи владельца (соль salt)
	cur = []byte("NEW-SALT-NEW-PWD")
	if a.passValid(pub, cur) {
		t.Errorf("регрессия: пропуск, выданный при старом пароле/составе, действует при новом (соль другая)")
	}
}

// Приёмка Э3, проба 6: гонки на map пропусков.
func TestRTPassRace(t *testing.T) {
	a := newAgent("", "123456789", nil)
	a.SpaceMember = func(s, _ []byte) bool { return true }
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, k, _ := ed25519.GenerateKey(nil)
			pub := k.Public().(ed25519.PublicKey)
			s := &session{salt: salt, byPass: pub}
			for j := range 300 {
				a.passGive(pub, salt)
				a.passValid(pub, salt)
				a.revoked(s)
				if (i+j)%3 == 0 {
					a.passDrop(pub)
				}
				passSkew.Store(int64(j) * int64(time.Hour))
			}
		}()
	}
	wg.Wait()
	passSkew.Store(0)
}

// rt2Client — как rtClient, но свой connect и полный ответ хоста.
func rt2Client(ctx context.Context, url, id string, req connectReq, key ed25519.PrivateKey, b func(am authMsg, cpub, csig []byte, pc *webrtc.PeerConnection) authMsg, got chan<- authMsg) error {
	return hostDial(ctx, url, id, req, func(pc *webrtc.PeerConnection, finish func(error)) {
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			if dc.Label() != "auth" {
				return
			}
			first := true
			dc.OnMessage(func(msg webrtc.DataChannelMessage) {
				var am authMsg
				json.Unmarshal(msg.Data, &am)
				if am.T == "a" && first {
					first = false
					cpub, csig, _ := signB(key, id, pc)
					bb, _ := json.Marshal(b(am, cpub, csig, pc))
					dc.SendText(string(bb))
					return
				}
				select {
				case got <- am:
				default:
				}
			})
		})
	})
}

// Приёмка Э3, круг 2, проба 2.2: соединение «снять» входа не даёт (пароль, пропуск), неудач не считает; что получает посторонний.
func TestRT2OffOnlyNoLogin(t *testing.T) {
	url := local(t)
	_, mkey, _ := ed25519.GenerateKey(nil)
	_, xkey, _ := ed25519.GenerateKey(nil)
	mpub := mkey.Public().(ed25519.PublicKey)
	p := passTarget(t, url, nil, mpub)
	d := passDial(url, p, mkey)
	if err := PassOpen(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	idle(t, p.a)
	p.a.mu.Lock()
	p.a.lockUntil = time.Now().Add(time.Hour) // хост заперт перебором
	p.a.mu.Unlock()
	off := connectReq{View: true, Off: true}
	run := func(name string, key ed25519.PrivateKey, b func(am authMsg, cpub, csig []byte, pc *webrtc.PeerConnection) authMsg) authMsg {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		got := make(chan authMsg, 4)
		go rt2Client(ctx, url, d.ID, off, key, b, got)
		var r authMsg
		select {
		case r = <-got:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: нет ответа", name)
		}
		time.Sleep(200 * time.Millisecond)
		f, _ := lock(p.a)
		t.Logf("%s → %q (pub %d байт, sig %d байт, conf %d); вошёл=%v; неудач=%d; пропуск мастера жив=%v", name, r.T, len(r.Pub), len(r.Sig), len(r.Conf), rtAuthed(p.a), f, p.a.passValid(mpub, salt))
		if r.T == "ok" || r.T == "otp" || rtAuthed(p.a) {
			t.Errorf("регрессия: %s — соединение «снять» дало вход (%s)", name, r.T)
		}
		return r
	}
	run("off-соединение, заперт: верный пароль в b (посторонний ключ)", xkey, func(am authMsg, cpub, csig []byte, pc *webrtc.PeerConnection) authMsg {
		return authMsg{T: "b", Msg: []byte("x"), Conf: []byte("y"), CPub: cpub, CSig: csig}
	})
	run("off-соединение: b без ключа", xkey, func(am authMsg, _, _ []byte, pc *webrtc.PeerConnection) authMsg {
		return authMsg{T: "b", Key: true, Off: true, CPub: mpub}
	})
	if r := run("off-соединение: посторонний ключ, off", xkey, func(am authMsg, cpub, csig []byte, pc *webrtc.PeerConnection) authMsg {
		return authMsg{T: "b", Key: true, Off: true, CPub: cpub, CSig: csig}
	}); r.T != "off" || len(r.Pub) > 0 || len(r.Sig) > 0 {
		t.Errorf("регрессия: посторонний ключ получил %q с ключом хоста (%d) и подписью (%d) — только члену M", r.T, len(r.Pub), len(r.Sig))
	}
	run("off-соединение: ключ мастера, вход по пропуску (key+pass, без off)", mkey, func(am authMsg, cpub, csig []byte, pc *webrtc.PeerConnection) authMsg {
		return authMsg{T: "b", Key: true, Pass: true, CPub: cpub, CSig: csig}
	})
}

var _ = sync.Mutex{}
