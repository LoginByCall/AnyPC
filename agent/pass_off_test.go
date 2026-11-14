package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anypc/hub"
	"anypc/pake"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func hasPass(a *Agent, pub ed25519.PublicKey) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.passes[string(pub)]
	return ok
}

// offBody — "data" сообщения off: тело pake.OffSign, после порчи mut (nil — без порчи), в base64 JSON.
func offBody(key ed25519.PrivateKey, id string, pid []byte, mut func([]byte)) json.RawMessage {
	b := pake.OffSign(key, id, pid)
	if mut != nil {
		mut(b)
	}
	d, _ := json.Marshal(b)
	return d
}

const offFrom = "c000000000001"

// ackOf — ответ цели a на тело data от клиента offFrom: nil — молчание; иначе статус (подпись ключом цели проверена).
func ackOf(t *testing.T, a *Agent, data json.RawMessage, pid []byte) (answered, dropped bool) {
	t.Helper()
	ack := a.offMsg(hub.Msg{Type: "off", From: offFrom, Data: data})
	if ack == nil {
		return false, false
	}
	dropped, ok := pake.OffAckVerify(a.Key.Public().(ed25519.PublicKey), ack, a.ID, pid)
	if !ok {
		t.Fatal("ответ цели не проверяется её ключом")
	}
	return true, dropped
}

// passOpenID — «Работаю тут» на p: d с id пропуска.
func passOpenID(t *testing.T, url string, p *passRig, mkey ed25519.PrivateKey) PassDial {
	t.Helper()
	d := passDial(url, p, mkey)
	pid, err := PassOpenID(context.Background(), d)
	if err != nil || len(pid) != pake.OffID {
		t.Fatalf("PassOpenID: %v, id %x", err, pid)
	}
	d.PID = pid
	idle(t, p.a)
	return d
}

// TestOffMsg — «снять» сообщением через хаб: цель снимает и отвечает подписью; повтор — «нет пропуска», тоже ответ;
// часы цели на ±3 ч — не мешают (времени в протоколе нет); цели нет в сети — ErrSpaceOffline.
func TestOffMsg(t *testing.T) {
	var logs syncBuf
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	url := local(t)
	_, mkey, _ := ed25519.GenerateKey(nil)
	mpub := mkey.Public().(ed25519.PublicKey)
	p := passTarget(t, url, nil, mpub)
	d := passOpenID(t, url, p, mkey)
	defer passSkew.Store(0)
	for i, sk := range []time.Duration{0, 3 * time.Hour, -3 * time.Hour} {
		passSkew.Store(int64(sk))
		if i > 0 {
			d.PID = p.a.passGive(mpub, salt)
		}
		if err := PassOff(context.Background(), d); err != nil {
			t.Fatalf("сдвиг %v: %v", sk, err)
		}
		if hasPass(p.a, mpub) {
			t.Fatalf("сдвиг %v: пропуск не снят", sk)
		}
		if err := PassOff(context.Background(), d); err != nil { // снять снятый — ответ «нет пропуска»
			t.Error(err)
		}
	}
	if !strings.Contains(logs.String(), "сообщение через хаб") {
		t.Error("снято не сообщением через хаб")
	}
	if err := PassOff(context.Background(), PassDial{Server: url, ID: "987654321", Key: mkey, PID: make([]byte, pake.OffID)}); !errors.Is(err, ErrSpaceOffline) {
		t.Errorf("цели нет в сети: %v", err)
	}
}

// TestOffMsgRejected — пропуск жив: подделка подписи, чужой ключ, исключённый член, другая цель, другой id, повтор
// после новой выдачи, мусор; молчание — всем, кроме члена с верной подписью.
func TestOffMsgRejected(t *testing.T) {
	url := local(t)
	_, mkey, _ := ed25519.GenerateKey(nil)
	mpub := mkey.Public().(ed25519.PublicKey)
	p := passTarget(t, url, nil, mpub)
	d := passOpenID(t, url, p, mkey)
	id, pid := p.a.ID, d.PID
	_, other, _ := ed25519.GenerateKey(nil)
	wrong := append([]byte(nil), pid...)
	wrong[0] ^= 1
	for why, data := range map[string]json.RawMessage{
		"подпись":     offBody(mkey, id, pid, func(b []byte) { b[len(b)-1] ^= 1 }),
		"id подменён": offBody(mkey, id, pid, func(b []byte) { b[ed25519.PublicKeySize] ^= 1 }),
		"чужой ключ":  offBody(other, id, pid, nil),
		"другая цель": offBody(mkey, "223456789", pid, nil),
		"мусор":       json.RawMessage(`{"x":1}`),
		"короткое":    json.RawMessage(`"AAAA"`),
	} {
		if ans, _ := ackOf(t, p.a, data, pid); ans || !hasPass(p.a, mpub) {
			t.Fatalf("%s: ответ %v, пропуск жив %v", why, ans, hasPass(p.a, mpub))
		}
	}
	if p.a.offMsg(hub.Msg{From: "123456789", Data: offBody(mkey, id, pid, nil)}) != nil || !hasPass(p.a, mpub) {
		t.Fatal("from — не клиент: ответ или снятие")
	}
	if ans, drop := ackOf(t, p.a, offBody(mkey, id, wrong, nil), wrong); !ans || drop || !hasPass(p.a, mpub) {
		t.Fatalf("другой id: ответ %v, снят %v, пропуск жив %v", ans, drop, hasPass(p.a, mpub))
	}
	p.member(mpub, false)
	if ans, _ := ackOf(t, p.a, offBody(mkey, id, pid, nil), pid); ans || !hasPass(p.a, mpub) {
		t.Fatal("исключённый член: ответ или снятие")
	}
	p.member(mpub, true)
	good := offBody(mkey, id, pid, nil)
	if ans, drop := ackOf(t, p.a, good, pid); !ans || !drop || hasPass(p.a, mpub) {
		t.Fatal("верное «снять» не сняло")
	}
	p.a.passGive(mpub, salt)
	if ans, drop := ackOf(t, p.a, good, pid); !ans || drop || !hasPass(p.a, mpub) { // повтор — к новому пропуску не относится
		t.Fatal("повтор снял новый пропуск")
	}
}

// TestOffMsgFlood — 1000 «снять» посторонних прямо на цель (мимо лимитов хаба: чужие ключи, ключ мастера с чужой
// подписью, мусор) и через хаб, одновременно с «снять» мастера: оно доходит, ответ проверен, журнал — пара строк.
func TestOffMsgFlood(t *testing.T) {
	var logs syncBuf
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	url := local(t)
	_, mkey, _ := ed25519.GenerateKey(nil)
	mpub := mkey.Public().(ed25519.PublicKey)
	p := passTarget(t, url, nil, mpub)
	d := passOpenID(t, url, p, mkey)
	_, other, _ := ed25519.GenerateKey(nil)
	fake := offBody(other, p.a.ID, d.PID, nil)
	raw, _ := base64.StdEncoding.DecodeString(strings.Trim(string(fake), `"`))
	copy(raw, mpub) // ключ мастера, подпись чужая
	fakeM, _ := json.Marshal(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for g := range 10 {
		wg.Go(func() {
			for i := range 100 {
				data := []json.RawMessage{fakeM, offBody(other, p.a.ID, d.PID, nil), json.RawMessage(`"мусор"`)}[(g+i)%3]
				if p.a.offMsg(hub.Msg{From: offFrom, Data: data}) != nil {
					t.Error("посторонний получил ответ")
				}
			}
		})
		wg.Go(func() { // и через хаб — до лимитов
			ws, _, err := websocket.Dial(ctx, url, nil)
			if err != nil {
				return
			}
			defer ws.CloseNow()
			for range 20 {
				wsjson.Write(ctx, ws, hub.Msg{V: 1, Type: "off", To: p.a.ID, Data: fakeM})
			}
		})
	}
	if err := PassOff(ctx, d); err != nil {
		t.Fatalf("«снять» посреди потока: %v", err)
	}
	wg.Wait()
	if hasPass(p.a, mpub) {
		t.Fatal("пропуск жив после «снять» мастера")
	}
	if n := strings.Count(logs.String(), "«снять» через хаб: отклонено"); n > 2 {
		t.Errorf("строк об отказах в журнале: %d", n)
	}
}

// offHost — хост id с ключом key на хабе url, объявивший «снять» сообщением; ничего сам не читает.
func offHost(t *testing.T, ctx context.Context, url, id string, key ed25519.PrivateKey) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.Dial(ctx, url+"?off=1&host="+id+"&key="+base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.CloseNow() })
	var m hub.Msg
	wsjson.Read(ctx, c, &m)
	var nonce string
	json.Unmarshal(m.Data, &nonce)
	sig, _ := json.Marshal(map[string][]byte{"sig": ed25519.Sign(key, pake.RegisterMsg(id, nonce))})
	wsjson.Write(ctx, c, hub.Msg{V: 1, Type: "register", Data: sig})
	if wsjson.Read(ctx, c, &m) != nil || m.Type != "hello" {
		t.Fatalf("регистрация: %+v", m)
	}
	return c
}

// TestOffMsgNoAck — хаб переслал, а цель не ответила (не читает, сон) — мастер не считает снятым; ответ не тем
// ключом хоста или на другой id — ErrSpaceHostKey.
func TestOffMsgNoAck(t *testing.T) {
	old := offAckWait
	offAckWait = 500 * time.Millisecond
	defer func() { offAckWait = old }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	url := local(t)
	_, hkey, _ := ed25519.GenerateKey(nil)
	_, mkey, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)
	h := offHost(t, ctx, url, "323456789", hkey)
	d := PassDial{Server: url, ID: "323456789", HostPub: hkey.Public().(ed25519.PublicKey), Key: mkey, PID: make([]byte, pake.OffID)}
	if err := passOffHub(ctx, d); err == nil || errors.Is(err, errOffOld) {
		t.Fatalf("цель молчит: %v", err)
	}
	type forge struct {
		key ed25519.PrivateKey
		pid []byte
	}
	var cur atomic.Pointer[forge]
	cur.Store(&forge{other, d.PID})
	go func() { // отвечает на каждое off, в том числе на пришедшее, пока не читал (его клиент ушёл — хаб не пропустит)
		var m hub.Msg
		for wsjson.Read(ctx, h, &m) == nil {
			if m.Type == "off" {
				f := cur.Load()
				ack, _ := json.Marshal(pake.OffAck(f.key, d.ID, f.pid, true))
				wsjson.Write(ctx, h, hub.Msg{V: 1, Type: "offack", To: m.From, Data: ack})
			}
		}
	}()
	if err := passOffHub(ctx, d); !errors.Is(err, ErrSpaceHostKey) {
		t.Errorf("ответ не тем ключом: %v", err)
	}
	cur.Store(&forge{hkey, []byte("другой-id-16байт")[:pake.OffID]})
	if err := passOffHub(ctx, d); !errors.Is(err, ErrSpaceHostKey) {
		t.Errorf("ответ на другой id: %v", err)
	}
	cur.Store(&forge{hkey, d.PID})
	if err := passOffHub(ctx, d); err != nil {
		t.Errorf("верный ответ: %v", err)
	}
}

// TestOffMsgOldHost — цель старой версии (?off=1 не объявляет): хаб отвечает "old", мастер снимает по-старому;
// без id пропуска — сразу по-старому; старый хаб (off — forbidden) — тоже запасной путь.
func TestOffMsgOldHost(t *testing.T) {
	url := local(t)
	_, mkey, _ := ed25519.GenerateKey(nil)
	mpub := mkey.Public().(ed25519.PublicKey)
	p := passTarget(t, url, nil, mpub, func(p *passRig) { p.a.noOffMsg = true })
	d := passOpenID(t, url, p, mkey)
	if err := passOffHub(context.Background(), d); !errors.Is(err, errOffOld) {
		t.Fatalf("старый хост: %v", err)
	}
	if !hasPass(p.a, mpub) {
		t.Fatal("старому хосту переслано")
	}
	if err := PassOff(context.Background(), d); err != nil || hasPass(p.a, mpub) {
		t.Fatalf("запасной путь: %v, пропуск жив %v", err, hasPass(p.a, mpub))
	}
	n := passTarget(t, local(t), nil, mpub)
	nd := passOpenID(t, n.a.Server, n, mkey)
	nd.PID = nil
	if err := PassOff(context.Background(), nd); err != nil || hasPass(n.a, mpub) {
		t.Fatalf("без id: %v, пропуск жив %v", err, hasPass(n.a, mpub))
	}
	oldHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // хаб v0.2.0: off не знает
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		wsjson.Write(r.Context(), c, hub.Msg{V: 1, Type: "hello", Data: json.RawMessage(`{"id":"c000000000002"}`)})
		var m hub.Msg
		for wsjson.Read(r.Context(), c, &m) == nil {
			wsjson.Write(r.Context(), c, hub.Msg{V: 1, Type: "error", Data: json.RawMessage(`"forbidden"`)})
		}
	}))
	defer oldHub.Close()
	nd.Server, nd.PID = "ws"+strings.TrimPrefix(oldHub.URL, "http"), make([]byte, pake.OffID)
	if err := passOffHub(context.Background(), nd); !errors.Is(err, errOffOld) {
		t.Fatalf("старый хаб: %v", err)
	}
}
