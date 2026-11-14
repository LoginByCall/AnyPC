package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"anypc/hub"
	"anypc/pake"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/pion/webrtc/v4"
)

func hasPass(a *Agent, pub ed25519.PublicKey) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.passes[string(pub)]
	return ok
}

func offBody(key ed25519.PrivateKey, id string, at time.Time) json.RawMessage {
	nonce := make([]byte, pake.OffNonce)
	rand.Read(nonce)
	b, _ := json.Marshal(pake.OffSign(key, id, at.Unix(), nonce))
	return b
}

// TestOffMsg — «снять» одним сообщением через хаб: доставлено, пропуск снят, соединения «снять» не было.
func TestOffMsg(t *testing.T) {
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
	d.HostPub = nil // ключ хоста цели «снять» сообщением не нужен: ответа от цели нет
	if err := PassOff(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if hasPass(p.a, mpub) {
		t.Fatal("пропуск не снят")
	}
	if !strings.Contains(logs.String(), "сообщение через хаб") || strings.Contains(logs.String(), "пропуск ПК "+pake.KeyFingerprint(mpub)[:9]+" снят\n") {
		t.Error("снято не сообщением через хаб")
	}
	if err := PassOff(context.Background(), d); err != nil { // снять снятый — тоже доставлено
		t.Error(err)
	}
	if err := PassOff(context.Background(), PassDial{Server: url, ID: "987654321", Key: mkey}); !errors.Is(err, ErrSpaceOffline) {
		t.Errorf("цели нет в сети: %v", err)
	}
}

// TestOffMsgRejected — пропуск жив: подделка подписи, чужой ключ, исключённый член, другая цель, старое и будущее
// время, повтор nonce, мусор.
func TestOffMsgRejected(t *testing.T) {
	url := local(t)
	_, mkey, _ := ed25519.GenerateKey(nil)
	mpub := mkey.Public().(ed25519.PublicKey)
	p := passTarget(t, url, nil, mpub)
	if err := PassOpen(context.Background(), passDial(url, p, mkey)); err != nil {
		t.Fatal(err)
	}
	id, now := p.a.ID, time.Now()
	_, other, _ := ed25519.GenerateKey(nil)
	forged := offBody(mkey, id, now)
	forged[len(forged)-3] ^= 'A' ^ 'B' // в base64 тела подписи
	for why, data := range map[string]json.RawMessage{
		"подделка":      forged,
		"чужой ключ":    offBody(other, id, now),
		"другая цель":   offBody(mkey, "223456789", now),
		"старое время":  offBody(mkey, id, now.Add(-offSkew-time.Minute)),
		"будущее время": offBody(mkey, id, now.Add(offSkew+time.Minute)),
		"мусор":         json.RawMessage(`{"x":1}`),
		"короткое":      json.RawMessage(`"AAAA"`),
	} {
		p.a.offMsg(data)
		if !hasPass(p.a, mpub) {
			t.Fatalf("%s: пропуск снят", why)
		}
	}
	p.member(mpub, false)
	p.a.offMsg(offBody(mkey, id, now))
	if !hasPass(p.a, mpub) {
		t.Fatal("исключённый член снял пропуск")
	}
	p.member(mpub, true)
	good := offBody(mkey, id, now)
	p.a.offMsg(good)
	if hasPass(p.a, mpub) {
		t.Fatal("верное «снять» не сняло")
	}
	p.a.passGive(mpub, salt)
	p.a.offMsg(good) // повтор того же nonce — новый пропуск жив
	if !hasPass(p.a, mpub) {
		t.Fatal("повтор nonce снял новый пропуск")
	}
}

// TestOffMsgFlood — посторонний (знает ID цели) шлёт 1000 «снять» с 10 соединений: мусор, свои подписи и копию тела
// с ключом мастера без подписи; «снять» мастера, отправленное посреди потока, доходит и снимает пропуск.
func TestOffMsgFlood(t *testing.T) {
	url := local(t)
	_, mkey, _ := ed25519.GenerateKey(nil)
	mpub := mkey.Public().(ed25519.PublicKey)
	p := passTarget(t, url, nil, mpub)
	d := passDial(url, p, mkey)
	if err := PassOpen(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, other, _ := ed25519.GenerateKey(nil)
	fake := offBody(other, p.a.ID, time.Now())
	copy(fake[1:44], offBody(mkey, p.a.ID, time.Now())[1:44]) // pub мастера, подпись чужая
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			ws, _, err := websocket.Dial(ctx, url, nil)
			if err != nil {
				return
			}
			defer ws.CloseNow()
			for i := range 100 {
				data := []json.RawMessage{fake, offBody(other, p.a.ID, time.Now()), json.RawMessage(`"мусор"`)}[i%3]
				if wsjson.Write(ctx, ws, hub.Msg{V: 1, Type: "off", To: p.a.ID, Data: data}) != nil {
					return
				}
			}
		})
	}
	for range maxOffs + 2 { // и молчуны в соединениях «снять» старого пути (они вытесняли «снять» мастера)
		go hostDial(ctx, url, p.a.ID, connectReq{View: true, Off: true}, func(*webrtc.PeerConnection, func(error)) {})
	}
	time.Sleep(50 * time.Millisecond)
	if err := PassOff(ctx, d); err != nil {
		t.Fatalf("«снять» посреди потока: %v", err)
	}
	wg.Wait()
	time.Sleep(200 * time.Millisecond)
	if hasPass(p.a, mpub) {
		t.Fatal("пропуск жив после «снять» мастера")
	}
	idle(t, p.a)
	if err := PassLogin(context.Background(), d); !errors.Is(err, ErrPassNone) { // цель в сети и отвечает
		t.Fatalf("цель после потока: %v", err)
	}
}

// TestOffMsgOldHost — цель старой версии (?off=1 не объявляет): хаб отвечает "old", мастер снимает по-старому.
func TestOffMsgOldHost(t *testing.T) {
	url := local(t)
	_, mkey, _ := ed25519.GenerateKey(nil)
	mpub := mkey.Public().(ed25519.PublicKey)
	p := passTarget(t, url, nil, mpub, func(p *passRig) { p.a.noOffMsg = true })
	d := passDial(url, p, mkey)
	if err := PassOpen(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	idle(t, p.a)
	if err := passOffHub(context.Background(), d); !errors.Is(err, errOffOld) {
		t.Fatalf("старый хост: %v", err)
	}
	if !hasPass(p.a, mpub) {
		t.Fatal("старому хосту переслано")
	}
	if err := PassOff(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if hasPass(p.a, mpub) {
		t.Fatal("запасной путь не снял")
	}
}
