package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"anypc/hub"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/pion/webrtc/v4"
)

// TestHostDialDeadline — срок обмена истёк после offer (хост молчит): ошибка оборачивает context.DeadlineExceeded —
// окно пространства отдаёт код timeout (app/spaceapi.go), а не other.
func TestHostDialDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // хаб + хост: offer и тишина
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		ctx := r.Context()
		wsjson.Write(ctx, c, hub.Msg{V: 1, Type: "hello", Data: json.RawMessage(`{}`)})
		var m hub.Msg
		if wsjson.Read(ctx, c, &m) != nil || m.Type != "connect" {
			return
		}
		pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
		if err != nil {
			return
		}
		defer pc.Close()
		pc.CreateDataChannel("ctl", nil)
		offer, err := pc.CreateOffer(nil)
		if err != nil || pc.SetLocalDescription(offer) != nil {
			return
		}
		b, _ := json.Marshal(offer)
		wsjson.Write(ctx, c, hub.Msg{V: 1, Type: "offer", From: m.To, Data: b})
		for wsjson.Read(ctx, c, &m) == nil { // ответ и кандидаты клиента — в никуда
		}
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := hostDial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), "123456789", connectReq{View: true}, func(*webrtc.PeerConnection, func(error)) {})
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "нет ответа вовремя") {
		t.Fatalf("срок обмена: %v", err)
	}
}

// fakeHostHub — хаб и хост в одном (Ч12): hello, offer хоста, ответ и кандидаты клиента — хосту; ice — слать ли
// клиенту кандидаты хоста (без них ICE не сходится: «хост недостижим»); open — что хост делает, когда клиент
// открыл канал auth (соединение есть).
func fakeHostHub(t *testing.T, ice bool, open func(pc *webrtc.PeerConnection, dc *webrtc.DataChannel), rec ...func(typ string)) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		ctx := r.Context()
		var wmu sync.Mutex
		write := func(m hub.Msg) { wmu.Lock(); defer wmu.Unlock(); wsjson.Write(ctx, c, m) }
		write(hub.Msg{V: 1, Type: "hello", Data: json.RawMessage(fakeHello)})
		var m hub.Msg
		if wsjson.Read(ctx, c, &m) != nil || m.Type != "connect" {
			return
		}
		id := m.To
		pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
		if err != nil {
			return
		}
		defer pc.Close()
		dc, _ := pc.CreateDataChannel("auth", nil)
		dc.OnOpen(func() { open(pc, dc) })
		pc.OnICECandidate(func(ci *webrtc.ICECandidate) {
			if ci != nil && ice {
				b, _ := json.Marshal(ci.ToJSON())
				write(hub.Msg{V: 1, Type: "ice", From: id, Data: b})
			}
		})
		offer, err := pc.CreateOffer(nil)
		if err != nil || pc.SetLocalDescription(offer) != nil {
			return
		}
		b, _ := json.Marshal(offer)
		write(hub.Msg{V: 1, Type: "offer", From: id, Data: b})
		for wsjson.Read(ctx, c, &m) == nil {
			for _, f := range rec {
				f(m.Type)
			}
			switch {
			case !ice: // клиента не слышим
			case m.Type == "answer":
				var sd webrtc.SessionDescription
				if json.Unmarshal(m.Data, &sd) == nil {
					pc.SetRemoteDescription(sd)
				}
			case m.Type == "ice":
				var ci webrtc.ICECandidateInit
				if json.Unmarshal(m.Data, &ci) == nil {
					pc.AddICECandidate(ci)
				}
			}
		}
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

// fakeHello — hello хаба в fakeHostHub (ICE-серверы клиенту)
var fakeHello = `{}`

func linkWait(t *testing.T, d time.Duration) {
	old := spaceLinkWait
	spaceLinkWait = d
	t.Cleanup(func() { spaceLinkWait = old })
}

// TestHostDialNoLink — регрессия Ч12 («висит на Выполняется…»): хост ответил offer, но ICE не сходится (VPN,
// брандмауэр). Раньше hostDial ждал ctx (вступление — spaceWait + Confirm = 3 мин), теперь — ErrSpaceNoLink за
// spaceLinkWait; худший срок вступления до ошибки соединения — с запасом до 45 с.
func TestHostDialNoLink(t *testing.T) {
	if spaceDialWait+spaceLinkWait > 40*time.Second {
		t.Errorf("худший срок до ошибки соединения %v — окно ждёт дольше 45 с", spaceDialWait+spaceLinkWait)
	}
	linkWait(t, time.Second)
	url := fakeHostHub(t, false, func(*webrtc.PeerConnection, *webrtc.DataChannel) {})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	t0 := time.Now()
	err := hostDial(ctx, url, "123456789", connectReq{View: true}, func(*webrtc.PeerConnection, func(error)) {})
	if !errors.Is(err, ErrSpaceNoLink) || time.Since(t0) > 5*time.Second {
		t.Fatalf("ICE не сходится: %v за %v", err, time.Since(t0))
	}
	// и вступление целиком: срок соединения, а не spaceWait + Confirm
	t0 = time.Now()
	_, err = SpaceJoin(ctx, SpaceDial{Server: url, ID: "123456789", Confirm: time.Hour})
	if !errors.Is(err, ErrSpaceNoLink) || time.Since(t0) > 5*time.Second {
		t.Fatalf("SpaceJoin: %v за %v", err, time.Since(t0))
	}
}

// TestHostDialHostClosed — Ч12: соединение есть, а хост закрыл сессию (authWait, отказ) — ErrSpaceClosed сразу, а не
// по сроку; причина, пришедшая перед закрытием, важнее закрытия.
func TestHostDialHostClosed(t *testing.T) {
	url := fakeHostHub(t, true, func(pc *webrtc.PeerConnection, _ *webrtc.DataChannel) { pc.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	t0 := time.Now()
	err := hostDial(ctx, url, "123456789", connectReq{View: true}, func(*webrtc.PeerConnection, func(error)) {})
	if !errors.Is(err, ErrSpaceClosed) || time.Since(t0) > 15*time.Second {
		t.Fatalf("хост закрыл: %v за %v", err, time.Since(t0))
	}
	why := errors.New("причина от хоста")
	url = fakeHostHub(t, true, func(pc *webrtc.PeerConnection, dc *webrtc.DataChannel) {
		dc.SendText("fail")
		time.AfterFunc(20*time.Millisecond, func() { pc.Close() })
	})
	err = hostDial(ctx, url, "123456789", connectReq{View: true}, func(pc *webrtc.PeerConnection, finish func(error)) {
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			dc.OnMessage(func(webrtc.DataChannelMessage) { finish(why) })
		})
	})
	if !errors.Is(err, why) {
		t.Fatalf("отказ перед закрытием: %v", err)
	}
}

// TestDialNoKeyInLog — Ч12: адрес сигнализации с ?host=…&key=… (ключ хоста) не попадает в текст ошибки dial —
// а он идёт в журнал («сигнализация …: …») и в ошибки пространства; errors.As по исходной ошибке работает.
func TestDialNoKeyInLog(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := dial(ctx, "ws://127.0.0.1:1/ws?host=123456789&key=SECRETKEYxyz")
	var op *net.OpError
	if err == nil || strings.Contains(err.Error(), "SECRETKEY") || strings.Contains(err.Error(), "key=") || !errors.As(err, &op) {
		t.Fatalf("ошибка dial: %v (OpError: %v)", err, op != nil)
	}
	_, key, _ := ed25519.GenerateKey(nil)
	a := &Agent{ID: "123456789", Key: key}
	err = a.run(ctx, "ws://127.0.0.1:1/ws")
	pub := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	if err == nil || strings.Contains(err.Error(), pub) || strings.Contains(err.Error(), "key=") {
		t.Fatalf("журнал сигнализации: %v", err)
	}
}

// TestHostDialAnswerFirst — Ч12: кандидаты клиента уходят хосту только после answer: хост отвергает "ice" до remote
// description (AddICECandidate — ErrNoRemoteDescription, в журнале «ice: …»), а pion может выдать host-кандидат до
// send("answer"); пауза перед answer (hostDialBeforeAnswer) делает кандидаты заведомо ранними.
func TestHostDialAnswerFirst(t *testing.T) {
	hostDialBeforeAnswer = func() { time.Sleep(300 * time.Millisecond) } // кандидаты собраны раньше answer
	t.Cleanup(func() { hostDialBeforeAnswer = nil })
	for range 3 {
		var mu sync.Mutex
		var seen []string
		url := fakeHostHub(t, true, func(pc *webrtc.PeerConnection, _ *webrtc.DataChannel) {}, func(typ string) { mu.Lock(); seen = append(seen, typ); mu.Unlock() })
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		hostDial(ctx, url, "123456789", connectReq{View: true}, func(pc *webrtc.PeerConnection, finish func(error)) {
			pc.OnDataChannel(func(*webrtc.DataChannel) { time.AfterFunc(200*time.Millisecond, func() { finish(nil) }) })
		})
		cancel()
		mu.Lock()
		got := strings.Join(seen, ",")
		mu.Unlock()
		if !strings.HasPrefix(got, "answer") || !strings.Contains(got, "ice") {
			t.Fatalf("порядок сообщений клиента: %s — ждали answer, затем ice", got)
		}
	}
}

// TestHostDialNoUDP — Ч12: соединения нет, и этот процесс не собрал ни srflx, ни relay, хотя хаб дал STUN/TURN —
// исходящий UDP закрыт брандмауэром этого ПК (Мак: LuLu пускает окно-WebKit и не пускает AnyPC): ErrSpaceNoUDP,
// окну — код noudp («разрешите AnyPC в брандмауэре этого ПК»). Без ICE-серверов от хаба — просто ErrSpaceNoLink.
func TestHostDialNoUDP(t *testing.T) {
	linkWait(t, 2*time.Second)
	old := fakeHello
	fakeHello = `{"ICE":[{"urls":["stun:127.0.0.1:9"]}]}` // STUN молчит, как за брандмауэром
	t.Cleanup(func() { fakeHello = old })
	url := fakeHostHub(t, false, func(*webrtc.PeerConnection, *webrtc.DataChannel) {})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err := hostDial(ctx, url, "123456789", connectReq{View: true}, func(*webrtc.PeerConnection, func(error)) {})
	if !errors.Is(err, ErrSpaceNoUDP) || !errors.Is(err, ErrSpaceNoLink) {
		t.Fatalf("STUN недоступен: %v", err)
	}
	fakeHello = `{}`
	url = fakeHostHub(t, false, func(*webrtc.PeerConnection, *webrtc.DataChannel) {})
	if err := hostDial(ctx, url, "123456789", connectReq{View: true}, func(*webrtc.PeerConnection, func(error)) {}); !errors.Is(err, ErrSpaceNoLink) || errors.Is(err, ErrSpaceNoUDP) {
		t.Fatalf("без ICE-серверов: %v", err)
	}
}
