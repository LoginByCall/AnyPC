package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"anypc/hub"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/pion/webrtc/v4"
)

// Ч12: шаги вступления для окна — link → auth → list, и только потом Sign (превью); у отказа входа шага list нет.
func TestSpaceJoinStages(t *testing.T) {
	url := local(t)
	r := spaceHost(t, url, "123456789")
	_, nkey, _ := ed25519.GenerateKey(nil)
	var mu sync.Mutex
	var got []string
	add := func(s string) { mu.Lock(); got = append(got, s); mu.Unlock() }
	d := SpaceDial{Server: url, ID: "123456789", Key: nkey, Password: "secret123", Code: r.owner.code(), Stage: add,
		Sign: func(m []byte, _ ed25519.PublicKey, _ ...[]byte) ([]byte, error) {
			add("sign")
			return append(bytes.Clone(m), "+N"...), nil
		}}
	if _, err := SpaceJoin(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if s := strings.Join(got, ","); s != "link,auth,list,sign" {
		t.Errorf("шаги: %s", s)
	}
	got = nil
	mu.Unlock()
	d.Password = "wrong-pass"
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceAuth) {
		t.Fatalf("неверный пароль: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if s := strings.Join(got, ","); s != "link,auth" {
		t.Errorf("шаги отказа: %s", s)
	}
}

// Ч12, приёмка B3: отказы хоста до offer с причиной — свои ошибки (окно говорит, что делать), а не «тот ПК отказал»;
// для сверки и пропуска они по-прежнему ErrSpaceRefused.
func TestHostDialRefuseWhy(t *testing.T) {
	for _, c := range []struct {
		why  string
		want error
	}{{"busy", ErrSpaceBusyThere}, {"locked", ErrSpaceLockedThere}, {"nopass", ErrSpaceNoPassThere}, {"internal", ErrSpaceRefused}} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ws, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer ws.CloseNow()
			wsjson.Write(r.Context(), ws, hub.Msg{V: 1, Type: "hello", Data: json.RawMessage(`{}`)})
			var m hub.Msg
			if wsjson.Read(r.Context(), ws, &m) == nil {
				b, _ := json.Marshal(c.why)
				wsjson.Write(r.Context(), ws, hub.Msg{V: 1, Type: "error", Data: b})
			}
			wsjson.Read(r.Context(), ws, &m)
		}))
		err := hostDial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), "123456789", connectReq{View: true}, func(*webrtc.PeerConnection, func(error)) {})
		srv.Close()
		if !errors.Is(err, c.want) || !errors.Is(err, ErrSpaceRefused) {
			t.Errorf("error %q: %v", c.why, err)
		}
	}
}

// Ч12, приёмка B3: настоящий хост — вход закрыт после неверных попыток и занят: причина доходит до вступления.
func TestSpaceJoinLockedBusy(t *testing.T) {
	url := local(t)
	r := spaceHost(t, url, "123456789")
	_, nkey, _ := ed25519.GenerateKey(nil)
	d := SpaceDial{Server: url, ID: "123456789", Key: nkey, Password: "secret123", Code: r.owner.code(),
		Sign: func(m []byte, _ ed25519.PublicKey, _ ...[]byte) ([]byte, error) { return m, nil }}
	r.a.mu.Lock()
	r.a.lockUntil = time.Now().Add(time.Hour)
	r.a.mu.Unlock()
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceLockedThere) {
		t.Errorf("вход закрыт: %v", err)
	}
	r.a.mu.Lock()
	r.a.lockUntil, r.a.starting = time.Time{}, 1000
	r.a.mu.Unlock()
	if _, err := SpaceJoin(context.Background(), d); !errors.Is(err, ErrSpaceBusyThere) {
		t.Errorf("занят: %v", err)
	}
	r.a.mu.Lock()
	r.a.starting = 0
	r.a.mu.Unlock()
}

// Ч12: хаб принял TCP и молчит — дозвон к нему не дольше spaceDialWait, дальше следующий хаб (ErrSpaceOffline).
func TestHostDialDialWait(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	old := spaceDialWait
	spaceDialWait = time.Second
	t.Cleanup(func() { spaceDialWait = old })
	t0 := time.Now()
	err = hostDial(context.Background(), "ws://"+l.Addr().String()+"/ws", "123456789", connectReq{View: true}, func(*webrtc.PeerConnection, func(error)) {})
	if !errors.Is(err, ErrSpaceOffline) || time.Since(t0) > 3*time.Second {
		t.Fatalf("молчащий хаб: %v за %v", err, time.Since(t0))
	}
}

// Ч12, приёмка M5: зависший прокси из окружения съедает не весь срок дозвона — после proxyWait напрямую.
func TestDialHungProxy(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() }) // принял и молчит
		}
	}()
	oldP, oldW := proxy, proxyWait
	pu, _ := url.Parse("http://" + l.Addr().String())
	proxy, proxyWait = func(*http.Request) (*url.URL, error) { return pu, nil }, 500*time.Millisecond
	t.Cleanup(func() { proxy, proxyWait = oldP, oldW })
	hubURL := fakeHostHub(t, false, func(*webrtc.PeerConnection, *webrtc.DataChannel) {})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	t0 := time.Now()
	c, err := dialWait(ctx, hubURL, proxyWait)
	if err != nil || time.Since(t0) > 3*time.Second {
		t.Fatalf("зависший прокси: %v за %v", err, time.Since(t0))
	}
	c.CloseNow()
}

// Ч12: ни один кандидат клиента не теряется — все собранные (в т. ч. до answer) доходят до хоста.
func TestHostDialNoLostCandidates(t *testing.T) {
	var mu sync.Mutex
	n := 0
	u := fakeHostHub(t, true, func(*webrtc.PeerConnection, *webrtc.DataChannel) {}, func(typ string) {
		if typ == "ice" {
			mu.Lock()
			n++
			mu.Unlock()
		}
	})
	hostDialBeforeAnswer = func() { time.Sleep(300 * time.Millisecond) } // кандидаты — раньше answer
	t.Cleanup(func() { hostDialBeforeAnswer = nil })
	sdp := make(chan string, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hostDial(ctx, u, "123456789", connectReq{View: true}, func(pc *webrtc.PeerConnection, finish func(error)) {
		pc.OnDataChannel(func(*webrtc.DataChannel) {
			time.AfterFunc(time.Second, func() { sdp <- pc.LocalDescription().SDP; finish(nil) }) // сбор на петле — за доли секунды
		})
	})
	time.Sleep(200 * time.Millisecond)
	want := len(regexp.MustCompile(`(?m)^a=candidate:\S+ 1 `).FindAllString(<-sdp, -1)) // pion пишет каждый кандидат и для компонента 2
	mu.Lock()
	defer mu.Unlock()
	if want == 0 || n < want {
		t.Errorf("кандидатов собрано %d, хост получил %d", want, n)
	}
}
