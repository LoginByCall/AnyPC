package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"anypc/hub"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/pion/webrtc/v4"
)

// Ч12, круг 3: «locked»/«busy» в канале входа — причина (вход закрыт после неверных попыток / идёт сеанс), а не
// «неверный пароль или код»; для сверки и пропуска — по-прежнему ErrSpaceAuth.
func TestSpaceJoinAuthLockedBusy(t *testing.T) {
	for _, c := range []struct {
		t    string
		want error
	}{{"locked", ErrSpaceLockedThere}, {"busy", ErrSpaceBusyThere}, {"fail", ErrSpaceAuth}} {
		u := fakeHostHub(t, true, func(_ *webrtc.PeerConnection, dc *webrtc.DataChannel) { dc.SendText(`{"t":"` + c.t + `"}`) })
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		_, err := SpaceJoin(ctx, SpaceDial{Server: u, ID: "123456789"})
		cancel()
		if !errors.Is(err, c.want) || !errors.Is(err, ErrSpaceAuth) {
			t.Errorf("%s: %v", c.t, err)
		}
	}
}

// Ч12, круг 3: состояние соединения — connected снимает срок соединения; failed до соединения — why (nolink/noudp),
// после — closed.
func TestLinkState(t *testing.T) {
	var linked atomic.Bool
	fired := atomic.Bool{}
	timer := time.AfterFunc(time.Hour, func() { fired.Store(true) })
	var got error
	finish := func(err error) { got = err }
	why := func() error { return ErrSpaceNoUDP }
	linkState(webrtc.PeerConnectionStateFailed, &linked, timer, finish, why)
	if got != ErrSpaceNoUDP {
		t.Errorf("failed до соединения: %v", got)
	}
	linkState(webrtc.PeerConnectionStateConnected, &linked, timer, finish, why)
	if !linked.Load() || timer.Stop() {
		t.Error("connected: срок соединения не снят")
	}
	linkState(webrtc.PeerConnectionStateFailed, &linked, timer, finish, why)
	if got != ErrSpaceClosed {
		t.Errorf("failed после соединения: %v", got)
	}
}

// Ч12, круг 3: причина, пришедшая перед закрытием, важнее закрытия, даже если обработчик разбирает её не мгновенно
// (spaceLinkClosedDelay; без задержки побеждал бы «закрыл соединение»).
func TestHostDialReasonBeforeClose(t *testing.T) {
	why := errors.New("причина от хоста")
	u := fakeHostHub(t, true, func(pc *webrtc.PeerConnection, dc *webrtc.DataChannel) {
		dc.SendText("fail")
		time.AfterFunc(20*time.Millisecond, func() { pc.Close() })
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := hostDial(ctx, u, "123456789", connectReq{View: true}, func(pc *webrtc.PeerConnection, finish func(error)) {
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			dc.OnMessage(func(webrtc.DataChannelMessage) { time.Sleep(150 * time.Millisecond); finish(why) })
		})
	})
	if !errors.Is(err, why) {
		t.Fatalf("причина перед закрытием: %v", err)
	}
}

// Ч12, круг 3: "bye" хоста через хаб — «закрыл соединение» для окна и ErrSpaceRefused для сверки и пропуска.
func TestHostDialByeClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		ctx := r.Context()
		wsjson.Write(ctx, ws, hub.Msg{V: 1, Type: "hello", Data: json.RawMessage(`{}`)})
		var m hub.Msg
		if wsjson.Read(ctx, ws, &m) != nil {
			return
		}
		pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
		if err != nil {
			return
		}
		defer pc.Close()
		pc.CreateDataChannel("auth", nil)
		offer, _ := pc.CreateOffer(nil)
		pc.SetLocalDescription(offer)
		b, _ := json.Marshal(offer)
		wsjson.Write(ctx, ws, hub.Msg{V: 1, Type: "offer", From: m.To, Data: b})
		for wsjson.Read(ctx, ws, &m) == nil {
			if m.Type == "answer" {
				bb, _ := json.Marshal("host")
				wsjson.Write(ctx, ws, hub.Msg{V: 1, Type: "bye", From: m.To, Data: bb})
			}
		}
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := hostDial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), "123456789", connectReq{View: true}, func(*webrtc.PeerConnection, func(error)) {})
	if !errors.Is(err, ErrSpaceClosed) || !errors.Is(err, ErrSpaceRefused) {
		t.Fatalf("bye: %v", err)
	}
}
