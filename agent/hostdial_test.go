package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
