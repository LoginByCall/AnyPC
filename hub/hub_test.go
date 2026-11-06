package hub

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func dial(t *testing.T, ctx context.Context, url string) (*websocket.Conn, string) {
	t.Helper()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	var m Msg
	if err := wsjson.Read(ctx, c, &m); err != nil || m.Type != "hello" {
		t.Fatalf("hello: %v %+v", err, m)
	}
	var d struct{ ID string }
	json.Unmarshal(m.Data, &d)
	return c, d.ID
}

func read(t *testing.T, ctx context.Context, c *websocket.Conn) Msg {
	t.Helper()
	var m Msg
	if err := wsjson.Read(ctx, c, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv := httptest.NewServer(&Hub{})
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	host, _ := dial(t, ctx, url+"?host=123456789")
	cli, cid := dial(t, ctx, url)

	// happy path: клиент → хост, From проставлен сервером, подмена игнорируется
	wsjson.Write(ctx, cli, Msg{Type: "connect", To: "123456789", From: "999999999", Data: json.RawMessage(`{"pass":"x"}`)})
	if m := read(t, ctx, host); m.Type != "connect" || m.From != cid {
		t.Fatalf("relay: %+v", m)
	}
	// ошибки: нет такого хоста; клиент → клиент; занятый ID
	wsjson.Write(ctx, cli, Msg{Type: "connect", To: "987654321"})
	if m := read(t, ctx, cli); string(m.Data) != `"not_found"` {
		t.Fatalf("not_found: %+v", m)
	}
	wsjson.Write(ctx, cli, Msg{Type: "x", To: "c000"})
	if m := read(t, ctx, cli); string(m.Data) != `"forbidden"` {
		t.Fatalf("forbidden: %+v", m)
	}
	dup, _, _ := websocket.Dial(ctx, url+"?host=123456789", nil)
	if m := read(t, ctx, dup); string(m.Data) != `"id_taken"` {
		t.Fatalf("id_taken: %+v", m)
	}
}

func TestIDsAndTurn(t *testing.T) {
	for id, ok := range map[string]bool{"123456789": true, "012345678": false, "12345678": false, "12345678a": false, "c123": false} {
		if IsHostID(id) != ok {
			t.Errorf("IsHostID(%q) != %v", id, ok)
		}
	}
	if id := RandDigits(9); !IsHostID(id) {
		t.Errorf("RandDigits: %q", id)
	}
	s := (&Hub{TurnHost: "t.example", TurnSecret: "sec"}).ICEServers("c1")
	if len(s) != 2 {
		t.Fatalf("ice: %+v", s)
	}
	mac := hmac.New(sha1.New, []byte("sec"))
	mac.Write([]byte(s[1].Username))
	if s[1].Credential != base64.StdEncoding.EncodeToString(mac.Sum(nil)) || !strings.HasSuffix(s[1].Username, ":c1") {
		t.Fatalf("turn creds: %+v", s[1])
	}
	if (&Hub{}).ICEServers("c1") != nil {
		t.Fatal("без TurnHost серверов быть не должно")
	}
}
