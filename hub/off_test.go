package hub

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// TestOffRelay — «снять» сообщением (Э3, решение 8 A): хосту с ?off=1 — пересылка без connect и hello, отправителю
// "ok"; старому хосту — не пересылается, "old"; нет хоста — not_found; хост off не шлёт; сверх OffBurst с соединения
// — "busy"; мусор и слишком большое — хаб жив, хост тоже.
func TestOffRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv := httptest.NewServer(&Hub{})
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	_, k1, _ := ed25519.GenerateKey(nil)
	_, k2, _ := ed25519.GenerateKey(nil)
	host, _ := dialHostQ(t, ctx, url, "123456789", k1, true, "&off=1")
	old, _ := dialHost(t, ctx, url, "223456789", k2, true)
	cli, cid := dial(t, ctx, url)
	body := json.RawMessage(`"` + strings.Repeat("A", 160) + `"`)
	expect := func(want string) {
		t.Helper()
		if m := read(t, ctx, cli); string(m.Data) != `"`+want+`"` || m.From != "" {
			t.Fatalf("ждали %s: %+v", want, m)
		}
	}
	wsjson.Write(ctx, cli, Msg{Type: "off", To: "123456789", Data: body})
	if m := read(t, ctx, host); m.Type != "off" || m.From != cid || string(m.Data) != string(body) {
		t.Fatalf("хост получил %+v", m)
	}
	expect("ok")
	wsjson.Write(ctx, cli, Msg{Type: "off", To: "223456789", Data: body})
	expect("old")
	wsjson.Write(ctx, cli, Msg{Type: "off", To: "987654321", Data: body})
	expect("not_found")
	wsjson.Write(ctx, cli, Msg{Type: "off", To: "123456789", Data: body}) // четвёртое — последнее в OffBurst
	read(t, ctx, host)
	expect("ok")
	wsjson.Write(ctx, cli, Msg{Type: "off", To: "123456789", Data: body})
	expect("busy")
	wsjson.Write(ctx, host, Msg{Type: "off", To: cid, Data: body})
	if m := read(t, ctx, host); string(m.Data) != `"forbidden"` {
		t.Fatalf("off от хоста: %+v", m)
	}
	// мусор: тело не строка — пересылается как есть (разбирает хост); больше 512 Б — соединение закрыто
	c2, _ := dial(t, ctx, url)
	wsjson.Write(ctx, c2, Msg{Type: "off", To: "123456789", Data: json.RawMessage(`{"x":[1,2,3]}`)})
	if m := read(t, ctx, host); m.Type != "off" {
		t.Fatalf("хост получил %+v", m)
	}
	if m := read(t, ctx, c2); string(m.Data) != `"ok"` {
		t.Fatalf("мусор: %+v", m)
	}
	wsjson.Write(ctx, c2, Msg{Type: "off", To: "123456789", Data: json.RawMessage(`"` + strings.Repeat("A", 600) + `"`)})
	closed(t, ctx, c2)
	c3, _ := dial(t, ctx, url)
	c3.Write(ctx, websocket.MessageText, []byte("не json"))
	if _, _, err := c3.Read(ctx); err == nil {
		t.Fatal("не JSON — соединение не закрыто")
	}
	// хаб и оба хоста живы
	c4, _ := dial(t, ctx, url)
	wsjson.Write(ctx, c4, Msg{Type: "off", To: "123456789", Data: body})
	if m := read(t, ctx, host); m.Type != "off" {
		t.Fatalf("после мусора хост получил %+v", m)
	}
	wsjson.Write(ctx, c4, Msg{Type: "connect", To: "223456789"})
	read(t, ctx, old) // hello
	if m := read(t, ctx, old); m.Type != "connect" {
		t.Fatalf("старый хост: %+v", m)
	}
}
