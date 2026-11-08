package hub

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anypc/pake"

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

// dialHost — хост: подключение с ключом, подпись вызова сервера (sign=false — подписать мусор).
func dialHost(t *testing.T, ctx context.Context, url, id string, priv ed25519.PrivateKey, sign bool) (*websocket.Conn, Msg) {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	c, _, err := websocket.Dial(ctx, url+"?host="+id+"&key="+base64.RawURLEncoding.EncodeToString(pub), nil)
	if err != nil {
		t.Fatal(err)
	}
	ch := read(t, ctx, c)
	var nonce string
	json.Unmarshal(ch.Data, &nonce)
	if ch.Type != "challenge" || nonce == "" {
		t.Fatalf("ждали challenge: %+v", ch)
	}
	sig := ed25519.Sign(priv, pake.RegisterMsg(id, nonce))
	if !sign {
		sig = ed25519.Sign(priv, []byte("не то"))
	}
	d, _ := json.Marshal(map[string][]byte{"sig": sig})
	wsjson.Write(ctx, c, Msg{Type: "register", Data: d})
	return c, read(t, ctx, c)
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
	srv := httptest.NewServer(&Hub{TurnHosts: []string{"t.example"}, TurnSecret: "sec"})
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	_, priv, _ := ed25519.GenerateKey(nil)
	host, hello := dialHost(t, ctx, url, "123456789", priv, true)
	if hello.Type != "hello" {
		t.Fatalf("регистрация: %+v", hello)
	}
	cli, cid := dial(t, ctx, url)

	// happy path: клиент → хост, From проставлен сервером, подмена игнорируется
	wsjson.Write(ctx, cli, Msg{Type: "connect", To: "123456789", From: "999999999", Data: json.RawMessage(`{"pass":"x"}`)})
	// регрессия: хост в сети дольше TurnTTL получал протухший пароль TURN — перед connect приходит свежий hello
	if m := read(t, ctx, host); m.Type != "hello" || !strings.Contains(string(m.Data), `"credential"`) {
		t.Fatalf("нет свежего hello с TURN перед connect: %+v", m)
	}
	if m := read(t, ctx, host); m.Type != "connect" || m.From != cid {
		t.Fatalf("relay: %+v", m)
	}
	// Д-4: клиент шлёт хосту служебное (error id_taken выкидывал хост из сети, hello подменял TURN) — не пересылается
	for _, typ := range []string{"error", "hello", "challenge", "offer"} {
		wsjson.Write(ctx, cli, Msg{Type: typ, To: "123456789", Data: json.RawMessage(`"id_taken"`)})
		if m := read(t, ctx, cli); string(m.Data) != `"forbidden"` {
			t.Fatalf("%s от клиента: %+v", typ, m)
		}
	}
	wsjson.Write(ctx, cli, Msg{Type: "bye", To: "123456789"})
	if m := read(t, ctx, host); m.Type != "bye" { // первым до хоста доходит bye, а не что-то из служебного выше
		t.Fatalf("после служебного хост получил %+v", m)
	}
	for _, typ := range []string{"connect", "answer", "hello"} { // и в обратную сторону: хост → клиент
		wsjson.Write(ctx, host, Msg{Type: typ, To: cid})
		if m := read(t, ctx, host); string(m.Data) != `"forbidden"` {
			t.Fatalf("%s от хоста: %+v", typ, m)
		}
	}
	wsjson.Write(ctx, host, Msg{Type: "error", To: cid, Data: json.RawMessage(`"busy"`)})
	if m := read(t, ctx, cli); m.Type != "error" || m.From != "123456789" {
		t.Fatalf("ошибка хоста клиенту: %+v", m)
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
	if _, m := dialHost(t, ctx, url, "123456789", priv, true); string(m.Data) != `"id_taken"` { // уже в сети
		t.Fatalf("id_taken: %+v", m)
	}
}

// TestHostKeys — REQ-F-01: ID закреплён за ключом; подпись обязательна; привязка переживает перезапуск.
func TestHostKeys(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	file := filepath.Join(t.TempDir(), "hosts.json")
	srv := httptest.NewServer(&Hub{Keys: file})
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	_, mine, _ := ed25519.GenerateKey(nil)
	_, evil, _ := ed25519.GenerateKey(nil)

	if _, m := dialHost(t, ctx, url, "555555555", mine, false); string(m.Data) != `"bad_sig"` {
		t.Fatalf("подпись не проверяется: %+v", m)
	}
	c, m := dialHost(t, ctx, url, "555555555", mine, true)
	if m.Type != "hello" {
		t.Fatalf("регистрация: %+v", m)
	}
	c.Close(websocket.StatusNormalClosure, "")
	time.Sleep(100 * time.Millisecond)
	if _, m := dialHost(t, ctx, url, "555555555", evil, true); string(m.Data) != `"id_taken"` { // чужой ключ, хост не в сети
		t.Fatalf("ID перехвачен чужим ключом: %+v", m)
	}
	srv.Close()

	srv = httptest.NewServer(&Hub{Keys: file}) // перезапуск сервера
	defer srv.Close()
	url = "ws" + strings.TrimPrefix(srv.URL, "http")
	if _, m := dialHost(t, ctx, url, "555555555", evil, true); string(m.Data) != `"id_taken"` {
		t.Fatalf("привязка не пережила перезапуск: %+v", m)
	}
	if _, m := dialHost(t, ctx, url, "555555555", mine, true); m.Type != "hello" {
		t.Fatalf("владелец не вошёл после перезапуска: %+v", m)
	}
	r, _ := http.Get(srv.URL + "?host=555555555") // без ключа
	if r != nil && r.StatusCode != http.StatusBadRequest {
		t.Fatalf("хост без ключа: %d", r.StatusCode)
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
	s := (&Hub{TurnHosts: []string{"t.example", "t2.example"}, TurnSecret: "sec"}).ICEServers("c1")
	if len(s) != 4 || s[2].URLs[0] != "stun:t2.example:3478" || s[3].Username != s[1].Username || s[3].Credential != s[1].Credential {
		t.Fatalf("ice: %+v", s)
	}
	mac := hmac.New(sha1.New, []byte("sec"))
	mac.Write([]byte(s[1].Username))
	if s[1].Credential != base64.StdEncoding.EncodeToString(mac.Sum(nil)) || !strings.HasSuffix(s[1].Username, ":c1") {
		t.Fatalf("turn creds: %+v", s[1])
	}
	if (&Hub{}).ICEServers("c1") != nil {
		t.Fatal("без TurnHosts серверов быть не должно")
	}
}

// TestRegisterLimit — новых ID с одного IP не больше NewPerHour в час; уже привязанный ID входит и сверх лимита.
func TestRegisterLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv := httptest.NewServer(&Hub{})
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	_, key, _ := ed25519.GenerateKey(nil)
	for i := range NewPerHour {
		c, m := dialHost(t, ctx, url, fmt.Sprint(100000000+i), key, true)
		if m.Type != "hello" {
			t.Fatalf("регистрация %d: %+v", i, m)
		}
		c.Close(websocket.StatusNormalClosure, "")
	}
	if _, m := dialHost(t, ctx, url, "999999999", key, true); string(m.Data) != `"limit"` {
		t.Fatalf("сверх лимита: %+v", m)
	}
	time.Sleep(100 * time.Millisecond)
	if _, m := dialHost(t, ctx, url, "100000000", key, true); m.Type != "hello" {
		t.Fatalf("привязанный ID сверх лимита не вошёл: %+v", m)
	}
}

// TestKeepalive — хост, переставший отвечать (обрыв сети), снимается с хаба за ~PingEvery·4/3, а не через минуты:
// после переподключения ID свободен.
func TestKeepalive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv := httptest.NewServer(&Hub{Ping: 300 * time.Millisecond})
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	_, key, _ := ed25519.GenerateKey(nil)
	dead, m := dialHost(t, ctx, url, "123456789", key, true) // дальше не читает — на ping не отвечает
	if m.Type != "hello" {
		t.Fatalf("регистрация: %+v", m)
	}
	defer dead.CloseNow()
	time.Sleep(600 * time.Millisecond)
	if _, m := dialHost(t, ctx, url, "123456789", key, true); m.Type != "hello" {
		t.Fatalf("мёртвое соединение держит ID: %+v", m)
	}
}

// TestRemoteIP — лимит регистраций: за прокси на loopback — адрес из X-Forwarded-For, IPv6 — по /64,
// а заголовок от внешнего адреса не принимается (иначе лимит обходится подделкой).
func TestRemoteIP(t *testing.T) {
	for _, c := range []struct{ addr, xff, want string }{
		{"203.0.113.5:1234", "", "203.0.113.5"},
		{"203.0.113.5:1234", "198.51.100.1", "203.0.113.5"},
		{"127.0.0.1:1234", "10.0.0.1, 198.51.100.7", "198.51.100.7"},
		{"[2001:db8:1:2:3:4:5:6]:1234", "", "2001:db8:1:2::/64"},
		{"127.0.0.1:1234", "", "127.0.0.1"},
	} {
		r := httptest.NewRequest("GET", "/ws", nil)
		r.RemoteAddr = c.addr
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := remoteIP(r); got != c.want {
			t.Errorf("%s + %q: %s, ждали %s", c.addr, c.xff, got, c.want)
		}
	}
}
