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
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
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

// limHub — хаб с хостом 123456789 в сети; from — адрес клиентов через X-Forwarded-For (тест идёт с loopback,
// а loopback вне лимитов на IP).
func limHub(t *testing.T, ctx context.Context, h *Hub) (url string, host *websocket.Conn) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	url = "ws" + strings.TrimPrefix(srv.URL, "http")
	_, priv, _ := ed25519.GenerateKey(nil)
	host, m := dialHost(t, ctx, url, "123456789", priv, true)
	if m.Type != "hello" {
		t.Fatalf("регистрация: %+v", m)
	}
	host.SetReadLimit(64 << 10) // как у agent
	return url, host
}

// dialFrom — клиент «с адреса from»: соединение, его ID; ответ HTTP-кодом — (nil, "", код).
func dialFrom(t *testing.T, ctx context.Context, url, from string) (*websocket.Conn, string, int) {
	t.Helper()
	o := &websocket.DialOptions{HTTPHeader: http.Header{}}
	if from != "" {
		o.HTTPHeader.Set("X-Forwarded-For", from)
	}
	c, r, err := websocket.Dial(ctx, url, o)
	if err != nil {
		if r == nil {
			t.Fatal(err)
		}
		return nil, "", r.StatusCode
	}
	m := read(t, ctx, c)
	if m.Type != "hello" {
		t.Fatalf("hello: %+v", m)
	}
	var d struct{ ID string }
	json.Unmarshal(m.Data, &d)
	return c, d.ID, 0
}

// closed — соединение закрыто хабом с кодом 1008 (сообщения до закрытия пропускаются).
func closed(t *testing.T, ctx context.Context, c *websocket.Conn) {
	t.Helper()
	for {
		var m Msg
		err := wsjson.Read(ctx, c, &m)
		if err == nil {
			continue
		}
		if s := websocket.CloseStatus(err); s != websocket.StatusPolicyViolation {
			t.Fatalf("ждали закрытия 1008, получили %v (%d)", err, s)
		}
		return
	}
}

// untilFrom читает хост до сообщения typ от from; возвращает, сколько connect от других пришло по дороге.
func untilFrom(t *testing.T, ctx context.Context, host *websocket.Conn, typ, from string) (connects int) {
	t.Helper()
	for {
		m := read(t, ctx, host)
		if m.Type == typ && m.From == from {
			return connects
		}
		if m.Type == "connect" {
			connects++
		}
	}
}

// TestClientFlood — F4: клиент сверх ведра (сообщения или байты) закрыт 1008, хост остаётся в сети
// и получает сообщения другого клиента; законная попытка (≈45 ice + answer 6 КБ) лимит не задевает.
func TestClientFlood(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	url, host := limHub(t, ctx, &Hub{})

	ok, okID := dial(t, ctx, url) // граница: законный всплеск
	for range 45 {
		wsjson.Write(ctx, ok, Msg{Type: "ice", To: "123456789", Data: json.RawMessage(`{"candidate":"candidate:1 1 udp 2122260223 192.0.2.1 50000 typ host"}`)})
	}
	wsjson.Write(ctx, ok, Msg{Type: "answer", To: "123456789", Data: json.RawMessage(`{"sdp":"` + strings.Repeat("a", 6<<10) + `"}`)})
	wsjson.Write(ctx, ok, Msg{Type: "bye", To: "123456789"})
	untilFrom(t, ctx, host, "bye", okID)

	flood, _ := dial(t, ctx, url) // 1000 ice подряд
	go func() {
		for range 1000 {
			if wsjson.Write(ctx, flood, Msg{Type: "ice", To: "123456789", Data: json.RawMessage(`{}`)}) != nil {
				return
			}
		}
	}()
	closed(t, ctx, flood)

	big, _ := dial(t, ctx, url) // байты: 5 × 30 КБ > всплеска 128 КБ
	go func() {
		for range 5 {
			wsjson.Write(ctx, big, Msg{Type: "answer", To: "123456789", Data: json.RawMessage(`"` + strings.Repeat("b", 30<<10) + `"`)})
		}
	}()
	closed(t, ctx, big)

	// размер по типу: ice 3 КБ (> 2 КБ) — закрыт; иначе 64 КБ с конвертом from переполняли буфер чтения хоста
	// и выбивали его из сети одним сообщением
	for typ, n := range map[string]int{"ice": 3 << 10, "connect": 5 << 10, "bye": 1 << 10, "answer": 60 << 10} {
		c, _ := dial(t, ctx, url)
		wsjson.Write(ctx, c, Msg{Type: typ, To: "123456789", Data: json.RawMessage(`"` + strings.Repeat("c", n) + `"`)})
		closed(t, ctx, c)
	}

	other, oid := dial(t, ctx, url)
	wsjson.Write(ctx, other, Msg{Type: "connect", To: "123456789"})
	untilFrom(t, ctx, host, "connect", oid)
	wsjson.Write(ctx, ok, Msg{Type: "bye", To: "123456789"}) // законный клиент не задет
	untilFrom(t, ctx, host, "bye", okID)
}

// TestConnectSpamKeepsHost — регрессия F4 п. 1: спам connect не пересылается хосту (сверх всплеска — busy от хаба),
// а поток хоста сверх его ведра отбрасывается молча — хост остаётся в сети.
func TestConnectSpamKeepsHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	url, host := limHub(t, ctx, &Hub{})

	spam, sid := dial(t, ctx, url)
	for range 20 {
		wsjson.Write(ctx, spam, Msg{Type: "connect", To: "123456789"})
	}
	wsjson.Write(ctx, spam, Msg{Type: "x", To: "123456789"}) // метка конца: forbidden
	busy := 0
	for m := read(t, ctx, spam); string(m.Data) != `"forbidden"`; m = read(t, ctx, spam) {
		if m.Type != "error" || string(m.Data) != `"busy"` {
			t.Fatalf("спамеру: %+v", m)
		}
		busy++
	}
	if busy < 20-ConnectBurst-1 || busy > 20-ConnectBurst {
		t.Fatalf("busy: %d из 20 (всплеск %d)", busy, ConnectBurst)
	}
	wsjson.Write(ctx, spam, Msg{Type: "bye", To: "123456789"})
	if n := untilFrom(t, ctx, host, "bye", sid); n < ConnectBurst || n > ConnectBurst+1 {
		t.Fatalf("до хоста дошло connect: %d, ждали %d", n, ConnectBurst)
	}

	// хост шлёт сверх ведра (700 > 600) — не закрыт и дальше принимает и отправляет
	sink, cid := dial(t, ctx, url)
	for range 700 {
		if err := wsjson.Write(ctx, host, Msg{Type: "ice", To: cid, Data: json.RawMessage(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	got := 0
	wsjson.Write(ctx, host, Msg{Type: "bye", To: cid})
	time.Sleep(50 * time.Millisecond) // ведро хоста пополняется 100/с: bye мог отброситься — шлём ещё раз
	wsjson.Write(ctx, host, Msg{Type: "bye", To: cid})
	for m := read(t, ctx, sink); m.Type != "bye"; m = read(t, ctx, sink) {
		got++
	}
	if got < HostMsgBurst-10 || got >= 700 {
		t.Fatalf("клиент получил ice: %d (ждали ≈%d, сверх — отброшены)", got, HostMsgBurst)
	}
	other, oid := dial(t, ctx, url)
	wsjson.Write(ctx, other, Msg{Type: "connect", To: "123456789"})
	untilFrom(t, ctx, host, "connect", oid)
}

// TestNotFoundLimit — F4: not_found клиенту не больше NotFoundPerConn на соединение и NotFoundPerMin на IP;
// дальше — закрытие и 429 новым клиентским WS с этого IP; другой IP и хост не задеты.
func TestNotFoundLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	url, host := limHub(t, ctx, &Hub{})
	probe := func(c *websocket.Conn, n int) {
		t.Helper()
		for i := range n {
			wsjson.Write(ctx, c, Msg{Type: "ice", To: fmt.Sprint(900000000 + i)})
			if m := read(t, ctx, c); string(m.Data) != `"not_found"` {
				t.Fatalf("not_found %d: %+v", i, m)
			}
		}
	}

	c, _, _ := dialFrom(t, ctx, url, "") // на соединение — и с loopback
	probe(c, NotFoundPerConn)
	wsjson.Write(ctx, c, Msg{Type: "ice", To: "999999999"})
	closed(t, ctx, c)

	const ip = "203.0.113.7"
	spare, _, _ := dialFrom(t, ctx, url, ip) // открыто до исчерпания
	for i := range NotFoundPerMin / NotFoundPerConn {
		c, _, code := dialFrom(t, ctx, url, ip)
		if code != 0 {
			t.Fatalf("соединение %d с %s: %d", i, ip, code)
		}
		probe(c, NotFoundPerConn)
	}
	wsjson.Write(ctx, spare, Msg{Type: "ice", To: "999999999"}) // 31-й с IP
	closed(t, ctx, spare)
	if _, _, code := dialFrom(t, ctx, url, ip); code != http.StatusTooManyRequests {
		t.Fatalf("новое WS после %d not_found с IP: %d, ждали 429", NotFoundPerMin, code)
	}
	if c, _, code := dialFrom(t, ctx, url, "203.0.113.8"); code != 0 {
		t.Fatalf("другой IP: %d", code)
	} else {
		probe(c, 1)
	}
	if _, _, code := dialFrom(t, ctx, url, "127.0.0.1"); code != 0 { // loopback вне лимита на IP
		t.Fatalf("loopback: %d", code)
	}
	other, oid, _ := dialFrom(t, ctx, url, "203.0.113.9")
	wsjson.Write(ctx, other, Msg{Type: "connect", To: "123456789"})
	untilFrom(t, ctx, host, "connect", oid)
}

// TestConnLimit — F4: соединений с IPv4 (и /64) не больше ConnsPerIP, с /48 — ConnsPer48, всего — MaxConns;
// отказ 429/503 до Upgrade; закрытое соединение место освобождает; loopback и частные — вне лимита на IP.
func TestConnLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	h := &Hub{}
	url, _ := limHub(t, ctx, h)
	// ConnsPerIP настоящих WS упёрлись бы в NewClientBurst — первые ConnsPerIP-1 занимают счётчик напрямую
	a5 := netip.MustParseAddr("203.0.113.5")
	for i := range ConnsPerIP - 1 {
		if code := h.acquire(a5); code != 0 {
			t.Fatalf("соединение %d: %d", i, code)
		}
	}
	defer func() {
		for range ConnsPerIP - 1 {
			h.release(a5)
		}
	}()
	c, _, code := dialFrom(t, ctx, url, "203.0.113.5")
	if code != 0 {
		t.Fatalf("соединение %d: %d", ConnsPerIP, code)
	}
	keep := []*websocket.Conn{c}
	if _, _, code := dialFrom(t, ctx, url, "203.0.113.5"); code != http.StatusTooManyRequests {
		t.Fatalf("соединение %d с IP: %d, ждали 429", ConnsPerIP+1, code)
	}
	if _, _, code := dialFrom(t, ctx, url, "203.0.113.6"); code != 0 {
		t.Fatalf("соседний IP: %d", code)
	}
	for i := range ConnsPerIP + 1 { // loopback (свой прокси без XFF, тесты) — без лимита на IP
		c, _, code := dialFrom(t, ctx, url, "")
		if code != 0 {
			t.Fatalf("loopback %d: %d", i, code)
		}
		defer c.CloseNow()
	}
	keep[0].Close(websocket.StatusNormalClosure, "")
	ok := false
	for range 50 { // хаб снимает соединение после закрытия асинхронно
		if c, _, code := dialFrom(t, ctx, url, "203.0.113.5"); code == 0 {
			ok = true
			c.CloseNow()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ok {
		t.Fatal("закрытое соединение не освободило место")
	}
	for _, c := range keep {
		c.CloseNow()
	}

	// IPv6: /64 — как один IPv4, /48 — свой потолок (без 1000 настоящих соединений — счётчики напрямую)
	for i := range ConnsPer48 {
		a := netip.MustParseAddr(fmt.Sprintf("2001:db8:1:%x::1", i/ConnsPerIP))
		if code := h.acquire(a); code != 0 {
			t.Fatalf("v6 %d (%s): %d", i, a, code)
		}
	}
	if code := h.acquire(netip.MustParseAddr("2001:db8:1:ff::1")); code != http.StatusTooManyRequests {
		t.Fatalf("/48 сверх %d: %d", ConnsPer48, code)
	}
	if code := h.acquire(netip.MustParseAddr("2001:db8:1:0::2")); code != http.StatusTooManyRequests {
		t.Fatalf("/64 сверх %d: %d", ConnsPerIP, code)
	}
	if code := h.acquire(netip.MustParseAddr("2001:db8:2::1")); code != 0 {
		t.Fatalf("соседний /48: %d", code)
	}
	if !exempt(netip.MustParseAddr("10.1.2.3")) || !exempt(netip.MustParseAddr("172.17.0.1")) || exempt(netip.MustParseAddr("100.64.0.1")) {
		t.Fatal("частные адреса — вне лимита на IP, остальные — в нём")
	}

	// общий потолок — 503 и для loopback
	small := &Hub{MaxConns: 2}
	url, _ = limHub(t, ctx, small) // хост — первое соединение
	c, _, code = dialFrom(t, ctx, url, "")
	if code != 0 {
		t.Fatalf("второе соединение: %d", code)
	}
	defer c.CloseNow()
	if _, _, code := dialFrom(t, ctx, url, ""); code != http.StatusServiceUnavailable {
		t.Fatalf("сверх MaxConns: %d, ждали 503", code)
	}
}

// TestNewClientLimit — D1: ведро connect живёт в соединении, и раньше «WS → 5 connect → закрыть → повторить» с одного IP
// доносило до хоста ≈7000 connect/с (опыт A приёмки). Теперь новых клиентских WS с адреса — NewClientBurst и
// NewClientRate в секунду, сверх — 429 до Upgrade; уже открытое WS, соседний IP, loopback и хост не задеты.
func TestNewClientLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	url, host := limHub(t, ctx, &Hub{})
	var got atomic.Int64
	others := make(chan string, 16)
	go func() {
		for {
			var m Msg
			if wsjson.Read(ctx, host, &m) != nil {
				return
			}
			if m.Type == "connect" {
				got.Add(1)
				if !strings.HasPrefix(m.From, "c") {
					t.Errorf("connect от %q", m.From)
				}
				select {
				case others <- m.From:
				default:
				}
			}
		}
	}()
	const ip = "203.0.113.50"
	spare, sid, _ := dialFrom(t, ctx, url, ip) // открыто до исчерпания
	start := time.Now()
	ok, refused := 1, 0
	for range 3 * NewClientBurst {
		c, _, code := dialFrom(t, ctx, url, ip)
		if code == http.StatusTooManyRequests {
			refused++
			continue
		}
		if code != 0 {
			t.Fatalf("dial: %d", code)
		}
		ok++
		for range ConnectBurst {
			wsjson.Write(ctx, c, Msg{Type: "connect", To: "123456789"})
		}
		wsjson.Write(ctx, c, Msg{Type: "bye", To: "123456789"})
		c.Close(websocket.StatusNormalClosure, "")
	}
	if most := NewClientBurst + int(time.Since(start).Seconds()*NewClientRate) + 1; ok > most || refused == 0 {
		t.Fatalf("клиентских WS с одного IP открыто %d (ждали ≤ %d), отказов 429: %d", ok, most, refused)
	}
	time.Sleep(200 * time.Millisecond)
	if n := got.Load(); n > int64(ok*ConnectBurst) {
		t.Fatalf("до хоста дошло connect: %d, ждали ≤ %d", n, ok*ConnectBurst)
	}
	for len(others) > 0 {
		<-others
	}
	want := map[string]bool{sid: true} // уже открытое WS, соседний IP и loopback не задеты
	wsjson.Write(ctx, spare, Msg{Type: "connect", To: "123456789"})
	for _, from := range []string{"203.0.113.51", ""} {
		c, id, code := dialFrom(t, ctx, url, from)
		if code != 0 {
			t.Fatalf("с %q: %d", from, code)
		}
		defer c.CloseNow()
		want[id] = true
		wsjson.Write(ctx, c, Msg{Type: "connect", To: "123456789"})
	}
	for len(want) > 0 {
		select {
		case from := <-others:
			delete(want, from)
		case <-ctx.Done():
			t.Fatalf("до хоста не дошли connect от %v", want)
		}
	}
}
