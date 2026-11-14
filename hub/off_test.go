package hub

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

var offData = json.RawMessage(`"` + strings.Repeat("A", 150) + `"`)

func offHub(t *testing.T, ctx context.Context) (url string, host, old *websocket.Conn) {
	t.Helper()
	srv := httptest.NewServer(&Hub{})
	t.Cleanup(srv.Close)
	url = "ws" + strings.TrimPrefix(srv.URL, "http")
	_, k1, _ := ed25519.GenerateKey(nil)
	_, k2, _ := ed25519.GenerateKey(nil)
	host, _ = dialHostQ(t, ctx, url, "123456789", k1, true, "&off=1")
	old, _ = dialHost(t, ctx, url, "223456789", k2, true)
	return url, host, old
}

// silent — за d на c ничего не пришло.
func silent(t *testing.T, ctx context.Context, c *websocket.Conn, d time.Duration) {
	t.Helper()
	rctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	var m Msg
	if wsjson.Read(rctx, c, &m) == nil {
		t.Fatalf("пришло лишнее: %+v", m)
	}
}

// TestOffRelay — «снять» сообщением (Э3, решение 8 A): хосту с ?off=1 — пересылка, ответ хоста offack — только
// отправителю и один раз; старому хосту — "old"; нет хоста — not_found; хост off не шлёт; хост не пишет offack
// тому, кто off ему не слал; сверх OffBurst с соединения — "busy"; мусор и слишком большое — хаб и хосты живы.
func TestOffRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	url, host, old := offHub(t, ctx)
	cli, cid := dial(t, ctx, url)
	other, oid := dial(t, ctx, url)
	third, tid := dial(t, ctx, url)
	expect := func(c *websocket.Conn, want string) {
		t.Helper()
		if m := read(t, ctx, c); string(m.Data) != `"`+want+`"` || m.From != "" {
			t.Fatalf("ждали %s: %+v", want, m)
		}
	}
	ack := json.RawMessage(`"ack"`)
	wsjson.Write(ctx, cli, Msg{Type: "off", To: "123456789", Data: offData})
	if m := read(t, ctx, host); m.Type != "off" || m.From != cid || string(m.Data) != string(offData) {
		t.Fatalf("хост получил %+v", m)
	}
	wsjson.Write(ctx, host, Msg{Type: "offack", To: tid, Data: ack}) // не тому клиенту
	expect(host, "forbidden")
	wsjson.Write(ctx, old, Msg{Type: "offack", To: cid, Data: ack}) // не тот хост
	expect(old, "forbidden")
	wsjson.Write(ctx, host, Msg{Type: "offack", To: cid, Data: ack})
	if m := read(t, ctx, cli); m.Type != "offack" || m.From != "123456789" || string(m.Data) != string(ack) {
		t.Fatalf("ответ хоста: %+v", m)
	}
	wsjson.Write(ctx, host, Msg{Type: "offack", To: cid, Data: ack}) // второй — нет
	expect(host, "forbidden")

	wsjson.Write(ctx, cli, Msg{Type: "off", To: "223456789", Data: offData})
	expect(cli, "old")
	wsjson.Write(ctx, cli, Msg{Type: "off", To: "987654321", Data: offData})
	expect(cli, "not_found")
	wsjson.Write(ctx, cli, Msg{Type: "off", To: "123456789", Data: offData}) // четвёртое — последнее в OffBurst
	read(t, ctx, host)
	wsjson.Write(ctx, cli, Msg{Type: "off", To: "123456789", Data: offData})
	expect(cli, "busy")
	wsjson.Write(ctx, host, Msg{Type: "off", To: cid, Data: offData})
	expect(host, "forbidden")

	// клиент ушёл — его ожидания тоже: хост не пишет ему (и новому клиенту с тем же ID не написал бы)
	wsjson.Write(ctx, other, Msg{Type: "off", To: "123456789", Data: offData})
	read(t, ctx, host)
	other.CloseNow()
	time.Sleep(100 * time.Millisecond)
	wsjson.Write(ctx, host, Msg{Type: "offack", To: oid, Data: ack})
	expect(host, "forbidden")

	// мусор: тело не строка — пересылается как есть (разбирает хост); больше 512 Б — соединение закрыто
	c2, _ := dial(t, ctx, url)
	wsjson.Write(ctx, c2, Msg{Type: "off", To: "123456789", Data: json.RawMessage(`{"x":[1,2,3]}`)})
	if m := read(t, ctx, host); m.Type != "off" || string(m.Data) != `{"x":[1,2,3]}` { // отказанное busy не дошло
		t.Fatalf("хост получил %+v", m)
	}
	wsjson.Write(ctx, c2, Msg{Type: "off", To: "123456789", Data: json.RawMessage(`"` + strings.Repeat("A", 600) + `"`)})
	closed(t, ctx, c2)
	c3, _ := dial(t, ctx, url)
	c3.Write(ctx, websocket.MessageText, []byte("не json"))
	if _, _, err := c3.Read(ctx); err == nil {
		t.Fatal("не JSON — соединение не закрыто")
	}
	c4, _ := dial(t, ctx, url)
	wsjson.Write(ctx, c4, Msg{Type: "off", To: "123456789", Data: offData})
	if m := read(t, ctx, host); m.Type != "off" {
		t.Fatalf("после мусора хост получил %+v", m)
	}
	wsjson.Write(ctx, c4, Msg{Type: "connect", To: "223456789"})
	read(t, ctx, old) // hello
	if m := read(t, ctx, old); m.Type != "connect" {
		t.Fatalf("старый хост: %+v", m)
	}
	silent(t, ctx, cli, 200*time.Millisecond)   // ни «ok» хаба, ни ответов хоста сверх одного
	silent(t, ctx, third, 200*time.Millisecond) // ответ хоста не тому клиенту не дошёл
}

// TestOffBuckets — своё ведро «снять»: поток мелких ice (общее ведро toHost пусто) off не вытесняет; с одного
// адреса — OffSrcBurst, потом busy, другой адрес проходит; ведро цели (2·OffDst) кончается — busy, хосту не больше.
func TestOffBuckets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	url, host, _ := offHub(t, ctx)
	var offs atomic.Int64
	go func() {
		for {
			var m Msg
			if wsjson.Read(ctx, host, &m) != nil {
				return
			}
			if m.Type == "off" {
				offs.Add(1)
			}
		}
	}()
	ice := json.RawMessage(`"` + strings.Repeat("A", 1900) + `"`)
	for range 3 { // 3 × 60 × 2 КБ > ToHostBurst (256 КБ): общее ведро хоста пусто
		c, _ := dial(t, ctx, url)
		for range 60 {
			wsjson.Write(ctx, c, Msg{Type: "ice", To: "123456789", Data: ice})
		}
	}
	time.Sleep(300 * time.Millisecond)
	try := func(from string) string {
		t.Helper()
		c, _, code := dialFrom(t, ctx, url, from)
		if c == nil {
			t.Fatalf("код %d", code)
		}
		defer c.CloseNow()
		wsjson.Write(ctx, c, Msg{Type: "off", To: "123456789", Data: offData})
		rctx, rc := context.WithTimeout(ctx, 300*time.Millisecond)
		defer rc()
		var m Msg
		if wsjson.Read(rctx, c, &m) != nil {
			return "переслано" // хаб на успех не отвечает: ответит хост
		}
		var r string
		json.Unmarshal(m.Data, &r)
		return r
	}
	for i, want := range []string{"переслано", "переслано", "busy"} {
		if r := try("203.0.113.5"); r != want {
			t.Fatalf("адрес A, %d: %s, ждали %s", i, r, want)
		}
	}
	if r := try("198.51.100.9"); r != "переслано" {
		t.Fatalf("адрес B: %s", r)
	}
	if n := offs.Load(); n != 3 {
		t.Fatalf("хост получил off: %d, ждали 3", n)
	}
	var busy atomic.Int64 // loopback — без доли адреса: только ведро цели
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			c, _ := dial(t, ctx, url)
			defer c.CloseNow()
			for range OffBurst {
				wsjson.Write(ctx, c, Msg{Type: "off", To: "123456789", Data: offData})
			}
			rctx, rc := context.WithTimeout(ctx, 500*time.Millisecond)
			defer rc()
			for {
				var m Msg
				if wsjson.Read(rctx, c, &m) != nil {
					return
				}
				if string(m.Data) == `"busy"` {
					busy.Add(1)
				}
			}
		})
	}
	wg.Wait()
	if n := offs.Load() - 3; busy.Load() == 0 || n > 2*OffDst+OffDst || n+busy.Load() != 20*OffBurst {
		t.Fatalf("ведро цели: переслано %d, busy %d", n, busy.Load())
	}
}
