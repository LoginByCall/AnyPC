package hub

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func (h *Hub) day() Day {
	h.st.mu.Lock()
	defer h.st.mu.Unlock()
	d := h.st.d
	d.N, d.OS = map[string]int{}, map[string]int{}
	for k, v := range h.st.d.N {
		d.N[k] = v
	}
	for k, v := range h.st.d.OS {
		d.OS[k] = v
	}
	return d
}

// TestStats — суточная сводка: разные хосты по «ОС версия» (повторный вход того же ID — один), окна и браузеры, события.
func TestStats(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h := &Hub{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	_, k1, _ := ed25519.GenerateKey(nil)
	_, k2, _ := ed25519.GenerateKey(nil)

	h1, m := dialHostQ(t, ctx, url, "123456789", k1, true, "&os=linux&v=v0.1.23")
	if m.Type != "hello" {
		t.Fatalf("регистрация: %+v", m)
	}
	h1.Close(websocket.StatusNormalClosure, "")
	for h.get("123456789") != nil { // хаб ещё не увидел закрытия — повторный вход был бы id_taken
		time.Sleep(5 * time.Millisecond)
	}
	h1, _ = dialHostQ(t, ctx, url, "123456789", k1, true, "&os=linux&v=v0.1.23") // тот же хост снова — не второй
	dialHost(t, ctx, url, "234567891", k2, true)                                 // старая программа: без ?os=&v=

	cli, _ := dial(t, ctx, url+"?c=web")
	dial(t, ctx, url)
	wsjson.Write(ctx, cli, Msg{Type: "connect", To: "123456789"})
	read(t, ctx, h1) // свежий hello
	if m := read(t, ctx, h1); m.Type != "connect" {
		t.Fatalf("connect: %+v", m)
	}
	wsjson.Write(ctx, cli, Msg{Type: "connect", To: "999999999"})
	read(t, ctx, cli)

	d := h.day()
	if d.Hosts != 2 || d.HostsMax != 2 || d.ClientsMax != 2 {
		t.Fatalf("хосты/максимумы: %+v", d)
	}
	if fmt.Sprint(d.OS) != "map[? ?:1 linux v0.1.23:1]" {
		t.Fatalf("ОС: %v", d.OS)
	}
	for k, want := range map[string]int{"new_id": 2, "client_web": 1, "client_?": 1, "connect": 1, "not_found": 1} {
		if d.N[k] != want {
			t.Fatalf("%s=%d, ждали %d: %v", k, d.N[k], want, d.N)
		}
	}
	if b, _ := json.Marshal(d); strings.Contains(string(b), "123456789") {
		t.Fatalf("ID в сводке: %s", b)
	}
}

// TestStatsRoll — смена суток: прошлые — в очередь записи, множество хостов и соль новые; потолок ключей.
func TestStatsRoll(t *testing.T) {
	h := &Hub{}
	d1 := time.Date(2026, 11, 12, 23, 59, 0, 0, time.UTC)
	h.st.roll(d1)
	salt := h.st.salt
	h.online(true, "123456789", "windows v1", 1)
	h.st.roll(d1.Add(2 * time.Minute))
	if len(h.st.done) != 1 || h.st.done[0].Day != "2026-11-12" || h.st.done[0].Hosts != 1 {
		t.Fatalf("прошлые сутки: %+v", h.st.done)
	}
	if h.st.salt == salt || h.st.d.HostsMax != 1 { // хост в сети и в новых сутках — максимум с него
		t.Fatalf("новые сутки: %+v", h.st.d)
	}
	// ponytail: online/Count берут time.Now — смена суток здесь вручную, сам хост «входит» в новых сутках
	h.st.d.Day = time.Now().UTC().Format(time.DateOnly)
	h.online(true, "123456789", "windows v1", 1)
	if h.st.d.Hosts != 1 {
		t.Fatalf("тот же хост в новых сутках не посчитан: %+v", h.st.d)
	}
	for i := range 2 * MaxKeys {
		h.Count(fmt.Sprint("dl/f", i), 1)
	}
	if n := len(h.st.d.N); n > MaxKeys+1 || h.st.d.N["other"] == 0 {
		t.Fatalf("ключей %d, other=%d", n, h.st.d.N["other"])
	}
	for in, want := range map[[2]string]string{{"darwin", "v0.1.23"}: "darwin v0.1.23", {"", ""}: "? ?", {"Linux", "v1 x"}: "? ?", {"linux", strings.Repeat("9", 25)}: "linux ?"} {
		if got := osVer(in[0], in[1]); got != want {
			t.Fatalf("osVer%v = %q, ждали %q", in, got, want)
		}
	}
}

// TestStatsLoop — файлы: недописанные прошлые сутки → stats.jsonl; сегодняшние после перезапуска — продолжаются.
func TestStatsLoop(t *testing.T) {
	dir := t.TempDir()
	today := time.Now().UTC().Format(time.DateOnly)
	b, _ := json.Marshal(Day{Day: "2026-01-01", Hosts: 7, N: map[string]int{"connect": 3}, OS: map[string]int{}})
	os.WriteFile(filepath.Join(dir, "stats-today.json"), b, 0o600)
	run := func(h *Hub) Day {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan bool)
		go func() { h.StatsLoop(ctx, dir, 5*time.Millisecond); done <- true }()
		time.Sleep(30 * time.Millisecond)
		cancel()
		<-done
		var d Day
		b, _ := os.ReadFile(filepath.Join(dir, "stats-today.json"))
		json.Unmarshal(b, &d)
		return d
	}
	h := &Hub{}
	h.Count("connect", 2)
	if d := run(h); d.Day != today || d.N["connect"] != 2 || d.Restarted {
		t.Fatalf("сегодня: %+v", d)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "stats.jsonl")); !strings.HasPrefix(string(b), `{"day":"2026-01-01","hosts":7,`) || strings.Count(string(b), "\n") != 1 {
		t.Fatalf("stats.jsonl: %s", b)
	}
	h = &Hub{} // перезапуск узла в те же сутки
	h.Count("connect", 1)
	if d := run(h); d.N["connect"] != 3 || !d.Restarted {
		t.Fatalf("после перезапуска: %+v", d)
	}
}
