package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anypc/hub"
	"anypc/site"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func get(t *testing.T, h http.Handler, host, path string) (int, string) {
	t.Helper()
	r := httptest.NewRequest("GET", path, nil)
	r.Host = host
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	b, _ := io.ReadAll(w.Result().Body)
	return w.Code, string(b)
}

func TestRouting(t *testing.T) {
	dl := t.TempDir()
	os.WriteFile(filepath.Join(dl, "AnyPC.exe"), []byte("MZ-test"), 0o644)
	ws := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "WS") })
	h := newMux(ws, []string{"www.example.com", "example.com"}, dl, []string{"t1.example", "t2.example"}, []string{"wss://a.example/ws", "wss://b.example/ws"})

	if _, b := get(t, h, "WWW.example.com:443", "/"); !strings.Contains(b, `id="get"`) {
		t.Error("www → лендинг")
	}
	if _, b := get(t, h, "example.com", "/"); !strings.Contains(b, `id="get"`) {
		t.Error("голый домен (второй в списке -site) → лендинг")
	}
	if c, b := get(t, h, "any.example.com", "/download/AnyPC.exe"); c != 200 || b != "MZ-test" { // зеркало на хабе
		t.Errorf("скачивание с хаба: %d %q", c, b)
	}
	if c, b := get(t, h, "www.example.com", "/hubs"); c != 200 || !strings.Contains(b, "b.example") {
		t.Errorf("/hubs на лендинге: %d %q", c, b)
	}
	if c, b := get(t, h, "www.example.com", "/download/AnyPC.exe"); c != 200 || b != "MZ-test" {
		t.Errorf("скачивание: %d %q", c, b)
	}
	if c, _ := get(t, h, "www.example.com", "/download/../site.go"); c == 200 {
		t.Error("выход за каталог загрузок")
	}
	if c, b := get(t, h, "any.example.com", "/turns"); c != 200 || strings.TrimSpace(b) != `["t1.example","t2.example"]` {
		t.Errorf("/turns: %d %q", c, b)
	}
	if c, b := get(t, h, "any.example.com", "/hubs"); c != 200 || strings.TrimSpace(b) != `["wss://a.example/ws","wss://b.example/ws"]` {
		t.Errorf("/hubs: %d %q", c, b)
	}
	if c, _ := get(t, h, "www.example.com", "/ws"); c != 404 {
		t.Errorf("/ws на лендинге: %d", c)
	}
	if _, b := get(t, h, "any.example.com", "/"); !strings.Contains(b, "Удалённое рабочее место") && !strings.Contains(b, `id="sess"`) {
		t.Error("any → клиент")
	}
	if _, b := get(t, h, "any.example.com", "/ws"); b != "WS" {
		t.Error("any → /ws")
	}
}

// TestHeaders — F2: заголовки безопасности на обоих mux; HSTS только по TLS; полная CSP — только лендингу
// (у клиента она в <meta>, вторая полная политика с другим хешем убила бы страницу).
func TestHeaders(t *testing.T) {
	ws := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "WS") })
	h := newMux(ws, []string{"www.example.com"}, t.TempDir(), nil, nil)
	resp := func(host, path string, tls bool) *http.Response {
		r := httptest.NewRequest("GET", path, nil)
		if tls {
			r = httptest.NewRequest("GET", "https://"+host+path, nil)
		}
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Result()
	}
	for _, c := range []struct{ host, path, csp string }{
		{"www.example.com", "/", site.CSP},
		{"www.example.com", "/privacy.html", site.CSP},
		{"any.example.com", "/", "frame-ancestors 'none'"},
		{"any.example.com", "/pake.wasm", "frame-ancestors 'none'"},
		{"any.example.com", "/ws", "frame-ancestors 'none'"},
	} {
		for _, tls := range []bool{false, true} {
			r := resp(c.host, c.path, tls)
			if r.StatusCode != 200 {
				t.Errorf("%s%s: %d", c.host, c.path, r.StatusCode)
			}
			for k, v := range map[string]string{"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
				"Referrer-Policy": "no-referrer", "Content-Security-Policy": c.csp} {
				if got := r.Header.Get(k); got != v {
					t.Errorf("%s%s: %s = %q, ждали %q", c.host, c.path, k, got, v)
				}
			}
			hsts := r.Header.Get("Strict-Transport-Security")
			if tls && hsts != "max-age=86400" || !tls && hsts != "" {
				t.Errorf("%s%s tls=%v: HSTS %q", c.host, c.path, tls, hsts)
			}
		}
	}
	if !strings.Contains(site.CSP, "script-src 'sha256-") {
		t.Errorf("CSP лендинга без хеша скрипта: %q", site.CSP)
	}
	// nosniff: браузер не угадывает тип — wasm и скрипт клиента обязаны прийти со своим Content-Type
	for path, ct := range map[string]string{"/pake.wasm": "application/wasm", "/wasm_exec.js": "text/javascript; charset=utf-8"} {
		if got := resp("any.example.com", path, true).Header.Get("Content-Type"); got != ct {
			t.Errorf("%s: Content-Type %q, ждали %q", path, got, ct)
		}
	}
}

// TestList — регрессия: повтор в -turn (sed запустили дважды) не даёт дубля в /turns и в выдаче ICE.
func TestList(t *testing.T) {
	if got := strings.Join(list(" a,b,,a , c,b"), "|"); got != "a|b|c" {
		t.Fatalf("list: %q", got)
	}
}

// TestServe — F8: потолок заголовков (431 сверх 16 КБ) и таймауты, которые не рвут WebSocket:
// ReadTimeout/WriteTimeout остались бы дедлайном на захваченном соединении.
func TestServe(t *testing.T) {
	s := serve("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	if s.ReadTimeout != 0 || s.WriteTimeout != 0 || s.ReadHeaderTimeout == 0 || s.IdleTimeout == 0 || s.MaxHeaderBytes != 16<<10 {
		t.Fatalf("serve: %+v", s)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln)
	defer s.Close()
	req := func(n int) int {
		r, _ := http.NewRequest("GET", "http://"+ln.Addr().String()+"/", nil)
		r.Header.Set("X-Pad", strings.Repeat("a", n))
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := req(8 << 10); c != 200 {
		t.Fatalf("заголовки 8 КБ: %d", c)
	}
	if c := req(64 << 10); c != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("заголовки 64 КБ: %d, ждали 431", c)
	}
}

// TestMaxConnsFlag — D5: -maxconns < 0 принимался, и хаб отвечал 503 на всё (cmp.Or подменяет только 0).
// Теперь — ошибка при старте. main запускается в дочернем процессе (тот же тестовый бинарник).
func TestMaxConnsFlag(t *testing.T) {
	if args := os.Getenv("ANYPC_SERVER_ARGS"); args != "" {
		flag.CommandLine = flag.NewFlagSet("server", flag.ExitOnError)
		os.Args = append([]string{"server"}, strings.Fields(args)...)
		main()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMaxConnsFlag$")
	cmd.Env = append(os.Environ(), "ANYPC_SERVER_ARGS=-addr 127.0.0.1:0 -maxconns -1 -certs "+filepath.Join(t.TempDir(), "certs"))
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal("-maxconns -1: сервер запустился (отвечал бы 503 на всё)")
	}
	if err == nil || !strings.Contains(string(out), "-maxconns") {
		t.Fatalf("-maxconns -1: ждали ошибку при старте, получили %v: %s", err, out)
	}
}

// TestMemBudget — потолки из памяти узла (Д1″ приёмки-6): memory.max cgroup (наименьший по пути вверх) важнее ОЗУ,
// иначе 60 % MemTotal; потолок соединений — бюджет / ConnMem в [MinConns, MaxConnsDefault].
func TestMemBudget(t *testing.T) {
	fs := func(m map[string]string) func(string) ([]byte, error) {
		return func(p string) ([]byte, error) {
			if v, ok := m[p]; ok {
				return []byte(v), nil
			}
			return nil, os.ErrNotExist
		}
	}
	meminfo := "MemTotal:        1000000 kB\nMemFree:          500000 kB\n"
	for _, c := range []struct {
		name  string
		files map[string]string
		want  int64
		conns int
	}{
		{"unit с MemoryMax (прод: 60 % от 1 ГБ)", map[string]string{
			"/proc/self/cgroup": "0::/system.slice/anypc.service\n",
			"/sys/fs/cgroup/system.slice/anypc.service/memory.max": "601636864\n",
			"/sys/fs/cgroup/system.slice/memory.max":               "max\n",
			"/proc/meminfo":                                        meminfo}, 601636864, 1958},
		{"предел у предка меньше своего", map[string]string{
			"/proc/self/cgroup": "0::/a/b\n", "/sys/fs/cgroup/a/b/memory.max": "209715200", "/sys/fs/cgroup/a/memory.max": "104857600",
			"/proc/meminfo": meminfo}, 100 << 20, 341},
		{"контейнер с cgroupns", map[string]string{"/proc/self/cgroup": "0::/\n", "/sys/fs/cgroup/memory.max": "31457280"}, 30 << 20, hub.MinConns},
		{"без предела cgroup — 60 % ОЗУ", map[string]string{"/proc/self/cgroup": "0::/user.slice\n", "/sys/fs/cgroup/user.slice/memory.max": "max",
			"/proc/meminfo": meminfo}, 1000000 << 10 * 6 / 10, 2000},
		{"большой узел", map[string]string{"/proc/meminfo": "MemTotal: 16000000 kB\n"}, 16000000 << 10 * 6 / 10, hub.MaxConnsDefault},
		{"ничего не прочитать (не Linux)", map[string]string{}, 0, hub.MinConns},
		{"cgroup v1", map[string]string{"/proc/self/cgroup": "5:cpu,cpuacct:/x\n4:memory:/system.slice/anypc.service\n",
			"/sys/fs/cgroup/memory/system.slice/anypc.service/memory.limit_in_bytes": "601636864\n",
			"/sys/fs/cgroup/memory/system.slice/memory.limit_in_bytes":               "9223372036854771712\n",
			"/proc/meminfo": meminfo}, 601636864, 1958},
		{"предел cgroup больше ОЗУ — 60 % ОЗУ", map[string]string{"/proc/self/cgroup": "0::/a\n", "/sys/fs/cgroup/a/memory.max": "4294967296",
			"/proc/meminfo": meminfo}, 1000000 << 10 * 6 / 10, 2000},
	} {
		got, from := memBudget(fs(c.files))
		if got != c.want || hub.ConnsFor(got) != c.conns {
			t.Errorf("%s: бюджет %d (%s), соединений %d; ждали %d и %d", c.name, got, from, hub.ConnsFor(got), c.want, c.conns)
		}
	}
	if line := memLine(601636864, "x/memory.max", 1<<63-1, 1958, 2214); !strings.Contains(line, "бюджет 573 МиБ (x/memory.max)") ||
		!strings.Contains(line, "предел Go нет") || !strings.Contains(line, "сигнализации 1958, TCP 2214") {
		t.Errorf("журнал: %s", line)
	}
	if line := memLine(0, "не определена", 1<<63-1, hub.MinConns, 456); !strings.Contains(line, "бюджет неизвестен") {
		t.Errorf("журнал вне Linux: %s", line)
	}
	// plan: явный -maxconns важнее; предел Go — GoLimitPct бюджета, GOMEMLIMIT важнее
	if p := plan(0, 601636864, ""); p.conns != 1958 || p.tcp != 2214 || p.goLimit != 601636864*GoLimitPct/100 {
		t.Errorf("plan из памяти: %+v", p)
	}
	if p := plan(100, 601636864, "300MiB"); p.conns != 100 || p.tcp != 100+HTTPConns || p.goLimit != 0 {
		t.Errorf("plan с -maxconns и GOMEMLIMIT: %+v", p)
	}
}

// TestMainHelper — не тест: процесс-помощник TestMainWiring запускает в нём настоящий main.
func TestMainHelper(t *testing.T) {
	if os.Getenv("ANYPC_MAIN_HELPER") == "" {
		t.Skip("помощник TestMainWiring")
	}
	os.Args = append([]string{"anypc-server"}, strings.Fields(os.Getenv("ANYPC_MAIN_HELPER"))...)
	go func() { io.Copy(io.Discard, os.Stdin); os.Exit(0) }() // родитель умер (таймаут go test, Ctrl+C) — stdin закрыт, выйти: иначе сервер жил часами
	main()
}

// TestMainWiring — проводка main (мутации приёмки-7 З5): журнал при старте пишет, что действует на деле —
// предел Go из рантайма, потолок из хаба, лимит TCP из слушателя; без -maxconns — из памяти узла, с ним — он.
func TestMainWiring(t *testing.T) {
	budget, from := memBudget(os.ReadFile)
	for _, c := range []struct {
		args string
		want limits
	}{
		{"", plan(0, budget, "")},
		{"-maxconns 300", plan(300, budget, "")},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMainHelper$")
		cmd.Env = append(os.Environ(), "ANYPC_MAIN_HELPER=-addr 127.0.0.1:0 -certs "+t.TempDir()+"/c "+c.args, "GOMEMLIMIT=")
		out, _ := cmd.StderrPipe()
		stdin, _ := cmd.StdinPipe() // держим открытым: закрытие — сигнал помощнику выйти
		if err := cmd.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		t.Cleanup(func() { stdin.Close(); cancel(); cmd.Wait() }) // и при t.Fatal/панике помощник не остаётся
		buf := make([]byte, 4096)
		n, _ := io.ReadAtLeast(out, buf, 1)
		time.Sleep(200 * time.Millisecond)
		cmd.Process.Kill()
		rest, _ := io.ReadAll(out)
		m := copy(buf[n:], rest)
		goLimit := c.want.goLimit
		if goLimit == 0 {
			goLimit = 1<<63 - 1
		}
		if want := memLine(budget, from, goLimit, c.want.conns, c.want.tcp); !strings.Contains(string(buf[:n+m]), want) {
			t.Errorf("%q: журнал\n%s\nждали\n%s", c.args, buf[:n+m], want)
		}
	}
}

// TestServeTimeouts — сроки сервера: IdleTimeout 10 с (простаивающее keep-alive держит место под лимитом TCP).
func TestServeTimeouts(t *testing.T) {
	if s := serve("", nil); s.IdleTimeout != 10*time.Second || s.ReadHeaderTimeout != 10*time.Second {
		t.Fatalf("IdleTimeout %v, ReadHeaderTimeout %v", s.IdleTimeout, s.ReadHeaderTimeout)
	}
}

// TestListenLimit — общий лимит TCP (Д1″ приёмки-6): простаивающее keep-alive занимает место, следующее соединение
// ждёт, пока оно не освободится.
func TestListenLimit(t *testing.T) {
	l := listen("127.0.0.1:0", 1, TCPPerAddr)
	srv := serve("", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	go srv.Serve(l)
	defer srv.Close()
	url := "http://" + l.Addr().String() + "/"
	idle := &http.Client{Transport: &http.Transport{}} // держит keep-alive
	if r, err := idle.Get(url); err != nil {
		t.Fatal(err)
	} else {
		io.ReadAll(r.Body)
		r.Body.Close()
	}
	other := &http.Client{Transport: &http.Transport{}, Timeout: 500 * time.Millisecond}
	if _, err := other.Get(url); err == nil {
		t.Fatal("второе соединение принято сверх лимита 1")
	}
	idle.CloseIdleConnections()
	other.Timeout = 5 * time.Second
	if r, err := other.Get(url); err != nil {
		t.Fatalf("после освобождения места: %v", err)
	} else {
		r.Body.Close()
	}
}

// TestIdleTimeoutKeepsWS — IdleTimeout сервера (10 с) не рвёт захваченный WS: срок ожидания keep-alive заменяется
// при начале запроса и снимается после заголовков.
func TestIdleTimeoutKeepsWS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	l := listen("127.0.0.1:0", 10, TCPPerAddr)
	srv := serve("", &hub.Hub{})
	srv.IdleTimeout = 200 * time.Millisecond
	go srv.Serve(l)
	defer srv.Close()
	c, _, err := websocket.Dial(ctx, "ws://"+l.Addr().String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	var m hub.Msg
	if err := wsjson.Read(ctx, c, &m); err != nil || m.Type != "hello" {
		t.Fatalf("hello: %v %+v", err, m)
	}
	time.Sleep(time.Second) // 5 × IdleTimeout
	wsjson.Write(ctx, c, hub.Msg{Type: "ice", To: "123456789"})
	if err := wsjson.Read(ctx, c, &m); err != nil || string(m.Data) != `"not_found"` {
		t.Fatalf("WS после IdleTimeout: %v %+v", err, m)
	}
}

// TestMainHelperExits — помощник выходит сам, когда закрыт stdin (умер родитель): раньше прерванный прогон оставлял
// настоящий сервер на 127.0.0.1 работать часами.
func TestMainHelperExits(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainHelper$")
	cmd.Env = append(os.Environ(), "ANYPC_MAIN_HELPER=-addr 127.0.0.1:0 -certs "+t.TempDir()+"/c", "GOMEMLIMIT=")
	stdin, _ := cmd.StdinPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	stdin.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		t.Fatal("помощник не вышел после закрытия stdin")
	}
}

type counter map[string]int

func (c counter) Count(k string, n int)                            { c[k] += n }
func (c counter) ServeHTTP(w http.ResponseWriter, _ *http.Request) {}

// TestMuxCounts — суточная сводка: открытия лендинга и клиента, загрузки только существующих файлов.
func TestMuxCounts(t *testing.T) {
	dl := t.TempDir()
	os.WriteFile(filepath.Join(dl, "AnyPC.exe"), []byte("MZ-test"), 0o644)
	c := counter{}
	h := newMux(c, []string{"www.example.com"}, dl, nil, nil)
	get(t, h, "www.example.com", "/")
	get(t, h, "www.example.com", "/site.css")
	get(t, h, "hk.example.com", "/")
	get(t, h, "hk.example.com", "/download/AnyPC.exe")
	get(t, h, "hk.example.com", "/download/wp-login.php") // сканер: имени нет в каталоге
	get(t, h, "hk.example.com", "/download/")
	if fmt.Sprint(c) != "map[dl/AnyPC.exe:1 page_app:1 page_www:1]" {
		t.Fatalf("счётчики: %v", c)
	}
}
