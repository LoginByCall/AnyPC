package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"anypc/site"
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
