package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

// TestList — регрессия: повтор в -turn (sed запустили дважды) не даёт дубля в /turns и в выдаче ICE.
func TestList(t *testing.T) {
	if got := strings.Join(list(" a,b,,a , c,b"), "|"); got != "a|b|c" {
		t.Fatalf("list: %q", got)
	}
}
