package main

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"anypc/agent"
)

func TestLocalAPI(t *testing.T) {
	cfg, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	page, err := shimmed("wss://example/ws", "tok123")
	if err != nil || !strings.Contains(string(page), `const T = "tok123"`) || strings.Count(string(page), "<script>") < 2 {
		t.Fatalf("страница без привязок: %v", err)
	}
	h := handler("127.0.0.1:5000", "tok123", page, cfg, &agent.Agent{}, nil, func() map[string]any { return map[string]any{"id": cfg.ID} }, newFiles(t.TempDir()), nil)
	do := func(method, host, path, token string) (int, string) {
		r := httptest.NewRequest(method, path, strings.NewReader("[]"))
		r.Host = host
		if token != "" {
			r.Header.Set("X-Token", token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		b, _ := io.ReadAll(w.Result().Body)
		return w.Code, string(b)
	}
	for _, c := range []struct{ method, host, path, token string }{
		{"POST", "127.0.0.1:5000", "/api/hostInfo", ""},          // без токена
		{"POST", "127.0.0.1:5000", "/api/hostInfo", "wrong"},     // чужой токен
		{"POST", "evil.example:5000", "/api/hostInfo", "tok123"}, // DNS rebinding
		{"GET", "127.0.0.1:5000", "/api/hostInfo", "tok123"},     // не POST
		{"GET", "127.0.0.1:5000", "/", ""},                       // страница без ?t=
	} {
		if code, _ := do(c.method, c.host, c.path, c.token); code != 403 {
			t.Errorf("%+v → %d, ждали 403", c, code)
		}
	}
	if code, body := do("POST", "127.0.0.1:5000", "/api/hostInfo", "tok123"); code != 200 || !strings.Contains(body, cfg.ID) {
		t.Errorf("hostInfo: %d %s", code, body)
	}
	if code, body := do("POST", "127.0.0.1:5000", "/api/setPassword", "tok123"); code != 400 || !strings.Contains(body, "error") {
		t.Errorf("пустой пароль принят: %d %s", code, body)
	}
	if code, body := do("GET", "127.0.0.1:5000", "/?t=tok123", ""); code != 200 || !strings.Contains(body, "pakeRespond") {
		t.Errorf("страница: %d", code)
	}
}

// TestOnceCode: браузер открывается одноразовым кодом (токена нет в аргументах, /proc/*/cmdline): первый заход —
// переадресация на страницу с токеном, повторный и чужой код — отказ.
func TestOnceCode(t *testing.T) {
	cfg, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	once := &onceCode{code: "abc123"}
	h := handler("127.0.0.1:5000", "tok123", []byte("page"), cfg, &agent.Agent{}, nil, nil, newFiles(t.TempDir()), once)
	get := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = "127.0.0.1:5000"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := get("/?n=wrong"); w.Code != 403 {
		t.Errorf("чужой код: %d", w.Code)
	}
	if w := get("/?n=abc123"); w.Code != 303 || w.Header().Get("Location") != "/?t=tok123" {
		t.Errorf("первый заход: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := get("/?n=abc123"); w.Code != 403 {
		t.Errorf("повторный заход: %d", w.Code)
	}
}

// TestShimCSP: скрипт привязок (с токеном) разрешён в CSP страницы своим хэшем.
func TestShimCSP(t *testing.T) {
	page, err := shimmed("wss://example/ws", "tok123")
	if err != nil {
		t.Fatal(err)
	}
	s := string(page)
	i, j := strings.Index(s, "<script>"), strings.Index(s, "</script>")
	if !strings.Contains(s[i:j], "tok123") {
		t.Fatal("первый скрипт — не привязки")
	}
	sum := sha256.Sum256([]byte(s[i+len("<script>") : j]))
	if !strings.Contains(s, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
		t.Error("хэша скрипта привязок нет в CSP — браузер его не выполнит")
	}
}

// TestCLI — ключи командной строки: --version печатает версию из -ldflags, --id — ID из настроек, --help — список ключей;
// ни один не запускает хост.
func TestCLI(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "anypc")
	if out, err := exec.Command("go", "build", "-ldflags=-X main.version=v9.9.9", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("сборка: %v\n%s", err, out)
	}
	home := t.TempDir() // свои ~/.config и ~/.cache: не трогать настройки разработчика
	run := func(arg string) string {
		c := exec.Command(bin, arg)
		c.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+home+"/.config", "XDG_CACHE_HOME="+home+"/.cache")
		out, _ := c.CombinedOutput()
		return string(out)
	}
	if out := run("--version"); out != "AnyPC v9.9.9\n" {
		t.Errorf("--version: %q", out)
	}
	if out := strings.TrimSpace(run("--id")); len(out) != 9 || strings.Trim(out, "0123456789") != "" {
		t.Errorf("--id: %q", out)
	}
	if out := run("--help"); !strings.Contains(out, "-no-browser") || !strings.Contains(out, "-version") || !strings.Contains(out, "v9.9.9") {
		t.Errorf("--help: %q", out)
	}
}
