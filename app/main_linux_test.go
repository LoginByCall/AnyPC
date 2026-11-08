package main

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http/httptest"
	"os"
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
	h := handler("127.0.0.1:5000", "tok123", page, cfg, &agent.Agent{}, nil, func() map[string]any { return map[string]any{"id": cfg.ID} }, newFiles(t.TempDir()))
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

// TestPageLink: браузер открывается ссылкой на файл 0600 — токена нет в аргументах (/proc/*/cmdline).
func TestPageLink(t *testing.T) {
	dir := t.TempDir()
	url := "http://127.0.0.1:5000/?t=tok123"
	link, p, err := pageLink(filepath.Join(dir, "AnyPC Cfg"), url)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(link, "tok123") || !strings.HasPrefix(link, "file:///") || !strings.Contains(link, "AnyPC%20Cfg") {
		t.Errorf("аргумент для браузера: %q", link)
	}
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("права файла: %v %v", st.Mode(), err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), `content="0;url=`+url+`"`) || !strings.Contains(string(b), `location.replace("`+url+`")`) {
		t.Errorf("переадресация: %s", b)
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
