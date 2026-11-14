//go:build linux || darwin

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"anypc/agent"
)

// TestUIStateAPI: /api/uiGet и /api/uiSet — под X-Token, неизвестный ключ — 400; страница несёт настройки окна
// отдельным скриптом с хэшем в CSP, и имя ПК «</script>» из него не выходит.
func TestUIStateAPI(t *testing.T) {
	cfg, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	page, _ := shimmed("wss://example/ws", "tok123")
	h := handler("127.0.0.1:5000", "tok123", page, cfg, &agent.Agent{}, nil, nil, newFiles(t.TempDir()), nil)
	call := func(name, token, args string) (int, string) {
		r := httptest.NewRequest("POST", "/api/"+name, strings.NewReader(args))
		r.Host = "127.0.0.1:5000"
		r.Header.Set("X-Token", token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code, strings.TrimSpace(w.Body.String())
	}
	mine := `[{"id":"123456789","name":"</script><script>alert(1)</script>"}]`
	arg, _ := json.Marshal([]string{"mine", mine})
	if c, _ := call("uiSet", "wrong", string(arg)); c != 403 || len(cfg.uiGet()) != 0 {
		t.Errorf("чужой токен: %d", c)
	}
	if c, _ := call("uiGet", "", `[]`); c != 403 {
		t.Errorf("без токена: %d", c)
	}
	if c, b := call("uiGet", "tok123", `[]`); c != 200 || b != `{"result":{}}` {
		t.Errorf("пустые: %d %s", c, b)
	}
	if c, b := call("uiSet", "tok123", string(arg)); c != 200 {
		t.Fatalf("uiSet: %d %s", c, b)
	}
	if c, b := call("uiSet", "tok123", `["pass","{}"]`); c != 400 || !strings.Contains(b, "error") {
		t.Errorf("неизвестный ключ: %d %s", c, b)
	}
	if c, _ := call("uiSet", "tok123", `["stats","tru"]`); c != 400 {
		t.Errorf("не JSON: %d", c)
	}
	var got struct{ Result map[string]string }
	if c, b := call("uiGet", "tok123", `[]`); c != 200 || json.Unmarshal([]byte(b), &got) != nil || got.Result["mine"] != mine {
		t.Errorf("uiGet: %d %s", c, b)
	}
	r := httptest.NewRequest("GET", "/?t=tok123", nil)
	r.Host = "127.0.0.1:5000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	s := w.Body.String()
	i := strings.Index(s, "<script>window.ANYPC_UI = ")
	if i < 0 || i > strings.Index(s, "const T = ") {
		t.Fatal("настроек окна нет до привязок и основного скрипта")
	}
	j := strings.Index(s[i:], "</script>") + i
	js := s[i+len("<script>") : j]
	if esc := `\u00` + `3c/script`; strings.Contains(js, "<") || !strings.Contains(js, esc) {
		t.Errorf("имя ПК вышло из скрипта: %s", js)
	}
	sum := sha256.Sum256([]byte(js))
	if !strings.Contains(s, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
		t.Error("хэша скрипта настроек нет в CSP — браузер его не выполнит")
	}
}
