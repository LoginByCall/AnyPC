package agent

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestHubQuery — хост сообщает хабу ОС и версию (суточная сводка, hub/stats.go); без Version — как раньше.
func TestHubQuery(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.URL.RawQuery
		http.Error(w, "no", http.StatusBadRequest)
	}))
	defer srv.Close()
	_, key, _ := ed25519.GenerateKey(nil)
	for v, want := range map[string]string{"v0.1.23": "&os=" + runtime.GOOS + "&v=v0.1.23", "": ""} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		(&Agent{ID: "123456789", Key: key, Version: v}).run(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"))
		cancel()
		q := <-got
		if !strings.HasPrefix(q, "host=123456789&key=") || !strings.HasSuffix(q, want) || (want == "" && strings.Contains(q, "os=")) {
			t.Fatalf("Version %q: запрос %q", v, q)
		}
	}
}
