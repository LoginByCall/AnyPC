package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"anypc/agent"
)

func TestNormNode(t *testing.T) {
	for in, want := range map[string]string{
		"":                            "",
		"  my.example.com ":           "my.example.com",
		"https://My.Example.com/ws":   "my.example.com",
		"wss://node.example.org:8443": "node.example.org:8443",
	} {
		if got, err := normNode(in); err != nil || got != want {
			t.Errorf("%q → %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"localhost", "a b.com", "evil.com\"<", "-x.com", "x.com:", "x.com:123456", "x..com"} {
		if got, err := normNode(bad); err == nil {
			t.Errorf("%q принят как %q", bad, got)
		}
	}
}

func TestNodeServer(t *testing.T) {
	cases := []struct {
		node   string
		public bool
		server string
	}{
		{"", false, DefaultServer}, // пусто — только AnyPC, галочка не важна
		{"my.example.com", false, "wss://my.example.com/ws"},
		{"my.example.com", true, "wss://my.example.com/ws," + DefaultServer},
	}
	for _, c := range cases {
		if s := nodeServer(c.node, c.public); s != c.server {
			t.Errorf("nodeServer(%q,%v) = %q", c.node, c.public, s)
		}
		n, pub := nodeOf(c.server)
		if n != c.node || pub != (c.public || c.node == "") {
			t.Errorf("nodeOf(%q) = %q,%v", c.server, n, pub)
		}
	}
}

func TestCheckNode(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok/hubs", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`[]`)) })
	mux.HandleFunc("/html/hubs", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`<html>`)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if err := checkNode(srv.URL + "/ok"); err != nil {
		t.Fatal("узел не принят:", err)
	}
	for _, p := range []string{"/html", "/none"} { // чужой сайт, 404
		if checkNode(srv.URL+p) == nil {
			t.Error(p, "принят как узел")
		}
	}
}

// TestSpaceAllowOffDrops — выключение permanent-профиля закрывает активные и pending-входы, включение pending не трогает.
func TestSpaceAllowOffDrops(t *testing.T) {
	cfg, _ := loadConfig(filepath.Join(t.TempDir(), "c.json"))
	a := &agent.Agent{}
	oldRevoked, oldPending := dropRevoked, dropPending
	defer func() { dropRevoked, dropPending = oldRevoked, oldPending }()
	revoked, pending := 0, 0
	dropRevoked = func(*agent.Agent) { revoked++ }
	dropPending = func(*agent.Agent) { pending++ }
	if err := setSpaceAllow(cfg, a, true); err != nil || revoked != 1 || pending != 0 {
		t.Fatalf("включение: err=%v revoked=%d pending=%d", err, revoked, pending)
	}
	if err := setSpaceAllow(cfg, a, false); err != nil || revoked != 2 || pending != 1 {
		t.Fatalf("выключение: err=%v revoked=%d pending=%d", err, revoked, pending)
	}
}

// TestNetworkAllowControl — Allow control выключает и сигнализацию, и фоновую сверку пространства; Allow space сеть не включает.
func TestNetworkAllowControl(t *testing.T) {
	cfg, _ := loadConfig(filepath.Join(t.TempDir(), "c.json"))
	cfg.Server = syncHub(t)
	if err := cfg.setSpaceAllow(true); err != nil {
		t.Fatal(err)
	}
	a := &agent.Agent{ID: cfg.ID, Key: cfg.key(), Secret: cfg.secret, OneTimeSecret: cfg.oneTimeSecret, CodeUsed: cfg.codeUsed}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &runner{a: a, ctx: ctx}
	var spaceCancel context.CancelFunc
	cfg.networkSync = func() { syncNetwork(ctx, cfg, a, r, &spaceCancel) }
	syncNetwork(ctx, cfg, a, r, &spaceCancel)
	if r.done != nil || spaceCancel != nil {
		t.Fatal("сеть запущена при выключенном Allow control")
	}
	if _, err := cfg.setGive(true); err != nil {
		t.Fatal(err)
	}
	if r.done == nil || spaceCancel == nil {
		t.Fatal("сеть не запущена при включении Allow control")
	}
	if _, err := cfg.setGive(false); err != nil {
		t.Fatal(err)
	}
	if r.done != nil || spaceCancel != nil {
		t.Fatal("сеть не остановлена при выключении Allow control")
	}
}

// Смена узла: старый Run остановлен до старта нового; неверный адрес ничего не меняет.
func TestRunnerRestart(t *testing.T) {
	cfg, err := loadConfig(filepath.Join(t.TempDir(), "c.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &runner{a: &agent.Agent{ID: cfg.ID, Key: cfg.key(), Secret: cfg.secret}, ctx: ctx}
	r.start("ws://127.0.0.1:1/ws") // никуда не подключится — крутит повторы
	first := r.done
	r.start("ws://127.0.0.1:2/ws") // не боевые хабы: тест не должен регистрироваться на них
	select {
	case <-first:
	default:
		t.Fatal("прежний Run не остановлен")
	}
	if r.a.Server != "ws://127.0.0.1:2/ws" {
		t.Fatal("сервер:", r.a.Server)
	}
	if _, err := setNode(cfg, r, "bad host", true); err == nil || cfg.Server != DefaultServer || r.a.Server != "ws://127.0.0.1:2/ws" {
		t.Fatal("неверный адрес принят или настройка изменена:", err, cfg.Server)
	}
	cancel()
	done := make(chan struct{})
	go func() { r.wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("wait не вернулся")
	}
}
