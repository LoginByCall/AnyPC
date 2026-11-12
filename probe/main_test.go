package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"anypc/hub"

	"github.com/pion/turn/v5"
)

// TestNext — сбой подтверждается вторым запуском подряд, восстановление — сразу, «проба жива» — раз в сутки после 9:00.
func TestNext(t *testing.T) {
	at := func(h int) time.Time { return time.Date(2026, 11, 12, h, 0, 0, 0, time.Local) }
	var s State
	msg, s := s.Next(map[string]string{"hk.anypc.org": "таймаут"}, at(8))
	if msg != "" || len(s.Bad) != 0 {
		t.Fatalf("одиночный сбой будит: %q %+v", msg, s)
	}
	msg, s = s.Next(map[string]string{"hk.anypc.org": "таймаут"}, at(8))
	if !strings.Contains(msg, "сбой\nhk.anypc.org: таймаут") || len(s.Bad) != 1 {
		t.Fatalf("подтверждённый сбой: %q %+v", msg, s)
	}
	if msg, s = s.Next(map[string]string{"hk.anypc.org": "таймаут"}, at(8)); msg != "" {
		t.Fatalf("повтор того же сбоя: %q", msg)
	}
	msg, s = s.Next(nil, at(10)) // восстановление и первый запуск после 9:00 — одно сообщение, без «жива»
	if msg != "✅ AnyPC · восстановлено: hk.anypc.org" || s.Alive != "2026-11-12" {
		t.Fatalf("восстановление: %q %+v", msg, s)
	}
	if msg, _ = s.Next(nil, at(11)); msg != "" {
		t.Fatalf("второе «жива» за сутки: %q", msg)
	}
	if msg, _ = s.Next(nil, at(11).Add(24*time.Hour)); !strings.Contains(msg, "проба жива, сбоев сейчас: 0") {
		t.Fatalf("сводка «жива»: %q", msg)
	}
	if e := sameVersion(map[string]string{"hk": "v1", "ru": "v1"}); e != "" {
		t.Fatal(e)
	}
	if e := sameVersion(map[string]string{"ru": "v1", "hk": "v2"}); e != "разные версии: hk v2, ru v1" {
		t.Fatal(e)
	}
}

// TestCheckHub — настоящий хаб по TLS: VERSION и hello с ICE; без VERSION и без сигнализации — сбой.
func TestCheckHub(t *testing.T) {
	ctx := context.Background()
	m := http.NewServeMux()
	m.Handle("/ws", &hub.Hub{TurnHosts: []string{"t.example"}})
	m.HandleFunc("/download/VERSION", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "v0.1.23\n") })
	srv := httptest.NewTLSServer(m)
	defer srv.Close()
	if v, err := checkHub(ctx, srv.Client(), srv.URL); v != "v0.1.23" || err != nil {
		t.Fatalf("хаб: %q %v", v, err)
	}
	bare := httptest.NewTLSServer(http.NotFoundHandler())
	defer bare.Close()
	if _, err := checkHub(ctx, bare.Client(), bare.URL); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("без VERSION: %v", err)
	}
	m2 := http.NewServeMux()
	m2.HandleFunc("/download/VERSION", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "v1") })
	nows := httptest.NewTLSServer(m2)
	defer nows.Close()
	if _, err := checkHub(ctx, nows.Client(), nows.URL); err == nil || !strings.Contains(err.Error(), "сигнализация") {
		t.Fatalf("без сигнализации: %v", err)
	}
	if err := checkSite(ctx, bare.Client(), bare.URL); err == nil {
		t.Fatal("лендинг 404 — не сбой")
	}
}

// TestCheckTURN — выделение адреса на TURN с учёткой REST, как у coturn (use-auth-secret); чужой секрет — сбой.
func TestCheckTURN(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s, err := turn.NewServer(turn.ServerConfig{
		Realm:       "anypc",
		AuthHandler: turn.LongTermTURNRESTAuthHandler("sec", nil),
		PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := checkTURN(ctx, pc.LocalAddr().String(), "sec"); err != nil {
		t.Fatalf("TURN: %v", err)
	}
	if err := checkTURN(ctx, pc.LocalAddr().String(), "чужой"); err == nil {
		t.Fatal("чужой секрет прошёл")
	}
}
