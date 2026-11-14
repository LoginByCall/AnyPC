package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anypc/agent"
	"anypc/hub"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// Вторая копия в том же каталоге настроек — отказ (errRunning), в другом — своя блокировка; после выхода первой — снова можно.
func TestLockInstance(t *testing.T) {
	dir, other := filepath.Join(t.TempDir(), "AnyPC"), t.TempDir() // dir ещё нет — lockInstance создаёт
	unlock, err := lockInstance(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockInstance(dir); !errors.Is(err, errRunning) {
		t.Fatalf("вторая копия в том же каталоге: %v, нужен errRunning", err)
	}
	u2, err := lockInstance(other)
	if err != nil {
		t.Fatalf("другой пользователь (каталог): %v", err)
	}
	u2()
	unlock()
	u3, err := lockInstance(dir)
	if err != nil {
		t.Fatalf("после выхода первой: %v", err)
	}
	u3()
}

// singleInstance: занято — running, окно первой показано (не открылось — уведомление); блокировку не взять
// (каталог не создаётся) — запуск с записью в журнал, а не падение.
func TestSingleInstance(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	noticed := 0
	old := alreadyNotice
	alreadyNotice = func() { noticed++ }
	t.Cleanup(func() { alreadyNotice = old })

	dir := t.TempDir()
	unlock, running := singleInstance(dir, nil)
	if running {
		t.Fatal("первая копия: running")
	}
	defer unlock()
	shown := false
	if u, running := singleInstance(dir, func() error { shown = true; return errors.New("нет окна") }); !running || u != nil || !shown {
		t.Fatalf("вторая копия: running=%v shown=%v", running, shown)
	}
	if s := buf.String(); !strings.Contains(s, "AnyPC уже запущен") || !strings.Contains(s, "нет окна") {
		t.Fatalf("журнал второй копии: %q", s)
	}
	if noticed != 1 {
		t.Fatalf("окно первой не открылось — пользователю не сказано (уведомлений %d)", noticed)
	}
	if _, running := singleInstance(dir, func() error { return nil }); !running || noticed != 1 {
		t.Fatalf("окно открылось — лишнее уведомление: running=%v уведомлений %d", running, noticed)
	}

	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, nil, 0o600)
	buf.Reset()
	u, running := singleInstance(filepath.Join(file, "AnyPC"), func() error { t.Fatal("show без второй копии"); return nil })
	if running || u == nil {
		t.Fatalf("каталог не создаётся: running=%v unlock=%v — нужно запускаться", running, u != nil)
	}
	u()
	if !strings.Contains(buf.String(), "проверка второй копии не удалась") {
		t.Fatalf("журнал: %q", buf.String())
	}
}

// hostInfo отдаёт окну idTaken (agent.IDTaken): до отказа — false, хаб ответил id_taken — true.
func TestHostInfoIDTaken(t *testing.T) {
	cfg, err := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		nonce, _ := json.Marshal("n")
		wsjson.Write(r.Context(), c, hub.Msg{V: 1, Type: "challenge", Data: nonce})
		var reg hub.Msg
		wsjson.Read(r.Context(), c, &reg)
		wsjson.Write(r.Context(), c, hub.Msg{V: 1, Type: "error", Data: json.RawMessage(`"id_taken"`)})
		<-r.Context().Done()
	}))
	defer srv.Close()
	a := &agent.Agent{Server: "ws" + strings.TrimPrefix(srv.URL, "http"), ID: cfg.ID, Key: cfg.key()}
	if v, ok := hostInfo(cfg, a, false, "", "")["idTaken"]; !ok || v != false {
		t.Fatalf("до id_taken: idTaken=%v (есть: %v)", v, ok)
	}
	state := make(chan struct{}, 4)
	a.OnState = func(bool, string) { state <- struct{}{} }
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go a.Run(ctx)
	select {
	case <-state:
	case <-ctx.Done():
		t.Fatal("состояние не пришло")
	}
	if v := hostInfo(cfg, a, false, "", "")["idTaken"]; v != true {
		t.Fatalf("после id_taken: idTaken=%v", v)
	}
}
