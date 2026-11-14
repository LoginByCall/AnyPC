//go:build linux || darwin

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// showRunning: адрес и токен — из window.url первой копии, запрос — POST /api/showWindow с X-Token.
func TestShowRunning(t *testing.T) {
	got := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Method + " " + r.URL.Path + " " + r.Header.Get("X-Token")
		if r.Header.Get("X-Token") != "tok" {
			http.Error(w, "forbidden", http.StatusForbidden)
		}
	}))
	defer srv.Close()
	f := filepath.Join(t.TempDir(), "window.url")
	os.WriteFile(f, []byte(srv.URL+"/?t=tok\n"), 0o600)
	if err := showRunning(f); err != nil || got != "POST /api/showWindow tok" {
		t.Fatalf("err=%v запрос=%q", err, got)
	}
	os.WriteFile(f, []byte(srv.URL+"/?t=bad\n"), 0o600)
	if err := showRunning(f); err == nil {
		t.Fatal("403 — не ошибка")
	}
	if err := showRunning(filepath.Join(t.TempDir(), "нет")); err == nil {
		t.Fatal("нет файла — не ошибка")
	}
}

// Токен уходит только на 127.0.0.1 из файла: другое имя (localhost — тот же сервер) — запроса нет вовсе;
// редирект не выполняется (X-Token не уходит дальше).
func TestShowRunningNoLeak(t *testing.T) {
	var hits, leaked atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, other.URL+"/api/showWindow", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	f := filepath.Join(t.TempDir(), "window.url")
	os.WriteFile(f, []byte(strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)+"/?t=tok\n"), 0o600)
	if err := showRunning(f); err == nil || hits.Load() != 0 {
		t.Fatalf("не 127.0.0.1: err=%v, запросов %d", err, hits.Load())
	}
	os.WriteFile(f, []byte(srv.URL+"/?t=tok\n"), 0o600)
	if err := showRunning(f); err == nil || hits.Load() != 1 || leaked.Load() != 0 {
		t.Fatalf("редирект: err=%v, запросов %d, ушло дальше %d", err, hits.Load(), leaked.Load())
	}
}

// --no-browser (автозапуск) — вторая копия окно не открывает; без него — открывает.
func TestSecondShow(t *testing.T) {
	if secondShow(true, "x") != nil {
		t.Fatal("--no-browser: окно открывается")
	}
	if secondShow(false, "x") == nil {
		t.Fatal("без --no-browser: окна нет")
	}
}

// API showWindow — окно первой копии (raiseWindow).
func TestAPIShowWindow(t *testing.T) {
	raised := make(chan struct{}, 1)
	old := raiseWindow
	raiseWindow = func() { raised <- struct{}{} }
	t.Cleanup(func() { raiseWindow = old })
	w := httptest.NewRecorder()
	api(w, httptest.NewRequest("POST", "/api/showWindow", strings.NewReader("[]")), "showWindow", nil, nil, nil, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("ответ %d", w.Code)
	}
	select {
	case <-raised:
	case <-time.After(2 * time.Second):
		t.Fatal("showWindow не открыл окно")
	}
}
