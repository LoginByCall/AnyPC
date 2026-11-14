//go:build linux || darwin

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// showRunning: адрес и токен — из window.url первой копии, запрос — POST /api/showWindow с X-Token; не 127.0.0.1 — отказ.
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
	os.WriteFile(f, []byte("http://example.com/?t=tok\n"), 0o600)
	if err := showRunning(f); err == nil {
		t.Fatal("токен ушёл бы не на 127.0.0.1")
	}
	if err := showRunning(filepath.Join(t.TempDir(), "нет")); err == nil {
		t.Fatal("нет файла — не ошибка")
	}
}
