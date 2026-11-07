package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		remote, local string
		want          bool
	}{
		{"v0.1.2", "v0.1.1", true},
		{"v0.2.0", "v0.1.9", true},
		{"v0.10.0", "v0.9.0", true}, // числа, а не строки
		{"v0.1.1", "v0.1.1", false},
		{"v0.1.0", "v0.1.1", false},
		{"v0.1.2", "v0.1.1-3-gabc123-dirty", true}, // сборка между тегами — по её базовому выпуску
		{"v0.1.1", "v0.1.1-3-gabc123", false},
		{"v0.1.2", "dev", false},           // своя сборка без тега — не предлагать
		{"v0.1.2-1-gabc", "v0.1.1", false}, // на хабе выложена не выпущенная сборка
		{"<html>v9.9.9", "v0.1.1", false},
		{"", "v0.1.1", false},
	} {
		if got := newer(c.remote, c.local); got != c.want {
			t.Errorf("newer(%q, %q) = %v", c.remote, c.local, got)
		}
	}
}

// TestLatestVersion — первый хаб мёртв, второй отдаёт мусор, третий — выпуск; 404 и мусор не принимаются.
func TestLatestVersion(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + l.Addr().String() + "/download/VERSION"
	l.Close()
	junk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("<!doctype html>")) }))
	defer junk.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("v0.2.0\n")) }))
	defer good.Close()
	defer func(u []string) { updateURLs = u }(updateURLs)
	updateURLs = []string{dead, junk.URL, good.URL}
	if v := latestVersion(); v != "v0.2.0" {
		t.Fatalf("ждали v0.2.0, получили %q", v)
	}
	updateURLs = []string{dead, junk.URL}
	if v := latestVersion(); v != "" {
		t.Fatalf("без внятного ответа ждали пусто, получили %q", v)
	}
}

func TestUpdateURLs(t *testing.T) {
	if updateURLs[0] != "https://hk.anypc.org/download/VERSION" || len(updateURLs) != 2 {
		t.Fatalf("%v", updateURLs)
	}
}
