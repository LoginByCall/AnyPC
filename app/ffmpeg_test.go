package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// TestEnsureFFmpeg — FFmpeg не вшит: ffmpeg.exe из zip зеркала по HTTP Range, с проверкой SHA-256.
// Мёртвое первое зеркало → второе; чужой хэш → файла нет; сервер без Range → ошибка; повтор — без сети.
func TestEnsureFFmpeg(t *testing.T) {
	exe := make([]byte, 9<<20) // больше блока упреждения, несжимаемый — как настоящий exe
	rand.Read(exe)
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	for _, name := range []string{"x/bin/ffplay.exe", "x/bin/ffmpeg.exe", "x/bin/ffprobe.exe"} {
		w, _ := zw.Create(name)
		w.Write(exe)
	}
	zw.Close()
	var reqs atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs.Add(1)
		http.ServeContent(w, r, "ff.zip", time.Time{}, bytes.NewReader(zb.Bytes()))
	}))
	defer srv.Close()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + l.Addr().String() + "/ff.zip"
	l.Close()
	sum := sha256.Sum256(exe)
	defer func(m []string, e, s string) { ffMirrors, ffEntry, ffSHA256 = m, e, s }(ffMirrors, ffEntry, ffSHA256)
	ffMirrors, ffEntry, ffSHA256 = []string{dead, srv.URL + "/ff.zip"}, "x/bin/ffmpeg.exe", hex.EncodeToString(sum[:])

	dir := t.TempDir()
	var last int64
	p, err := ensureFFmpeg(dir, func(d, _ int64) { last = d })
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); !bytes.Equal(b, exe) || last != int64(len(exe)) {
		t.Fatalf("ffmpeg.exe: %d байт, прогресс %d", len(b), last)
	}
	if n := reqs.Load(); n > 12 { // три записи по 9 МБ, нужна одна: не весь архив и не тысячи мелких запросов
		t.Errorf("запросов к зеркалу: %d", n)
	}
	reqs.Store(0)
	if _, err := ensureFFmpeg(dir, nil); err != nil || reqs.Load() != 0 {
		t.Fatalf("уже скачанный — без сети: %v, запросов %d", err, reqs.Load())
	}

	ffSHA256 = hex.EncodeToString(make([]byte, 32)) // подменённая сборка
	bad := t.TempDir()
	if _, err := ensureFFmpeg(bad, nil); err == nil {
		t.Fatal("чужой хэш принят")
	}
	if left, _ := os.ReadDir(bad); len(left) != 0 {
		t.Fatalf("после неудачи остались файлы: %v", left)
	}

	noRange := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(zb.Bytes()) }))
	defer noRange.Close()
	ffMirrors, ffSHA256 = []string{noRange.URL}, hex.EncodeToString(sum[:])
	if _, err := ensureFFmpeg(t.TempDir(), nil); err == nil {
		t.Fatal("сервер без Range: ждали ошибку, а не скачивание всего архива")
	}

	// архив, скачанный вручную: без сети; чужой хэш — не принят
	zipFile := t.TempDir() + "/ff.zip"
	os.WriteFile(zipFile, zb.Bytes(), 0o644)
	defer func(l []string) { ffLocal = l }(ffLocal)
	ffLocal, ffMirrors = []string{t.TempDir() + "/нет.zip", zipFile}, []string{dead}
	if p, err := ensureFFmpeg(t.TempDir(), nil); err != nil {
		t.Fatalf("ручной архив: %v", err)
	} else if b, _ := os.ReadFile(p); !bytes.Equal(b, exe) {
		t.Fatal("ручной архив: не тот ffmpeg.exe")
	}
	ffSHA256 = hex.EncodeToString(make([]byte, 32))
	if _, err := ensureFFmpeg(t.TempDir(), nil); err == nil {
		t.Fatal("ручной архив с чужим хэшем принят")
	}
}

// TestFFmpegMirrors — живые зеркала отдают ровно закреплённую сборку (запуск: ANYPC_FFMIRRORS=1; при смене версии FFmpeg).
func TestFFmpegMirrors(t *testing.T) {
	if os.Getenv("ANYPC_FFMIRRORS") == "" {
		t.Skip("ANYPC_FFMIRRORS=1 — проверка настоящих зеркал (~40 МБ с каждого)")
	}
	all := ffMirrors
	defer func() { ffMirrors = all }()
	for _, u := range all {
		ffMirrors = []string{u}
		start := time.Now()
		if _, err := ensureFFmpeg(t.TempDir(), nil); err != nil {
			t.Errorf("%s: %v", u, err)
			continue
		}
		t.Logf("%s: ok за %v", u, time.Since(start).Round(time.Second))
	}
}
