package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"anypc/hub"
)

// fromAll — в тесте все адреса (loopback) — один адрес под лимитом.
func fromAll(t *testing.T) {
	old := addrKeys
	addrKeys = func(netip.Addr) []hub.AddrKey { return []hub.AddrKey{{Key: "one", Mul: 1}} }
	t.Cleanup(func() { addrKeys = old })
}

// within — f закончилась за d (иначе — зависла).
func within(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s: не закончилось за %v", what, d)
	}
}

// TestTCPPerAddr — Д2 приёмки-7: сверх TCPPerAddr с адреса соединение закрывается сразу и места общего лимита
// не держит; закрытое своё — освобождает место адреса.
func TestTCPPerAddr(t *testing.T) {
	fromAll(t)
	l := listen("127.0.0.1:0", TCPPerAddr+10)
	defer l.Close()
	var mu sync.Mutex
	var acc []net.Conn
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			acc = append(acc, c)
			mu.Unlock()
		}
	}()
	var cs []net.Conn
	for range TCPPerAddr + 1 {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		cs = append(cs, c)
	}
	cs[TCPPerAddr].SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := cs[TCPPerAddr].Read(make([]byte, 1)); err != io.EOF && !strings.Contains(err.Error(), "reset") {
		t.Fatalf("соединение сверх лимита адреса не закрыто: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(l.sem); n != TCPPerAddr+1 { // +1 — у Accept, ждущего следующее соединение
		t.Fatalf("занято мест общего лимита %d, ждали %d", n, TCPPerAddr+1)
	}
	mu.Lock()
	acc[0].Close()
	acc[0].Close() // повторный Close не освобождает второе место (once)
	mu.Unlock()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(acc)
		mu.Unlock()
		if n == TCPPerAddr+1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("место адреса не освободилось после Close")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(l.sem); n != TCPPerAddr+1 {
		t.Fatalf("после Close и нового: занято %d, ждали %d", n, TCPPerAddr+1)
	}
}

// TestLimitListenerAccept — ошибка Accept (слушатель закрыт) возвращает место; сверх общего лимита Accept ждёт.
func TestLimitListenerAccept(t *testing.T) {
	l := listen("127.0.0.1:0", 1)
	go net.Dial("tcp", l.Addr().String())
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan error, 1)
	go func() { _, err := l.Accept(); got <- err }()
	go net.Dial("tcp", l.Addr().String())
	select {
	case <-got:
		t.Fatal("второе соединение принято сверх лимита 1")
	case <-time.After(300 * time.Millisecond):
	}
	within(t, 2*time.Second, "Close", func() { c.Close() })
	if err := <-got; err != nil {
		t.Fatal(err)
	}
	l.Close()
	within(t, 2*time.Second, "освобождение места", func() { <-l.sem })
	if _, err := l.Accept(); err == nil || len(l.sem) != 0 {
		t.Fatalf("Accept на закрытом: %v, занято %d", err, len(l.sem))
	}
}

// TestHeavy — Д1 приёмки-7: тяжёлых ответов с адреса не больше HeavyPerAddr, лишний ждёт места.
func TestHeavy(t *testing.T) {
	fromAll(t)
	release := make(chan struct{})
	var started sync.WaitGroup
	h := heavy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/block" {
			started.Done()
			<-release
		}
		io.WriteString(w, "ok")
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	started.Add(HeavyPerAddr)
	for range HeavyPerAddr {
		go http.Get(srv.URL + "/block")
	}
	started.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/x", nil)
	if _, err := http.DefaultClient.Do(req); err == nil {
		t.Fatalf("тяжёлый ответ сверх %d с адреса не ждёт", HeavyPerAddr)
	}
	close(release)
	r, err := http.Get(srv.URL + "/x")
	if err != nil || r.StatusCode != 200 {
		t.Fatalf("после освобождения: %v %v", err, r)
	}
	l := &heavyLim{per: map[string]int{}}
	for range HeavyTotal {
		l.try(nil)
	}
	if l.try(nil) {
		t.Fatalf("сверх HeavyTotal %d принято", HeavyTotal)
	}
}

// dlWriter — ResponseWriter, запоминающий сроки записи (их ставит http.ResponseController).
type dlWriter struct {
	httptest.ResponseRecorder
	dl []time.Time
}

func (w *dlWriter) SetWriteDeadline(t time.Time) error { w.dl = append(w.dl, t); return nil }

// TestStallWrite — срок записи тяжёлого ответа — на каждый кусок stallChunk, после ответа снят (keep-alive).
func TestStallWrite(t *testing.T) {
	fromAll(t)
	w := &dlWriter{ResponseRecorder: *httptest.NewRecorder()}
	heavy(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(make([]byte, 2*stallChunk+1))
	})).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if len(w.dl) != 4 || w.dl[0].IsZero() || time.Until(w.dl[2]) < StallWrite-time.Second || !w.dl[3].IsZero() {
		t.Fatalf("сроки записи: %v (ждали три по StallWrite и сброс)", w.dl)
	}
	if w.Body.Len() != 2*stallChunk+1 {
		t.Fatalf("записано %d", w.Body.Len())
	}
}

var _ interface{ SetWriteBuffer(int) error } = (*limConn)(nil) // hub ставит SndBuf захваченному WS через него

// TestHeavyRoutes — проводка: страница, сайт и загрузки идут через heavy (при занятых местах адреса — 503 по сроку
// запроса), а /turns и /hubs — нет.
func TestHeavyRoutes(t *testing.T) {
	fromAll(t)
	ks := addrKeys(netip.Addr{})
	for range HeavyPerAddr {
		heavyNow.try(ks)
	}
	defer func() {
		for range HeavyPerAddr {
			heavyNow.done(ks)
		}
	}()
	dl := t.TempDir()
	h := newMux(http.NotFoundHandler(), []string{"www.example.com"}, dl, nil, nil)
	for _, c := range []struct {
		host, path string
		code       int
	}{
		{"app.example.com", "/", 503}, {"www.example.com", "/", 503}, {"app.example.com", "/download/x", 503},
		{"app.example.com", "/turns", 200}, {"www.example.com", "/hubs", 200},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		r := httptest.NewRequest("GET", c.path, nil).WithContext(ctx)
		r.Host = c.host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		cancel()
		if w.Code != c.code {
			t.Errorf("%s%s: %d, ждали %d", c.host, c.path, w.Code, c.code)
		}
	}
}
