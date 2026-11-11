package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
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
	l := listen("127.0.0.1:0", TCPPerAddr+10, TCPPerAddr)
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
	l := listen("127.0.0.1:0", 1, TCPPerAddr)
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

// TestHeavy — Д1 приёмки-7: тяжёлых ответов с адреса не больше доли пула, лишний ждёт места.
func TestHeavy(t *testing.T) {
	fromAll(t)
	pool := &heavyLim{max: 10, perAddr: 2, per: map[string]int{}}
	release := make(chan struct{})
	var started sync.WaitGroup
	h := heavy(pool, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/block" {
			started.Done()
			<-release
		}
		io.WriteString(w, "ok")
	}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	started.Add(pool.perAddr)
	for range pool.perAddr {
		go http.Get(srv.URL + "/block")
	}
	started.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/x", nil)
	if _, err := http.DefaultClient.Do(req); err == nil {
		t.Fatalf("тяжёлый ответ сверх %d с адреса не ждёт", pool.perAddr)
	}
	close(release)
	r, err := http.Get(srv.URL + "/x")
	if err != nil || r.StatusCode != 200 {
		t.Fatalf("после освобождения: %v %v", err, r)
	}
}

// TestHeavyLim — пул: всего max, с адреса perAddr, /48 — ×10, все ключи адреса или ни одного; отмена запроса
// в ожидании места — сразу отказ.
func TestHeavyLim(t *testing.T) {
	l := &heavyLim{max: 100, perAddr: 2, per: map[string]int{}}
	p48 := []hub.AddrKey{{Key: "a/64", Mul: 1}, {Key: "a/48", Mul: 10}}
	for i := range 10 { // десять /64 одного /48 — по 2 с каждого
		ks := []hub.AddrKey{{Key: fmt.Sprint("b", i), Mul: 1}, {Key: "b/48", Mul: 10}}
		for range 2 {
			if !l.try(ks) {
				t.Fatalf("/64 №%d: отказ в пределах доли /48 ×10", i)
			}
		}
	}
	if l.try([]hub.AddrKey{{Key: "b10", Mul: 1}, {Key: "b/48", Mul: 10}}) {
		t.Fatal("/48 сверх perAddr × 10 принят")
	}
	if !l.try(p48) || !l.try(p48) || l.try(p48) {
		t.Fatal("доля /64 не 2")
	}
	if l.per["b10"] != 0 {
		t.Fatalf("отказ занял ключ /64: %d (ждали «все или ничего»)", l.per["b10"])
	}
	for range 100 - 22 {
		l.try(nil)
	}
	if l.try(nil) {
		t.Fatalf("сверх max %d принято", l.max)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	t0 := time.Now()
	if l.acquire(ctx, nil) || time.Since(t0) > time.Second {
		t.Fatalf("отмена запроса в ожидании: место или ждал %v", time.Since(t0))
	}
}

// TestTCPPerAddrKeys — лимит TCP с адреса: /48 — ×10, все ключи или ни одного.
func TestTCPPerAddrKeys(t *testing.T) {
	l := &limitListener{perAddr: 3, per: map[string]int{}}
	for i := range 10 {
		for range 3 {
			if !l.take([]hub.AddrKey{{Key: fmt.Sprint("p", i), Mul: 1}, {Key: "p/48", Mul: 10}}) {
				t.Fatalf("/64 №%d: отказ в пределах /48 ×10", i)
			}
		}
	}
	if l.take([]hub.AddrKey{{Key: "p10", Mul: 1}, {Key: "p/48", Mul: 10}}) || l.per["p10"] != 0 {
		t.Fatalf("сверх /48 ×10: принят или занял ключ /64 (%d)", l.per["p10"])
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
	heavy(pagePool, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(make([]byte, 2*stallChunk+1))
	})).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if len(w.dl) != 4 || w.dl[0].IsZero() || time.Until(w.dl[2]) < StallWrite-time.Second || time.Until(w.dl[3]) < StallWrite-time.Second {
		t.Fatalf("сроки записи: %v (ждали три по StallWrite и срок на хвост)", w.dl)
	}
	if w.Body.Len() != 2*stallChunk+1 {
		t.Fatalf("записано %d", w.Body.Len())
	}
}

var _ interface{ SetWriteBuffer(int) error } = (*limConn)(nil) // hub ставит SndBuf захваченному WS через него

// TestPagePoolFree — Н3: занятые загрузками места не отнимают у страницы (свой пул).
func TestPagePoolFree(t *testing.T) {
	fromAll(t)
	ks := addrKeys(netip.Addr{})
	for range dlPool.perAddr {
		dlPool.try(ks)
	}
	defer func() {
		for range dlPool.perAddr {
			dlPool.done(ks)
		}
	}()
	h := newMux(http.NotFoundHandler(), nil, t.TempDir(), nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	r.Host = "app.example.com"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("страница при занятых загрузках: %d", w.Code)
	}
}

// TestHeavyRoutes — проводка: страница, сайт и загрузки идут через heavy (при занятых местах адреса — 503 по сроку
// запроса), а /turns и /hubs — нет.
func TestHeavyRoutes(t *testing.T) {
	fromAll(t)
	ks := addrKeys(netip.Addr{})
	for _, p := range []*heavyLim{pagePool, dlPool} {
		for range p.perAddr {
			p.try(ks)
		}
		defer func() {
			for range p.perAddr {
				p.done(ks)
			}
		}()
	}
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

// TestNoHTTP2 — Н1, Н2 повторной приёмки-7: serve не согласует h2 по ALPN (клиент предлагает h2 первым — получает
// http/1.1), а noH2 убирает h2 из ALPN autocert, оставляя acme-tls/1.
func TestNoHTTP2(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	kb, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	os.WriteFile(dir+"/c.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(dir+"/k.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	l := listen("127.0.0.1:0", 10, TCPPerAddr)
	srv := serve("", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	go srv.ServeTLS(l, dir+"/c.pem", dir+"/k.pem")
	defer srv.Close()
	c, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if p := c.ConnectionState().NegotiatedProtocol; p == "h2" {
		t.Fatalf("ALPN согласовал %q", p)
	}
	if got := noH2(&tls.Config{NextProtos: []string{"h2", "http/1.1", "acme-tls/1"}}).NextProtos; strings.Join(got, ",") != "http/1.1,acme-tls/1" {
		t.Fatalf("noH2: %v", got)
	}
}

// TestMuxResetsDeadline — каждый запрос снимает срок записи, оставленный прошлым тяжёлым ответом на этом keep-alive.
func TestMuxResetsDeadline(t *testing.T) {
	w := &dlWriter{ResponseRecorder: *httptest.NewRecorder()}
	r := httptest.NewRequest("GET", "/turns", nil)
	r.Host = "app.example.com"
	newMux(http.NotFoundHandler(), nil, "", nil, nil).ServeHTTP(w, r)
	if len(w.dl) == 0 || !w.dl[0].IsZero() {
		t.Fatalf("сроки записи: %v (ждали сброс первым)", w.dl)
	}
}
