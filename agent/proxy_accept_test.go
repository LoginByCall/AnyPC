package agent

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// slowProxy — живой, но медленный HTTP-прокси: ждёт delay, затем пересылает запрос (ws:// — обычный GET с Upgrade)
// на адрес из Host и гонит байты в обе стороны. fwd — сколько соединений прошло через прокси.
func slowProxy(t *testing.T, delay time.Duration) (*url.URL, *atomic.Int32) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var fwd atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				time.Sleep(delay)
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				up, err := net.Dial("tcp", req.Host)
				if err != nil {
					return
				}
				defer up.Close()
				fwd.Add(1)
				req.Write(up)
				go io.Copy(up, br)
				io.Copy(c, up)
			}()
		}
	}()
	pu, _ := url.Parse("http://" + l.Addr().String())
	return pu, &fwd
}

// приёмка Ч12, круг 2: живой, но медленный прокси (дольше proxyWait) — каким путём идёт регистрация ПК на хабе
// (dial из a.run) и каким — служебное соединение вступления (hostDial).
func TestAcceptSlowLiveProxy(t *testing.T) {
	pu, fwd := slowProxy(t, 1500*time.Millisecond)
	oldP, oldW := proxy, proxyWait
	proxy, proxyWait = func(*http.Request) (*url.URL, error) { return pu, nil }, 500*time.Millisecond
	t.Cleanup(func() { proxy, proxyWait = oldP, oldW })
	hubURL := fakeHostHub(t, true, func(pc *webrtc.PeerConnection, _ *webrtc.DataChannel) { pc.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	t0 := time.Now()
	c, err := dial(ctx, hubURL) // путь регистрации
	t.Logf("РЕГИСТРАЦИЯ (dial): err=%v, через прокси=%d, за %v", err, fwd.Load(), time.Since(t0).Round(100*time.Millisecond))
	reg := fwd.Load()
	if c != nil {
		c.CloseNow()
	}
	time.Sleep(1500 * time.Millisecond) // брошенная попытка через прокси догорела
	fwd.Store(0)
	t0 = time.Now()
	err = hostDial(ctx, hubURL, "123456789", connectReq{View: true}, func(*webrtc.PeerConnection, func(error)) {})
	t.Logf("ВСТУПЛЕНИЕ (hostDial): err=%v, через прокси=%d, за %v", err, fwd.Load(), time.Since(t0).Round(100*time.Millisecond))
	if want := true; (reg > 0) != want { // живой прокси регистрацию не обходит (TZ.md, TestDeadProxy)
		t.Errorf("регистрация через прокси: %v, ждали %v", reg > 0, want)
	}
}
