package hub

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestSndBuf — SndBuf ставится захваченному соединению (WS) и без TLS, и по TLS (боевой server — ServeTLS: Hijack
// отдаёт *tls.Conn, буфер — на его NetConn). Linux удваивает заданное значение.
func TestSndBuf(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		got := make(chan int, 1)
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, _, err := sndWriter{w}.Hijack()
			if err != nil {
				got <- -1
				return
			}
			defer c.Close()
			raw := c
			if tc, ok := raw.(*tls.Conn); ok {
				raw = tc.NetConn()
			}
			n := -1
			if rc, err := raw.(*net.TCPConn).SyscallConn(); err == nil {
				rc.Control(func(fd uintptr) { n, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF) })
			}
			got <- n
		}))
		if useTLS {
			srv.StartTLS()
		} else {
			srv.Start()
		}
		srv.Client().Get(srv.URL) // ответа нет: соединение захвачено и закрыто
		if n := <-got; n != 2*SndBuf {
			t.Errorf("TLS=%v: SO_SNDBUF %d, ждали %d", useTLS, n, 2*SndBuf)
		}
		srv.Close()
	}
}

// capL запоминает принятые соединения.
type capL struct {
	net.Listener
	conns chan *net.TCPConn
}

func (l capL) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if tc, ok := c.(*net.TCPConn); ok {
		l.conns <- tc
	}
	return c, err
}

// TestSndBufWS — проводка: ServeHTTP хаба принимает WS через sndWriter (буфер отправки — SndBuf).
func TestSndBufWS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv := httptest.NewUnstartedServer(&Hub{})
	l := capL{srv.Listener, make(chan *net.TCPConn, 4)}
	srv.Listener = l
	srv.Start()
	defer srv.Close()
	c, _ := dial(t, ctx, "ws"+strings.TrimPrefix(srv.URL, "http"))
	defer c.CloseNow()
	n := -1
	rc, _ := (<-l.conns).SyscallConn()
	rc.Control(func(fd uintptr) { n, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF) })
	if n != 2*SndBuf {
		t.Fatalf("SO_SNDBUF принятого WS %d, ждали %d", n, 2*SndBuf)
	}
}
