package main

import (
	"net"
	"syscall"
	"testing"
	"time"
)

// TestBufs — буферы ядра у принятых соединений (Д1″ (в) приёмки-6, Д1 приёмки-7); Linux удваивает заданное.
func TestBufs(t *testing.T) {
	l := listen("127.0.0.1:0", 2, TCPPerAddr)
	defer l.Close()
	go func() {
		if c, err := net.Dial("tcp", l.Addr().String()); err == nil {
			defer c.Close()
			time.Sleep(time.Second)
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rc, _ := c.(*limConn).SyscallConn()
	var rcv, snd int
	rc.Control(func(fd uintptr) {
		rcv, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		snd, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	})
	if rcv != 2*RcvBuf || snd != 2*SndBuf {
		t.Fatalf("SO_RCVBUF %d, SO_SNDBUF %d; ждали %d и %d", rcv, snd, 2*RcvBuf, 2*SndBuf)
	}
}
