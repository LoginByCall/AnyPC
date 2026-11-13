package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

func init() { peerOK = samePeerUID }

// samePeerUID — TCP-партнёр запроса (браузер на loopback) принадлежит пользователю, запустившему AnyPC.
// Сокет клиента ищется в /proc/net/tcp{,6} по паре «его адрес → наш адрес»; не нашёлся — отказ.
// Браузер того же пользователя (Chrome, Firefox из snap) проходит: сокеты его сетевого процесса — с нашим uid.
func samePeerUID(r *http.Request) bool {
	la, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if la == nil {
		return false
	}
	peer, err1 := netip.ParseAddrPort(r.RemoteAddr)
	local, err2 := netip.ParseAddrPort(la.String())
	if err1 != nil || err2 != nil {
		return false
	}
	for _, f := range []struct {
		path string
		v6   bool
	}{{"/proc/net/tcp", false}, {"/proc/net/tcp6", true}} {
		b, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}
		if uid, ok := tcpUID(string(b), peer, local, f.v6); ok {
			return uid == os.Getuid()
		}
	}
	return false
}

// tcpUID — uid владельца сокета src→dst из таблицы формата /proc/net/tcp (поля: sl local rem st queues tr retr uid …).
func tcpUID(table string, src, dst netip.AddrPort, v6 bool) (int, bool) {
	s, d := procAddr(src, v6), procAddr(dst, v6)
	if s == "" || d == "" {
		return 0, false
	}
	for _, line := range strings.Split(table, "\n") {
		f := strings.Fields(line)
		if len(f) > 7 && f[1] == s && f[2] == d {
			uid, err := strconv.Atoi(f[7])
			return uid, err == nil
		}
	}
	return 0, false
}

// procAddr — адрес как в /proc/net/tcp: каждые 4 байта IP — число в порядке байт машины (%08X), порт — %04X.
// tcp6 показывает IPv4 сокетов двойного стека как ::ffff:a.b.c.d.
func procAddr(a netip.AddrPort, v6 bool) string {
	var ip []byte
	if v6 {
		x := a.Addr().As16()
		ip = x[:]
	} else if ad := a.Addr().Unmap(); ad.Is4() {
		x := ad.As4()
		ip = x[:]
	} else {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(ip); i += 4 {
		fmt.Fprintf(&b, "%08X", binary.NativeEndian.Uint32(ip[i:]))
	}
	fmt.Fprintf(&b, ":%04X", a.Port())
	return b.String()
}
