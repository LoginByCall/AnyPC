package agent

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/pion/webrtc/v4"
)

// TestPickTURN — «Авто» берёт минимум суммы плеч, а не ближайший к клиенту; сервер, недоступный хосту, не выбирается;
// явный выбор клиента главнее; старый клиент без замеров — без выбора (все серверы).
func TestPickTURN(t *testing.T) {
	hs := []string{"ru", "hk", "us"}
	host := map[string]int{"ru": 230, "hk": 40} // us хосту недоступен
	cases := []struct {
		req  connectReq
		mine map[string]int
		want string
	}{
		{connectReq{TURN: "auto", RTT: map[string]int{"ru": 5, "hk": 300, "us": 1}}, host, "ru"}, // 235 < 340; us — мимо
		{connectReq{TURN: "auto", RTT: map[string]int{"ru": 200, "hk": 60}}, host, "hk"},         // 430 > 100
		{connectReq{TURN: "hk", RTT: map[string]int{"ru": 5}}, host, "hk"},                       // выбор человека
		{connectReq{TURN: "zz", RTT: map[string]int{"ru": 5}}, host, "ru"},                       // чужой сервер — как «Авто»
		{connectReq{}, host, ""}, // старый клиент
		{connectReq{RTT: map[string]int{"ru": 50, "hk": 20}}, nil, "hk"}, // хост ещё не мерил
	}
	for i, c := range cases {
		if got := pickTURN(c.req, c.mine, hs); got != c.want {
			t.Errorf("%d: %q, ждали %q", i, got, c.want)
		}
	}
	ice := []webrtc.ICEServer{{URLs: []string{"stun:ru:3478"}}, {URLs: []string{"turn:ru:3478?transport=udp", "turn:ru:3478?transport=tcp"}}, {URLs: []string{"stun:hk:3478"}}}
	if got := onlyTURN(ice, "ru"); len(got) != 2 || len(onlyTURN(ice, "")) != 3 {
		t.Fatalf("onlyTURN: %+v", got)
	}
	if got := turnHosts(ice); len(got) != 2 || got[0] != "ru" || got[1] != "hk" {
		t.Fatalf("turnHosts: %v", got)
	}
}

// TestStunRTT — замер по настоящему STUN Binding: отвечающий сервер даёт RTT, молчащий — ok=false.
func TestStunRTT(t *testing.T) {
	c, err := net.ListenPacket("udp", "127.0.0.1:3478")
	if err != nil {
		t.Skip("порт 3478 занят:", err)
	}
	defer c.Close()
	go func() {
		b := make([]byte, 512)
		for {
			n, a, err := c.ReadFrom(b)
			if err != nil {
				return
			}
			if n == 20 {
				binary.BigEndian.PutUint16(b, 0x0101) // Binding Success, тот же transaction ID
				c.WriteTo(b[:20], a)
			}
		}
	}()
	if ms, ok := stunRTT("127.0.0.1"); !ok || ms > 50 {
		t.Fatalf("локальный STUN: %d мс, ok=%v", ms, ok)
	}
	if r := measureTURN([]string{"127.0.0.1", "127.0.0.2"}); len(r) != 1 { // 127.0.0.2:3478 молчит
		t.Fatalf("measureTURN: %v", r)
	}
}
