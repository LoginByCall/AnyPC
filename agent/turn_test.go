package agent

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

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

// TestMeasureDue — замер TURN не чаще measureEvery на набор: hello приходит перед каждым connect.
func TestMeasureDue(t *testing.T) {
	var a Agent
	hk, ru := []string{"hk"}, []string{"ru"}
	if !a.measureDue(hk) || a.measureDue(hk) || !a.measureDue(ru) {
		t.Fatal("первый замер набора — да, повтор сразу — нет, другой набор — да")
	}
	a.rttAt["hk"] = time.Now().Add(-measureEvery)
	if !a.measureDue(hk) {
		t.Fatal("через measureEvery — снова мерить")
	}
}

// TestClientID — ID клиента только как выдаёт хаб: перевод строки подделал бы «IP:» в окне «Разрешить».
func TestClientID(t *testing.T) {
	for id, ok := range map[string]bool{"c" + strings.Repeat("1", 12): true, "c12345678901\nIP: 1.2.3.4": false, "123456789": false, "": false} {
		if clientID.MatchString(id) != ok {
			t.Errorf("%q: ждали %v", id, ok)
		}
	}
}

func TestNotches(t *testing.T) {
	var acc int32
	for _, c := range []struct{ d, want, rest int32 }{{60, 0, 60}, {60, 1, 0}, {-250, -2, -10}, {130, 1, 0}, {-119, 0, -119}} {
		if n := notches(&acc, c.d); n != c.want || acc != c.rest {
			t.Fatalf("+%d: %d ост %d, ждал %d ост %d", c.d, n, acc, c.want, c.rest)
		}
	}
}
