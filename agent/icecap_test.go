package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"anypc/hub"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/pion/webrtc/v4"
)

// iceClient — хост за локальным хабом и клиент, получивший offer: answer pion-клиента без кандидатов.
type iceClient struct {
	a      *Agent
	c      *websocket.Conn
	answer webrtc.SessionDescription
	send   func(typ string, v any)
}

func newICEClient(t *testing.T, ctx context.Context) *iceClient {
	url, id := local(t), "123456789"
	a := newAgent(url, id, nil)
	go a.Run(ctx)
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.CloseNow() })
	ic := &iceClient{a: a, c: c}
	ic.send = func(typ string, v any) {
		d, _ := json.Marshal(v)
		wsjson.Write(ctx, c, hub.Msg{V: 1, Type: typ, To: id, Data: d})
	}
	var m hub.Msg
	wsjson.Read(ctx, c, &m) // hello
	for {
		ic.send("connect", connectReq{})
		if err := wsjson.Read(ctx, c, &m); err != nil {
			t.Fatal(err)
		}
		if m.Type == "offer" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	var offer webrtc.SessionDescription
	json.Unmarshal(m.Data, &offer)
	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	if err := pc.SetRemoteDescription(offer); err != nil {
		t.Fatal(err)
	}
	if ic.answer, err = pc.CreateAnswer(nil); err != nil {
		t.Fatal(err)
	}
	return ic
}

// lanIP — адрес не-loopback интерфейса: pion не берёт loopback в локальные кандидаты.
func lanIP(t *testing.T) string {
	addrs, _ := net.InterfaceAddrs()
	for _, ad := range addrs {
		if n, ok := ad.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			return n.IP.String()
		}
	}
	t.Skip("нет сетевого интерфейса кроме loopback")
	return ""
}

// listeners — n UDP-сокетов; hit[i] — на i-й пришёл хоть один пакет (STUN-проверка хоста).
func listeners(t *testing.T, ctx context.Context, ip string, n int) ([]int, []atomic.Bool) {
	ports, hit := make([]int, n), make([]atomic.Bool, n)
	for i := range n {
		l, err := net.ListenPacket("udp4", ip+":0")
		if err != nil {
			t.Fatal(err)
		}
		context.AfterFunc(ctx, func() { l.Close() })
		ports[i] = l.LocalAddr().(*net.UDPAddr).Port
		go func() {
			b := make([]byte, 1500)
			if _, _, err := l.ReadFrom(b); err == nil {
				hit[i].Store(true)
			}
		}()
	}
	return ports, hit
}

func hits(hit []atomic.Bool) (n int) {
	for i := range hit {
		if hit[i].Load() {
			n++
		}
	}
	return
}

func cand(i int, ip string, port int, typ string) webrtc.ICECandidateInit {
	return webrtc.ICECandidateInit{Candidate: fmt.Sprintf("candidate:%d 1 udp %d %s %d typ %s", i, 2130706431-i, ip, port, typ)}
}

// TestICECap — F5: 200 кандидатов до входа → хост шлёт STUN-проверки не больше чем на 32 адреса.
func TestICECap(t *testing.T) {
	ip := lanIP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ports, hit := listeners(t, ctx, ip, 200)
	ic := newICEClient(t, ctx)
	ic.send("answer", ic.answer)
	for i, p := range ports {
		ic.send("ice", cand(i, ip, p, "host"))
	}
	time.Sleep(4 * time.Second)
	if n := hits(hit); n == 0 || n > 32 {
		t.Fatalf("проверки ушли на %d адресов из 200, потолок 32", n)
	}
}

// TestICECapKeepsRelay — F5: relay приходят последними; 40 host и TCP-кандидаты перед ними не отнимают у них места.
func TestICECapKeepsRelay(t *testing.T) {
	ip := lanIP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ports, hit := listeners(t, ctx, ip, 1)
	ic := newICEClient(t, ctx)
	ic.send("answer", ic.answer)
	for i := range 40 {
		ic.send("ice", cand(i, "192.0.2.1", 10000+i, "host")) // TEST-NET-1: ответа не будет
		ic.send("ice", webrtc.ICECandidateInit{Candidate: fmt.Sprintf("candidate:t%d 1 tcp 1518280447 192.0.2.2 9 typ host tcptype active", i)})
	}
	ic.send("ice", webrtc.ICECandidateInit{Candidate: fmt.Sprintf("candidate:r 1 udp 16777215 %s %d typ relay raddr 0.0.0.0 rport 0", ip, ports[0])})
	for range 40 {
		if hits(hit) == 1 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("relay-кандидат после 40 host отброшен: проверок на него нет")
}

// TestAnswerCandidates — F5: answer со 300 a=candidate (в обход счёта trickle) → отказ в сессии;
// answer с несколькими кандидатами — сессия живёт.
func TestAnswerCandidates(t *testing.T) {
	for _, n := range []int{3, 300} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			ic := newICEClient(t, ctx)
			var b strings.Builder
			b.WriteString(ic.answer.SDP)
			for i := range n {
				fmt.Fprintf(&b, "a=candidate:%d 1 udp %d 192.0.2.%d %d typ host\r\n", i, 2130706431-i, 1+i%250, 10000+i)
			}
			ic.answer.SDP = b.String()
			ic.send("answer", ic.answer)
			rctx, rcancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			defer rcancel()
			bye := false
			for {
				var m hub.Msg
				if wsjson.Read(rctx, ic.c, &m) != nil {
					break
				}
				if m.Type == "bye" {
					bye = true
					break
				}
			}
			ic.a.mu.Lock()
			pend := len(ic.a.pend)
			ic.a.mu.Unlock()
			if want := n > 32; bye != want || (pend == 0) != want {
				t.Fatalf("%d кандидатов в answer: bye=%v, ожидающих сессий %d", n, bye, pend)
			}
		})
	}
}

// TestICEKind — разбор строки кандидата и потолки по видам.
func TestICEKind(t *testing.T) {
	for c, want := range map[string]string{
		"": "",
		"candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host":                       "direct",
		"a=candidate:1 1 UDP 16777215 1.2.3.4 5000 typ relay raddr 0.0.0.0 rport 0": "relay",
		"candidate:1 1 tcp 1518280447 10.0.0.1 9 typ host tcptype active":           "tcp-active",
		"candidate:1 1 tcp 1518280447 10.0.0.1 9 typ host tcptype passive":          "direct",
		"мусор": "direct",
	} {
		if got := iceKind(c); got != want {
			t.Errorf("%q: %q, ждали %q", c, got, want)
		}
	}
	var c iceCap
	n := 0
	for range 100 {
		if c.admit("c1", "candidate:1 1 udp 1 10.0.0.1 5000 typ srflx", false) {
			n++
		}
	}
	r := 0
	for range 100 {
		if c.admit("c1", "candidate:1 1 udp 1 10.0.0.1 5000 typ relay", false) {
			r++
		}
	}
	a := 0
	for range 1000 {
		if c.admit("c1", "candidate:1 1 udp 1 10.0.0.1 5000 typ host", true) {
			a++
		}
	}
	if n != 32 || r != 16 || n+r+a != 256 {
		t.Fatalf("до входа %d+%d, всего %d", n, r, n+r+a)
	}
}
