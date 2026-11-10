package agent

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
)

// Выбор TURN. Через relay путь «клиент → TURN → хост», поэтому «Авто» — минимум суммы плеч:
// клиент мерит своё и шлёт в connect, хост добавляет своё и отвечает выбором в offer.
// Прямое соединение (P2P) выбор не отключает: TURN нужен, только когда напрямую не вышло.

type connectReq struct {
	TURN string         `json:"turn"` // "", "auto" или хост TURN
	RTT  map[string]int `json:"rtt"`  // мс от клиента до каждого TURN
	CPub []byte         `json:"cpub"` // ключ клиента (У3) — заявка, не доказательство: проверка подписью в auth
	VP9  bool           `json:"vp9"`  // клиент просит VP9 («Турбо»); хост даёт его, если собран с кодером (VP9Built), иначе H.264
	View bool           `json:"view"` // клиент просит «только просмотр» (REQ-F-20)
}

type offerMsg struct {
	webrtc.SessionDescription
	TURN string         `json:"turn,omitempty"` // через какой TURN идёт relay; "" — все (старый клиент)
	RTT  map[string]int `json:"rtt,omitempty"`  // мс от хоста до каждого TURN
}

// turnHost: "turn:h:3478?transport=udp", "stun:h:3478" → h.
func turnHost(u string) string {
	_, rest, _ := strings.Cut(u, ":")
	h, _, _ := strings.Cut(rest, ":")
	return h
}

func turnHosts(ice []webrtc.ICEServer) (hs []string) {
	for _, s := range ice {
		for _, u := range s.URLs {
			if h := turnHost(u); h != "" && !slices.Contains(hs, h) {
				hs = append(hs, h)
			}
		}
	}
	return hs
}

// pickTURN — выбор клиента, если он есть в списке; иначе минимум (клиент + хост) по серверам,
// доступным обоим. "" — выбирать не из чего (старый клиент без замеров): ICE получает все серверы.
func pickTURN(req connectReq, mine map[string]int, hosts []string) string {
	if req.TURN != "" && req.TURN != "auto" && slices.Contains(hosts, req.TURN) {
		return req.TURN
	}
	best, bestV := "", 0
	for _, h := range hosts {
		c, ok := req.RTT[h]
		m, ok2 := mine[h]
		if !ok || (!ok2 && len(mine) > 0) { // недоступен клиенту или хосту; хост ещё не мерил — только плечо клиента
			continue
		}
		if v := c + m; best == "" || v < bestV {
			best, bestV = h, v
		}
	}
	return best
}

func onlyTURN(ice []webrtc.ICEServer, host string) []webrtc.ICEServer {
	if host == "" {
		return ice
	}
	var r []webrtc.ICEServer
	for _, s := range ice {
		if len(s.URLs) > 0 && turnHost(s.URLs[0]) == host {
			r = append(r, s)
		}
	}
	return r
}

// stunRTT — лучшее из трёх STUN Binding (RFC 5389) до host:3478, мс; ok=false — не ответил.
func stunRTT(host string) (int, bool) {
	c, err := net.Dial("udp", net.JoinHostPort(host, "3478"))
	if err != nil {
		return 0, false
	}
	defer c.Close()
	best := time.Duration(-1)
	for range 3 {
		req := make([]byte, 20)
		binary.BigEndian.PutUint16(req[0:], 0x0001) // Binding Request
		binary.BigEndian.PutUint32(req[4:], 0x2112A442)
		rand.Read(req[8:])
		t := time.Now()
		c.SetDeadline(t.Add(time.Second))
		if _, err := c.Write(req); err != nil {
			continue
		}
		resp := make([]byte, 512)
		for {
			n, err := c.Read(resp)
			if err != nil {
				break
			}
			if n >= 20 && binary.BigEndian.Uint16(resp) == 0x0101 && string(resp[8:20]) == string(req[8:20]) {
				if d := time.Since(t); best < 0 || d < best {
					best = d
				}
				break
			}
		}
	}
	return int(best.Milliseconds()), best >= 0
}

// measureTURN — RTT хоста до каждого TURN параллельно (до ~3 с).
func measureTURN(hosts []string) map[string]int {
	r := map[string]int{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range hosts {
		wg.Go(func() {
			if ms, ok := stunRTT(h); ok {
				mu.Lock()
				r[h] = ms
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return r
}
