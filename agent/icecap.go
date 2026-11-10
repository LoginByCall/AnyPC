package agent

import (
	"log"
	"strings"
	"sync"
)

// Потолок удалённых ICE-кандидатов на сессию (F5): каждый кандидат — пары и STUN-проверки с хоста
// на адрес, который назвал клиент; без потолка любой, кто знает ID, гонит хост слать UDP куда угодно.
// До входа host+srflx(+prflx) и relay считаются отдельно: relay приходят последними, и общий порог
// обрезал бы ровно их. После входа клиент доказал пароль — общий потолок больше: Chrome собирает
// кандидаты всю сессию (смена сети). TCP active не считаются: pion их отбрасывает сам (ice agent.go
// AddRemoteCandidate), а Chrome шлёт их на каждый интерфейс. TCP passive pion набирает сам — считаются.
const (
	iceCapDirect = 32
	iceCapRelay  = 16
	iceCapAuthed = 256
)

type iceCap struct {
	mu                   sync.Mutex
	direct, relay, total int
	logged               bool
}

// iceKind — вид кандидата по строке SDP: "" (пустая — конец сбора), "tcp-active", "relay", "direct".
// Неразборчивая строка — "direct": pion её отвергнет, но место она займёт.
func iceKind(cand string) string {
	cand = strings.TrimPrefix(strings.TrimPrefix(cand, "a="), "candidate:")
	f := strings.Fields(cand)
	if len(f) == 0 {
		return ""
	}
	tcp := len(f) > 2 && strings.EqualFold(f[2], "tcp")
	for i := 6; i+1 < len(f); i += 2 {
		switch strings.ToLower(f[i]) {
		case "typ":
			if !tcp && strings.EqualFold(f[i+1], "relay") {
				return "relay"
			}
		case "tcptype":
			if tcp && strings.EqualFold(f[i+1], "active") {
				return "tcp-active"
			}
		}
	}
	return "direct"
}

// admit — пропустить ли кандидат в pion. Сверх потолка — молча отбрасываются, в журнал — одна строка на сессию.
func (c *iceCap) admit(cid, cand string, authed bool) bool {
	n, lim := &c.direct, iceCapDirect
	switch iceKind(cand) {
	case "":
		return true
	case "tcp-active":
		return false // pion всё равно отбросит
	case "relay":
		n, lim = &c.relay, iceCapRelay
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if authed && c.total < iceCapAuthed || !authed && *n < lim {
		*n++
		c.total++
		return true
	}
	if !c.logged {
		c.logged = true
		log.Printf("сессия %s: удалённых ICE-кандидатов больше потолка — лишние отброшены", cid)
	}
	return false
}

// sdpCandidates — строки a=candidate в SDP.
func sdpCandidates(sdp string) []string {
	var out []string
	for l := range strings.Lines(sdp) {
		if l = strings.TrimRight(l, "\r\n"); strings.HasPrefix(l, "a=candidate:") {
			out = append(out, l)
		}
	}
	return out
}

// answerCands — кандидаты из answer умещаются в потолок (и занимают в нём места).
func (s *session) answerCands(sdp string) bool {
	for _, l := range sdpCandidates(sdp) {
		if iceKind(l) != "tcp-active" && !s.ice.admit(s.cid, l, s.authed.Load()) {
			return false
		}
	}
	return true
}
