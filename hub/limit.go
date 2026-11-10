package hub

import (
	"cmp"
	"net/http"
	"net/netip"
	"time"
)

// Лимиты хаба (F4, числа — fixes-review.md). Через хаб идут только connect/offer/answer/ice/bye/error/hello:
// законная попытка клиента — ≈45 сообщений и ≈20 КБ. Хост за объём не закрывается никогда: его сообщения
// вызывают клиенты (1 connect → offer + 5–30 ice), иначе аноним выбивал бы хост из сети самим лимитом —
// ограничивается причина, connect клиента. Новых типов сообщений и кодов ошибок нет: старые клиенты
// на неизвестный код посреди сессии её обрывают.
const (
	ClientMsgBurst, ClientMsgRate   = 100, 10             // сообщений клиента: всплеск, в секунду; сверх — закрыть WS (1008)
	ClientByteBurst, ClientByteRate = 128 << 10, 16 << 10 // байт клиента: всплеск, в секунду; сверх — закрыть
	ConnectBurst                    = 5                   // connect клиента: всплеск…
	ConnectEvery                    = 3 * time.Second     // …и пополнение; сверх — существующий ответ busy, не пересылать
	HostMsgBurst, HostMsgRate       = 600, 100            // сообщений хоста; сверх — молча отбросить (+ журнал)
	HostByteBurst, HostByteRate     = 2 << 20, 256 << 10  // байт хоста; сверх — так же
	NotFoundPerConn                 = 5                   // not_found клиенту на соединение; следующий — закрыть
	NotFoundPerMin                  = 30                  // not_found на IP (/64) в минуту; сверх — закрыть и 429 новым клиентским WS
	ConnsPerIP                      = 100                 // соединений с адреса IPv4 или /64 (офис, школа, CGNAT); сверх — 429 до Upgrade
	ConnsPer48                      = 1000                // соединений с /48 (у владельца /48 — 65 536 разных /64)
	MaxConnsDefault                 = 5000                // всех соединений (≈55 КБ на WS по TLS → ≈280 МБ); сверх — 503
)

// maxSize — потолок сообщения клиента по типу (законные: ice ≤ 268 Б, answer 5–6 КБ). Сверх — как превышение лимита.
// Без него сообщение под REQ-S-07 (64 КБ) плюс from от хаба не влезало в буфер чтения хоста (agent: 64 КБ) —
// хост рвал WS и переподключался: одно сообщение анонима выбивало хост из сети.
func maxSize(typ string) int {
	switch typ {
	case "ice":
		return 2 << 10
	case "connect":
		return 4 << 10
	case "answer":
		return 32 << 10
	}
	return 256 // bye и всё, что хаб не пересылает
}

// bucket — маркерное ведро: до burst маркеров, пополнение rate в секунду. Нулевое значение не пропускает ничего.
type bucket struct {
	burst, rate, tokens float64
	at                  time.Time
}

func newBucket(burst, rate float64) bucket {
	return bucket{burst: burst, rate: rate, tokens: burst, at: time.Now()}
}

func (b *bucket) fill() {
	now := time.Now()
	b.tokens = min(b.burst, b.tokens+now.Sub(b.at).Seconds()*b.rate)
	b.at = now
}

func (b *bucket) take(n float64) bool {
	b.fill()
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

// exempt — адреса вне лимитов «на IP»: loopback и частные. Это свой узел за обратным прокси без X-Forwarded-For
// (Docker bridge — все пользователи с одного 172.17.0.1) и тесты на 127.0.0.1. Общий потолок на них действует.
func exempt(a netip.Addr) bool {
	return !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified()
}

type limKey struct {
	key string
	max int
}

// limKeys — по каким счётчикам считать соединение с адреса a: IPv4 — адрес, IPv6 — /64 и /48.
func limKeys(a netip.Addr) []limKey {
	if exempt(a) {
		return nil
	}
	if a.Is4() {
		return []limKey{{a.String(), ConnsPerIP}}
	}
	p64, _ := a.Prefix(64)
	p48, _ := a.Prefix(48)
	return []limKey{{p64.String(), ConnsPerIP}, {p48.String(), ConnsPer48}}
}

// acquire занимает место под соединение с a: 0 — можно, иначе HTTP-код отказа (429 — лимит адреса, 503 — общий).
// Каждый успешный acquire закрывается release(a).
func (h *Hub) acquire(a netip.Addr) int {
	h.lim.Lock()
	defer h.lim.Unlock()
	if h.total >= cmp.Or(h.MaxConns, MaxConnsDefault) {
		return http.StatusServiceUnavailable
	}
	ks := limKeys(a)
	for _, k := range ks {
		if h.conns[k.key] >= k.max {
			return http.StatusTooManyRequests
		}
	}
	if h.conns == nil {
		h.conns = map[string]int{}
	}
	for _, k := range ks {
		h.conns[k.key]++
	}
	h.total++
	return 0
}

func (h *Hub) release(a netip.Addr) {
	h.lim.Lock()
	defer h.lim.Unlock()
	h.total--
	for _, k := range limKeys(a) {
		if h.conns[k.key]--; h.conns[k.key] <= 0 {
			delete(h.conns, k.key)
		}
	}
}

// notFound считает not_found для адреса a (take) или только проверяет, остался ли запас (для отказа новым WS).
// Счёт на соединение перечислению ID не мешает (новое WS на каждую пробу) — поэтому ещё и на IP.
func (h *Hub) notFound(a netip.Addr, take bool) bool {
	ks := limKeys(a)
	if ks == nil {
		return true
	}
	h.lim.Lock()
	defer h.lim.Unlock()
	if time.Since(h.nfSweep) > time.Minute { // полные вёдра не нужны: память — только под недавних нарушителей
		for k, b := range h.nf {
			if b.fill(); b.tokens >= b.burst {
				delete(h.nf, k)
			}
		}
		h.nfSweep = time.Now()
	}
	b, ok := h.nf[ks[0].key]
	if !ok {
		if !take {
			return true
		}
		if h.nf == nil {
			h.nf = map[string]*bucket{}
		}
		nb := newBucket(NotFoundPerMin, NotFoundPerMin/60.0)
		b = &nb
		h.nf[ks[0].key] = b
	}
	if take {
		return b.take(1)
	}
	b.fill()
	return b.tokens >= 1
}
