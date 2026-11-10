package hub

import (
	"cmp"
	"log"
	"net/http"
	"net/netip"
	"time"

	"github.com/coder/websocket"
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
	ToHostBurst, ToHostRate         = 256 << 10, 64 << 10 // байт всех клиентов вместе одному хосту (попытка ≈20 КБ); сверх — молча отбросить
	NotFoundPerConn                 = 5                   // not_found клиенту на соединение; следующий — закрыть
	NotFoundPerMin                  = 30                  // not_found на IPv4 и /64 (/48 — ×10) в минуту; сверх — закрыть и 429 новым клиентским WS
	NewClientBurst, NewClientRate   = 60, 1               // новых клиентских WS с адреса (IPv4, /64; /48 — ×10): всплеск, в секунду; сверх — 429 до Upgrade
	ConnsPerIP                      = 100                 // соединений с адреса IPv4 или /64 (офис, школа, CGNAT); сверх — 429 до Upgrade
	ConnsPer48                      = 1000                // соединений с /48 (у владельца /48 — 65 536 разных /64)
	MaxConnsDefault                 = 5000                // всех соединений (≈55 КБ на WS по TLS → ≈280 МБ); сверх — 503
)

// maxSize — потолок сообщения клиента по типу (законные: ice ≤ 268 Б, answer 5–6 КБ). Сверх — как превышение лимита.
// Без него сообщение под REQ-S-07 (64 КБ) плюс from от хаба не влезало в буфер чтения хоста (agent: 64 КБ) —
// хост рвал WS и переподключался: одно сообщение анонима выбивало хост из сети. Потолок держит, только пока
// хаб пересылает без экранирования HTML (encode, N1): иначе 32 КБ из «<» уходили хосту как 192 КБ.
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
// Счёт на соединение перечислению ID не мешает (новое WS на каждую пробу) — поэтому ещё и на адрес: IPv4, /64 и /48 (D5).
func (h *Hub) notFound(a netip.Addr, take bool) bool {
	return h.perAddr(&h.nf, a, NotFoundPerMin, NotFoundPerMin/60.0, take)
}

// sweep — раз в минуту убрать полные вёдра «на адрес»: память — только под недавних клиентов. Под h.lim.
func (h *Hub) sweep() {
	if time.Since(h.sweepAt) < time.Minute {
		return
	}
	for _, m := range []map[string]*bucket{h.nf, h.fresh} {
		for k, b := range m {
			if b.fill(); b.tokens >= b.burst {
				delete(m, k)
			}
		}
	}
	h.sweepAt = time.Now()
}

// perAddr снимает маркер со всех вёдер адреса a в *m (все или ничего; take == false — только проверить запас).
// Ключи — как у соединений (limKeys): IPv4 — адрес, IPv6 — /64 и /48; ведро /48 в ConnsPer48/ConnsPerIP раз шире,
// иначе у владельца /48 65 536 независимых вёдер /64. Нет записи — ведро полное. Loopback и частные — без лимита.
func (h *Hub) perAddr(m *map[string]*bucket, a netip.Addr, burst, rate float64, take bool) bool {
	ks := limKeys(a)
	if ks == nil {
		return true
	}
	h.lim.Lock()
	defer h.lim.Unlock()
	h.sweep()
	var bs []*bucket
	for _, k := range ks {
		b := (*m)[k.key]
		if b == nil {
			if !take {
				continue
			}
			if *m == nil {
				*m = map[string]*bucket{}
			}
			f := float64(k.max) / ConnsPerIP
			nb := newBucket(burst*f, rate*f)
			b = &nb
			(*m)[k.key] = b
		}
		if b.fill(); b.tokens < 1 {
			return false
		}
		bs = append(bs, b)
	}
	if take {
		for _, b := range bs {
			b.tokens--
		}
	}
	return true
}

// newClient — можно ли открыть ещё одно клиентское WS с адреса a (D1). Ведро connect живёт в соединении:
// без этого WS → 5 connect → закрыть → повторить давало тысячи connect в секунду до хоста с одного IP.
func (h *Hub) newClient(a netip.Addr) bool {
	return h.perAddr(&h.fresh, a, NewClientBurst, NewClientRate, true)
}

// hostIn — ведро байт от всех клиентов к одному хосту (D2): ведро клиента ограничивает одно соединение, а сотни
// соединений вместе переполняли буфер записи медленного хоста — запись ждала дольше 5 с, и хаб закрывал WS хоста.
type hostIn struct {
	c         *websocket.Conn // чья запись: после переподключения хоста старое соединение чужую не снимает
	b         bucket
	dropped   int
	droppedAt time.Time
}

func (h *Hub) hostOpen(id string, c *websocket.Conn) {
	h.lim.Lock()
	defer h.lim.Unlock()
	if h.in == nil {
		h.in = map[string]*hostIn{}
	}
	h.in[id] = &hostIn{c: c, b: newBucket(ToHostBurst, ToHostRate)}
}

func (h *Hub) hostClose(id string, c *websocket.Conn) {
	h.lim.Lock()
	defer h.lim.Unlock()
	if in := h.in[id]; in != nil && in.c == c {
		delete(h.in, id)
	}
}

// toHost — можно ли переслать хосту id ещё n байт от клиентов. Нет — сообщение отбрасывается молча: ни клиент
// (законный в общей очереди), ни хост не закрываются; в журнал — не чаще раза в минуту.
func (h *Hub) toHost(id string, n int) bool {
	h.lim.Lock()
	defer h.lim.Unlock()
	in := h.in[id]
	if in == nil || in.b.take(float64(n)) { // нет записи — хост уходит или только что пришёл
		return true
	}
	if in.dropped++; time.Since(in.droppedAt) > time.Minute {
		log.Printf("hub: клиентов к хосту %s сверх %d КБ/с, отброшено %d", id, ToHostRate>>10, in.dropped)
		in.dropped, in.droppedAt = 0, time.Now()
	}
	return false
}
