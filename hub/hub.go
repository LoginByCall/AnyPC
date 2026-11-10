// Package hub — сервер сигнализации: пересылает сообщения между хостом и клиентом
// и выдаёт временные учётки TURN. Содержимое сессии через него не идёт.
package hub

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"anypc/pake"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// Msg — конверт сигнализации (ТЗ §7). From проставляет только сервер.
type Msg struct {
	V    int             `json:"v"`
	Type string          `json:"type"`
	To   string          `json:"to,omitempty"`
	From string          `json:"from,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// TurnTTL: coturn проверяет срок учётки и при refresh аллокации, поэтому TTL ≥ длины сессии.
const TurnTTL = 24 * time.Hour

type Hub struct {
	TurnHosts  []string      // STUN/TURN по порядку предпочтения (общий TurnSecret); пусто — без них (локальная отладка)
	TurnSecret string        // static-auth-secret coturn; "" — только STUN
	Keys       string        // файл привязок ID → ключ хоста (JSON); "" — только в памяти
	Ping       time.Duration // проверка живости соединений; 0 — PingEvery
	MaxConns   int           // потолок всех соединений; 0 — MaxConnsDefault

	mu    sync.Mutex
	peers map[string]*websocket.Conn
	keys  map[string]string // ID → публичный ключ (base64url)
	news  map[string]int    // новых привязок с IP за текущий час
	newAt time.Time

	lim     sync.Mutex         // лимиты F4 (limit.go)
	conns   map[string]int     // открытых соединений по адресу IPv4 / префиксу IPv6
	total   int                // всех открытых соединений
	nf      map[string]*bucket // not_found по адресу
	nfSweep time.Time
}

// NewPerHour — новых ID с одного IP в час. Привязка вечная, файл переписывается целиком:
// без лимита поток регистраций случайных ID раздувает hosts.json и память хаба.
// ponytail: файл O(n) на каждую новую привязку — дозапись, если узел вырастет до сотен тысяч хостов.
const NewPerHour = 20

// bind закрепляет ID за ключом при первой регистрации (REQ-F-01); чужой ключ для занятого ID — отказ.
func (h *Hub) bind(id, key, ip string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.keys == nil {
		h.keys = map[string]string{}
		if b, err := os.ReadFile(h.Keys); err == nil {
			json.Unmarshal(b, &h.keys)
		}
	}
	if k, ok := h.keys[id]; ok {
		if k != key {
			return "id_taken"
		}
		return ""
	}
	if time.Since(h.newAt) > time.Hour {
		h.news, h.newAt = map[string]int{}, time.Now()
	}
	if h.news[ip] >= NewPerHour {
		return "limit"
	}
	h.news[ip]++
	h.keys[id] = key
	if h.Keys != "" {
		b, _ := json.Marshal(h.keys)
		tmp := h.Keys + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil {
			os.Rename(tmp, h.Keys)
		}
	}
	return ""
}

// register: вызов → подпись ключом хоста (proof of possession), затем привязка ID.
func (h *Hub) register(ctx context.Context, c *websocket.Conn, id, ip string, pub ed25519.PublicKey) string {
	nb := make([]byte, 32)
	rand.Read(nb)
	nonce := base64.RawURLEncoding.EncodeToString(nb)
	d, _ := json.Marshal(nonce)
	send(ctx, c, Msg{V: 1, Type: "challenge", Data: d})
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var m Msg
	var reg struct{ Sig []byte }
	if wsjson.Read(rctx, c, &m) != nil || m.Type != "register" || json.Unmarshal(m.Data, &reg) != nil ||
		!ed25519.Verify(pub, pake.RegisterMsg(id, nonce), reg.Sig) {
		return "bad_sig"
	}
	return h.bind(id, base64.RawURLEncoding.EncodeToString(pub), ip)
}

// remoteIP — адрес для лимита регистраций. За обратным прокси на loopback (README: -addr 127.0.0.1:8080) —
// последний X-Forwarded-For (его дописал наш прокси); IPv6 — по /64 (внутри префикса адресов без счёта).
func remoteIP(r *http.Request) string {
	ip := clientAddr(r)
	if !ip.IsValid() {
		h, _, _ := net.SplitHostPort(r.RemoteAddr)
		return h
	}
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.String()
	}
	return ip.String()
}

// clientAddr — адрес клиента по той же логике (X-Forwarded-For — только от loopback); не разобран — нулевой.
func clientAddr(r *http.Request) netip.Addr {
	h, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip, err := netip.ParseAddr(h)
	if err != nil {
		return netip.Addr{}
	}
	if xff := r.Header.Values("X-Forwarded-For"); ip.IsLoopback() && len(xff) > 0 {
		all := strings.Split(xff[len(xff)-1], ",")
		if a, err := netip.ParseAddr(strings.TrimSpace(all[len(all)-1])); err == nil {
			ip = a
		}
	}
	return ip.Unmap()
}

// IsHostID: ID хоста — 9 цифр, первая ненулевая. Клиенты получают "c…".
func IsHostID(id string) bool {
	if len(id) != 9 || id[0] == '0' {
		return false
	}
	for _, c := range id {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func RandDigits(n int) string {
	b := make([]byte, n)
	for i := range b {
		d, _ := rand.Int(rand.Reader, big.NewInt(10))
		b[i] = byte('0' + d.Int64())
	}
	if b[0] == '0' {
		b[0] = '1'
	}
	return string(b)
}

func errMsg(code string) Msg {
	d, _ := json.Marshal(code)
	return Msg{V: 1, Type: "error", Data: d}
}

func send(ctx context.Context, c *websocket.Conn, m Msg) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = wsjson.Write(ctx, c, m)
}

// PingEvery — проверка живости WebSocket. Без неё обрыв (смена сети, NAT забыл маппинг) виден только
// по TCP keepalive через минуты: хост «в сети», а клиенты получают not_found, и хаб держит мёртвую запись
// (хост после переподключения — id_taken).
const PingEvery = 30 * time.Second

// Keepalive пингует c раз в every, пока жив ctx; нет ответа за every/3 — закрывает c (у читателя — ошибка чтения).
// Pong обрабатывается только при чтении: вызывать, когда c кто-то читает.
func Keepalive(ctx context.Context, c *websocket.Conn, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pctx, cancel := context.WithTimeout(ctx, every/3)
		err := c.Ping(pctx)
		cancel()
		if err != nil {
			c.CloseNow()
			return
		}
	}
}

func (h *Hub) ICEServers(id string) []ICEServer {
	var s []ICEServer
	user := fmt.Sprintf("%d:%s", time.Now().Add(TurnTTL).Unix(), id)
	mac := hmac.New(sha1.New, []byte(h.TurnSecret))
	mac.Write([]byte(user))
	for _, t := range h.TurnHosts {
		s = append(s, ICEServer{URLs: []string{"stun:" + t + ":3478"}})
		if h.TurnSecret != "" { // одна учётка на все серверы: у coturn общий static-auth-secret
			s = append(s, ICEServer{
				URLs:       []string{"turn:" + t + ":3478?transport=udp", "turn:" + t + ":3478?transport=tcp"},
				Username:   user,
				Credential: base64.StdEncoding.EncodeToString(mac.Sum(nil)),
			})
		}
	}
	return s
}

func (h *Hub) add(id string, c *websocket.Conn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peers == nil {
		h.peers = map[string]*websocket.Conn{}
	}
	if _, busy := h.peers[id]; busy {
		return false
	}
	h.peers[id] = c
	return true
}

func (h *Hub) del(id string, c *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peers[id] == c {
		delete(h.peers, id)
	}
}

func (h *Hub) get(id string) *websocket.Conn {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.peers[id]
}

// ServeHTTP: /ws?host=<ID>&key=<ed25519, base64url> — хост, /ws — клиент.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("host")
	var pub ed25519.PublicKey
	if id != "" {
		k, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("key"))
		if !IsHostID(id) || err != nil || len(k) != ed25519.PublicKeySize {
			http.Error(w, "bad host id or key", http.StatusBadRequest)
			return
		}
		pub = k
	}
	// Лимиты до Upgrade: отказ HTTP-кодом, старые клиенты видят его как «нет связи с сервером».
	addr := clientAddr(r)
	if id == "" && !h.notFound(addr, false) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many not_found", http.StatusTooManyRequests)
		return
	}
	if code := h.acquire(addr); code != 0 {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many connections", code)
		return
	}
	defer h.release(addr)
	// Origin любой: страница одного хаба ходит в соседние (резервная сигнализация), окно AnyPC.exe — с 127.0.0.1.
	// У сигнализации нет cookie/полномочий — то же доступно любому клиенту вне браузера; вход защищает CPace.
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
	if err != nil {
		return
	}
	defer c.CloseNow()
	c.SetReadLimit(64 << 10) // REQ-S-07
	ctx := r.Context()
	if id == "" {
		id = "c" + RandDigits(12)
	} else if e := h.register(ctx, c, id, remoteIP(r), pub); e != "" {
		send(ctx, c, errMsg(e))
		return
	}
	if !h.add(id, c) {
		send(ctx, c, errMsg("id_taken"))
		return
	}
	defer h.del(id, c)
	kctx, stop := context.WithCancel(ctx)
	defer stop()
	go Keepalive(kctx, c, cmp.Or(h.Ping, PingEvery))

	hello, _ := json.Marshal(map[string]any{"id": id, "ice": h.ICEServers(id)})
	send(ctx, c, Msg{V: 1, Type: "hello", Data: hello})
	isHost := IsHostID(id)
	msgs, size := newBucket(ClientMsgBurst, ClientMsgRate), newBucket(ClientByteBurst, ClientByteRate)
	connects := newBucket(ConnectBurst, 1/ConnectEvery.Seconds())
	if isHost {
		msgs, size = newBucket(HostMsgBurst, HostMsgRate), newBucket(HostByteBurst, HostByteRate)
	}
	notFound, dropped, droppedAt := 0, 0, time.Time{}
	for {
		typ, b, err := c.Read(ctx)
		if err != nil || typ != websocket.MessageText {
			return
		}
		if !msgs.take(1) || !size.take(float64(len(b))) {
			if !isHost {
				c.Close(websocket.StatusPolicyViolation, "rate limit")
				return
			}
			if dropped++; time.Since(droppedAt) > time.Minute { // хост не закрываем: его поток вызывают клиенты
				log.Printf("hub: хост %s сверх лимита, отброшено %d", id, dropped)
				dropped, droppedAt = 0, time.Now()
			}
			continue
		}
		var m Msg
		if json.Unmarshal(b, &m) != nil {
			return
		}
		if !isHost && len(b) > maxSize(m.Type) {
			c.Close(websocket.StatusPolicyViolation, "message too big")
			return
		}
		if m.To == "" {
			continue
		}
		if isHost == IsHostID(m.To) { // только хост ↔ клиент
			send(ctx, c, errMsg("forbidden"))
			continue
		}
		if !relayed(isHost, m.Type) { // Д-4: служебные типы (hello, challenge, error от клиента) не пересылаются
			send(ctx, c, errMsg("forbidden"))
			continue
		}
		if m.Type == "connect" && !connects.take(1) { // спам connect рождал offer и ice хоста на каждый
			send(ctx, c, errMsg("busy"))
			continue
		}
		dst := h.get(m.To)
		if dst == nil {
			if !isHost { // хост шлёт ушедшему клиенту законно (клиент закрыл вкладку посреди ice)
				if notFound++; notFound > NotFoundPerConn || !h.notFound(addr, true) {
					c.Close(websocket.StatusPolicyViolation, "not_found limit")
					return
				}
			}
			send(ctx, c, errMsg("not_found"))
			continue
		}
		if m.Type == "connect" { // пароль TURN живёт TurnTTL, а хост в сети неделями — свежий перед каждой сессией
			fresh, _ := json.Marshal(map[string]any{"id": m.To, "ice": h.ICEServers(m.To)})
			send(ctx, dst, Msg{V: 1, Type: "hello", Data: fresh})
		}
		m.V, m.From = 1, id
		send(ctx, dst, m)
	}
}

// relayed — что хаб пересылает: клиент → хост — connect/answer/ice/bye, хост → клиент — offer/ice/error/bye.
// Остальное (hello, challenge, error клиента) получатель принял бы за слова самого хаба.
func relayed(fromHost bool, typ string) bool {
	switch typ {
	case "ice", "bye":
		return true
	case "connect", "answer":
		return !fromHost
	case "offer", "error":
		return fromHost
	}
	return false
}
