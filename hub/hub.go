// Package hub — сервер сигнализации: пересылает сообщения между хостом и клиентом
// и выдаёт временные учётки TURN. Содержимое сессии через него не идёт.
package hub

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

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
	TurnHost   string // "" — без STUN/TURN (локальная отладка)
	TurnSecret string // static-auth-secret coturn; "" — только STUN

	mu    sync.Mutex
	peers map[string]*websocket.Conn
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

func (h *Hub) ICEServers(id string) []ICEServer {
	if h.TurnHost == "" {
		return nil
	}
	s := []ICEServer{{URLs: []string{"stun:" + h.TurnHost + ":3478"}}}
	if h.TurnSecret != "" {
		user := fmt.Sprintf("%d:%s", time.Now().Add(TurnTTL).Unix(), id)
		mac := hmac.New(sha1.New, []byte(h.TurnSecret))
		mac.Write([]byte(user))
		s = append(s, ICEServer{
			URLs:       []string{"turn:" + h.TurnHost + ":3478?transport=udp", "turn:" + h.TurnHost + ":3478?transport=tcp"},
			Username:   user,
			Credential: base64.StdEncoding.EncodeToString(mac.Sum(nil)),
		})
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

// ServeHTTP: /ws?host=<ID> — регистрация хоста, /ws — клиент.
// ponytail: ID хоста не привязан к ключу (squatting возможен) — Э1, REQ-F-01.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("host")
	if id != "" && !IsHostID(id) {
		http.Error(w, "bad host id", http.StatusBadRequest)
		return
	}
	// Origin: свой сайт, окно AnyPC.exe (страница с 127.0.0.1) и агент (без Origin).
	// У сигнализации нет cookie/полномочий, поэтому проверка Origin здесь не защита, а гигиена.
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"127.0.0.1:*"}})
	if err != nil {
		return
	}
	defer c.CloseNow()
	c.SetReadLimit(64 << 10) // REQ-S-07
	ctx := r.Context()
	if id == "" {
		id = "c" + RandDigits(12)
	}
	if !h.add(id, c) {
		send(ctx, c, errMsg("id_taken"))
		return
	}
	defer h.del(id, c)

	hello, _ := json.Marshal(map[string]any{"id": id, "ice": h.ICEServers(id)})
	send(ctx, c, Msg{V: 1, Type: "hello", Data: hello})
	for {
		var m Msg
		if err := wsjson.Read(ctx, c, &m); err != nil {
			return
		}
		if m.To == "" {
			continue
		}
		if IsHostID(id) == IsHostID(m.To) { // только хост ↔ клиент
			send(ctx, c, errMsg("forbidden"))
			continue
		}
		dst := h.get(m.To)
		if dst == nil {
			send(ctx, c, errMsg("not_found"))
			continue
		}
		m.V, m.From = 1, id
		send(ctx, dst, m)
	}
}
