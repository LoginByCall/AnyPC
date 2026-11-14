package agent

// «Моё пространство», этап Э4: сверка состава M между членами по служебному соединению «без видео» (UI-REDESIGN.md,
// «Сверка»). Формат и правила приёма — app (SpaceSyncer); здесь только доставка. ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (CLAUDE.md
// A13: протокол, ключевой материал).
//
// Соединение — connect {"sync":true,"view":true}: вне места сессии, maxPending и блокировки перебора, не больше
// maxSyncs сразу (лишнее — "busy"); входа не даёт. Канал "auth", только добавления:
//
//	хост → {"t":"a",…,"sync":true}                     хост понимает сверку (иначе клиент кончает: ErrSpaceOld)
//	клиент → {"t":"b",cpub,csig,"key":true,"sync":true} ключ клиента доказан подписью над DTLS-отпечатками
//	хост → {"t":"sp","sync":true,pub,sig}               ключ хоста и подпись (как в "ok") — любому доказавшему ключ:
//	                                                    по ним клиент отличает чужой ПК под ID члена (С4)
//	клиент → {"t":"sp","sync":true,"m":Mc}              свой M (только хосту, чей ключ — член M клиента)
//	хост → {"t":"sp","r":R}… {"t":"sp","sync":true,"m":Mh}  записи цепочки, которых нет у клиента, и свой M
//	                                                    | {"t":"sp","err":"rights"} — ключ клиента не член
//	клиент → {"t":"sp","r":R}… {"t":"sp","ok":true,"m":Mc'} записи для хоста и свой M после приёма
//	хост → {"t":"sp","ok":true,"m":Mh'}                 свой M после приёма: равен Mc' — составы сошлись
//
// M и записи — байты marshal() (base64 в JSON); подпись владельца и правила приёма проверяет SpaceSyncer.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"anypc/pake"

	"github.com/coder/websocket"
	"github.com/pion/webrtc/v4"
)

// SpaceSyncer — состав этого ПК для сверки (app/spsync.go).
type SpaceSyncer interface {
	// SyncGate — текущий M этого ПК, если ключ pub — член (или член в составе peer того же пространства и не
	// исключён здесь); peer nil — только по своему M. nil — отказ.
	SyncGate(pub ed25519.PublicKey, peer []byte) []byte
	// SyncRecs — записи цепочки (смены входа), которых нет у peer, по порядку; без текущего M.
	SyncRecs(peer []byte) [][]byte
	// SyncApply — принять recs и затем peer (или отметить раскол); вернуть текущий M после.
	SyncApply(peer []byte, recs [][]byte) []byte
}

// ErrSpaceIDKey — под ID члена ответил ПК с другим ключом (С4): ID в составе не того ПК.
var ErrSpaceIDKey = errors.New("пространство: под ID члена ответил другой ПК")

const (
	maxSyncs    = 4  // соединений сверки одновременно
	maxSyncRecs = 32 // записей за один обмен
)

// spSync — состояние сверки на хосте (под mu).
type spSync struct {
	mu    sync.Mutex
	phase int // 0 — ждём "b"; 1 — ключ доказан, ждём M клиента; 2 — ждём записи и итог; 3 — кончено
	pub   ed25519.PublicKey
	recs  [][]byte
}

// syncConnect — connect {"sync":true}: соединение только для сверки.
func (a *Agent) syncConnect(ctx context.Context, c *websocket.Conn, cid string, req connectReq) {
	a.mu.Lock()
	busy := len(a.syncs)+a.syncStarting >= maxSyncs
	if !busy {
		a.syncStarting++
	}
	turn := pickTURN(req, a.rtt, turnHosts(a.ice))
	ice := onlyTURN(a.ice, turn)
	a.mu.Unlock()
	if busy {
		a.send(ctx, c, "error", cid, "busy")
		return
	}
	s, err := a.newSession(ctx, c, cid, ice, offerMsg{TURN: turn}, false, true, true) // offOnly: входа не даёт
	a.mu.Lock()
	a.syncStarting--
	if err == nil && !s.gone.Load() {
		s.sy.Store(&spSync{})
		if a.syncs == nil {
			a.syncs = map[*session]bool{}
		}
		a.syncs[s] = true
	}
	a.mu.Unlock()
	if err != nil {
		a.send(ctx, c, "error", cid, "internal")
	}
}

// syncB — "b" соединения сверки: доказать свой ключ доказавшему свой (иначе "denied").
func (a *Agent) syncB(s *session, m authMsg, keyOK bool, fpc, fph string, send func(any)) {
	st := s.sy.Load()
	if !m.Sync || !m.Key || !keyOK {
		send(authMsg{T: "denied"})
		a.release(s)
		time.AfterFunc(500*time.Millisecond, func() { s.pc.Close() })
		return
	}
	st.mu.Lock()
	st.phase, st.pub = 1, ed25519.PublicKey(bytes.Clone(m.CPub))
	st.mu.Unlock()
	send(spMsg{T: "sp", Sync: true, Pub: a.Key.Public().(ed25519.PublicKey), Sig: pake.HostSign(a.Key, a.ID, fpc, fph)})
}

// syncMsg — "sp" соединения сверки на хосте.
func (a *Agent) syncMsg(s *session, data []byte, send func(any)) {
	var m spMsg
	if json.Unmarshal(data, &m) != nil {
		return
	}
	st := s.sy.Load()
	end := func() {
		st.phase = 3
		a.release(s)
		time.AfterFunc(500*time.Millisecond, func() { s.pc.Close() })
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	switch {
	case st.phase == 1 && m.Sync && len(m.M) > 0:
		cur := a.SpaceSync.SyncGate(st.pub, m.M)
		if cur == nil {
			send(spMsg{T: "sp", Err: "rights"})
			end()
			return
		}
		for _, r := range a.SpaceSync.SyncRecs(m.M) {
			send(spMsg{T: "sp", R: r})
		}
		send(spMsg{T: "sp", Sync: true, M: cur})
		st.phase = 2
	case st.phase == 2 && len(m.R) > 0 && len(st.recs) < maxSyncRecs:
		st.recs = append(st.recs, m.R)
	case st.phase == 2 && m.OK && len(m.M) > 0:
		send(spMsg{T: "sp", OK: true, M: a.SpaceSync.SyncApply(m.M, st.recs)})
		end()
	default:
		send(spMsg{T: "sp", Err: "bad"})
		end()
	}
}

// SyncDial — сверка с членом ID (ключ HostPub из M этого ПК); Key — ключ хоста этого ПК.
type SyncDial struct {
	Server  string // хабы через запятую, как Agent.Server
	ID      string
	HostPub ed25519.PublicKey
	Key     ed25519.PrivateKey
	S       SpaceSyncer
}

// syncWait — весь обмен сверки.
var syncWait = 60 * time.Second

// SpaceSync — сверить состав с членом d.ID: обе стороны получают недостающие записи по порядку. same — после обмена
// M обеих сторон совпали (подтверждение); false без ошибки — разошлись (раскол или неполная цепочка — решает S).
func SpaceSync(ctx context.Context, d SyncDial) (same bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, syncWait)
	defer cancel()
	for _, u := range strings.Split(d.Server, ",") {
		if same, err = syncVia(ctx, strings.TrimSpace(u), d); !errors.Is(err, ErrSpaceOffline) {
			return same, err
		}
	}
	return false, err
}

func syncVia(ctx context.Context, server string, d SyncDial) (bool, error) {
	var (
		mu   sync.Mutex
		mine []byte // свой M после приёма (отправлен хосту)
		same bool
	)
	err := hostDial(ctx, server, d.ID, connectReq{View: true, Sync: true}, func(pc *webrtc.PeerConnection, finish func(error)) {
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			if dc.Label() != "auth" {
				return
			}
			first, proved := true, false
			var recs [][]byte
			send := func(v any) { b, _ := json.Marshal(v); dc.SendText(string(b)) }
			dc.OnMessage(func(msg webrtc.DataChannelMessage) {
				var am authMsg
				var sm spMsg
				if json.Unmarshal(msg.Data, &am) != nil || json.Unmarshal(msg.Data, &sm) != nil {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				switch t := am.T; {
				case t == "a" && first:
					first = false
					if !am.Sync { // старый хост: сверки нет
						finish(ErrSpaceOld)
						return
					}
					cpub, csig, err := signB(d.Key, d.ID, pc)
					if err != nil {
						finish(err)
						return
					}
					send(authMsg{T: "b", CPub: cpub, CSig: csig, Key: true, Sync: true})
				case t == "sp" && sm.Err != "":
					finish(fmt.Errorf("%w: %s", ErrSpaceRefused, sm.Err))
				case t == "sp" && !proved && sm.Sync:
					fc, fh := pake.Fingerprint(pc.LocalDescription().SDP), pake.Fingerprint(pc.RemoteDescription().SDP)
					switch {
					case pake.HostVerify(sm.Pub, sm.Sig, d.ID, fc, fh) != nil:
						finish(ErrSpaceHostKey)
					case !bytes.Equal(sm.Pub, d.HostPub):
						finish(ErrSpaceIDKey)
					default:
						proved = true
						m := d.S.SyncGate(d.HostPub, nil)
						if m == nil {
							finish(ErrSpaceRefused)
							return
						}
						send(spMsg{T: "sp", Sync: true, M: m})
					}
				case t == "sp" && proved && len(sm.R) > 0 && mine == nil && len(recs) < maxSyncRecs:
					recs = append(recs, sm.R)
				case t == "sp" && proved && sm.Sync && len(sm.M) > 0 && mine == nil:
					mine = d.S.SyncApply(sm.M, recs)
					for _, r := range d.S.SyncRecs(sm.M) {
						send(spMsg{T: "sp", R: r})
					}
					send(spMsg{T: "sp", OK: true, M: mine})
				case t == "sp" && proved && sm.OK && mine != nil:
					same = bytes.Equal(sm.M, mine)
					finish(nil)
				case t == "denied" || t == "busy":
					finish(fmt.Errorf("%w: %s", ErrSpaceRefused, t))
				case t == "sp":
					finish(errSpaceProtocol)
				}
			})
		})
	})
	mu.Lock()
	defer mu.Unlock()
	return same, err
}
