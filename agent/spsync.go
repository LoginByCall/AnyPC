package agent

// «Моё пространство», этап Э4: сверка состава M между членами по служебному соединению «без видео» (UI-REDESIGN.md,
// «Сверка»). Формат и правила приёма — app (SpaceSyncer); здесь только доставка. ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (CLAUDE.md
// A13: протокол, ключевой материал).
//
// Соединение — connect {"sync":true,"view":true,"spub","st","ssig","hpub"}: ssig — подпись ключом члена spub над
// (syncDomain, ID хоста, st — время unix), hpub — ключ хоста из M клиента (не его — "notme" без ключа: под ID члена
// другой ПК, С4). Хост проверяет подпись по ключам членов своего M до того, как что-то выделить:
// недоказанному — ничего ("rights"), часы расходятся больше syncSkew — "skew"; место — одно на ключ члена, не
// вытесняется ("busy"), вне места сессии, maxPending и блокировки перебора; входа не даёт. Канал "auth", только
// добавления:
//
//	хост → {"t":"a",…,"sync":true}                     хост понимает сверку (иначе клиент кончает: ErrSpaceOld)
//	клиент → {"t":"b",cpub,csig,"key":true,"sync":true,"pub":P}  cpub = spub, подпись над DTLS-отпечатками; P —
//	                                                    ключ хоста из M клиента
//	хост → {"t":"sp","sync":true,pub,sig}               это он (pub = P): подпись хоста, как в "ok"
//	       | {"t":"sp","err":"notme"}                   P — не его ключ (под ID члена другой ПК, С4); ключа не выдаёт
//	клиент → {"t":"sp","sync":true,"m":Mc}              свой M (только хосту с ключом P)
//	хост → {"t":"sp","r":R}… {"t":"sp","sync":true,"m":Mh}  записи цепочки, которых нет у клиента, и свой M
//	                                                    | {"t":"sp","err":"rights"}
//	клиент → {"t":"sp","r":R}… {"t":"sp","ok":true,"m":Mc'} записи для хоста и свой M после приёма
//	хост → {"t":"sp","ok":true,"m":Mh'}                 свой M после приёма (подтверждение сверяет app по подписи)
//
// M и записи — байты marshal() (base64 в JSON); подпись владельца и правила приёма проверяет SpaceSyncer.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"anypc/pake"

	"github.com/coder/websocket"
	"github.com/pion/webrtc/v4"
)

// SpaceSyncer — состав этого ПК для сверки (app/spsync.go).
type SpaceSyncer interface {
	// SyncKey — pub — ключ члена этого ПК (или ветви раскола, известной здесь), не исключённый и не свой.
	SyncKey(pub ed25519.PublicKey) bool
	// SyncGate — текущий M этого ПК, если ключ pub — член (или член в составе peer того же пространства и не
	// исключён здесь); peer nil — только по своему M. nil — отказ.
	SyncGate(pub ed25519.PublicKey, peer []byte) []byte
	// SyncRecs — записи цепочки (смены входа), которых нет у peer, по порядку; без текущего M.
	SyncRecs(peer []byte) [][]byte
	// SyncApply — принять recs и затем peer (или отметить раскол); вернуть текущий M после.
	SyncApply(peer []byte, recs [][]byte) []byte
}

var (
	// ErrSpaceIDKey — под ID члена ответил ПК с другим ключом (С4): ID в составе не того ПК.
	ErrSpaceIDKey = errors.New("пространство: под ID члена ответил другой ПК")
	// ErrSpaceSkew — часы этого ПК и хоста расходятся больше syncSkew: сверка не принята.
	ErrSpaceSkew = errors.New("пространство: часы этого ПК и того ПК расходятся — проверьте время")
)

const (
	syncDomain  = "anypc-space-sync-v1\x00"
	syncSkew    = 10 * time.Minute
	maxSyncRecs = 32 // записей за один обмен
)

// syncProof — подписываемое доказательство ключа члена в connect.
func syncProof(hostID string, t int64) []byte {
	return []byte(syncDomain + hostID + "\x00" + strconv.FormatInt(t, 10))
}

// Испытательные подмены сверки: в рабочем пути — тождество; подделки (syncTamper, syncOther) — только в
// agent/spsync_test.go.
var (
	syncHostKey = func(k ed25519.PrivateKey) ed25519.PrivateKey { return k } // ключ подписи хоста в "sp"
	syncCliKey  = func(k ed25519.PrivateKey) ed25519.PrivateKey { return k } // ключ клиента в "b"
	syncSignID  = func(side, id string) string { return id }                 // ID в подписи стороны side
	syncEarly   = func() bool { return false }                               // клиент шлёт M до "b"
)

// spSync — состояние сверки на хосте (под mu).
type spSync struct {
	mu    sync.Mutex
	phase int               // 1 — ждём "b"; 2 — ждём M клиента; 3 — ждём записи и итог; 4 — кончено
	pub   ed25519.PublicKey // ключ члена, доказанный в connect
	recs  [][]byte
}

// syncConnect — connect {"sync":true}: доказательство ключа члена до того, как выделить место.
func (a *Agent) syncConnect(ctx context.Context, c *websocket.Conn, cid string, req connectReq) {
	pub := ed25519.PublicKey(req.SPub)
	sigOK := len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, syncProof(a.ID, req.ST), req.SSig)
	switch {
	case sigOK && !bytes.Equal(req.HPub, a.Key.Public().(ed25519.PublicKey)): // клиент ждёт под этим ID другой ПК (С4)
		a.send(ctx, c, "error", cid, "notme")
		return
	case !sigOK || !a.SpaceSync.SyncKey(pub):
		a.send(ctx, c, "error", cid, "rights")
		return
	case time.Since(time.Unix(req.ST, 0)).Abs() > syncSkew:
		a.send(ctx, c, "error", cid, "skew")
		return
	}
	k := string(pub)
	a.mu.Lock()
	_, busy := a.syncs[k]
	if !busy {
		if a.syncs == nil {
			a.syncs = map[string]*session{}
		}
		a.syncs[k] = nil // место занято, пока newSession шлёт offer
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
	if err == nil && !s.gone.Load() {
		s.sy.Store(&spSync{phase: 1, pub: bytes.Clone(pub)})
		a.syncs[k] = s
	} else {
		delete(a.syncs, k)
	}
	a.mu.Unlock()
	if err != nil {
		a.send(ctx, c, "error", cid, "internal")
	}
}

// syncDrop — место сверки сессии s свободно (release).
func (a *Agent) syncDrop(s *session) {
	for k, v := range a.syncs {
		if v == s {
			delete(a.syncs, k)
		}
	}
}

// syncEnd — сверка кончена: место свободно, соединение закрыть, дав дойти ответу.
func (a *Agent) syncEnd(s *session) {
	a.release(s)
	time.AfterFunc(500*time.Millisecond, func() { s.pc.Close() })
}

// syncB — "b" соединения сверки: ключ cpub — доказанный в connect и подписью над отпечатками; хост доказывает свой,
// только если клиент ждёт именно его (иначе "notme" без ключа).
func (a *Agent) syncB(s *session, m authMsg, keyOK bool, fpc, fph string, send func(any)) {
	st := s.sy.Load()
	st.mu.Lock()
	defer st.mu.Unlock()
	me := a.Key.Public().(ed25519.PublicKey)
	switch {
	case st.phase != 1 || !m.Sync || !m.Key || !keyOK || !bytes.Equal(m.CPub, st.pub):
		send(authMsg{T: "denied"})
	case !bytes.Equal(m.Pub, me):
		send(spMsg{T: "sp", Err: "notme"})
	default:
		st.phase = 2
		key := syncHostKey(a.Key)
		send(spMsg{T: "sp", Sync: true, Pub: key.Public().(ed25519.PublicKey), Sig: pake.HostSign(key, syncSignID("host", a.ID), fpc, fph)})
		return
	}
	st.phase = 4
	a.syncEnd(s)
}

// syncMsg — "sp" соединения сверки на хосте.
func (a *Agent) syncMsg(s *session, data []byte, send func(any)) {
	var m spMsg
	if json.Unmarshal(data, &m) != nil {
		return
	}
	st := s.sy.Load()
	st.mu.Lock()
	defer st.mu.Unlock()
	switch {
	case st.phase == 2 && m.Sync && len(m.M) > 0:
		cur := a.SpaceSync.SyncGate(st.pub, m.M)
		if cur == nil {
			send(spMsg{T: "sp", Err: "rights"})
			break
		}
		for _, r := range a.SpaceSync.SyncRecs(m.M) {
			send(spMsg{T: "sp", R: r})
		}
		send(spMsg{T: "sp", Sync: true, M: cur})
		st.phase = 3
		return
	case st.phase == 3 && len(m.R) > 0 && len(st.recs) < maxSyncRecs:
		st.recs = append(st.recs, m.R)
		return
	case st.phase == 3 && m.OK && len(m.M) > 0:
		send(spMsg{T: "sp", OK: true, M: a.SpaceSync.SyncApply(m.M, st.recs)})
	default:
		send(spMsg{T: "sp", Err: "bad"})
	}
	st.phase = 4
	a.syncEnd(s)
}

// SyncDial — сверка с членом ID (ключ HostPub из M этого ПК); Key — ключ хоста этого ПК (ключ члена).
type SyncDial struct {
	Server  string // хабы через запятую, как Agent.Server
	ID      string
	HostPub ed25519.PublicKey
	Key     ed25519.PrivateKey
	S       SpaceSyncer
}

// syncWait — весь обмен сверки.
var syncWait = 60 * time.Second

// SpaceSync — сверить состав с членом d.ID: обе стороны получают недостающие записи по порядку. Итог — M хоста после
// обмена (подтверждение: совпал ли он с M этого ПК, проверяет вызывающий по подписи).
func SpaceSync(ctx context.Context, d SyncDial) (hostM []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, syncWait)
	defer cancel()
	for _, u := range strings.Split(d.Server, ",") {
		if hostM, err = syncVia(ctx, strings.TrimSpace(u), d); !errors.Is(err, ErrSpaceOffline) {
			return hostM, err
		}
	}
	return nil, err
}

func syncVia(ctx context.Context, server string, d SyncDial) ([]byte, error) {
	var (
		mu    sync.Mutex
		mine  []byte // свой M после приёма (отправлен хосту)
		hostM []byte
	)
	now := time.Now().Unix()
	req := connectReq{View: true, Sync: true, SPub: d.Key.Public().(ed25519.PublicKey), ST: now, SSig: ed25519.Sign(d.Key, syncProof(d.ID, now)), HPub: d.HostPub}
	err := hostDial(ctx, server, d.ID, req, func(pc *webrtc.PeerConnection, finish func(error)) {
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
					key := syncCliKey(d.Key)
					if syncEarly() {
						send(spMsg{T: "sp", Sync: true, M: d.S.SyncGate(d.HostPub, nil)})
					}
					cpub, csig, err := signB(key, syncSignID("client", d.ID), pc)
					if err != nil {
						finish(err)
						return
					}
					send(authMsg{T: "b", CPub: cpub, CSig: csig, Key: true, Sync: true, Pub: d.HostPub})
				case t == "sp" && sm.Err == "notme":
					finish(ErrSpaceIDKey)
				case t == "sp" && sm.Err != "":
					finish(fmt.Errorf("%w: %s", ErrSpaceRefused, sm.Err))
				case t == "sp" && !proved && sm.Sync:
					fc, fh := pake.Fingerprint(pc.LocalDescription().SDP), pake.Fingerprint(pc.RemoteDescription().SDP)
					if !bytes.Equal(sm.Pub, d.HostPub) || pake.HostVerify(sm.Pub, sm.Sig, d.ID, fc, fh) != nil {
						finish(ErrSpaceHostKey)
						return
					}
					proved = true
					m := d.S.SyncGate(d.HostPub, nil)
					if m == nil {
						finish(ErrSpaceRefused)
						return
					}
					send(spMsg{T: "sp", Sync: true, M: m})
				case t == "sp" && proved && len(sm.R) > 0 && mine == nil && len(recs) < maxSyncRecs:
					recs = append(recs, sm.R)
				case t == "sp" && proved && sm.Sync && len(sm.M) > 0 && mine == nil:
					mine = d.S.SyncApply(sm.M, recs)
					for _, r := range d.S.SyncRecs(sm.M) {
						send(spMsg{T: "sp", R: r})
					}
					send(spMsg{T: "sp", OK: true, M: mine})
				case t == "sp" && proved && sm.OK && mine != nil:
					hostM = bytes.Clone(sm.M)
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
	return hostM, err
}
