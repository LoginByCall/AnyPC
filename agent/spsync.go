package agent

// «Моё пространство», этап Э4: сверка состава M между членами по служебному соединению «без видео» (UI-REDESIGN.md,
// «Сверка»). Формат и правила приёма — app (SpaceSyncer); здесь только доставка. ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (CLAUDE.md
// A13: протокол, ключевой материал).
//
// Соединение — connect того же вида, что вступление и пропуск ({"view":true,"sx":…}, Э4в): sx — доказательство
// ключа члена, запечатанное к ключу хоста из M клиента (spseal.go; хаб не отличит его от случайных байт обычного
// connect). Хост открывает sx ключами членов своего M до того, как что-то выделить: не открылось, часы расходятся
// больше syncSkew, повтор, место ключа занято — обычный connect (место сессии, maxPending, блокировка), статус — в "a";
// иначе место — одно на ключ члена, не вытесняется, вне maxPending и блокировки перебора (решение владельца
// 2026-11-14, A); места сессии не занимает, но пока сессия идёт, сверка получает тот же "busy"/"locked", что обычный
// connect (syncConnect); входа не даёт. Канал "auth", только добавления:
//
//	хост → {"t":"a",…,"sync":true,"sx":X}              хост понимает сверку (иначе клиент кончает: ErrSpaceOld); X —
//	                                                    статус под ключом из sx, привязан к DTLS: ok — дальше;
//	                                                    skew — ErrSpaceSkew; busy — отказ; не открылся — "who"
//	клиент → {"t":"who"}  хост → {"t":"who",pub,sig}    ключ хоста: тот, что в M, — цель не считает этот ПК членом
//	                                                    (отказ); другой — под ID члена другой ПК (ErrSpaceIDKey, С4)
//	клиент → {"t":"b",cpub,csig,"key":true,"sync":true,"pub":P}  cpub — ключ из sx, подпись над DTLS-отпечатками; P —
//	                                                    ключ хоста из M клиента
//	хост → {"t":"sp","sync":true,pub,sig}               это он (pub = P): подпись хоста, как в "ok"
//	       | {"t":"sp","err":"notme"}                   P — не его ключ (не бывает: sx открылся его ключом)
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
	"maps"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"anypc/pake"

	"github.com/coder/websocket"
	"github.com/pion/webrtc/v4"
)

// SpaceSyncer — состав этого ПК для сверки (app/spsync.go).
type SpaceSyncer interface {
	// SyncKey — pub — ключ члена этого ПК (или ветви раскола, известной здесь), не исключённый и не свой.
	SyncKey(pub ed25519.PublicKey) bool
	// SyncKeys — все ключи, для которых SyncKey — true: ими хост открывает sx connect (spseal.go).
	SyncKeys() []ed25519.PublicKey
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
	syncSkew    = 10 * time.Minute
	maxSyncRecs = 32 // записей за один обмен
)

// syncTamper — тест: подделка на одной стороне, проверка — на другой: "host"/"client" — ID в подписи; "hostkey" —
// хост подписывает чужим ключом; "sx" — sx клиента сбит; "old" — время в sx за окном; "cpub" — клиент в "b"
// доказывает не тот ключ, что в connect; "early" — клиент шлёт M до "b".
var syncTamper atomic.Value

func syncFake(side string) bool { s, _ := syncTamper.Load().(string); return s == side }

// syncOther — постоянный посторонний ключ для syncTamper.
var syncOther = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

func syncID(side, id string) string {
	if s, _ := syncTamper.Load().(string); s == side {
		return id + "x"
	}
	return id
}

// spSync — состояние сверки на хосте (под mu).
type spSync struct {
	mu    sync.Mutex
	phase int               // 1 — ждём "b"; 2 — ждём M клиента; 3 — ждём записи и итог; 4 — кончено
	pub   ed25519.PublicKey // ключ члена, доказанный в connect
	recs  [][]byte
}

// whoResult — клиент сверки, чей sx не открылся: ответ хоста на "who" (am) в соединении с отпечатками fc, fh. Подпись
// не над этими отпечатками — ErrSpaceHostKey (посредник в DTLS или подделка); ключ тот, что в M клиента (want), — цель
// не считает этот ПК членом (ErrSpaceRefused); другой — под ID члена другой ПК (ErrSpaceIDKey, С4). Всегда ошибка.
func whoResult(am authMsg, id string, want ed25519.PublicKey, fc, fh string) error {
	switch {
	case pake.HostVerify(am.Pub, am.Sig, id, fc, fh) != nil:
		return ErrSpaceHostKey
	case bytes.Equal(am.Pub, want):
		return fmt.Errorf("%w: rights", ErrSpaceRefused) // тот ПК, но этот ПК там не член
	default:
		return ErrSpaceIDKey
	}
}

// syncConnect — connect, чей sx открылся ключом члена pub (spseal.go, sxCheck): доказательство до того, как выделить
// место. false — место ключа занято: seal.status = sxBusy, вызывающий ведёт connect как обычный. Идёт сессия —
// ответ тот же, что обычному connect без ключа ("locked" или "busy"): хаб, сам получив "busy", узнал бы сверку по offer.
func (a *Agent) syncConnect(ctx context.Context, c *websocket.Conn, cid string, req connectReq, pub ed25519.PublicKey, seal *sxSeal) bool {
	k := string(pub)
	a.mu.Lock()
	refuse := ""
	switch {
	case a.sess != nil && time.Now().Before(a.lockUntil):
		refuse = "locked"
	case a.sess != nil:
		refuse = "busy"
	}
	_, busy := a.syncs[k]
	if !busy && refuse == "" {
		if a.syncs == nil {
			a.syncs = map[string]*session{}
		}
		a.syncs[k] = nil // место занято, пока newSession шлёт offer
	}
	turn := pickTURN(req, a.rtt, turnHosts(a.ice))
	ice, rtt := onlyTURN(a.ice, turn), maps.Clone(a.rtt)
	a.mu.Unlock()
	switch {
	case refuse != "":
		a.send(ctx, c, "error", cid, refuse)
		return true
	case busy:
		seal.status = sxBusy
		return false
	}
	s, err := a.newSession(ctx, c, cid, ice, offerMsg{TURN: turn, RTT: rtt}, false, true, true, seal) // offOnly: входа не даёт
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
	return true
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
		key := a.Key
		if syncFake("hostkey") {
			key = syncOther
		}
		send(spMsg{T: "sp", Sync: true, Pub: key.Public().(ed25519.PublicKey), Sig: pake.HostSign(key, syncID("host", a.ID), fpc, fph)})
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
	now := time.Now()
	if syncFake("old") {
		now = now.Add(-syncSkew - time.Minute)
	}
	sx, h2c, err := sxMake(d.Key, d.HostPub, d.ID, now.Unix())
	if err != nil {
		return nil, err
	}
	if syncFake("sx") {
		sx[len(sx)-1] ^= 1
	}
	req := connectReq{View: true, SX: sx} // как у вступления и пропуска (hostDial): хаб сверку не отличит
	err = hostDial(ctx, server, d.ID, req, func(pc *webrtc.PeerConnection, finish func(error)) {
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			if dc.Label() != "auth" {
				return
			}
			first, proved, who := true, false, false
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
				fps := func() (string, string) {
					return pake.Fingerprint(pc.LocalDescription().SDP), pake.Fingerprint(pc.RemoteDescription().SDP)
				}
				switch t := am.T; {
				case t == "a" && first:
					first = false
					if !am.Sync || am.SX == nil { // старый хост: сверки нет
						finish(ErrSpaceOld)
						return
					}
					fc, fh := fps()
					st, ok := sxStatus(h2c, am.SX, fc, fh)
					switch {
					case !ok: // не тот ПК, не член там или посредник в DTLS — спросить ключ
						who = true
						send(authMsg{T: "who"})
						return
					case st == sxSkew:
						finish(ErrSpaceSkew)
						return
					case st != sxOK:
						finish(fmt.Errorf("%w: busy", ErrSpaceRefused))
						return
					}
					key := d.Key
					if syncFake("cpub") {
						key = syncOther
					}
					if syncFake("early") {
						send(spMsg{T: "sp", Sync: true, M: d.S.SyncGate(d.HostPub, nil)})
					}
					cpub, csig, err := signB(key, syncID("client", d.ID), pc)
					if err != nil {
						finish(err)
						return
					}
					send(authMsg{T: "b", CPub: cpub, CSig: csig, Key: true, Sync: true, Pub: d.HostPub})
				case t == "who" && who:
					who = false
					fc, fh := fps()
					finish(whoResult(am, d.ID, d.HostPub, fc, fh))
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
