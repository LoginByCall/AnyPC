package agent

// «Моё пространство», этап Э2 (UI-REDESIGN.md, «Проект ядра пространства»): обмен составом M по каналу ctl уже
// вошедшей сессии. Сам состав (формат, подпись владельца, правила) — app/space.go; здесь только доставка.
// ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (CLAUDE.md A13: ключевой материал, протокол).
//
// Совместимость — только добавления: хост объявляет space:true в первом "a"; старый клиент и браузер "sp" не шлют,
// старый хост "sp" пропускает (неизвестный t) — клиент вступления получает отказ «хост не поддерживает».

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"anypc/hub"
	"anypc/pake"

	"github.com/coder/websocket/wsjson"
	"github.com/pion/webrtc/v4"
)

// spMsg — канал "ctl", состав пространства (Э2). Клиент → {"t":"sp"} — запрос состава; хост → {"t":"sp","m":…}
// (запись M, base64) | {"t":"sp","err":"rights"|"none"}. Клиент → {"t":"sp","m":…} — M следующей эпохи с ним самим;
// хост → {"t":"sp","ok":true} | {"t":"sp","err":"rights"|"key"|"again"|"bad"}.
// err: rights — сессия вошла не паролем и кодом записи по умолчанию; none — пространства нет (или пароль записи
// не его); key — клиент не доказал свой ключ в "b"; again — второе вступление в сессии; bad — состав не принят.
type spMsg struct {
	T   string `json:"t"`
	M   []byte `json:"m,omitempty"`
	OK  bool   `json:"ok,omitempty"`
	Err string `json:"err,omitempty"`
}

// spaceCtl — хост: ответ на "sp" вошедшей сессии.
func (a *Agent) spaceCtl(s *session, data []byte, reply func(spMsg)) {
	var m spMsg
	if json.Unmarshal(data, &m) != nil {
		return
	}
	if !s.spaceOK.Load() {
		reply(spMsg{T: "sp", Err: "rights"})
		return
	}
	s.mu.Lock()
	salt, cpub := s.salt, s.cpub
	s.mu.Unlock()
	if len(m.M) == 0 { // запрос состава
		if b := a.SpaceGet(salt); b != nil {
			reply(spMsg{T: "sp", M: b})
		} else {
			reply(spMsg{T: "sp", Err: "none"})
		}
		return
	}
	switch {
	case a.SpaceJoin == nil || a.SpaceGet(salt) == nil: // пароль записи сменили после входа — не её пространство
		reply(spMsg{T: "sp", Err: "none"})
	case cpub == nil:
		reply(spMsg{T: "sp", Err: "key"})
	case !s.spJoin.CompareAndSwap(false, true):
		reply(spMsg{T: "sp", Err: "again"})
	default:
		if err := a.SpaceJoin(m.M, cpub); err != nil {
			log.Printf("сессия %s: состав пространства не принят: %v", s.label(), err)
			reply(spMsg{T: "sp", Err: "bad"})
			return
		}
		log.Printf("сессия %s: ПК %s вступил в пространство", s.label(), pake.KeyFingerprint(cpub)[:9])
		reply(spMsg{T: "sp", OK: true})
	}
}

// SpaceDial — клиент вступления (Э2): обычный вход на ПК пространства ID паролем Password и кодом TOTP Code записи
// по умолчанию, ключ клиента — Key (ключ хоста этого ПК: им P сверяет ключ нового члена в M). После входа: запрос
// M, Sign(M, ключ хоста P) — новый M с этим ПК (подпись владельца на этом ПК), ответ P.
type SpaceDial struct {
	Server   string             // хабы через запятую, как Agent.Server: пробуются по очереди
	ID       string             // ПК пространства P
	Key      ed25519.PrivateKey // ключ хоста этого ПК
	Password string
	Code     string
	// Sign — по M от P (проверенный подписью хоста P и CPace) вернуть новый M; ошибка — отказ, P ничего не получит.
	Sign func(m []byte, hostPub ed25519.PublicKey) ([]byte, error)
}

// Ошибки SpaceJoin (для окна в следующих этапах).
var (
	ErrSpaceOffline  = errors.New("пространство: ПК не в сети")
	ErrSpaceAuth     = errors.New("пространство: неверный пароль или код")
	ErrSpaceOld      = errors.New("пространство: на том ПК старая версия AnyPC")
	ErrSpaceAsk      = errors.New("пространство: тот ПК в режиме «Спрашивать» — нужен вход паролем и кодом")
	ErrSpaceRefused  = errors.New("пространство: тот ПК отказал")
	errSpaceProtocol = errors.New("пространство: нарушение протокола")
)

// spaceWait — весь обмен вступления (вход с Argon2 на обеих сторонах, ICE через TURN).
var spaceWait = 60 * time.Second

// SpaceJoin — вступить через ПК d.ID: вернуть новый M, который P принял. Ошибка — P его не сохранил (или ответа
// не было: тогда состояние P неизвестно, повтор безопасен — второй раз P ответит "bad" на дубль ПК).
func SpaceJoin(ctx context.Context, d SpaceDial) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, spaceWait)
	defer cancel()
	var err error
	for _, u := range strings.Split(d.Server, ",") {
		var out []byte
		if out, err = spaceJoinVia(ctx, strings.TrimSpace(u), d); !errors.Is(err, ErrSpaceOffline) {
			return out, err
		}
	}
	return nil, err
}

func spaceJoinVia(ctx context.Context, server string, d SpaceDial) ([]byte, error) {
	ws, err := dial(ctx, server)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSpaceOffline, err)
	}
	defer ws.CloseNow()
	ws.SetReadLimit(64 << 10)
	var wmu sync.Mutex
	send := func(typ string, v any) {
		b, _ := json.Marshal(v)
		wmu.Lock()
		defer wmu.Unlock()
		wsjson.Write(ctx, ws, hub.Msg{V: 1, Type: typ, To: d.ID, Data: b})
	}
	var m hub.Msg
	if err := wsjson.Read(ctx, ws, &m); err != nil || m.Type != "hello" {
		return nil, fmt.Errorf("%w: хаб не ответил", ErrSpaceOffline)
	}
	var hello struct{ ICE []webrtc.ICEServer }
	json.Unmarshal(m.Data, &hello)
	pub := d.Key.Public().(ed25519.PublicKey)
	send("connect", connectReq{CPub: pub, View: true}) // только просмотр: вступлению ввод не нужен
	if err := wsjson.Read(ctx, ws, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSpaceOffline, err)
	}
	if m.Type != "offer" {
		var why string
		json.Unmarshal(m.Data, &why)
		if m.Type == "error" && why == "not_found" {
			return nil, ErrSpaceOffline
		}
		return nil, fmt.Errorf("%w: %s %s", ErrSpaceRefused, m.Type, why)
	}
	defer send("bye", "client")
	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{ICEServers: hello.ICE})
	if err != nil {
		return nil, err
	}
	defer pc.Close()
	type result struct {
		m   []byte
		err error
	}
	done := make(chan result, 1)
	finish := func(m []byte, err error) {
		select {
		case done <- result{m, err}:
		default:
		}
	}
	var (
		mu      sync.Mutex
		hostPub ed25519.PublicKey // из "ok", подпись проверена
		ctl     *webrtc.DataChannel
		authed  bool
		asked   bool // запрос M ушёл
		newM    []byte
	)
	fps := func() (string, string) { // свой отпечаток, отпечаток хоста
		return pake.Fingerprint(pc.LocalDescription().SDP), pake.Fingerprint(pc.RemoteDescription().SDP)
	}
	askM := func() { // под mu: вход есть и ctl открыт — запросить M один раз
		if authed && ctl != nil && !asked {
			asked = true
			ctl.SendText(`{"t":"sp"}`)
		}
	}
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		switch dc.Label() {
		case "auth":
			var want []byte // ожидаемое подтверждение хоста (CPace)
			space, first := false, true
			otpN := 0
			sendA := func(v authMsg) { b, _ := json.Marshal(v); dc.SendText(string(b)) }
			hostOK := func(am authMsg) bool { // хост доказал пароль (conf) и ключ (подпись над DTLS-отпечатками)
				fc, fh := fps()
				return len(want) > 0 && bytes.Equal(am.Conf, want) && pake.HostVerify(am.Pub, am.Sig, d.ID, fc, fh) == nil
			}
			dc.OnMessage(func(msg webrtc.DataChannelMessage) {
				var am authMsg
				if json.Unmarshal(msg.Data, &am) != nil {
					return
				}
				switch am.T {
				case "a":
					if !first || am.User != "" {
						finish(nil, errSpaceProtocol)
						return
					}
					first, space = false, am.Space
					if !space {
						finish(nil, ErrSpaceOld)
						return
					}
					fc, fh := fps()
					b, conf, hc, err := pake.ClientRespond(d.Password, am.Salt, am.Msg, d.ID, fc, fh)
					if err != nil {
						finish(nil, err)
						return
					}
					want = hc
					// ключ клиента — ключ хоста этого ПК: P сверит с ним ключ нового члена в M
					k, err := pake.ClientSignB64(base64.StdEncoding.EncodeToString(d.Key.Seed()), d.ID, pc.LocalDescription().SDP, pc.RemoteDescription().SDP)
					if err != nil {
						finish(nil, err)
						return
					}
					csig, _ := base64.StdEncoding.DecodeString(k["sig"])
					sendA(authMsg{T: "b", Msg: b, Conf: conf, CPub: pub, CSig: csig})
				case "otp":
					if otpN++; otpN > 1 || !hostOK(am) { // второй запрос — код не подошёл
						finish(nil, ErrSpaceAuth)
						return
					}
					sendA(authMsg{T: "otp", Code: d.Code})
				case "ok":
					if !hostOK(am) {
						finish(nil, ErrSpaceAuth)
						return
					}
					mu.Lock()
					hostPub, authed = bytes.Clone(am.Pub), true
					askM()
					mu.Unlock()
				case "ask":
					finish(nil, ErrSpaceAsk)
				case "fail", "locked", "denied", "nokey", "busy":
					finish(nil, fmt.Errorf("%w: %s", ErrSpaceAuth, am.T))
				}
			})
		case "ctl":
			dc.OnOpen(func() { mu.Lock(); ctl = dc; askM(); mu.Unlock() })
			dc.OnMessage(func(msg webrtc.DataChannelMessage) {
				var sm spMsg
				if json.Unmarshal(msg.Data, &sm) != nil || sm.T != "sp" {
					return // monitors, state, cur… — вступлению не нужны
				}
				mu.Lock()
				hp, mine := hostPub, newM
				mu.Unlock()
				switch {
				case hp == nil:
					finish(nil, errSpaceProtocol)
				case sm.Err != "":
					finish(nil, fmt.Errorf("%w: %s", ErrSpaceRefused, sm.Err))
				case sm.OK && mine != nil:
					finish(mine, nil)
				case len(sm.M) > 0 && mine == nil:
					out, err := d.Sign(sm.M, hp)
					if err != nil {
						finish(nil, err)
						return
					}
					mu.Lock()
					newM = out
					mu.Unlock()
					b, _ := json.Marshal(spMsg{T: "sp", M: out})
					dc.SendText(string(b))
				default:
					finish(nil, errSpaceProtocol)
				}
			})
		}
	})
	pc.OnICECandidate(func(ci *webrtc.ICECandidate) {
		if ci != nil {
			send("ice", ci.ToJSON())
		}
	})
	var offer webrtc.SessionDescription
	if err := json.Unmarshal(m.Data, &offer); err != nil {
		return nil, errSpaceProtocol
	}
	if err := pc.SetRemoteDescription(offer); err != nil {
		return nil, err
	}
	ans, err := pc.CreateAnswer(nil)
	if err == nil {
		err = pc.SetLocalDescription(ans)
	}
	if err != nil {
		return nil, err
	}
	send("answer", ans)
	go func() {
		for {
			var m hub.Msg
			if wsjson.Read(ctx, ws, &m) != nil {
				return
			}
			switch {
			case m.From != d.ID: // служебное хаба — сессии не касается
			case m.Type == "ice":
				var ci webrtc.ICECandidateInit
				if json.Unmarshal(m.Data, &ci) == nil {
					pc.AddICECandidate(ci)
				}
			case m.Type == "bye":
				finish(nil, fmt.Errorf("%w: разрыв", ErrSpaceRefused))
			}
		}
	}()
	select {
	case r := <-done:
		return r.m, r.err
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("пространство: нет ответа за %v", spaceWait)
		}
		return nil, ctx.Err()
	}
}
