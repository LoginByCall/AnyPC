package agent

// «Моё пространство», этап Э3: пропуск 12 ч (UI-REDESIGN.md, решения владельца 2 и 5). Мастер вводит пароль и код
// один раз («Работаю тут»), каждая цель T проверяет их сама и выдаёт пропуск на ключ мастера; дальше мастер входит
// на T ключом без пароля и кода, пока пропуск жив. ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (CLAUDE.md A13: вход без второго фактора).
//
// Пропуск — только в памяти T: {ключ мастера → срок, соль записи владельца}. Привязан к ключу, доказанному подписью в
// "b" над DTLS-отпечатками этого соединения (не к ID и не к адресу), и к записи владельца, при которой выдан (смена
// пароля его гасит); не переживает перезапуск T. Истёк — если истёк по монотонным часам ИЛИ по настенным (сон ПК
// монотонные не двигает). Каждое использование сверяет членство ключа в M (Agent.SpaceMember), режим входа
// («Спрашивать» пропуск не обходит) и «Только показ экрана» (там пропуска нет, как M в Э2). Сессию по пропуску агент
// проверяет сам раз в passCheckEvery и рвёт, как только пропуск не годен. В журнал — только факт и начало отпечатка.
//
// Канал "auth", только добавления (старый клиент и браузер полей не шлют, старый хост их не знает):
//
//	хост → {"t":"a",…,"pass":true}                       хост понимает пропуска (первое "a")
//	клиент → {"t":"b",msg,conf,cpub,csig,"pass":true}    вход паролем; после верного кода — выдать пропуск ключу cpub
//	хост → {"t":"ok",…,"pass":true}                       пропуск выдан (или вход по пропуску)
//	клиент → {"t":"b",cpub,csig,"key":true,"pass":true}  вход по пропуску: без пароля и кода
//	хост → {"t":"nopass"}                                 пропуска на этот ключ нет (истёк, снят, не член) — неудача не считается
//	клиент → {"t":"b",cpub,csig,"key":true,"off":true}   снять свой пропуск (блокировка экрана мастера, выход)
//	хост → {"t":"off",pub,sig}                            снят (или его не было), подпись хоста как в "ok"; вход не выполняется
//
// «Снять» приходит отдельным connect {"off":true,"view":true}: такое соединение не занимает место сессии и
// незавершённых входов, не упирается в блокировку перебора и само ничего не открывает — в "b" годится только "off"
// с доказанным ключом. Таких соединений не больше maxOffs; лишнее вытесняет самое старое (молчуны не задержат
// «снять» дольше, чем шлют connect).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"strings"
	"sync/atomic"
	"time"

	"anypc/pake"

	"github.com/coder/websocket"
	"github.com/pion/webrtc/v4"
)

// PassTTL — срок пропуска (решение владельца 5: 12 ч).
const PassTTL = 12 * time.Hour

// passNow — часы пропусков; passSkew — сдвиг для теста (нс).
func passNow() time.Time { return time.Now().Add(time.Duration(passSkew.Load())) }

var passSkew atomic.Int64

// passCheckEvery — как часто агент сам проверяет сессию по пропуску (срок, снятие, членство); атомарно — тест.
var passCheckEvery atomic.Int64

func init() { passCheckEvery.Store(int64(2 * time.Second)) }

// maxOffs — соединений «снять» одновременно (вне maxPending).
const maxOffs = 4

// ErrPassNone — цель вход приняла, а пропуск не выдала (ключ мастера не член её состава, гость, «Спрашивать»,
// «Только показ экрана») или пропуска на этот ключ у неё нет.
var ErrPassNone = errors.New("пространство: пропуска нет")

type passEntry struct {
	exp  time.Time // с монотонным показанием
	wall time.Time // тот же срок по настенным часам (Round(0))
	salt []byte    // соль записи владельца при выдаче
}

func (e passEntry) live(now time.Time) bool { return now.Before(e.exp) && now.Round(0).Before(e.wall) }

// passGive — выдать пропуск ключу pub на PassTTL при записи владельца с солью salt (заменяет прежний). Истёкшие —
// вон: их не больше членов состава.
func (a *Agent) passGive(pub, salt []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := passNow()
	maps.DeleteFunc(a.passes, func(_ string, e passEntry) bool { return !e.live(now) })
	if a.passes == nil {
		a.passes = map[string]passEntry{}
	}
	exp := now.Add(PassTTL)
	a.passes[string(pub)] = passEntry{exp: exp, wall: exp.Round(0), salt: bytes.Clone(salt)}
}

// passDrop — снять пропуск ключа pub (был ли он); сессию, вошедшую по нему, рвёт DropRevoked.
func (a *Agent) passDrop(pub []byte) bool {
	a.mu.Lock()
	_, had := a.passes[string(pub)]
	delete(a.passes, string(pub))
	a.mu.Unlock()
	a.DropRevoked()
	return had
}

// passValid — у ключа pub живой пропуск, выданный при записи владельца с солью salt; pub — член состава этого ПК;
// хост не в «Только показ экрана» (без a.mu).
func (a *Agent) passValid(pub, salt []byte) bool {
	a.mu.Lock()
	e, ok := a.passes[string(pub)]
	a.mu.Unlock()
	return ok && e.live(passNow()) && bytes.Equal(e.salt, salt) && !a.viewOnlyHost() && a.SpaceMember != nil && a.SpaceMember(salt, pub)
}

func (a *Agent) viewOnlyHost() bool { return a.ViewOnly != nil && a.ViewOnly() }

// passIssue — в accept: сессия s просила пропуск ("b" с pass) и вошла паролем и кодом записи владельца (spaceOK)
// с доказанным ключом члена состава, хост не в «Только показ экрана» — выдать; вернуть этот ключ (nil — не выдан).
func (a *Agent) passIssue(s *session) []byte {
	s.mu.Lock()
	salt, cpub := s.salt, s.cpub
	s.mu.Unlock()
	if !s.passAsk.Load() || !s.spaceOK.Load() || cpub == nil || a.viewOnlyHost() || a.SpaceMember == nil || !a.SpaceMember(salt, cpub) {
		return nil
	}
	a.passGive(cpub, salt)
	return cpub
}

// watchPass — сессия s вошла по пропуску ключа pub: пока она жива, проверять пропуск самому (опроса настроек на
// Windows нет) и рвать сессию, как только он истёк, снят, ключ не член M или включили «Только показ экрана».
func (a *Agent) watchPass(ctx context.Context, s *session, pub, salt []byte) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(passCheckEvery.Load())):
		}
		if s.gone.Load() {
			return
		}
		if !a.passValid(pub, salt) {
			log.Printf("сессия %s: пропуск больше не годен — разорвана", s.cid)
			a.send(context.Background(), s.conn, "bye", s.cid, "host")
			s.pc.Close()
			return
		}
	}
}

// passOff — "b" с off: снять пропуск ключа, доказанного в этом соединении. Не вход: неудачей не считается и
// блокировку не трогает. Ответ "off" подписан ключом хоста только члену M; не члену — тот же "off" без ключа и
// подписи (ключ хоста и подпись до пароля не раздаются; мастер-член такого не получает — для него это отказ).
// Оракула сверх прежнего нет: отличить «член / не член» можно только для ключа, которым владеешь сам. Без
// доказанного ключа — "denied".
func (a *Agent) passOff(s *session, m authMsg, keyOK bool, fpc, fph string, send func(authMsg)) {
	if m.Key && keyOK && a.SpaceMember != nil {
		if a.passDrop(m.CPub) {
			log.Printf("сессия %s: пропуск ПК %s снят", s.cid, pake.KeyFingerprint(m.CPub)[:9])
		}
		s.mu.Lock()
		salt := s.salt
		s.mu.Unlock()
		r := authMsg{T: "off"}
		if a.SpaceMember(salt, m.CPub) {
			r.Pub, r.Sig = a.Key.Public().(ed25519.PublicKey), pake.HostSign(a.Key, a.ID, fpc, fph)
		}
		send(r)
	} else {
		send(authMsg{T: "denied"})
	}
	a.release(s)
	time.AfterFunc(500*time.Millisecond, func() { s.pc.Close() })
}

// offConnect — connect {"off":true}: соединение только для «снять», вне места сессии, maxPending и блокировки.
// ОГРАНИЧЕНИЕ (приёмка Э3, круг 2; вопрос владельцу): посторонний, знающий ID, потоком connect {"off":true}
// вытесняет соединение «снять» мастера раньше, чем тот докажет ключ, — «снять» задерживается (мастер повторяет),
// пропуск живёт до 12 ч или перезапуска цели. SECURITY.md.
func (a *Agent) offConnect(ctx context.Context, c *websocket.Conn, cid string, req connectReq) {
	a.mu.Lock()
	var drop []*session
	for p := range a.offs { // переподключение того же клиента
		if p.cid == cid {
			drop = append(drop, p)
			delete(a.offs, p)
		}
	}
	for len(a.offs) > 0 && len(a.offs)+a.offStarting >= maxOffs { // вытеснить самое старое
		var old *session
		for p, at := range a.offs {
			if old == nil || at.Before(a.offs[old]) {
				old = p
			}
		}
		drop = append(drop, old)
		delete(a.offs, old)
	}
	busy := a.offStarting >= maxOffs
	if !busy {
		a.offStarting++
	}
	turn := pickTURN(req, a.rtt, turnHosts(a.ice))
	ice := onlyTURN(a.ice, turn)
	a.mu.Unlock()
	for _, p := range drop {
		p.gone.Store(true)
		p.pc.Close()
	}
	if busy {
		a.send(ctx, c, "error", cid, "busy")
		return
	}
	s, err := a.newSession(ctx, c, cid, ice, offerMsg{TURN: turn}, false, true, true)
	a.mu.Lock()
	a.offStarting--
	if err == nil && !s.gone.Load() {
		if a.offs == nil {
			a.offs = map[*session]time.Time{}
		}
		a.offs[s] = time.Now()
	}
	a.mu.Unlock()
	if err != nil {
		log.Printf("сессия: %v", err)
		a.send(ctx, c, "error", cid, "internal")
	}
}

// PassDial — мастер (Э3) к цели ID пространства. ID и HostPub — из состава M этого ПК; Key — ключ хоста мастера
// (на него выдаётся пропуск). Password и Code — только для PassOpen.
type PassDial struct {
	Server   string             // хабы через запятую, как Agent.Server
	ID       string             // цель T
	HostPub  ed25519.PublicKey  // ключ хоста T из M: другой — отказ до отправки кода
	Key      ed25519.PrivateKey // ключ хоста мастера
	Password string
	Code     string
	user     string // тест: вход записью по имени (гость) — пропуска не будет
}

type passMode int

const (
	passOpen  passMode = iota // вход паролем и кодом с просьбой пропуска
	passLogin                 // вход по пропуску
	passOff                   // снять пропуск
)

// passWait — весь обмен с одной целью.
var passWait = 60 * time.Second

// PassOpen — «Работаю тут» на одной цели: войти паролем и кодом владельца и получить пропуск. Сессия тут же
// закрывается (видео и ввод — в следующих этапах, по пропуску).
func PassOpen(ctx context.Context, d PassDial) error { return passDo(ctx, d, passOpen) }

// PassLogin — войти на цель по пропуску (без пароля и кода) и закрыть сессию: пропуск жив.
func PassLogin(ctx context.Context, d PassDial) error { return passDo(ctx, d, passLogin) }

// PassOff — снять свой пропуск на цели: только доказательство ключа, вход не выполняется (ни плашки, ни видео).
func PassOff(ctx context.Context, d PassDial) error { return passDo(ctx, d, passOff) }

func passDo(ctx context.Context, d PassDial, mode passMode) error {
	ctx, cancel := context.WithTimeout(ctx, passWait)
	defer cancel()
	var err error
	for _, u := range strings.Split(d.Server, ",") {
		if err = passVia(ctx, strings.TrimSpace(u), d, mode); !errors.Is(err, ErrSpaceOffline) {
			return err
		}
	}
	return err
}

func passVia(ctx context.Context, server string, d PassDial, mode passMode) error {
	return hostDial(ctx, server, d.ID, connectReq{View: true, Off: mode == passOff}, func(pc *webrtc.PeerConnection, finish func(error)) {
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			if dc.Label() != "auth" {
				return
			}
			var want []byte // ожидаемое подтверждение хоста (CPace), только passOpen
			first, named, otpN := true, false, 0
			sendA := func(v authMsg) { b, _ := json.Marshal(v); dc.SendText(string(b)) }
			// хост — цель из M: подпись его ключом над отпечатками этого соединения; при входе паролем — и conf
			hostOK := func(am authMsg) bool {
				fc, fh := pake.Fingerprint(pc.LocalDescription().SDP), pake.Fingerprint(pc.RemoteDescription().SDP)
				return (mode != passOpen || len(want) > 0 && bytes.Equal(am.Conf, want)) &&
					bytes.Equal(am.Pub, d.HostPub) && pake.HostVerify(am.Pub, am.Sig, d.ID, fc, fh) == nil
			}
			dc.OnMessage(func(msg webrtc.DataChannelMessage) {
				var am authMsg
				if json.Unmarshal(msg.Data, &am) != nil {
					return
				}
				switch am.T {
				case "a":
					switch {
					case first && am.User == "":
						first = false
						if !am.Pass { // старый хост: пароль не отдаём, ключом не входим (неудач у него не будет)
							finish(ErrSpaceOld)
							return
						}
						if d.user != "" {
							sendA(authMsg{T: "a", User: d.user})
							return
						}
					case !first && !named && d.user != "" && am.User == d.user:
						named = true
					default:
						finish(errSpaceProtocol)
						return
					}
					cpub, csig, err := signB(d.Key, d.ID, pc)
					if err != nil {
						finish(err)
						return
					}
					b := authMsg{T: "b", CPub: cpub, CSig: csig, Key: mode != passOpen, Pass: mode != passOff, Off: mode == passOff}
					if mode == passOpen {
						fc, fh := pake.Fingerprint(pc.LocalDescription().SDP), pake.Fingerprint(pc.RemoteDescription().SDP)
						if b.Msg, b.Conf, want, err = pake.ClientRespond(d.Password, am.Salt, am.Msg, d.ID, fc, fh); err != nil {
							finish(err)
							return
						}
					}
					sendA(b)
				case "otp":
					switch {
					case mode != passOpen: // по пропуску код не спрашивают: пропуска нет
						finish(ErrPassNone)
					case otpN > 0: // второй запрос — код не подошёл
						finish(ErrSpaceAuth)
					case !hostOK(am): // код — только цели из M
						finish(ErrSpaceHostKey)
					default:
						otpN++
						sendA(authMsg{T: "otp", Code: d.Code})
					}
				case "ok":
					switch {
					case mode == passOff:
						finish(errSpaceProtocol)
					case !hostOK(am):
						finish(ErrSpaceHostKey)
					case !am.Pass:
						finish(ErrPassNone)
					default:
						finish(nil)
					}
				case "off":
					switch {
					case mode != passOff:
						finish(errSpaceProtocol)
					case !hostOK(am): // «снят» — только от цели из M
						finish(ErrSpaceHostKey)
					default:
						finish(nil)
					}
				case "nopass":
					finish(ErrPassNone)
				case "ask":
					finish(ErrSpaceAsk)
				case "fail", "locked", "denied", "nokey", "busy":
					finish(fmt.Errorf("%w: %s", ErrSpaceAuth, am.T))
				}
			})
		})
	})
}
