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
//	хост → {"t":"ok",…,"pass":true,"pid":id}              пропуск выдан (или вход по пропуску); id — 16 случайных байт пропуска
//	клиент → {"t":"b",cpub,csig,"key":true,"pass":true}  вход по пропуску: без пароля и кода
//	хост → {"t":"nopass"}                                 пропуска на этот ключ нет (истёк, снят, не член) — неудача не считается
//	клиент → {"t":"b",cpub,csig,"key":true,"off":true}   снять свой пропуск (блокировка экрана мастера, выход)
//	хост → {"t":"off",pub,sig}                            снят (или его не было), подпись хоста как в "ok"; вход не выполняется
//
// «Снять» (решение владельца 8 A) — одно подписанное сообщение через хаб {"type":"off","to":ID,"data":тело}
// (pake.OffSign: pub мастера ‖ id пропуска ‖ подпись над доменом, ID цели и id), без WebRTC и места сессии: поток
// посторонних его не вытесняет. Цель отвечает {"type":"offack","to":клиент,"data":pake.OffAck} — подпись ключа хоста
// над доменом ответа, ID, id и статусом (снят / такого нет); мастер проверяет её ключом T из M и до ответа повторяет.
// Хост объявляет поддержку хабу (?off=1); старому хосту хаб не пересылает и отвечает "old", старый хаб — "forbidden";
// тогда, как и без id (пропуск выдан старой целью), мастер шлёт по-старому: отдельный connect {"off":true,"view":true}. Такое соединение не занимает
// место сессии и незавершённых входов, не упирается в блокировку перебора и само ничего не открывает — в "b"
// годится только "off" с доказанным ключом. Таких соединений не больше maxOffs; лишнее вытесняет самое старое.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"strings"
	"sync/atomic"
	"time"

	"anypc/hub"
	"anypc/pake"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
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
	id   []byte    // id пропуска (pake.OffID случайных байт): мастер получает его в "ok" и им снимает пропуск через хаб
}

func (e passEntry) live(now time.Time) bool { return now.Before(e.exp) && now.Round(0).Before(e.wall) }

// passGive — выдать пропуск ключу pub на PassTTL при записи владельца с солью salt (заменяет прежний). Истёкшие —
// вон: их не больше членов состава. Вернуть id нового пропуска.
func (a *Agent) passGive(pub, salt []byte) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := passNow()
	maps.DeleteFunc(a.passes, func(_ string, e passEntry) bool { return !e.live(now) })
	if a.passes == nil {
		a.passes = map[string]passEntry{}
	}
	exp, id := now.Add(PassTTL), make([]byte, pake.OffID)
	rand.Read(id)
	a.passes[string(pub)] = passEntry{exp: exp, wall: exp.Round(0), salt: bytes.Clone(salt), id: id}
	return id
}

// passID — id пропуска ключа pub (nil — пропуска нет): в "ok" выдачи и входа по пропуску.
func (a *Agent) passID(pub []byte) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.passes[string(pub)].id
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

// offMsg — «снять» сообщением через хаб (m от клиента m.From): тело подписано ключом члена M этого ПК над его ID и
// id пропуска — снять пропуск этого ключа, если id совпал, и ответить клиенту подписью ключа хоста (offack): «снят»
// или «такого пропуска нет». Часов и кэша нет: повтор приходит к уже снятому (у нового пропуска id другой).
// Проверка подписи открывается по членству ключа в M, а не по наличию пропуска: путь «есть / нет пропуска» до ответа
// одинаков. Не член, не та подпись, мусор — молча, nil (счёт и строка в журнале раз в минуту). Вернуть ответ.
func (a *Agent) offMsg(m hub.Msg) []byte {
	var b []byte
	salt, _, _ := a.Secret("")
	if json.Unmarshal(m.Data, &b) != nil || len(b) != pake.OffSize || !clientID.MatchString(m.From) || !a.SpaceMember(salt, b[:ed25519.PublicKeySize]) {
		a.offReject()
		return nil
	}
	pub, pid, ok := pake.OffVerify(b, a.ID)
	if !ok {
		a.offReject()
		return nil
	}
	a.mu.Lock()
	hit := bytes.Equal(a.passes[string(pub)].id, pid)
	if hit {
		delete(a.passes, string(pub))
	}
	a.mu.Unlock()
	if hit {
		a.DropRevoked()
		log.Printf("пропуск ПК %s снят (сообщение через хаб)", pake.KeyFingerprint(pub)[:9])
	}
	return pake.OffAck(a.Key, a.ID, pid, hit)
}

// offReject — отказ «снять» через хаб: в журнал не чаще раза в минуту (поток посторонних журнал не раздует).
func (a *Agent) offReject() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.offRej++; time.Since(a.offRejAt) > time.Minute {
		log.Printf("«снять» через хаб: отклонено %d (не член M, подпись или мусор)", a.offRej)
		a.offRej, a.offRejAt = 0, time.Now()
	}
}

// offConnect — connect {"off":true}: соединение только для «снять», вне места сессии, maxPending и блокировки.
// Запасной путь для хостов без «снять» сообщением (старые версии). ОГРАНИЧЕНИЕ (приёмка Э3, круг 2): посторонний,
// знающий ID, потоком connect {"off":true} вытесняет соединение «снять» мастера раньше, чем тот докажет ключ, —
// «снять» задерживается (мастер повторяет), пропуск живёт до 12 ч или перезапуска цели. SECURITY.md.
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
	PID      []byte                  // для PassOff: id пропуска на T (из PassOpenID); nil — пропуск выдан старой целью, «снять» по-старому
	pidOut   *atomic.Pointer[[]byte] // PassOpenID: куда положить id из первого "ok"
	user     string                  // тест: вход записью по имени (гость) — пропуска не будет
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
func PassOpen(ctx context.Context, d PassDial) error { _, err := PassOpenID(ctx, d); return err }

// PassOpenID — PassOpen и id выданного пропуска (nil — цель старой версии id не выдаёт): им PassOff снимает пропуск.
func PassOpenID(ctx context.Context, d PassDial) ([]byte, error) {
	d.pidOut = new(atomic.Pointer[[]byte])
	err := passDo(ctx, d, passOpen)
	if p := d.pidOut.Load(); p != nil {
		return *p, err
	}
	return nil, err
}

// PassLogin — войти на цель по пропуску (без пароля и кода) и закрыть сессию: пропуск жив.
func PassLogin(ctx context.Context, d PassDial) error { return passDo(ctx, d, passLogin) }

// PassOff — снять свой пропуск d.PID на цели одним сообщением через хаб; nil — цель ответила подписью своего ключа
// (d.HostPub из M): «снят» или «такого пропуска нет». Без id (пропуск выдан старой целью), цели или хабу старой версии
// — отдельным соединением с доказательством ключа (вход не выполняется: ни плашки, ни видео).
func PassOff(ctx context.Context, d PassDial) error {
	if len(d.PID) == pake.OffID {
		if err := passOffHub(ctx, d); !errors.Is(err, errOffOld) {
			return err
		}
	}
	return passDo(ctx, d, passOff)
}

var errOffOld = errors.New("пространство: цель или хаб не знают «снять» сообщением")

// offAckWait — сколько ждать ответа цели через один хаб.
var offAckWait = 10 * time.Second

// passOffHub — «снять» через хабы по очереди, пока цель не ответит через один из них (хост в сети на всех хабах
// сразу, Run); тело одно на все хабы, повтор безвреден. errOffOld — хост или хаб этого не знают.
func passOffHub(ctx context.Context, d PassDial) error {
	data, _ := json.Marshal(pake.OffSign(d.Key, d.ID, d.PID))
	err, old := ErrSpaceOffline, false
	for _, u := range strings.Split(d.Server, ",") {
		switch r := offVia(ctx, strings.TrimSpace(u), d, data); r {
		case "acked":
			return nil
		case "old", "forbidden": // хост старый или старый хаб не пересылает off
			old = true
		case "badack":
			err = ErrSpaceHostKey
		case "not_found", "": // хоста на этом хабе нет, нет связи с хабом или ответа цели
		default:
			err = fmt.Errorf("%w: хаб: %s", ErrSpaceRefused, r)
		}
	}
	if old {
		return errOffOld
	}
	return err
}

// offVia — одно «снять» через хаб server: "acked" — верный ответ цели, "badack" — ответ не её ключом или не на этот
// пропуск, иначе отказ хаба ("old", "busy", "not_found", "forbidden"); "" — нет связи или ответа за offAckWait.
func offVia(ctx context.Context, server string, d PassDial, data []byte) string {
	ctx, cancel := context.WithTimeout(ctx, offAckWait)
	defer cancel()
	ws, err := dial(ctx, server)
	if err != nil {
		return ""
	}
	defer ws.CloseNow()
	var m hub.Msg
	if wsjson.Read(ctx, ws, &m) != nil || m.Type != "hello" || wsjson.Write(ctx, ws, hub.Msg{V: 1, Type: "off", To: d.ID, Data: data}) != nil {
		return ""
	}
	for {
		if wsjson.Read(ctx, ws, &m) != nil {
			return ""
		}
		switch {
		case m.From == "" && (m.Type == "off" || m.Type == "error"):
			var r string
			json.Unmarshal(m.Data, &r)
			return r
		case m.From == d.ID && m.Type == "offack":
			var b []byte
			if json.Unmarshal(m.Data, &b) == nil {
				if _, ok := pake.OffAckVerify(d.HostPub, b, d.ID, d.PID); ok {
					return "acked"
				}
			}
			return "badack"
		}
	}
}

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
						if d.pidOut != nil && len(am.PID) == pake.OffID {
							d.pidOut.CompareAndSwap(nil, &am.PID)
						}
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
