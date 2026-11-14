package agent

// «Моё пространство», этап Э3: пропуск 12 ч (UI-REDESIGN.md, решения владельца 2 и 5). Мастер вводит пароль и код
// один раз («Работаю тут»), каждая цель T проверяет их сама и выдаёт пропуск на ключ мастера; дальше мастер входит
// на T ключом без пароля и кода, пока пропуск жив. ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (CLAUDE.md A13: вход без второго фактора).
//
// Пропуск — только в памяти T: {ключ мастера → срок}. Привязан к ключу, доказанному подписью в "b" над DTLS-отпечатками
// этого соединения (не к ID и не к адресу); не переживает перезапуск T; срок — по монотонным часам. Каждое
// использование сверяет членство ключа в составе M (Agent.SpaceMember) и режим входа: в «Спрашивать» пропуск не
// действует (строже: окно «Разрешить» он не обходит). В журнал — только факт и начало отпечатка ключа.
//
// Канал "auth", только добавления (старый клиент и браузер полей не шлют, старый хост их не знает):
//
//	хост → {"t":"a",…,"pass":true}                       хост понимает пропуска (первое "a")
//	клиент → {"t":"b",msg,conf,cpub,csig,"pass":true}    вход паролем; после верного кода — выдать пропуск ключу cpub
//	хост → {"t":"ok",…,"pass":true}                       пропуск выдан (или вход по пропуску)
//	клиент → {"t":"b",cpub,csig,"key":true,"pass":true}  вход по пропуску: без пароля и кода
//	хост → {"t":"nopass"}                                 пропуска на этот ключ нет (истёк, снят, не член) — неудача не считается
//	клиент → {"t":"b",cpub,csig,"key":true,"off":true}   снять свой пропуск (блокировка экрана мастера, выход)
//	хост → {"t":"off"}                                    снят (или его не было); вход не выполняется

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"anypc/pake"

	"github.com/pion/webrtc/v4"
)

// PassTTL — срок пропуска (решение владельца 5: 12 ч).
const PassTTL = 12 * time.Hour

// passNow — часы пропусков. time.Now несёт монотонное показание, Add его сохраняет, Before сравнивает по нему:
// перевод системных часов срок не продлевает. passSkew — сдвиг часов для теста (нс).
func passNow() time.Time { return time.Now().Add(time.Duration(passSkew.Load())) }

var passSkew atomic.Int64

// ErrPassNone — цель вход приняла, а пропуск не выдала (ключ мастера не член её состава, гость, «Спрашивать») или
// пропуска на этот ключ у неё нет.
var ErrPassNone = errors.New("пространство: пропуска нет")

// passGive — выдать пропуск ключу pub на PassTTL (заменяет прежний). Истёкшие — вон: их не больше членов состава.
func (a *Agent) passGive(pub []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := passNow()
	for k, exp := range a.passes {
		if !now.Before(exp) {
			delete(a.passes, k)
		}
	}
	if a.passes == nil {
		a.passes = map[string]time.Time{}
	}
	a.passes[string(pub)] = now.Add(PassTTL)
}

// passDrop — снять пропуск ключа pub; сессию, вошедшую по нему, рвёт DropRevoked.
func (a *Agent) passDrop(pub []byte) {
	a.mu.Lock()
	delete(a.passes, string(pub))
	a.mu.Unlock()
	a.DropRevoked()
}

// passValid — у ключа pub живой пропуск, и pub — член состава этого ПК для записи с солью salt (без a.mu).
func (a *Agent) passValid(pub, salt []byte) bool {
	a.mu.Lock()
	exp, ok := a.passes[string(pub)]
	a.mu.Unlock()
	return ok && passNow().Before(exp) && a.SpaceMember != nil && a.SpaceMember(salt, pub)
}

// passIssue — в accept: сессия s просила пропуск ("b" с pass) и вошла паролем и кодом записи владельца (spaceOK)
// с доказанным ключом члена состава — выдать; вернуть этот ключ (nil — не выдан).
func (a *Agent) passIssue(s *session) []byte {
	s.mu.Lock()
	salt, cpub := s.salt, s.cpub
	s.mu.Unlock()
	if !s.passAsk.Load() || !s.spaceOK.Load() || cpub == nil || a.SpaceMember == nil || !a.SpaceMember(salt, cpub) {
		return nil
	}
	a.passGive(cpub)
	return cpub
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
	return hostDial(ctx, server, d.ID, func(pc *webrtc.PeerConnection, finish func(error)) {
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
					if mode == passOff {
						finish(nil)
					} else {
						finish(errSpaceProtocol)
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
