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
	"sync/atomic"
	"time"

	"anypc/hub"
	"anypc/pake"

	"github.com/coder/websocket/wsjson"
	"github.com/pion/webrtc/v4"
)

// spMsg — канал "ctl", состав пространства (Э2). Клиент → {"t":"sp"} — запрос состава; хост → {"t":"sp","m":…,"h":[…]}
// (главная верхушка M и остальные, base64; h — только добавление, решение 12 A) | {"t":"sp","err":"rights"|"none"}. Клиент → {"t":"sp","m":…} — M следующей эпохи с ним самим (named-вход — заявка, может быть без изменений);
// хост → {"t":"sp","ok":true} | {"t":"sp","ok":true,"m":…,"h":[…]} — named-входу актуальный состав в OK | {"t":"sp","err":"rights"|"key"|"again"|"bad"}.
// err: rights — сессия вошла не паролем и кодом записи (не ключом, не одноразовым кодом); none — пространства нет (или пароль записи
// не его); key — клиент не доказал свой ключ в "b"; again — второе вступление в сессии; bad — состав не принят.
// Ч12б (admit.go, решение B): хост с окном «Пустить?» отдаёт состав сессии входа паролем в запись по умолчанию только
// после «Разрешить» (named-вход — запись по имени — окно не ждёт: eligibility решает app в SpaceJoin);
// иначе err: admit_no | admit_timeout | admit_later (старый клиент показывает «тот ПК отказал»).
type spMsg struct {
	T   string   `json:"t"`
	M   []byte   `json:"m,omitempty"`
	OK  bool     `json:"ok,omitempty"`
	Err string   `json:"err,omitempty"`
	H   [][]byte `json:"h,omitempty"` // в ответе на запрос состава: остальные верхушки
	// Э4, сверка (spsync.go): sync — шаг обмена M; r — ещё одна верхушка M; pub, sig — ключ хоста и подпись (как в "ok")
	Sync bool   `json:"sync,omitempty"`
	R    []byte `json:"r,omitempty"`
	Pub  []byte `json:"pub,omitempty"`
	Sig  []byte `json:"sig,omitempty"`
}

// spaceCtl — хост: ответ на "sp" вошедшей сессии.
func (a *Agent) spaceCtl(ctx context.Context, s *session, data []byte, reply func(spMsg)) {
	var m spMsg
	if json.Unmarshal(data, &m) != nil {
		return
	}
	// «Только показ экрана» на хосте — никаких правок через сессию, и состава тоже (решение приёмки Э2, строже)
	if !s.spaceOK.Load() || a.viewOnlyFor(s) {
		reply(spMsg{T: "sp", Err: "rights"})
		return
	}
	s.mu.Lock()
	salt, cpub, jid, cid, cname, asend, user := s.salt, s.cpub, s.joinID, s.claimID, s.claimName, s.authSend, s.user
	tag, tagged := bytes.Clone(s.tag), s.tagged
	s.mu.Unlock()
	if user != "" && tagged && a.LoginTag != nil && !bytes.Equal(tag, a.LoginTag(user, cpub)) {
		reply(spMsg{T: "sp", Err: "rights"}) // TOTP именной записи сменили после входа: старая сессия больше не авторизует вступление
		return
	}
	if user != "" { // named (запись по имени, пароль и код): окна нет — ID заявлен в "b" (claimID), eligibility — app в SpaceJoin по соли
		jid = cid
	}
	give := func() {
		var b [][]byte
		if user != "" {
			if a.SpaceGetTagged == nil {
				reply(spMsg{T: "sp", Err: "rights"})
				return
			}
			b = a.SpaceGetTagged(salt, tag)
		} else {
			b = a.SpaceGet(salt)
		}
		if len(b) > 0 {
			reply(spMsg{T: "sp", M: b[0], H: b[1:]})
			if spaceDupM.Load() {
				reply(spMsg{T: "sp", M: b[0], H: b[1:]})
			}
		} else {
			reply(spMsg{T: "sp", Err: "none"})
		}
	}
	admit := a.SpaceAdmit != nil && !s.admitted.Load() && user == "" // Ч12б: окно «Пустить?» — только запись по умолчанию; named полный аккаунт его не ждёт
	if len(m.M) == 0 {                                               // запрос состава
		switch {
		case !admit:
			give()
		case cpub == nil: // окну нужен ключ нового члена (клиенты вступления доказывают его всегда)
			reply(spMsg{T: "sp", Err: "key"})
		case s.admitting.CompareAndSwap(false, true): // второй запрос, пока окно открыто, — без ответа
			go func() { // окно ждёт человека до AdmitTimeout — не в потоке SCTP
				s.admitBlock.Store(true) // вошедшая сессия сама «Разрешить» не нажмёт: ввод выключен на время окна
				for _, e := range s.keys.release() {
					sendInput(e, nil)
				}
				if asend != nil { // новый клиент покажет «ждём «Разрешить»»; старый неизвестный t в "auth" пропускает
					asend(authMsg{T: "admit"})
				}
				ok, why := a.admitAsk(ctx, s, AdmitReq{ID: cid, Name: cname, FP: pake.KeyFingerprint(cpub)})
				s.admitBlock.Store(false)
				if !ok {
					reply(spMsg{T: "sp", Err: "admit_" + why})
					return
				}
				s.mu.Lock()
				s.joinID = cid // новый член M — под ID из окна ("" — старый клиент ID не сообщил)
				s.mu.Unlock()
				s.admitted.Store(true)
				give()
			}()
		}
		return
	}
	switch {
	case a.SpaceJoin == nil:
		reply(spMsg{T: "sp", Err: "none"})
	case cpub == nil:
		reply(spMsg{T: "sp", Err: "key"})
	case admit: // состав до «Разрешить» — нарушение порядка
		reply(spMsg{T: "sp", Err: "rights"})
	case !s.spJoin.CompareAndSwap(false, true):
		reply(spMsg{T: "sp", Err: "again"})
	default:
		var err error
		if user != "" {
			if a.SpaceJoinTagged == nil {
				reply(spMsg{T: "sp", Err: "rights"})
				return
			}
			err = a.SpaceJoinTagged(salt, tag, m.M, cpub, jid)
		} else {
			err = a.SpaceJoin(salt, m.M, cpub, jid)
		}
		if err != nil {
			log.Printf("сессия %s: состав пространства не принят: %v", s.label(), err)
			reply(spMsg{T: "sp", Err: "bad"})
			return
		}
		log.Printf("сессия %s: ПК %s вступил в пространство", s.label(), pake.KeyFingerprint(cpub)[:9])
		if user != "" { // named: новый M подписал хост — отдать актуальный состав (клиент предпочитает его отправленному)
			if a.SpaceGetTagged == nil {
				reply(spMsg{T: "sp", Err: "rights"})
				return
			}
			if b := a.SpaceGetTagged(salt, tag); len(b) > 0 {
				reply(spMsg{T: "sp", OK: true, M: b[0], H: b[1:]})
				return
			}
		}
		reply(spMsg{T: "sp", OK: true})
	}
}

// SpaceDial — клиент вступления (Э2): обычный вход на ПК пространства ID паролем Password и кодом TOTP Code записи
// по умолчанию, ключ клиента — Key (ключ хоста этого ПК: им P сверяет ключ нового члена в M). После входа: запрос
// M, Sign(M, ключ хоста P) — новый M с этим ПК (подпись владельца на этом ПК), ответ P. Password — пароль входа
// (уходит только в CPace); фразы пространства (ключ подписи M, решение 8 B) здесь нет: её держит Sign у вызывающего.
type SpaceDial struct {
	Server   string             // хабы через запятую, как Agent.Server: пробуются по очереди
	ID       string             // ПК пространства P
	Key      ed25519.PrivateKey // ключ хоста этого ПК
	Password string
	Code     string
	// User — named CPace (REQ-S-20): вход в запись по имени паролем Password и кодом Code этой записи (не
	// владельца): первое "a" → {"t":"a","user":User} → второе "a" (соль записи или чужое имя — поддельная) → "b".
	// Хост не открывает окно «Пустить?»; eligibility решает app в SpaceJoin по соли записи, новый M подписывает
	// хост и возвращает в OK — ключа владельца у клиента нет (Sign вернёт M как был, заявка уходит хосту).
	// Self — ID этого ПК: обязателен и валиден (hub.IsHostID), app добавит новый член M по ключу и этому ID.
	// "" — запись по умолчанию (владелец): прежний путь с окном «Пустить?».
	User string
	// Known — отпечаток ключа P (pake.KeyFingerprint), если этот ПК уже входил на P (config.Known): другой ключ —
	// отказ до отправки кода. "" — первое знакомство (TOFU). TODO(Э4): сверка ключей P по составам других членов.
	Known string
	// Heads — named-вступление: все верхушки из OK хоста (главная и остальные), чтобы не потерять исключения.
	Heads *[][]byte
	// Sign — по M от P (главная верхушка; heads — остальные; проверены подписью хоста P и CPace) вернуть новый M,
	// подписанный фразой пространства на этом ПК (сначала сверка opub из фразы); ошибка — отказ, P ничего не получит.
	// Вернул тот же M — этот ПК в нём уже есть (P сохранил прошлое вступление, а ответ не дошёл): P ничего не шлём.
	// Sign зовётся в своей горутине и может ждать человека (окно «Это все ваши ПК?»): ctx SpaceJoin — до конца обмена.
	Sign func(m []byte, hostPub ed25519.PublicKey, heads ...[]byte) ([]byte, error)
	// Confirm — сколько Sign может ждать подтверждения состава человеком: прибавляется к spaceWait (решение 12 A).
	Confirm time.Duration
	// Stage — ход обмена для окна (Ч12): "link" — соединяюсь, "auth" — соединение есть, проверка пароля и кода,
	// "list" — вход есть, запрос состава. nil — не сообщать. Зовётся из потоков pion — не блокировать.
	// Ч12б: "admit" — на том ПК открыто окно «Пустить?» (ждём «Разрешить» до AdmitTimeout).
	Stage func(string)
	// Ч12б, решение A' (admit.go): Password "" — вступление без пароля: код Code, доказательство фразы ключом
	// владельца OwnerKey(osalt) (ключ из фразы и соли от поручителя; ключ стирается после подписи), Self и Name — ID и
	// имя этого ПК для окна «Пустить?» поручителя. Поручитель не объявил join (≤ v0.3.1) — ErrSpaceNeedPass до
	// отправки чего-либо: нужен запасной путь с паролем.
	Self, Name string
	OwnerKey   func(osalt []byte) (ed25519.PrivateKey, error)
}

// Ошибки SpaceJoin (для окна в следующих этапах).
var (
	ErrSpaceOffline = errors.New("пространство: ПК не в сети")
	ErrSpaceAuth    = errors.New("пространство: неверный пароль или код")
	ErrSpaceOld     = errors.New("пространство: на том ПК старая версия AnyPC")
	ErrSpaceAsk     = errors.New("пространство: тот ПК в режиме «Спрашивать» — нужен вход паролем и кодом")
	ErrSpaceRefused = errors.New("пространство: тот ПК отказал")
	ErrSpaceHostKey = errors.New("пространство: ключ того ПК не совпал с запомненным")
	// Ч12: соединение (ICE/DTLS) с тем ПК не установилось за spaceLinkWait или сорвалось до установки
	ErrSpaceNoLink = errors.New("пространство: не удалось соединиться с тем ПК")
	// Ч12: соединения нет, и этот ПК не собрал ни одного кандидата через STUN/TURN (srflx, relay), хотя хаб их дал:
	// исходящий UDP этого процесса закрыт — брандмауэр этого ПК (LuLu/Little Snitch на Маке пускает окно — WebKit,
	// процесс Apple — и не пускает AnyPC). errors.Is(ErrSpaceNoLink) — тоже.
	ErrSpaceNoUDP = errors.New("пространство: этот ПК не достучался до STUN/TURN — брандмауэр этого ПК не пускает AnyPC")
	// Ч12, приёмка: отказы хоста с причиной, по которой человек может действовать (обёрнуты в ErrSpaceRefused, а
	// "busy"/"locked" входа — ещё и в ErrSpaceAuth, как было): на том ПК идёт сеанс или очередь входов полна; вход там
	// временно закрыт после неверных попыток (lockUntil); там не задан пароль
	ErrSpaceBusyThere   = errors.New("пространство: на том ПК идёт сеанс")
	ErrSpaceLockedThere = errors.New("пространство: тот ПК временно закрыл вход после неверных попыток")
	ErrSpaceNoPassThere = errors.New("пространство: на том ПК не задан пароль")
	// Ч12: тот ПК закрыл соединение (или оно оборвалось) до конца обмена
	ErrSpaceClosed   = errors.New("пространство: тот ПК закрыл соединение")
	errSpaceProtocol = errors.New("пространство: нарушение протокола")

	// Ч12б (admit.go): вступление без пароля
	ErrSpaceNeedPass      = errors.New("пространство: на том ПК AnyPC ≤ 0.3.1 — вступление через него только с паролем")
	ErrSpaceBadCode       = errors.New("пространство: неверный код")                 // и errors.Is(ErrSpaceAuth)
	ErrSpaceBadPhrase     = errors.New("пространство: фраза не подошла тому ПК")     // и errors.Is(ErrSpaceAuth)
	ErrSpaceDeclined      = errors.New("пространство: на том ПК нажали «Отклонить»") // и errors.Is(ErrSpaceRefused)
	ErrSpaceNoAnswer      = errors.New("пространство: на том ПК не ответили в окне «Пустить?»")
	ErrSpaceNoWindow      = errors.New("пространство: на том ПК не смогло появиться окно «Пустить?»")
	ErrSpaceJoinLocked    = errors.New("пространство: вступление через тот ПК временно закрыто после неверных кодов") // и errors.Is(ErrSpaceLockedThere)
	ErrSpaceViewOnlyThere = errors.New("пространство: на том ПК включено «Только показ экрана»")
	ErrSpaceSlowHere      = errors.New("пространство: этот ПК не успел отдать код или доказательство фразы")
	ErrSpaceLater         = errors.New("пространство: тот ПК недавно отказал этому ПК — повторите позже")
	ErrSpaceNotThere      = errors.New("пространство: тот ПК сейчас не пускает в пространство")
	ErrSpaceWaitThere     = errors.New("пространство: тот ПК ещё не сверился с другим членом после своего вступления") // и errors.Is(ErrSpaceAuth)
)

// SpaceWaitError — отказ окна «Пустить?» с паузой (Ч12б): новое окно на том ПК не раньше чем через Secs секунд.
type SpaceWaitError struct {
	Err  error
	Secs int
}

func (e SpaceWaitError) Error() string {
	return fmt.Sprintf("%v (новое окно через %d с)", e.Err, e.Secs)
}
func (e SpaceWaitError) Unwrap() error { return e.Err }

// joinRefusal — отказ хоста в канале auth при вступлении (Ч12б и вход паролем): ошибка для окна; nil — не отказ.
// Пауза окна (left) — SpaceWaitError вокруг.
func joinRefusal(am authMsg) error {
	err := joinRefusal0(am.T, am.Why)
	if err != nil && am.Left > 0 && (am.T == "later" || am.T == "denied" && (am.Why == "no" || am.Why == "timeout")) {
		return SpaceWaitError{Err: err, Secs: am.Left}
	}
	return err
}

func joinRefusal0(t, why string) error {
	switch {
	case t == "fail" && why == "code":
		return fmt.Errorf("%w (%w)", ErrSpaceBadCode, ErrSpaceAuth)
	case t == "fail" && why == "phrase":
		return fmt.Errorf("%w (%w)", ErrSpaceBadPhrase, ErrSpaceAuth)
	case t == "denied" && why == "no":
		return fmt.Errorf("%w (%w)", ErrSpaceDeclined, ErrSpaceRefused)
	case t == "denied" && why == "timeout":
		return fmt.Errorf("%w (%w)", ErrSpaceNoAnswer, ErrSpaceRefused)
	case t == "denied" && why == "slow":
		return fmt.Errorf("%w (%w)", ErrSpaceSlowHere, ErrSpaceRefused)
	case t == "locked" && why == "join":
		return fmt.Errorf("%w (%w)", ErrSpaceJoinLocked, ErrSpaceLockedThere)
	case t == "denied" && why == "nowin":
		return fmt.Errorf("%w (%w)", ErrSpaceNoWindow, ErrSpaceRefused)
	case t == "denied" && why == "wait": // и errors.Is(ErrSpaceAuth) с «denied», как было до Ч12б
		return fmt.Errorf("%w (%w: denied)", ErrSpaceWaitThere, ErrSpaceAuth)
	case t == "later":
		return fmt.Errorf("%w (%w)", ErrSpaceLater, ErrSpaceRefused)
	case t == "nojoin" && why == "ask":
		return ErrSpaceAsk
	case t == "nojoin" && why == "rights":
		return fmt.Errorf("%w (%w)", ErrSpaceViewOnlyThere, ErrSpaceRefused)
	case t == "nojoin":
		return fmt.Errorf("%w: %s (%w)", ErrSpaceNotThere, why, ErrSpaceRefused)
	case t == "ask":
		return ErrSpaceAsk
	case t == "locked":
		return fmt.Errorf("%w (%w)", ErrSpaceLockedThere, ErrSpaceAuth)
	case t == "busy":
		return fmt.Errorf("%w (%w)", ErrSpaceBusyThere, ErrSpaceAuth)
	case t == "fail" || t == "denied" || t == "nokey":
		return fmt.Errorf("%w: %s", ErrSpaceAuth, t)
	}
	return nil
}

// joinSigHook — тест: подменить доказательство фразы перед отправкой (перенос в другое соединение, чужой домен);
// joinFP — тест: отпечатки этого соединения перед подписью (клиента, хоста).
// joinAsUser — тест: вступающий сначала называет запись по имени; spEarlyM — тест: после входа паролем шлёт состав без
// запроса; joinBadCSig — тест: подпись ключа клиента в «b» вступления испорчена.
var (
	joinSigHook func(sig []byte) []byte
	joinFP      func(fc, fh string)
	joinAsUser  string
	spEarlyM    []byte
	joinBadCSig atomic.Bool
	// joinCodeHook — тест: перед отправкой кода вступления (блокировка во время ожидания кода).
	joinCodeHook func()
)

// spaceDupM — испытательная подмена: хост шлёт состав дважды (agent/space_test.go); в рабочем пути — нет.
var spaceDupM atomic.Bool

// spaceWait — весь обмен вступления (вход с Argon2 на обеих сторонах, ICE через TURN).
var spaceWait = 60 * time.Second

// Ч12: spaceLinkWait — от начала hostDial до установленного соединения (хаб, offer, ICE, DTLS): дольше хост и сам
// не ждёт (authWait 20 с — и закрывает сессию молча, без "bye"); spaceDialWait — WebSocket к одному хабу. Худший
// случай вступления с двумя хабами — spaceDialWait + spaceLinkWait ≈ 35 с, а не spaceWait + Confirm (3 мин).
var (
	spaceLinkWait = 25 * time.Second
	spaceDialWait = 10 * time.Second
)

// linkState — состояние служебного соединения (hostDial): соединилось — срок соединения снят; failed до
// соединения — нет связи (why: nolink или noudp), после — оборвалось (closed).
func linkState(st webrtc.PeerConnectionState, linked *atomic.Bool, noLink *time.Timer, finish func(error), why func() error) {
	switch st {
	case webrtc.PeerConnectionStateConnected:
		linked.Store(true)
		noLink.Stop()
	case webrtc.PeerConnectionStateFailed:
		if linked.Load() {
			finish(ErrSpaceClosed)
		} else {
			finish(why())
		}
	}
}

// hostDialBeforeAnswer — тест: пауза между SetLocalDescription и answer (кандидаты собираются раньше answer)
var hostDialBeforeAnswer func()

// spaceLinkClosedDelay — после закрытия SCTP подождать, пока pion отдаст обработчикам уже пришедшие сообщения
// (отказ хоста с причиной приходит перед закрытием): причина важнее «закрыл соединение».
const spaceLinkClosedDelay = 300 * time.Millisecond

// SpaceJoin — вступить через ПК d.ID: вернуть новый M, который P принял. Ошибка — P его не сохранил (или ответа
// не было: тогда состояние P неизвестно, повтор безопасен — второй раз P ответит "bad" на дубль ПК).
func SpaceJoin(ctx context.Context, d SpaceDial) ([]byte, error) {
	wait := spaceWait + d.Confirm
	if d.Password == "" || d.OwnerKey != nil { // Ч12б: и окно «Пустить?» на том ПК
		wait += admitWait
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
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
	var (
		mu      sync.Mutex
		hostPub ed25519.PublicKey // из "ok", подпись проверена
		ctl     *webrtc.DataChannel
		authed  bool
		asked   bool   // запрос M ушёл
		newM    []byte // M, отданный P
		out     []byte // итог: M, который P принял
	)
	stage := func(s string) {
		if d.Stage != nil {
			d.Stage(s)
		}
	}
	stage("link")
	err := hostDial(ctx, server, d.ID, connectReq{View: true}, func(pc *webrtc.PeerConnection, finish func(error)) {
		done := func(m []byte) { mu.Lock(); out = m; mu.Unlock(); finish(nil) }
		fps := func() (string, string) { // свой отпечаток, отпечаток хоста
			return pake.Fingerprint(pc.LocalDescription().SDP), pake.Fingerprint(pc.RemoteDescription().SDP)
		}
		askM := func() { // под mu: вход есть и ctl открыт — запросить M один раз
			if authed && ctl != nil && !asked {
				asked = true
				if spEarlyM != nil { // тест: состав без запроса (до «Разрешить» при входе паролем)
					b, _ := json.Marshal(spMsg{T: "sp", M: spEarlyM})
					ctl.SendText(string(b))
					return
				}
				ctl.SendText(`{"t":"sp"}`)
			}
		}
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			switch dc.Label() {
			case "auth":
				var want []byte // ожидаемое подтверждение хоста (CPace)
				first := true
				otpN := 0
				join := d.Password == "" // Ч12б: вступление без пароля (admit.go)
				var cpub []byte          // свой ключ из "b"
				salted := false          // соль ключа владельца пришла (один раз)
				named := false           // запись названа (d.User с паролем, тест joinAsUser без него): ждём второе «a»
				sendA := func(v authMsg) { b, _ := json.Marshal(v); dc.SendText(string(b)) }
				hostOK := func(am authMsg) bool { // хост доказал пароль (conf) и ключ (подпись над DTLS-отпечатками)
					fc, fh := fps()
					if join { // без пароля conf нет: только ключ хоста (и Known, если он уже знаком)
						return am.Join && pake.HostVerify(am.Pub, am.Sig, d.ID, fc, fh) == nil
					}
					return len(want) > 0 && bytes.Equal(am.Conf, want) && pake.HostVerify(am.Pub, am.Sig, d.ID, fc, fh) == nil
				}
				knownOK := func(am authMsg) bool { return d.Known == "" || pake.KeyFingerprint(am.Pub) == d.Known }
				dc.OnMessage(func(msg webrtc.DataChannelMessage) {
					var am authMsg
					if json.Unmarshal(msg.Data, &am) != nil {
						return
					}
					switch am.T {
					case "a":
						sendJoinB := func() {
							k, sig, err := signB(d.Key, d.ID, pc)
							if err != nil {
								finish(err)
								return
							}
							if joinBadCSig.Load() {
								sig[0] ^= 1
							}
							cpub = k
							sendA(authMsg{T: "b", Join: true, Phrase: d.Code == "", CPub: k, CSig: sig, From: d.Self, Name: d.Name})
						}
						sendPassB := func(am authMsg) { // CPace пароля на salt/msg этой "a" и "b" с доказательством ключа клиента
							fc, fh := fps()
							salt, msg := am.Salt, am.Msg
							permanent := len(am.PermSalt) > 0 && len(am.PermMsg) > 0
							if permanent { // новый хост: основной "a" — одноразовый код, permanent — отдельный CPace
								salt, msg = am.PermSalt, am.PermMsg
							}
							b, conf, hc, err := pake.ClientRespond(d.Password, salt, msg, d.ID, fc, fh)
							if err != nil {
								finish(err)
								return
							}
							want = hc
							// ключ клиента — ключ хоста этого ПК: P сверит с ним ключ нового члена в M
							cpub, csig, err := signB(d.Key, d.ID, pc)
							if err != nil {
								finish(err)
								return
							}
							sendA(authMsg{T: "b", Msg: b, Conf: conf, Permanent: permanent, CPub: cpub, CSig: csig, From: d.Self, Name: d.Name}) // Ч12б: ID и имя — в окно «Пустить?» нового поручителя
						}
						if named && am.User != "" && !first { // хост принял имя записи (d.User; тест joinAsUser)
							named = false
							if join {
								sendJoinB()
								return
							}
							sendPassB(am)
							return
						}
						if !first || am.User != "" {
							finish(errSpaceProtocol)
							return
						}
						first = false
						if !am.Space {
							finish(ErrSpaceOld)
							return
						}
						if join && (!am.Join || d.OwnerKey == nil) { // поручитель ≤ v0.3.1: только путь с паролем
							finish(ErrSpaceNeedPass)
							return
						}
						stage("auth")
						if join {
							if joinAsUser != "" { // тест: вступление в запись по имени
								named = true
								sendA(authMsg{T: "a", User: joinAsUser})
								return
							}
							sendJoinB()
							return
						}
						if d.User != "" { // named CPace (REQ-S-20): запись по имени — CPace на втором "a"
							named = true
							sendA(authMsg{T: "a", User: d.User})
							return
						}
						sendPassB(am)
					case "otp":
						if d.Code == "" {
							finish(ErrSpaceNeedPass) // старый поручитель не понимает phrase-only
							return
						}
						if otpN++; otpN > 1 || !hostOK(am) { // второй запрос — код не подошёл
							finish(ErrSpaceAuth)
							return
						}
						if !knownOK(am) { // код — только запомненному P
							finish(ErrSpaceHostKey)
							return
						}
						if join && joinCodeHook != nil {
							joinCodeHook()
						}
						sendA(authMsg{T: "otp", Code: d.Code})
					case "join": // Ч12б: соль ключа владельца — доказать фразу над этим соединением
						if !join || (otpN != 1 && (d.Code != "" || otpN != 0)) || salted || len(am.Salt) == 0 {
							finish(errSpaceProtocol)
							return
						}
						salted = true
						go func() { // Argon2 — не в потоке SCTP
							key, err := d.OwnerKey(am.Salt)
							if err != nil {
								finish(err)
								return
							}
							fc, fh := fps()
							sig := pake.SpaceJoinSign(key, d.ID, fc, fh, cpub)
							clear(key)
							if joinFP != nil {
								joinFP(fc, fh)
							}
							if joinSigHook != nil {
								sig = joinSigHook(sig)
							}
							sendA(authMsg{T: "join", Sig: sig})
						}()
					case "admit": // окно «Пустить?» на том ПК открыто (без пароля — после доказательства; с паролем — до состава)
						if join && !salted {
							finish(errSpaceProtocol)
							return
						}
						stage("admit")
					case "ok":
						if !hostOK(am) {
							finish(ErrSpaceAuth)
							return
						}
						if !knownOK(am) {
							finish(ErrSpaceHostKey)
							return
						}
						stage("list")
						mu.Lock()
						hostPub, authed = bytes.Clone(am.Pub), true
						askM()
						mu.Unlock()
					default:
						if err := joinRefusal(am); err != nil {
							finish(err)
						}
					}
				})
			case "ctl":
				signing := false // только в OnMessage этого канала (pion зовёт его по очереди)
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
						finish(errSpaceProtocol)
					case sm.Err == "admit_no": // Ч12б: окно «Пустить?» при входе паролем (новый поручитель)
						finish(fmt.Errorf("%w (%w)", ErrSpaceDeclined, ErrSpaceRefused))
					case sm.Err == "admit_timeout":
						finish(fmt.Errorf("%w (%w)", ErrSpaceNoAnswer, ErrSpaceRefused))
					case sm.Err == "admit_later":
						finish(fmt.Errorf("%w (%w)", ErrSpaceLater, ErrSpaceRefused))
					case sm.Err != "":
						finish(fmt.Errorf("%w: %s", ErrSpaceRefused, sm.Err))
					case sm.OK && mine != nil:
						if len(sm.M) > 0 { // named: хост сам подписал новый M — актуальный состав важнее отправленного
							if d.Heads != nil {
								*d.Heads = append([][]byte{bytes.Clone(sm.M)}, sm.H...)
							}
							done(sm.M)
						} else {
							done(mine)
						}
					case len(sm.M) > 0 && mine == nil && !signing:
						// второй M во время Sign — нарушение протокола (default); Sign ждёт подтверждения человеком —
						// в своей горутине, не в потоке SCTP (решение 12 A)
						signing = true
						go func() {
							m, err := d.Sign(sm.M, hp, sm.H...)
							if err != nil {
								finish(err)
								return
							}
							if bytes.Equal(m, sm.M) && d.User == "" { // owner: уже в составе P (полу-вступление) — принять как есть; named: ключа владельца нет, M без изменений и есть заявка — новый состав подписывает хост
								done(m)
								return
							}
							mu.Lock()
							newM = m
							mu.Unlock()
							b, _ := json.Marshal(spMsg{T: "sp", M: m})
							dc.SendText(string(b))
						}()
					default:
						finish(errSpaceProtocol)
					}
				})
			}
		})
	})
	if err != nil {
		return nil, err
	}
	mu.Lock()
	defer mu.Unlock()
	return out, nil
}

// signB — ключ клиента key и его подпись над DTLS-отпечатками этого соединения — для "b" (У3).
func signB(key ed25519.PrivateKey, id string, pc *webrtc.PeerConnection) (cpub, csig []byte, err error) {
	k, err := pake.ClientSignB64(base64.StdEncoding.EncodeToString(key.Seed()), id, pc.LocalDescription().SDP, pc.RemoteDescription().SDP)
	if err != nil {
		return nil, nil, err
	}
	csig, _ = base64.StdEncoding.DecodeString(k["sig"])
	return bytes.Clone(key.Public().(ed25519.PublicKey)), csig, nil
}

// hostDial — служебное соединение с хостом id через хаб server (вступление Э2, пропуск Э3): connect «только
// просмотр» без ключа (хаб видит connect открытым и узнал бы по ключу, какой ПК к какому ходит; ключ идёт только в
// "b" внутри DTLS), offer/answer, ICE. setup вешает обработчики каналов на pc до ответа; обмен кончает первый
// finish (nil — успех), разрыв или ctx. Хост не в сети — ErrSpaceOffline (вызывающий пробует следующий хаб).
// Э4в: sx — у сверки запечатанный (spsync.go), у остальных случайный той же длины: connect у всех одного вида.
// Ч12: соединение не установилось за spaceLinkWait или сорвалось (ICE failed) — ErrSpaceNoLink; оборвалось или
// хост закрыл его после установки — ErrSpaceClosed. Без этого обмен ждал ctx (у вступления — 3 мин): хост
// закрывает невошедшую сессию молча, а ICE без связи клиенту ничего не сообщает.
func hostDial(ctx context.Context, server, id string, req connectReq, setup func(pc *webrtc.PeerConnection, finish func(error))) error {
	if req.SX == nil {
		req.SX = sxRand(sxLen)
	}
	lctx, lcancel := context.WithCancel(ctx) // до соединения — не дольше spaceLinkWait
	defer lcancel()
	var linked atomic.Bool
	noLink := time.AfterFunc(spaceLinkWait, func() {
		if !linked.Load() {
			lcancel()
		}
	})
	defer noLink.Stop()
	noLinkErr := func(err error) error { // lctx кончился сроком соединения, а не ctx вызывающего
		if ctx.Err() == nil && lctx.Err() != nil {
			return ErrSpaceNoLink
		}
		return err
	}
	dctx, dcancel := context.WithTimeout(lctx, spaceDialWait)
	ws, err := dialWait(dctx, server, proxyWait)
	dcancel()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSpaceOffline, err)
	}
	defer ws.CloseNow()
	ws.SetReadLimit(64 << 10)
	var wmu sync.Mutex
	send := func(typ string, v any) {
		b, _ := json.Marshal(v)
		wmu.Lock()
		defer wmu.Unlock()
		wsjson.Write(lctx, ws, hub.Msg{V: 1, Type: typ, To: id, Data: b})
	}
	var m hub.Msg
	if err := wsjson.Read(lctx, ws, &m); err != nil || m.Type != "hello" {
		return fmt.Errorf("%w: хаб не ответил", ErrSpaceOffline)
	}
	var hello struct{ ICE []webrtc.ICEServer }
	json.Unmarshal(m.Data, &hello)
	send("connect", req) // View: ввод служебному соединению не нужен
	if err := wsjson.Read(lctx, ws, &m); err != nil {
		return noLinkErr(fmt.Errorf("%w: %v", ErrSpaceOffline, err))
	}
	if m.Type != "offer" {
		var why string
		json.Unmarshal(m.Data, &why)
		switch {
		case m.Type == "error" && why == "not_found":
			return ErrSpaceOffline
		case m.Type == "error" && why == "busy":
			return fmt.Errorf("%w (%w)", ErrSpaceBusyThere, ErrSpaceRefused)
		case m.Type == "error" && why == "locked":
			return fmt.Errorf("%w (%w)", ErrSpaceLockedThere, ErrSpaceRefused)
		case m.Type == "error" && why == "nopass":
			return fmt.Errorf("%w (%w)", ErrSpaceNoPassThere, ErrSpaceRefused)
		}
		return fmt.Errorf("%w: %s %s", ErrSpaceRefused, m.Type, why)
	}
	defer send("bye", "client")
	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{ICEServers: hello.ICE})
	if err != nil {
		return err
	}
	defer pc.Close()
	done := make(chan error, 1)
	finish := func(err error) {
		select {
		case done <- err:
		default:
		}
	}
	setup(pc, finish)
	var outside atomic.Bool // собран srflx или relay: STUN/TURN этому процессу доступны
	noLinkWhy := func() error {
		if len(hello.ICE) > 0 && !outside.Load() {
			return fmt.Errorf("%w (%w)", ErrSpaceNoUDP, ErrSpaceNoLink)
		}
		return ErrSpaceNoLink
	}
	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) { linkState(st, &linked, noLink, finish, noLinkWhy) })
	pc.SCTP().OnClose(func(error) { // хост закрыл сессию (authWait, отказ) или связь оборвалась
		time.AfterFunc(spaceLinkClosedDelay, func() { finish(ErrSpaceClosed) })
	})
	// кандидаты — только после answer: хост отвергает "ice" до remote description (AddICECandidate), а pion собирает
	// host-кандидаты сразу в SetLocalDescription — до send("answer") (окно-браузер шлёт их позже, после answer)
	var (
		cmu      sync.Mutex
		answered bool
		early    []webrtc.ICECandidateInit
	)
	pc.OnICECandidate(func(ci *webrtc.ICECandidate) {
		if ci == nil {
			return
		}
		if ci.Typ == webrtc.ICECandidateTypeSrflx || ci.Typ == webrtc.ICECandidateTypeRelay {
			outside.Store(true)
		}
		cmu.Lock()
		if !answered {
			early = append(early, ci.ToJSON())
			cmu.Unlock()
			return
		}
		cmu.Unlock()
		send("ice", ci.ToJSON())
	})
	var offer webrtc.SessionDescription
	if err := json.Unmarshal(m.Data, &offer); err != nil {
		return errSpaceProtocol
	}
	if err := pc.SetRemoteDescription(offer); err != nil {
		return err
	}
	ans, err := pc.CreateAnswer(nil)
	if err == nil {
		err = pc.SetLocalDescription(ans)
	}
	if err != nil {
		return err
	}
	if hostDialBeforeAnswer != nil {
		hostDialBeforeAnswer()
	}
	send("answer", ans)
	cmu.Lock()
	answered = true
	cs := early
	cmu.Unlock()
	for _, c := range cs {
		send("ice", c)
	}
	go func() {
		for {
			var m hub.Msg
			if wsjson.Read(lctx, ws, &m) != nil {
				return
			}
			switch {
			case m.From != id: // служебное хаба — сессии не касается
			case m.Type == "ice":
				var ci webrtc.ICECandidateInit
				if json.Unmarshal(m.Data, &ci) == nil {
					pc.AddICECandidate(ci)
				}
			case m.Type == "bye": // и «закрыл соединение» (окно), и отказ (сверка, пропуск: состояние "refused" как было)
				finish(fmt.Errorf("%w: разрыв (%w)", ErrSpaceRefused, ErrSpaceClosed))
			}
		}
	}()
	select {
	case err := <-done:
		return err
	case <-lctx.Done():
		if ctx.Err() == nil {
			return noLinkWhy()
		}
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("пространство: нет ответа вовремя (%w)", ctx.Err()) // окно: errors.Is(context.DeadlineExceeded)
		}
		return ctx.Err()
	}
}
