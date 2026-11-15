package agent

// Ч10.1 «приём на хосте» (UI-REDESIGN.md, «Ч10 «Отправить»»; решения владельца 2026-11-15, TZ.md §16): файлы и
// текст на этот ПК вне сессии управления. ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (CLAUDE.md A13): проверка ключа члена (recvMember),
// разового кода и закреплённого ключа (recvB), потолки (rxStart, rxCount). Новых криптопримитивов нет: ключ члена —
// запечатанный sx сверки (spseal.go), код — CPace записи по умолчанию (как вход), ключ клиента — подпись в "b" (У3).
//
// Соединение «приём» — connect того же вида, что сверка, вступление и пропуск ({"view":true,"sx":…}, hostDial): хаб
// его не отличит от них сильнее, чем сверку (свой ПК — ровно connect сверки, чужой — ровно connect вступления).
// Сессия приёма не входит (authed не ставится никогда): ни видео, ни ввода, ни буфера на отправку, ни звука; каналы
// хоста "input" и "ctl" глухие (гейт authed/control), из каналов клиента принимаются только "file" и "text".
// Места: своё (recvs, не больше rxMaxSess) — вне места сессии и maxPending; до "b" — место сверки (свой) или место
// незавершённого входа (чужой), как раньше. Идёт сессия управления — connect получает тот же "busy", что всегда.
//
// Только добавления (старые клиенты не затронуты: recv не шлют; старый хост recv в "a" не объявляет — отправитель
// кончает до "b": ErrRecvOld «На том ПК старая версия AnyPC»):
//
//	хост → {"t":"a",…,"recv":true}                       хост понимает приём
//
// Свой ПК (решение A): sx connect — доказательство ключа члена M цели (sxMake, как у сверки); дальше как сверка:
//
//	клиент → {"t":"b",cpub,csig,"key":true,"recv":true,"pub":P,"from":ID,"name":имя}  cpub — ключ из sx
//	хост → {"t":"rx",pub,sig,"lim":{…}}                 файлы и текст — сразу, без окна
//	       | {"t":"rx","why":"notme"|"gone"|"rate"|"busy"} | {"t":"denied"} (ключ не тот, что в sx, или не доказан)
//
// Чужой ПК (решение A): sx случайный, connect обычный (место входа, блокировка перебора — как у входа):
//
//	первый раз: клиент → {"t":"b",msg,conf,cpub,csig,"recv":true,"from","name"} — CPace разовым кодом записи по
//	  умолчанию (только в режиме «Спрашивать», CodeMode); хост → {"t":"rx",conf,pub,sig,"lim"} — код израсходован,
//	  ключ cpub закреплён (RecvPin) | "fail" (неудача в счёт перебора) | "locked" | {"t":"rx","why":"nocode"|…}
//	дальше: клиент → {"t":"b",cpub,csig,"key":true,"recv":true,"from","name"}; ключ закреплён (RecvPinned) —
//	  {"t":"rx",pub,sig,"ask":true,"lim"}: первое принимаемое — окно «Принять?» (RecvAsk, не дольше AskTimeout;
//	  «Принять» — и остальные файлы сессии); незнакомый ключ — {"t":"nokey","why":"none"}
//
// Каналы клиента после "rx":
//
//	"file" — протокол file.go (докачка); потолок — {"t":"err","msg","code":"size"|"total"|"count"|"denied"|"gone"};
//	         Ч10.2: файл папки — "meta" + "path":"Папка/подпапка/файл" (safeRel; хост объявляет "lim":{"dirs":true},
//	         иначе — хост Ч10.1: папку ему не шлём, ErrRecvOldDirs), отказ пути — "code":"path"
//	"text" — клиент → {"t":"text","size":N} (1 ≤ N ≤ lim.text), двоичные куски, {"t":"end"}; хост → {"t":"done"} |
//	         {"t":"err","code":…}: свой ПК — сразу в буфер обмена; чужой — окно «Принять?» с текстом, после
//	         «Принять» — в буфер. «Отклонить» или нет ответа — "denied", сессия закрывается.
//
// Журнал: одна строка на принятый приём (от кого, сколько файлов и байт, был ли текст) — без имён файлов и текста.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"anypc/hub"
	"anypc/pake"

	"filippo.io/cpace"
	"github.com/pion/webrtc/v4"
)

// rxLimits — потолки сессии приёма; уходят отправителю в "rx" (lim), проверяет хост.
type rxLimits struct {
	File  int64 `json:"file"`           // байт в одном файле
	Total int64 `json:"total"`          // байт файлов за сессию (докачка считается целым файлом)
	Items int   `json:"items"`          // файлов и текстов за сессию
	Text  int64 `json:"text"`           // байт одного текста
	Dirs  bool  `json:"dirs,omitempty"` // Ч10.2: хост принимает папки (fileMsg.Path); нет — хост Ч10.1, папку ему не слать
}

// Потолки (NOTIFY: числа выбраны исполнителем; атомарные — тесты меняют их при живых сессиях). Место на диске сверх
// них бережёт diskReserve (и на каждом мегабайте записи, Receiver.Write).
var (
	rxLimP    atomic.Pointer[rxLimits]
	rxRateOwn atomic.Int32 // сессий приёма с одного ключа члена за rxRatePer
	rxRateFor atomic.Int32 // с одного чужого ключа (закреплённого или с кодом) — каждая может открыть окно
	rxIdle    atomic.Int64 // нс: без сообщений (кроме кусков текста) — сессия приёма закрывается
	rxLife    atomic.Int64 // нс: после стольких — сессия закрывается, как только байты перестали идти (N2 приёмки)
	rxSlowWin atomic.Int64 // нс: окно скорости — байты шли, но меньше rxMinRate за окно — сессия закрывается
	rxMinRate atomic.Int64 // байт/с
	rxPartMax atomic.Int64 // байт: заявленный размер одновременно открытых .part всех сессий приёма
)

const rxRatePer = time.Minute // окно счёта частоты

func init() {
	rxLimP.Store(&rxLimits{File: 16 << 30, Total: 64 << 30, Items: 1000, Text: 1 << 20, Dirs: true})
	rxRateOwn.Store(10)
	rxRateFor.Store(3)
	rxIdle.Store(int64(2 * time.Minute))
	rxLife.Store(int64(30 * time.Minute))
	rxSlowWin.Store(int64(2 * time.Minute))
	rxMinRate.Store(64 << 10)
	rxPartMax.Store(32 << 30)
}

func rxLim() rxLimits { return *rxLimP.Load() }

const (
	rxMaxSess = 4    // сессий приёма одновременно (все ключи)
	rxMaxKeys = 1024 // ключей в счёте частоты; больше — новые ключи получают "rate", пока старые не выйдут из окна
	rxNameMax = 32   // заявленное имя отправителя, рун
)

// RecvReq — что спросить в окне «Принять?» (AskRecv): от кого, файл (имя после safeName, размер) или текст.
type RecvReq struct {
	From   string
	Name   string
	Size   int64
	Text   string
	IsText bool
}

// rxState — сессия приёма (session.rx).
type rxState struct {
	own   bool              // ключ члена M (свой ПК): без окна
	t0    time.Time         // начало: живёт не дольше life
	idle  time.Duration     // снимок rxIdle
	life  time.Duration     // снимок rxLife
	win   time.Duration     // снимок rxSlowWin
	rate  int64             // снимок rxMinRate
	moved atomic.Int64      // принято байт (файлы и текст): продвижение для rxWatch
	pub   ed25519.PublicKey // доказанный ключ отправителя
	from  string            // кто — для окна и журнала: заявленные имя и ID (не доказаны) и отпечаток ключа
	lim   rxLimits

	mu    sync.Mutex
	ok    bool              // файлы — без окна: свой ПК, разовый код или уже «Принять» в этой сессии
	roots map[string]string // Ч10.2: папка, заявленная отправителем → папка приёма в «Загрузках» (mkRoot)
	items int               // начато файлов и текстов
	bytes int64             // байт начатых файлов
	nf    int               // принято файлов
	nb    int64             // байт в принятых файлах
	nt    int               // принято текстов

	declined atomic.Bool
	asking   atomic.Int32 // открыто окно «Принять?»: ждём человека — простой и срок не считаются (rxWatch)
	pinning  atomic.Bool  // приём разовым кодом: ключ закрепляется (RecvPin) — rxStill закрепления ещё не требует
	texting  atomic.Bool  // идёт приём текста (один за раз)
	ask      sync.Mutex   // окно «Принять?» — одно за раз в сессии
	last     atomic.Int64
	logged   sync.Once
}

func (r *rxState) touch() { r.last.Store(time.Now().UnixNano()) }

func (r *rxState) accepted() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.ok }

// rxWhy — текст отказа по коду (отправителю в "err"; окно отправителя покажет свой текст по коду).
var rxWhy = map[string]string{
	"size":     "файл больше потолка приёма",
	"total":    "превышен объём приёма за сессию",
	"count":    "слишком много файлов за сессию",
	"denied":   "получатель отклонил",
	"gone":     "этот ПК больше не в пространстве получателя",
	"text":     "текст пустой, больше 1 МБ или не UTF-8",
	"clip":     "буфер обмена получателя недоступен",
	"viewonly": "на том ПК включено «Только показ экрана»",
	"disk":     "на том ПК мало места",
	"io":       "ошибка приёма на том ПК",
	"path":     "недопустимый путь в папке",
}

// rxRoot — папка приёма для заявленной папки name (safeRel) в этой сессии: первая — новая «Загрузки/name[ (n)]»
// (mkRoot), дальше — та же. Ч10.2.
func (r *rxState) rxRoot(dir, name string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := r.roots[name]; ok {
		return v, nil
	}
	v, err := mkRoot(dir, name)
	if err != nil {
		return "", err
	}
	if r.roots == nil {
		r.roots = map[string]string{}
	}
	r.roots[name] = v
	return v, nil
}

// rxCount — ещё один файл размера size (text — текст) в сессии: потолки числа и объёма. "" — можно.
// ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (A13): потолки.
func (r *rxState) count(size int64, text bool) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case r.items >= r.lim.Items:
		return "count"
	case !text && (size < 0 || size > r.lim.File):
		return "size"
	case !text && r.bytes+size > r.lim.Total:
		return "total"
	}
	r.items++
	if !text {
		r.bytes += size
	}
	return ""
}

// rxClean — заявленная строка отправителя: буквы, цифры, пробел и « . _ - @ », не длиннее n рун.
func rxClean(s string, n int) string {
	s = strings.Map(func(c rune) rune {
		if unicode.IsLetter(c) || unicode.IsDigit(c) || strings.ContainsRune(" ._-@", c) {
			return c
		}
		return -1
	}, s)
	if r := []rune(strings.TrimSpace(s)); len(r) > n {
		s = string(r[:n])
	}
	return strings.TrimSpace(s)
}

// rxClaim — заявленные в "b" ID и имя отправителя (подсказка для окна и закрепления, не доказательство).
func rxClaim(m authMsg) (id, name string) {
	if hub.IsHostID(m.From) {
		id = m.From
	}
	return id, rxClean(m.Name, rxNameMax)
}

// rxLabel — подпись отправителя: «имя (ID …, ключ …)».
func rxLabel(id, name string, pub []byte) string {
	fp := pake.KeyFingerprint(pub)
	if len(fp) > 9 {
		fp = fp[:9]
	}
	who := "ключ " + fp
	if id != "" {
		who = "ID " + id + ", " + who
	}
	if name == "" {
		return who
	}
	return name + " (" + who + ")"
}

// rxStart — сессия s становится сессией приёма rx: не больше rxMaxSess одновременно и rate сессий с ключа за
// rxRatePer; место незавершённого входа или сверки освобождается. "" — принята, иначе причина отказа ("busy", "rate").
// ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (A13): потолок частоты.
func (a *Agent) rxStart(s *session, rx *rxState, rate int) string {
	now := time.Now()
	k := string(rx.pub)
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.gone.Load() || len(a.recvs) >= rxMaxSess {
		return "busy"
	}
	if !rx.own { // чужой ключ — не больше одной сессии сразу (M2 приёмки)
		for o := range a.recvs {
			if p := o.rx.Load(); p != nil && bytes.Equal(p.pub, rx.pub) {
				return "busy"
			}
		}
	}
	fresh := func(l []time.Time) []time.Time {
		var out []time.Time
		for _, t := range l {
			if now.Sub(t) < rxRatePer {
				out = append(out, t)
			}
		}
		return out
	}
	if a.rxRate == nil {
		a.rxRate = map[string][]time.Time{}
	}
	l := fresh(a.rxRate[k])
	if len(l) >= rate {
		a.rxRate[k] = l
		return "rate"
	}
	if _, known := a.rxRate[k]; !known && len(a.rxRate) >= rxMaxKeys {
		for kk, v := range a.rxRate {
			if v = fresh(v); len(v) == 0 {
				delete(a.rxRate, kk)
			} else {
				a.rxRate[kk] = v
			}
		}
		if len(a.rxRate) >= rxMaxKeys {
			return "rate"
		}
	}
	a.rxRate[k] = append(l, now)
	delete(a.pend, s)
	a.syncDrop(s)
	if a.recvs == nil {
		a.recvs = map[*session]bool{}
	}
	a.recvs[s] = true
	rx.t0, rx.idle, rx.life = now, time.Duration(rxIdle.Load()), time.Duration(rxLife.Load())
	rx.win, rx.rate = time.Duration(rxSlowWin.Load()), rxMinRate.Load()
	if a.noDirs { // тест: хост Ч10.1 — папок не объявляет, путь пропускает
		rx.lim.Dirs = false
	}
	rx.touch()
	s.rx.Store(rx)
	return ""
}

// rxWatch — когда закрыть сессию приёма (N2 приёмки): без единого сообщения rxIdle (отправитель ушёл, не закрыв
// соединение); байты шли, но медленнее rate за окно win (держит место по капле); дольше life — как только байты
// перестали идти (длинный файл, который идёт, не рвётся).
func (a *Agent) rxWatch(ctx context.Context, s *session, rx *rxState) {
	t := time.NewTicker(min(rx.idle, rx.life, rx.win) / 4)
	defer t.Stop()
	winAt, winMoved, last := rx.t0, int64(0), int64(-1)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			m, why := rx.moved.Load(), ""
			switch {
			case rx.asking.Load() > 0: // окно «Принять?» (до AskTimeout): ждёт человек, не отправитель
				rx.touch()
				m = -1
			case now.Sub(time.Unix(0, rx.last.Load())) > rx.idle:
				why = fmt.Sprintf("нет данных %v", rx.idle)
			case now.Sub(winAt) >= rx.win:
				// скорость — только после life: до него мелкие файлы подряд и медленный канал — честная передача
				if d := m - winMoved; now.Sub(rx.t0) > rx.life && float64(d) < float64(rx.rate)*now.Sub(winAt).Seconds() {
					why = fmt.Sprintf("дольше %v и медленнее %d байт/с за %v", rx.life, rx.rate, rx.win)
				}
				winAt, winMoved = now, m
			case now.Sub(rx.t0) > rx.life && m == last:
				why = fmt.Sprintf("дольше %v без данных", rx.life)
			}
			last = m
			if why != "" {
				log.Printf("приём от %s: %s — закрыт", rx.from, why)
				s.pc.Close()
				return
			}
		}
	}
}

// end — журнал приёма (одна строка, без содержимого), когда сессия кончилась (release).
func (r *rxState) end() {
	r.logged.Do(func() {
		r.mu.Lock()
		nf, nb, nt := r.nf, r.nb, r.nt
		r.mu.Unlock()
		if nf+nt == 0 {
			return
		}
		text := ""
		if nt > 0 {
			text = fmt.Sprintf(", текстов %d", nt)
		}
		kind := map[bool]string{true: "свой ПК", false: "чужой ПК"}[r.own]
		log.Printf("приём от %s (%s): файлов %d, %d байт%s", r.from, kind, nf, nb, text)
	})
}

// recvMember — "b" приёма в соединении, чей sx открылся ключом члена (syncConnect): ключ cpub — тот, что в sx, и
// доказан подписью над отпечатками; хост доказывает свой, только если клиент ждёт именно его.
// ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (A13): проверка ключа члена.
func (a *Agent) recvMember(ctx context.Context, s *session, m authMsg, keyOK bool, fpc, fph string, send func(any)) {
	st := s.sy.Load()
	st.mu.Lock()
	defer st.mu.Unlock()
	me := a.Key.Public().(ed25519.PublicKey)
	switch {
	case st.phase != 1 || !m.Recv || !m.Key || !keyOK || !bytes.Equal(m.CPub, st.pub):
		send(authMsg{T: "denied"})
	case !bytes.Equal(m.Pub, me):
		send(authMsg{T: "rx", Why: "notme"})
	case a.viewOnlyHost(): // REQ-F-25: «Только показ экрана» — ни файлов, ни буфера
		send(authMsg{T: "rx", Why: "viewonly"})
	case a.LoginShut != nil && a.LoginShut(""): // решение 12 A: до сверки с членом ≠ поручитель состав не проверен (M3)
		send(authMsg{T: "rx", Why: "wait"})
	case a.SpaceSync == nil || !a.SpaceSync.SyncKey(st.pub): // исключили между connect и "b"
		send(authMsg{T: "rx", Why: "gone"})
	default:
		id, name := rxClaim(m)
		rx := &rxState{own: true, ok: true, pub: bytes.Clone(st.pub), from: rxLabel(id, name, st.pub), lim: rxLim()}
		if why := a.rxStart(s, rx, int(rxRateOwn.Load())); why != "" {
			send(authMsg{T: "rx", Why: why})
			break
		}
		st.phase = 4 // "sp" сверки в этом соединении больше не принимаются
		send(authMsg{T: "rx", Pub: me, Sig: pake.HostSign(a.Key, a.ID, fpc, fph), Lim: &rx.lim})
		go a.rxWatch(ctx, s, rx)
		return
	}
	st.phase = 4
	a.syncEnd(s)
}

// recvB — "b" приёма в обычном соединении (чужой ПК): разовый код записи по умолчанию (cur — CPace этой сессии)
// или закреплённый ключ. Ключ клиента обязан быть доказан: его закрепляют и по нему считают частоту.
// ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (A13): проверка кода (та же блокировка перебора, что у входа) и закреплённого ключа.
func (a *Agent) recvB(ctx context.Context, s *session, m authMsg, cur *cpace.State, keyOK bool, user, fpc, fph string, send func(authMsg)) {
	reject := func(t, why string) {
		send(authMsg{T: t, Why: why})
		a.release(s)
		time.AfterFunc(500*time.Millisecond, func() { s.pc.Close() }) // дать дойти ответу
	}
	if !keyOK || user != "" { // ключ не доказан — закреплять и считать нечего; приём — только записью по умолчанию
		reject("denied", "")
		return
	}
	if a.viewOnlyHost() { // REQ-F-25: до кода — код не расходуется, неудач нет
		reject("rx", "viewonly")
		return
	}
	id, name := rxClaim(m)
	me := a.Key.Public().(ed25519.PublicKey)
	sig := pake.HostSign(a.Key, a.ID, fpc, fph)
	if m.Key { // закреплённый ключ: без кода, первое принимаемое — окно «Принять?»
		pid, pname, ok := "", "", false
		if a.RecvPinned != nil {
			pid, pname, ok = a.RecvPinned(m.CPub)
		}
		if !ok || a.RecvAsk == nil { // незнакомый ключ без кода — отказ без неудачи (ключ доказан, перебирать нечего)
			reject("nokey", "none")
			return
		}
		rx := &rxState{pub: bytes.Clone(m.CPub), from: rxLabel(pid, pname, m.CPub), lim: rxLim()} // в окно — закреплённые ID и имя, не заявленные сейчас (B2)
		if why := a.rxStart(s, rx, int(rxRateFor.Load())); why != "" {
			reject("rx", why)
			return
		}
		send(authMsg{T: "rx", Pub: me, Sig: sig, Ask: true, Lim: &rx.lim})
		go a.rxWatch(ctx, s, rx)
		return
	}
	if a.CodeMode == nil || !a.CodeMode() { // разового кода на этом ПК нет (вход паролем): пароль чужим не годится
		reject("rx", "nocode")
		return
	}
	// блокировка перебора и счёт — как у входа кодом (authChannel): под одним a.mu
	a.mu.Lock()
	if a.pwLocked("", time.Now()) {
		a.mu.Unlock()
		reject("locked", "")
		return
	}
	conf, err := pake.HostFinish(cur, m.Msg, m.Conf)
	a.countAuth(s.cid, "", err == nil)
	a.mu.Unlock()
	if err != nil {
		reject("fail", "")
		return
	}
	rx := &rxState{ok: true, pub: bytes.Clone(m.CPub), from: rxLabel(id, name, m.CPub), lim: rxLim()}
	rx.pinning.Store(true) // до RecvPin ключ ещё не закреплён: rxPrune (опрос настроек) сессию не трогает
	why := a.rxStart(s, rx, int(rxRateFor.Load()))
	if a.CodeUsed != nil { // разовый: израсходован и при отказе по частоте (его знает отправитель)
		go a.codeUsed()
	}
	if why != "" {
		reject("rx", why)
		return
	}
	if a.RecvPin != nil { // после принятого кода — закрепить ключ отправителя (решение A)
		a.RecvPin(m.CPub, id, name)
	}
	rx.pinning.Store(false)
	log.Printf("приём от %s: разовый код верный, ключ закреплён", rx.from)
	send(authMsg{T: "rx", Conf: conf, Pub: me, Sig: sig, Lim: &rx.lim})
	go a.rxWatch(ctx, s, rx)
}

// rxConfirm — перед приёмом файла или текста: ключ члена ещё в составе (свой ПК); чужой — окно «Принять?» (текст —
// всегда, файлы — один раз за сессию). "" — принимать; "denied" — сессия закрывается.
func (a *Agent) rxConfirm(s *session, rx *rxState, q RecvReq) string {
	if code := a.rxStill(rx); code != "" {
		return code
	}
	if rx.own {
		return ""
	}
	if !q.IsText && rx.accepted() {
		return ""
	}
	rx.ask.Lock()
	defer rx.ask.Unlock()
	if !q.IsText && rx.accepted() { // «Принять» дали, пока ждали окна
		return ""
	}
	q.From = rx.from
	yes := false
	if a.RecvAsk != nil && !s.gone.Load() && !rx.declined.Load() {
		rx.asking.Add(1)
		yes = a.RecvAsk(q)
		rx.asking.Add(-1)
	}
	if !yes {
		rx.declined.Store(true) // ждавшие окна — отказ без второго окна
		rx.touch()
		log.Printf("приём от %s: отклонён на этом ПК", rx.from)
		time.AfterFunc(500*time.Millisecond, func() { s.pc.Close() }) // дать дойти отказу
		return "denied"
	}
	rx.touch()
	rx.mu.Lock()
	rx.ok = true
	rx.mu.Unlock()
	return ""
}

// rxStill — сессия приёма ещё вправе принимать: хост не «Только показ экрана», ключ члена в составе, ключ чужого
// закреплён. "" — да.
func (a *Agent) rxStill(rx *rxState) string {
	switch {
	case a.viewOnlyHost():
		return "viewonly"
	case rx.own && (a.SpaceSync == nil || !a.SpaceSync.SyncKey(rx.pub)):
		return "gone"
	case !rx.own && !rx.pinning.Load() && a.RecvPinned != nil:
		if _, _, ok := a.RecvPinned(rx.pub); !ok {
			return "denied"
		}
	}
	return ""
}

// rxPrune — сессии приёма исключённых и откреплённых ключей и все при «Только показ экрана» — закрыть (DropRevoked).
func (a *Agent) rxPrune() {
	a.mu.Lock()
	var l []*session
	for s := range a.recvs {
		l = append(l, s)
	}
	a.mu.Unlock()
	for _, s := range l {
		if rx := s.rx.Load(); rx != nil && a.rxStill(rx) != "" {
			log.Printf("приём от %s: ключ исключён, откреплён или «Только показ экрана» — закрыт", rx.from)
			s.pc.Close()
		}
	}
}

// receiveText — канал "text" сессии приёма: текст целиком, затем (окно «Принять?» у чужого) — в буфер обмена.
func (a *Agent) receiveText(dc *webrtc.DataChannel, s *session, rx *rxState) {
	var mu sync.Mutex
	var buf []byte
	size, done, mine := int64(-1), false, false
	free := func() { // под mu: текст кончен (принят, отказ, обрыв) — место «один текст за раз» свободно
		if mine {
			mine, buf = false, nil
			rx.texting.Store(false)
		}
	}
	dc.OnClose(func() { mu.Lock(); free(); mu.Unlock() })
	fail := func(code string) {
		free()
		done = true
		sendJSON(dc, fileMsg{T: "err", Code: code, Msg: rxWhy[code]})
		dc.Close()
	}
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		mu.Lock()
		defer mu.Unlock()
		if done {
			return
		}
		if !m.IsString { // куски текста сессию не продлевают: текст ≤ 1 МБ приходит сразу (по капле — rxIdle)
			if size < 0 || int64(len(buf)+len(m.Data)) > size {
				fail("text")
				return
			}
			buf = append(buf, m.Data...)
			rx.moved.Add(int64(len(m.Data)))
			return
		}
		rx.touch()
		var fm fileMsg
		json.Unmarshal(m.Data, &fm)
		switch {
		case fm.T == "text" && size < 0:
			if fm.Size < 1 || fm.Size > rx.lim.Text {
				fail("text")
				return
			}
			if !rx.texting.CompareAndSwap(false, true) { // один текст за раз: память сессии — не больше lim.Text
				fail("count")
				return
			}
			mine = true
			if code := rx.count(0, true); code != "" {
				fail(code)
				return
			}
			size = fm.Size // память — по пришедшим данным, не по заявленному
		case fm.T == "end" && size >= 0:
			if int64(len(buf)) != size || !utf8.Valid(buf) {
				fail("text")
				return
			}
			done = true
			text := rxClipText(string(buf))
			go func() { // окно «Принять?» ждёт человека — не в цикле чтения SCTP
				defer func() { mu.Lock(); free(); mu.Unlock() }()
				if code := a.rxConfirm(s, rx, RecvReq{IsText: true, Text: text, Size: size}); code != "" {
					sendJSON(dc, fileMsg{T: "err", Code: code, Msg: rxWhy[code]})
					dc.Close()
					return
				}
				if err := setClip(text); err != nil {
					log.Printf("приём от %s: буфер обмена: %v", rx.from, err)
					sendJSON(dc, fileMsg{T: "err", Code: "clip", Msg: rxWhy["clip"]})
					dc.Close()
					return
				}
				rx.mu.Lock()
				rx.nt++
				rx.mu.Unlock()
				sendJSON(dc, fileMsg{T: "done"})
			}()
		case fm.T == "cancel":
			done = true
			dc.Close()
		default:
			fail("text")
		}
	})
}

// rxClipText — текст в буфер обмена: без управляющих C0/C1 (кроме \t \n \r) и форматных (U+202E и др.) — они
// подменяют вид команды при вставке в терминал и порядок символов.
func rxClipText(t string) string {
	return strings.Map(func(c rune) rune {
		if c == '\t' || c == '\n' || c == '\r' {
			return c
		}
		if unicode.Is(unicode.Cc, c) || c >= 0x202A && c <= 0x202E || c >= 0x2066 && c <= 0x2069 {
			return -1
		}
		return c
	}, t)
}

// rxReserve — место под .part размера n в общем потолке rxPartMax; false — потолок (M4 приёмки). rxFree — вернуть.
func (a *Agent) rxReserve(n int64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n < 0 || a.rxParts+n > rxPartMax.Load() {
		return false
	}
	a.rxParts += n
	return true
}

func (a *Agent) rxFree(n int64) { a.mu.Lock(); a.rxParts -= n; a.mu.Unlock() }

// Ошибки SendTo (окно отправителя, Ч10.3–Ч10.5, показывает свой текст по ним).
var (
	ErrRecvOld    = errors.New("На том ПК старая версия AnyPC")
	ErrRecvCode   = errors.New("приём: неверный код")
	ErrRecvLocked = errors.New("приём: слишком много неверных кодов — подождите")
	ErrRecvNoKey  = errors.New("приём: тот ПК вас не знает — нужен разовый код с его экрана")
	ErrRecvNoCode = errors.New("приём: тот ПК не показывает разовый код (вход паролем)")
	ErrRecvDenied = errors.New("приём: получатель отклонил")
	ErrRecvBusy   = errors.New("приём: тот ПК занят — попробуйте позже")
	ErrRecvRate   = errors.New("приём: слишком часто — попробуйте через минуту")
	ErrRecvLimit  = errors.New("приём: превышен потолок")
	ErrRecvGone   = errors.New("приём: этот ПК больше не в пространстве того ПК")
	// ErrRecvViewOnly — на том ПК «Только показ экрана» (REQ-F-25): файлы и буфер не принимаются.
	ErrRecvViewOnly = errors.New("приём: на том ПК включено «Только показ экрана»")
	// ErrRecvWait — тот ПК ещё не сверил состав пространства (решение 12 A).
	ErrRecvWait = errors.New("приём: тот ПК ещё не сверил состав пространства — попробуйте позже")
	// ErrRecvOldDirs — тот ПК понимает приём, но не папки (Ч10.1): папку не шлём — он сложил бы её файлы в одну кучу.
	ErrRecvOldDirs = errors.New("На том ПК версия AnyPC без приёма папок — обновите её")
	// ErrRecvPath — путь в папке тот ПК не принял (safeRel; RecvError "path").
	ErrRecvPath = errors.New("приём: недопустимый путь в папке")
	// ErrRecvKnown — чужой ПК без кода: нужен закреплённый ключ получателя (SendDial.Known).
	ErrRecvKnown = errors.New("приём: ключ того ПК не закреплён — нужен разовый код")
)

// RecvError — отказ получателя по файлу или тексту: код из "err" (rxWhy).
type RecvError struct{ Code, Msg string }

func (e *RecvError) Error() string { return "получатель: " + e.Msg + " (" + e.Code + ")" }

func (e *RecvError) Unwrap() error {
	switch e.Code {
	case "size", "total", "count", "text":
		return ErrRecvLimit
	case "denied":
		return ErrRecvDenied
	case "gone":
		return ErrRecvGone
	case "viewonly":
		return ErrRecvViewOnly
	case "path":
		return ErrRecvPath
	}
	return nil
}

func rxErr(why string) error {
	switch why {
	case "nocode":
		return ErrRecvNoCode
	case "rate":
		return ErrRecvRate
	case "busy":
		return ErrRecvBusy
	case "gone":
		return ErrRecvGone
	case "notme":
		return ErrSpaceIDKey
	case "viewonly":
		return ErrRecvViewOnly
	case "wait":
		return ErrRecvWait
	}
	return fmt.Errorf("%w: %s", ErrSpaceRefused, why)
}

// SendDial — отправить файлы, папки и текст на ПК ID (Ч10.1–Ч10.3; send.go).
type SendDial struct {
	Server   string             // хабы через запятую, как Agent.Server
	ID       string             // получатель
	HostPub  ed25519.PublicKey  // свой ПК: ключ хоста получателя из M этого ПК; nil — чужой ПК
	Key      ed25519.PrivateKey // ключ хоста этого ПК (ключ члена; у чужого закрепляется он)
	From     string             // ID этого ПК — подсказка получателю для закрепления
	Name     string             // имя этого ПК — подсказка получателю
	Code     string             // чужой ПК, первый раз: разовый код с его экрана; "" — по закреплённому ключу («Принять?»)
	Known    string             // чужой ПК: отпечаток его ключа (pake.KeyFingerprint) с прошлого раза; другой — отказ
	Files    []string
	Dirs     []string           // Ч10.2: папки целиком (ссылки внутри не идут, send.go makePlan)
	Text     string             // "" — без текста
	Clip     bool               // текст — из буфера обмена этого ПК (Text не нужен)
	Progress func(SendProgress) // ход отправки (из потока отправки); nil — не нужен
}

// Испытательные подмены приёма (agent/recv_test.go); в рабочем пути — nil.
var (
	recvTestDC func(*webrtc.DataChannel)          // каналы хоста, кроме "auth" ("input", "ctl")
	recvTestPC func(*webrtc.PeerConnection) error // после "rx" — вместо файлов и текста
	sendNoFit  bool                               // не проверять план по lim: потолки проверяет хост
)

// sendWait — от connect до "rx"; recvWait — ответ получателя на файл или текст (окно «Принять?» — до AskTimeout).
var (
	sendWait = 60 * time.Second
	recvWait = 30*time.Second + AskTimeout
	// sendGrace — сколько соединение живёт после отмены ctx (sendVia)
	sendGrace = 3 * time.Second
)

// SendTo — отправить d.Files, d.Dirs и текст на ПК d.ID. Итог — ключ получателя (подпись проверена; чужой ПК с
// кодом — и код): его запоминает вызывающий (избранные, Ч10.4), сколько ушло и что пропущено в папках.
func SendTo(ctx context.Context, d SendDial) (res SendResult, err error) {
	text := d.Text
	if d.Clip {
		if text, err = clipRead(); err != nil || text == "" {
			return res, ErrSendClip
		}
	}
	p, err := makePlan(d.Files, d.Dirs, text)
	if err != nil {
		return res, err
	}
	defer p.close()
	res.Skipped = p.skipped // пустой план — только доказательство сторон (и закрепление ключа разовым кодом)
	for _, u := range strings.Split(d.Server, ",") {
		if res.HostPub, err = sendVia(ctx, strings.TrimSpace(u), d, p); !errors.Is(err, ErrSpaceOffline) {
			break
		}
	}
	res.Files, res.Bytes, res.Text = p.sentFiles, p.sentBytes, p.sentText
	return res, err
}

func sendVia(ctx context.Context, server string, d SendDial, p *sendPlan) (ed25519.PublicKey, error) {
	own := d.HostPub != nil
	if !own && d.Code == "" && d.Known == "" { // без кода получатель ничем себя не докажет, кроме закреплённого ключа (M7)
		return nil, ErrRecvKnown
	}
	req := connectReq{View: true} // как у вступления и пропуска (hostDial): хаб приём не отличит
	var h2c []byte
	if own {
		sx, h, err := sxMake(d.Key, d.HostPub, d.ID, time.Now().Unix())
		if err != nil {
			return nil, err
		}
		req.SX, h2c = sx, h
	}
	var (
		mu      sync.Mutex
		hostPub ed25519.PublicKey
		sending sync.WaitGroup // отправка плана: SendTo читает итог и закрывает os.Root папок только после её конца
		over    bool           // hostDial вернулся: запоздавший "rx" отправку не начинает
	)
	// отмена ctx: соединение живёт ещё sendGrace — отправитель успевает послать "cancel" (получатель удалит часть)
	dctx, stop := context.WithCancel(context.WithoutCancel(ctx))
	defer stop()
	defer context.AfterFunc(ctx, func() { time.AfterFunc(sendGrace, stop) })()
	err := hostDial(dctx, server, d.ID, req, func(pc *webrtc.PeerConnection, finish func(error)) {
		wait := time.AfterFunc(sendWait, func() {
			finish(fmt.Errorf("приём: нет ответа вовремя (%w)", context.DeadlineExceeded))
		})
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			if dc.Label() != "auth" { // "input", "ctl" хоста — приёму не нужны
				if recvTestDC != nil {
					recvTestDC(dc)
				}
				return
			}
			first, who := true, false
			var want []byte // подтверждение хоста (CPace кода)
			send := func(v authMsg) { b, _ := json.Marshal(v); dc.SendText(string(b)) }
			dc.OnMessage(func(msg webrtc.DataChannelMessage) {
				var am authMsg
				if json.Unmarshal(msg.Data, &am) != nil {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				if over {
					return
				}
				fc, fh := pake.Fingerprint(pc.LocalDescription().SDP), pake.Fingerprint(pc.RemoteDescription().SDP)
				switch t := am.T; {
				case t == "a" && first:
					first = false
					switch {
					case !am.Recv: // старый хост: приёма нет — кончить до "b" (старый принял бы код за вход)
						finish(ErrRecvOld)
						return
					case own && (!am.Sync || am.SX == nil): // тот ПК не в пространстве
						finish(fmt.Errorf("%w: rights", ErrSpaceRefused))
						return
					}
					b := authMsg{T: "b", Key: true}
					switch {
					case own:
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
							finish(ErrRecvBusy)
							return
						}
						b.Pub = d.HostPub
					case d.Code != "":
						mb, conf, hc, err := pake.ClientRespond(d.Code, am.Salt, am.Msg, d.ID, fc, fh)
						if err != nil {
							finish(err)
							return
						}
						want, b = hc, authMsg{T: "b", Msg: mb, Conf: conf}
					}
					cpub, csig, err := signB(syncCliKey(d.Key), syncSignID("client", d.ID), pc) // подмены — только в тестах сверки
					if err != nil {
						finish(err)
						return
					}
					b.CPub, b.CSig, b.Recv, b.From, b.Name = cpub, csig, true, d.From, d.Name
					send(b)
				case t == "who" && who:
					who = false
					finish(whoResult(am, d.ID, d.HostPub, fc, fh))
				case t == "rx" && am.Why != "":
					finish(rxErr(am.Why))
				case t == "rx" && hostPub == nil:
					switch {
					case pake.HostVerify(am.Pub, am.Sig, d.ID, fc, fh) != nil, own && !bytes.Equal(am.Pub, d.HostPub):
						finish(ErrSpaceHostKey)
						return
					case want != nil && !bytes.Equal(am.Conf, want): // код хост не доказал — хаб-самозванец
						finish(ErrSpaceHostKey)
						return
					case !own && d.Known != "" && pake.KeyFingerprint(am.Pub) != d.Known:
						finish(ErrSpaceHostKey)
						return
					}
					wait.Stop()
					hostPub = bytes.Clone(am.Pub)
					if err := p.fits(am.Lim); err != nil && !sendNoFit { // потолки и папки — до первого байта
						finish(err)
						return
					}
					sending.Go(func() {
						if recvTestPC != nil {
							finish(recvTestPC(pc))
							return
						}
						finish(p.send(ctx, pc, d.Progress))
					})
				case t == "fail":
					finish(ErrRecvCode)
				case t == "locked":
					finish(ErrRecvLocked)
				case t == "nokey":
					finish(ErrRecvNoKey)
				case t == "denied":
					finish(ErrRecvDenied)
				case t == "busy":
					finish(ErrRecvBusy)
				}
			})
		})
	})
	mu.Lock()
	over = true
	mu.Unlock()
	sending.Wait() // соединение закрыто (hostDial): каналы закрыты — отправка кончается сразу
	mu.Lock()
	defer mu.Unlock()
	if err != nil && ctx.Err() != nil && errors.Is(err, context.Canceled) { // остановил sendGrace — причина в ctx
		err = ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	return hostPub, nil
}

// sendText — текст по каналу "text" (протокол — в начале файла).
func sendText(ctx context.Context, pc *webrtc.PeerConnection, text string) error {
	dc, err := pc.CreateDataChannel("text", nil)
	if err != nil {
		return err
	}
	defer dc.Close()
	open, closed := make(chan struct{}), make(chan struct{})
	result := make(chan fileMsg, 1)
	dc.OnOpen(func() { close(open) })
	dc.OnClose(func() { close(closed) })
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		var fm fileMsg
		if json.Unmarshal(m.Data, &fm) == nil {
			select {
			case result <- fm:
			default:
			}
		}
	})
	select {
	case <-open:
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
		return errors.New("канал не открылся")
	}
	b := []byte(text)
	sendJSON(dc, fileMsg{T: "text", Size: int64(len(b))})
	for len(b) > 0 {
		n := min(len(b), fileChunk)
		if err := dc.Send(b[:n]); err != nil {
			return err
		}
		b = b[n:]
	}
	sendJSON(dc, fileMsg{T: "end"})
	select {
	case r := <-result:
		if r.T != "done" {
			return &RecvError{Code: r.Code, Msg: r.Msg}
		}
		return nil
	case <-closed:
		select { // отказ и закрытие приходят почти вместе
		case r := <-result:
			if r.T != "done" {
				return &RecvError{Code: r.Code, Msg: r.Msg}
			}
			return nil
		default:
		}
		return errors.New("отменено получателем")
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(recvWait):
		return errors.New("получатель не ответил")
	}
}
