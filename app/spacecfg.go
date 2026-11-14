package main

// «Моё пространство», этап Э2: хранение состава M в настройках, создание пространства и вступление ПК
// (UI-REDESIGN.md). Без окна, без пропуска 12 ч (Э3), без сверки и исключения по сети (Э4), без миграции (Э5).
// ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (CLAUDE.md A13: ключевой материал).
//
// Состав лежит только байтами marshal() (settings.Space) и разбирается spaceParse; разобранный — только по указателю
// (печать значения и json выдали бы секрет TOTP и хэш пароля). Закреплённый ключ владельца — opub сохранённого M.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"slices"
	"sync"
	"time"

	"anypc/agent"
	"anypc/hub"
	"anypc/pake"
	"anypc/totp"
)

var (
	errSpaceIn     = errors.New("пространство: этот ПК уже в пространстве")
	errSpaceNotIn  = errors.New("пространство: этот ПК не в пространстве")
	errSpaceChange = errors.New("пространство: настройки изменились во время операции — повторите")
	errSpaceLogin  = errors.New("пространство: сначала пароль этого ПК и TOTP (вход без подтверждения)")
	errSpaceDraft  = errors.New("пространство: создание не начато или отменено — начните заново")
	errSpaceNo     = errors.New("пространство: вступление отменено")
	errSpaceSlow   = errors.New("пространство: состав не подтверждён вовремя — вступите заново")
	errSpaceHostID = errors.New("пространство: неверный ID ПК")
)

// spaceLocked — объединение сохранённых верхушек (под c.mu, spaceView); nil — пространства нет или записи
// испорчены (в журнал — без секретов: ошибки разбора их не содержат). Подписи у объединения нет.
func (c *config) spaceLocked() *space {
	if len(c.Space) == 0 {
		c.sp, c.spRaw = nil, nil
		return nil
	}
	snap := c.spaceSnapLocked()
	if c.spRaw != nil && bytes.Equal(c.spRaw, snap) {
		return c.sp
	}
	var m *space
	stored, err := c.spaceStoredLocked()
	pend, perr := c.spacePendLocked()
	if err == nil {
		err = perr
	}
	if err != nil {
		log.Printf("пространство в настройках не читается: %v", err)
	} else if heads, err := spaceHeadsAll(append(stored, pend...)); err != nil {
		log.Printf("пространство в настройках не читается: %v", err)
	} else {
		m = spaceView(heads)
	}
	c.sp, c.spRaw = m, snap
	return m
}

// spaceCreate — создать пространство в один шаг (тесты, CLI): черновик и сразу сохранение той же фразой.
func (c *config) spaceCreate(password string) (string, error) {
	phrase, err := c.spaceDraft(password)
	if err == nil {
		err = c.spaceCreateOK(phrase)
	}
	if err != nil {
		return "", err
	}
	return phrase, nil
}

// spaceDraft — шаг 1 создания (Э2, п. 2; решения 8 B, 12): новое пространство с этим ПК — пароль входа записи по
// умолчанию (сверяется с её хэшем: создать пространство за незаблокированным чужим ПК без пароля нельзя), её секрет
// TOTP и ключ хоста. Фразу выдаёт генератор (С3) — она возвращается один раз: окно показывает её для записи и
// просит ввести снова (spaceCreateOK). Состав до того — черновик в памяти (фраза не хранится), Space пуст. Нужен
// режим «пароль + TOTP» (не «Спрашивать»). Новый черновик заменяет прежний.
func (c *config) spaceDraft(password string) (string, error) {
	c.mu.Lock()
	c.reload()
	if len(c.Space) > 0 {
		err := errSpaceIn
		if c.spaceDamagedLocked() {
			err = errSpaceDamaged
		}
		c.mu.Unlock()
		return "", err
	}
	if c.codeModeLocked() || len(c.Users[0].Hash) == 0 {
		c.mu.Unlock()
		return "", errSpaceLogin
	}
	u := c.Users[0]
	salt, hash, sec, id, key := bytes.Clone(u.Salt), bytes.Clone(u.Hash), u.TOTP, c.ID, bytes.Clone(c.Key)
	c.mu.Unlock()
	if subtle.ConstantTimeCompare(pake.KDF(password, salt), hash) != 1 { // Argon2 — без c.mu
		return "", errSpacePassword
	}
	m, phrase, err := spaceNew(salt, hash, sec, id, ed25519.PrivateKey(key).Public().(ed25519.PublicKey))
	if err != nil {
		return "", err
	}
	if err := spacePhraseLoginOK(phrase, password); err != nil { // С1; у фразы генератора — 2^-80
		return "", err
	}
	b, err := m.marshal()
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.spNew = b
	c.mu.Unlock()
	return phrase, nil
}

// spaceCreateNo — отменить черновик создания (Space остаётся пуст).
func (c *config) spaceCreateNo() {
	c.mu.Lock()
	c.spNew = nil
	c.mu.Unlock()
}

// spaceCreateOK — шаг 2 создания: владелец ввёл фразу снова — ключ из неё сверяется с opub черновика (Argon2, без
// c.mu), затем черновик сохраняется. Неверная фраза — ошибка, черновик остаётся (повторить ввод), Space пуст.
func (c *config) spaceCreateOK(phrase string) error {
	c.mu.Lock()
	b := c.spNew
	c.mu.Unlock()
	if b == nil {
		return errSpaceDraft
	}
	m, err := spaceParse(b)
	if err != nil {
		return err
	}
	if err := spaceCreateCheck(m, phrase); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	if !bytes.Equal(c.spNew, b) {
		return errSpaceDraft // отменён или заменён новым, пока шла сверка
	}
	u := c.Users[0]
	key := ed25519.PrivateKey(c.Key)
	if len(c.Space) > 0 || c.codeModeLocked() || !bytes.Equal(u.Salt, m.PSalt) || !bytes.Equal(u.Hash, m.PHash) || u.TOTP != m.TOTP ||
		len(c.Key) != ed25519.PrivateKeySize || m.Members[0].ID != c.ID || !bytes.Equal(m.Members[0].Pub, key.Public().(ed25519.PublicKey)) {
		c.spNew = nil
		return errSpaceChange
	}
	c.Space, c.spNew = b, nil
	if err := c.save(); err != nil {
		c.Space = nil
		return err
	}
	if spaceChanged != nil { // метка входа (agent.LoginTag) — уже с пространством; без c.mu: DropRevoked читает настройки
		c.mu.Unlock()
		spaceChanged()
		c.mu.Lock()
	}
	return nil
}

// spaceCreateCheck — сверка фразы с черновиком (Argon2); переменная — для теста (черновик меняется во время сверки).
var spaceCreateCheck = spaceOwnerCheck

// spaceGet — agent.Agent.SpaceGet (на ПК P): все верхушки M (главная первой; состав — их объединение, решение 10 A)
// для сессии, вошедшей записью по умолчанию с солью salt. Только если запись по умолчанию — запись владельца из
// объединения (те же соль, хэш и секрет TOTP) и режим не «Спрашивать».
func (c *config) spaceGet(salt []byte) [][]byte {
	if s := c.syn; s != nil { // Э4: до выдачи M новому ПК — сверка с остальными (иначе он вступит в устаревший состав)
		ctx, cancel := context.WithTimeout(s.bgCtx(), spaceGetSync)
		s.spread(ctx, false)
		cancel()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	if c.spaceOwnerLocked(salt) == nil {
		return nil
	}
	out := [][]byte{bytes.Clone(c.Space)}
	for _, h := range c.SpaceHeads {
		out = append(out, bytes.Clone(h))
	}
	return out
}

// spaceMember — agent.Agent.SpaceMember (Э3, пропуск на цели): ключ pub — член состава этого ПК (не исключён и не
// сам этот ПК), а вход с солью salt — запись владельца из него (как spaceGet; «Спрашивать» — нет). Членство — по
// объединению (исключённый в любой известной M — нет); вход скомпрометирован или нет сверки после вступления — нет.
func (c *config) spaceMember(salt, pub []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	m := c.spaceOwnerLocked(salt)
	if m == nil || c.SpaceWait != "" {
		return false
	}
	return m.member(pub) && !m.gone(pub) && !bytes.Equal(pub, ed25519.PrivateKey(c.Key).Public().(ed25519.PublicKey))
}

// spaceOwnerLocked — состав (под c.mu), если вход с солью salt — запись владельца из него: запись по умолчанию с теми
// же солью, хэшем и секретом TOTP, режим не «Спрашивать». Иначе nil. Э4 (С6): на члене смена пароля, кода и
// «Спрашивать» записи по умолчанию запрещены (errSpaceVia) — только правкой M (spaceChangeLogin, фраза); принятый M
// повторяется в записи по умолчанию (spaceAddLocked). Расхождение остаётся только от правки файла старой версией.
// Вход скомпрометирован (секрет кода видел исключённый ПК) — nil: ни пропусков, ни выдачи M, ни вступления до нового
// кода фразой.
func (c *config) spaceOwnerLocked(salt []byte) *space {
	m := c.spaceLocked()
	if m == nil || m.Compromised || c.SpaceOver != "" || c.codeModeLocked() {
		return nil
	}
	u := c.Users[0]
	if !bytes.Equal(salt, m.PSalt) || !bytes.Equal(u.Salt, m.PSalt) || !bytes.Equal(u.Hash, m.PHash) || u.TOTP != m.TOTP {
		return nil
	}
	return m
}

// spaceJoin — agent.Agent.SpaceJoin (на ПК P): принять M, который новый ПК подписал фразой пространства. Годен только
// «объединение верхушек (их отдал spaceGet) + ровно один ПК с ключом pub» (ключ, которым новый ПК доказал себя в
// канале), эпоха max+1, остальное без изменений (перекрывает все верхушки); подпись — закреплённым opub (сравнение байтов с ожидаемым). Сессия —
// записи владельца (salt, как в spaceGet): сверка под тем же c.mu, что и запись. Принятый M — ещё одна верхушка.
// ID нового ПК (С4) проверяет рассылка после приёма: ПК под этим ID должен ответить ключом pub (spaceSyncer.one).
func (c *config) spaceJoin(salt, b []byte, pub ed25519.PublicKey) error {
	if err := c.spaceJoinSave(salt, b, pub); err != nil {
		return err
	}
	if s := c.syn; s != nil { // остальным — до ответа новому ПК (его сверка с ними сразу пройдёт); ему — проверка ID
		ctx, cancel := context.WithTimeout(s.bgCtx(), spaceGetSync)
		s.spread(ctx, true)
		cancel()
	}
	return nil
}

func (c *config) spaceJoinSave(salt, b []byte, pub ed25519.PublicKey) error {
	in, err := spaceParse(b)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	v := c.spaceOwnerLocked(salt)
	if v == nil {
		return errSpaceNotIn
	}
	want, err := v.next()
	if err != nil {
		return err
	}
	i := slices.IndexFunc(in.Members, func(x spaceMember) bool { return bytes.Equal(x.Pub, pub) })
	if i < 0 {
		return errors.New("пространство: в составе нет ключа, которым вошёл новый ПК")
	}
	want.Members = append(want.Members, spaceMember{ID: in.Members[i].ID, Pub: bytes.Clone(pub)})
	slices.SortFunc(want.Members, func(x, y spaceMember) int { return bytes.Compare(x.Pub, y.Pub) })
	if !bytes.Equal(want.signBytes(), in.signBytes()) {
		return errors.New("пространство: состав — не «текущий и новый ПК»")
	}
	if _, _, err := c.spaceAddLocked(in); err != nil {
		return err
	}
	return c.save()
}

// spaceOwnerCheck — Н1 приёмки Э1: первому составу из сети верят, только если ключ владельца из введённой фразы и
// osalt состава равен его opub. Сверка локальная: фраза не уходит никуда.
func spaceOwnerCheck(m *space, phrase string) error {
	if err := spacePhraseOK(phrase); err != nil { // до Argon2; окну — номер слова с опечаткой
		return err
	}
	key := spaceOwnerKey(phrase, m.OSalt)
	defer clear(key)
	if subtle.ConstantTimeCompare(key.Public().(ed25519.PublicKey), m.OPub) != 1 {
		return fmt.Errorf("%w: ключ владельца из фразы не совпал", errSpaceForeign)
	}
	return nil
}

// spaceLoginCheck — пароль входа — тот, чей хэш записан в составе (им входят на ПК пространства и «Работаю тут»).
func spaceLoginCheck(m *space, password string) error {
	if subtle.ConstantTimeCompare(pake.KDF(password, m.PSalt), m.PHash) != 1 {
		return errSpacePassword
	}
	return nil
}

// spaceGetSync — сколько spaceGet сверяется с остальными (вступающий ждёт весь обмен spaceWait = 60 с).
var spaceGetSync = 20 * time.Second

// spaceDial — вход на ПК пространства (agent.SpaceJoin); переменная — для теста.
var spaceDial = agent.SpaceJoin

// spaceChanges — что вступление поменяло на этом ПК (для окна; секретов нет).
type spaceChanges struct {
	Password bool // пароль записи по умолчанию — теперь пароль владельца
	TOTP     bool // секрет кода записи по умолчанию — теперь секрет пространства
	Trusted  int  // сброшено закреплённых ключей записи по умолчанию (У3)
	KeyLogin int  // сброшено ключей входа без пароля записи по умолчанию (REQ-S-24)
	Ask      bool // остался режим «Спрашивать»: вход паролем и кодом — после его выключения
	Already  bool // этот ПК уже был в составе P (прошлое вступление P сохранил, а ответ не дошёл)
	Fresh    bool // Э4: состав сверен с другим членом (или других нет) — пропуска выдаются
}

func (s spaceChanges) String() string {
	return fmt.Sprintf("пароль заменён: %v, код заменён: %v, сброшено ключей: %d+%d, «Спрашивать» остался: %v, уже в составе: %v, сверен: %v",
		s.Password, s.TOTP, s.Trusted, s.KeyLogin, s.Ask, s.Already, s.Fresh)
}

// spacePC — член состава для окна вступления: ID и отпечаток ключа (pake.KeyFingerprint).
type spacePC struct{ ID, FP string }

// spacePreview — окно «Это все ваши ПК?» до подписи (решение 12 A): состав — объединение верхушек, которые отдал P
// (члены и исключённые), и что вступление поменяет на этом ПК (Fresh — всегда false: сверка — после). Секретов нет.
type spacePreview struct {
	Members []spacePC
	spaceChanges
	Gone []string // отпечатки ключей исключённых ПК
}

// spaceChangesLocked — что поменяет вступление в m на этом ПК (под c.mu): то же, что spaceEnterAsk сделает с записью
// по умолчанию. «Спрашивать» после вступления — только явный режим подтверждения (TOTP будет из m).
func (c *config) spaceChangesLocked(m *space) spaceChanges {
	u := c.Users[0]
	return spaceChanges{Password: !bytes.Equal(u.Salt, m.PSalt) || !bytes.Equal(u.Hash, m.PHash), TOTP: u.TOTP != m.TOTP,
		Trusted: len(u.Trusted), KeyLogin: len(u.KeyLogin), Ask: c.Confirm == nil || *c.Confirm}
}

func (c *config) spaceChangesFor(m *space, half bool) spaceChanges {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	ch := c.spaceChangesLocked(m)
	ch.Already = half
	return ch
}

// spaceConfirmWait — сколько вступление ждёт подтверждения состава (решение 12 A, план этапа: 2 мин).
var spaceConfirmWait = 2 * time.Minute

// spaceAsk — показать состав m (half — этот ПК в нём уже есть) и ждать ответа владельца (решение 12 A). Итог —
// показанные изменения; к ответу «да» они должны быть те же (иначе errSpaceChange: показано не то, что применится).
func (c *config) spaceAsk(ctx context.Context, m *space, half bool, preview func(spacePreview), ok <-chan bool) (spaceChanges, error) {
	if err := ctx.Err(); err != nil { // вступление уже кончилось — ни окна, ни подписи
		return spaceChanges{}, err
	}
	p := spacePreview{spaceChanges: c.spaceChangesFor(m, half)}
	for _, x := range m.Members {
		p.Members = append(p.Members, spacePC{ID: x.ID, FP: pake.KeyFingerprint(x.Pub)})
	}
	for _, g := range m.Gone {
		p.Gone = append(p.Gone, pake.KeyFingerprint(g))
	}
	if preview != nil {
		preview(p)
	}
	t := time.NewTimer(spaceConfirmWait)
	defer t.Stop()
	select {
	case yes := <-ok:
		switch {
		case ctx.Err() != nil:
			return p.spaceChanges, ctx.Err()
		case !yes:
			return p.spaceChanges, errSpaceNo
		case c.spaceChangesFor(m, half) != p.spaceChanges:
			return p.spaceChanges, errSpaceChange
		}
		return p.spaceChanges, nil
	case <-t.C:
		return p.spaceChanges, errSpaceSlow
	case <-ctx.Done():
		return p.spaceChanges, ctx.Err()
	}
}

// spaceEnterAsk — вступить этим ПК в пространство через его ПК hostID (Э2, п. 3–4; решения 8 B, 10 A, 12 A): владелец
// ввёл здесь ID, пароль входа, код и фразу пространства. Пароль и код — вход в сессию на P (пароль в сеть не уходит:
// CPace); фраза — только здесь: ключ из неё сверяется с opub пришедших верхушек до доверия им. Состав — объединение
// верхушек P (каждая подлинная, одного пространства, не больше spaceMaxHeads). Затем preview (если не nil; зовётся в
// горутине обмена) получает состав и изменения, и вступление ждёт ответа из ok не дольше spaceConfirmWait: true —
// подписать M от объединения (эпоха max+1, перекрывает все верхушки) и отдать P; false или срок — отказ (errSpaceNo,
// errSpaceSlow), P нового M не получает; запись по умолчанию сменилась после показа — errSpaceChange. После успеха
// запись по умолчанию этого ПК — запись владельца из объединения. Режим подтверждения и записи гостей не меняются
// (С3 приёмки Э2: иначе ожили бы спящие гостевые записи «Спрашивать»).
// ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (A13: подпись состава фразой).
func (c *config) spaceEnterAsk(ctx context.Context, hostID, password, code, phrase string, preview func(spacePreview), ok <-chan bool) (spaceChanges, error) {
	ctx, cancel := context.WithCancel(ctx) // Sign ждёт в горутине обмена: конец вступления его отпускает
	defer cancel()
	c.mu.Lock()
	c.reload()
	in, bad := len(c.Space) > 0, c.spaceDamagedLocked()
	id, key, server, known := c.ID, bytes.Clone(c.Key), c.Server, c.Known[hostID]
	c.mu.Unlock()
	switch {
	case bad:
		return spaceChanges{}, errSpaceDamaged
	case in:
		return spaceChanges{}, errSpaceIn // переход в другое пространство и слияние — не Э2
	case !hub.IsHostID(hostID) || hostID == id:
		return spaceChanges{}, errSpaceHostID
	}
	if err := spacePhraseOK(phrase); err != nil { // опечатка во фразе — до сети: код не тратится
		return spaceChanges{}, err
	}
	pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	type result struct {
		view  *space       // объединение: из него запись по умолчанию
		recs  [][]byte     // что сохранить: новый M или (уже в составе) верхушки P
		want  []byte       // что должен вернуть spaceDial
		shown spaceChanges // показано окну
	}
	var (
		jmu sync.Mutex // Sign — в горутине обмена, она может пережить ошибку spaceDial
		res *result
	)
	out, err := spaceDial(ctx, agent.SpaceDial{Server: server, ID: hostID, Key: key, Password: password, Code: code, Known: known, Confirm: spaceConfirmWait,
		Sign: func(b []byte, hostPub ed25519.PublicKey, rest ...[]byte) ([]byte, error) {
			var ms []*space
			for _, x := range append([][]byte{b}, rest...) {
				m, err := spaceParse(x) // подпись своим opub; чей это opub — spaceOwnerCheck ниже
				if err != nil {
					return nil, err
				}
				ms = append(ms, m)
			}
			heads, err := spaceHeads(ms) // одно пространство, не больше spaceMaxHeads (иначе, как SpaceOver, — отказ)
			if err != nil {
				return nil, err
			}
			m := spaceView(heads)
			if m.Compromised {
				return nil, errSpaceCompromised
			}
			if err := spaceOwnerCheck(m, phrase); err != nil {
				return nil, err
			}
			if err := spaceLoginCheck(m, password); err != nil { // P отдал M с чужим паролем входа — не наш
				return nil, err
			}
			if !m.has(spaceMember{ID: hostID, Pub: hostPub}) {
				return nil, errors.New("пространство: ПК, отдавший состав, в нём не числится")
			}
			// свежесть (исключённый P может отдать старые подлинные M) — сверка с остальными после (spaceFresh)
			half := m.has(spaceMember{ID: id, Pub: pub})
			shown, err := c.spaceAsk(ctx, m, half, preview, ok)
			if err != nil {
				return nil, err
			}
			r := &result{view: m, shown: shown}
			if half { // полу-вступление (С1): P уже сохранил нас — принять его верхушки как есть
				for _, h := range heads {
					hb, err := h.marshal()
					if err != nil {
						return nil, err
					}
					r.recs = append(r.recs, hb)
				}
				r.want = b
			} else {
				n, err := spaceAdd(m, phrase, id, pub)
				if err != nil {
					return nil, err
				}
				nb, err := n.marshal()
				if err != nil {
					return nil, err
				}
				r.recs, r.want = [][]byte{nb}, nb
			}
			jmu.Lock()
			res = r
			jmu.Unlock()
			return r.want, nil
		}})
	if err != nil {
		return spaceChanges{}, err
	}
	jmu.Lock()
	r := res
	jmu.Unlock()
	if r == nil {
		return spaceChanges{}, errors.New("пространство: нет подписанного состава") // SpaceJoin без Sign — не бывает
	}
	if !bytes.Equal(r.want, out) {
		return spaceChanges{}, errors.New("пространство: принятый состав — не подписанный здесь")
	}
	joined := r.view
	step, _ := totp.Check(joined.TOTP, code, time.Now(), 0) // этот код уже вошёл на P — здесь он повтор
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	if len(c.Space) > 0 || c.ID != id || !bytes.Equal(c.Key, key) {
		return spaceChanges{}, errSpaceChange
	}
	ch := c.spaceChangesLocked(joined)
	ch.Already = r.shown.Already
	if ch != r.shown { // запись по умолчанию сменилась после «да»: P уже принял — повтор даст «уже в составе»
		return spaceChanges{}, errSpaceChange
	}
	c.Space, c.SpaceHeads, c.SpaceClock, c.SpaceOver, c.SpacePend = r.recs[0], r.recs[1:], nil, "", nil
	if len(c.SpaceHeads) == 0 {
		c.SpaceHeads = nil
	}
	u := &c.Users[0]
	u.Salt, u.Hash, u.TOTP, u.TOTPStep = bytes.Clone(joined.PSalt), bytes.Clone(joined.PHash), joined.TOTP, step
	u.Trusted, u.KeyLogin = nil, nil // новый пароль — доверие ключам заново (как setAccount); гостей не трогаем
	c.SpaceWait = hostID             // пропусков нет до сверки с другим членом (spaceSyncer.one)
	if !slices.ContainsFunc(joined.Members, func(x spaceMember) bool { return x.ID != id && x.ID != hostID }) {
		c.SpaceWait = "" // других членов нет — сверять не с кем
	}
	if err := c.save(); err != nil {
		return ch, err
	}
	c.mu.Unlock()
	if spaceChanged != nil { // вход записи по умолчанию — из M (пароль или код могли смениться): сессии со старым — вон
		spaceChanged()
	}
	ch.Fresh = c.spaceFresh(ctx)
	c.mu.Lock()
	log.Printf("пространство: этот ПК вступил через %s (%s)", hostID, ch)
	return ch, nil
}
