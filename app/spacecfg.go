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
	if stored, err := c.spaceStoredLocked(); err != nil {
		log.Printf("пространство в настройках не читается: %v", err)
	} else if heads, err := spaceHeads(stored); err != nil {
		log.Printf("пространство в настройках не читается: %v", err)
	} else {
		m = spaceView(heads)
	}
	c.sp, c.spRaw = m, snap
	return m
}

// spaceCreate — новое пространство с этим ПК (Э2, п. 2; решение 8 B): пароль входа записи по умолчанию (сверяется с
// её хэшем: создать пространство за незаблокированным чужим ПК без пароля нельзя), её секрет TOTP и ключ хоста.
// Фразу выдаёт генератор (С3) — она возвращается один раз: окно показывает её для записи. Нужен режим «пароль +
// TOTP» (не «Спрашивать»).
func (c *config) spaceCreate(password string) (string, error) {
	c.mu.Lock()
	c.reload()
	if len(c.Space) > 0 {
		c.mu.Unlock()
		return "", errSpaceIn
	}
	if c.codeModeLocked() || len(c.Users[0].Hash) == 0 {
		c.mu.Unlock()
		return "", errors.New("пространство: сначала пароль этого ПК и TOTP (вход без подтверждения)")
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
	defer c.mu.Unlock()
	c.reload()
	if len(c.Space) > 0 || !bytes.Equal(c.Users[0].Salt, salt) || c.Users[0].TOTP != sec || c.ID != id || !bytes.Equal(c.Key, key) {
		return "", errSpaceChange
	}
	c.Space = b
	return phrase, c.save()
}

// spaceGet — agent.Agent.SpaceGet (на ПК P): запись M для сессии, вошедшей записью по умолчанию с солью salt. Только
// если запись по умолчанию — запись владельца из M (те же соль, хэш и секрет TOTP) и режим не «Спрашивать».
func (c *config) spaceGet(salt []byte) []byte {
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
	return bytes.Clone(c.Space)
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
// «главная верхушка (её отдал spaceGet) + ровно один ПК с ключом pub» (ключ, которым новый ПК доказал себя в
// канале), эпоха +1, остальное без изменений; подпись — закреплённым opub (сравнение байтов с ожидаемым). Сессия —
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
	if c.spaceOwnerLocked(salt) == nil {
		return errSpaceNotIn
	}
	top, err := spaceParse(c.Space)
	if err != nil {
		return err
	}
	want, err := top.next()
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

// spaceEnter — вступить этим ПК в пространство через его ПК hostID (Э2, п. 3–4; решение 8 B): владелец ввёл здесь
// ID, пароль входа, код и фразу пространства. Пароль и код — вход в сессию на P (пароль в сеть не уходит: CPace);
// фраза — только здесь: ключ из неё сверяется с opub пришедшего M до доверия ему и подписывает вступление. После
// успеха запись по умолчанию этого ПК — запись владельца из M (тот же пароль и код). Режим подтверждения и записи
// гостей не меняются (С3 приёмки Э2: иначе ожили бы спящие гостевые записи режима «Спрашивать»).
func (c *config) spaceEnter(ctx context.Context, hostID, password, code, phrase string) (spaceChanges, error) {
	var ch spaceChanges
	c.mu.Lock()
	c.reload()
	in := len(c.Space) > 0
	id, key, server, known := c.ID, bytes.Clone(c.Key), c.Server, c.Known[hostID]
	c.mu.Unlock()
	switch {
	case in:
		return ch, errSpaceIn // переход в другое пространство и слияние — не Э2
	case !hub.IsHostID(hostID) || hostID == id:
		return ch, errors.New("пространство: неверный ID ПК")
	}
	if err := spacePhraseOK(phrase); err != nil { // опечатка во фразе — до сети: код не тратится
		return ch, err
	}
	pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	var joined *space
	out, err := spaceDial(ctx, agent.SpaceDial{Server: server, ID: hostID, Key: key, Password: password, Code: code, Known: known,
		Sign: func(b []byte, hostPub ed25519.PublicKey) ([]byte, error) {
			m, err := spaceParse(b)
			if err != nil {
				return nil, err
			}
			if err := spaceOwnerCheck(m, phrase); err != nil {
				return nil, err
			}
			if err := spaceLoginCheck(m, password); err != nil { // P отдал M с чужим паролем входа — не наш
				return nil, err
			}
			if !slices.ContainsFunc(m.Members, func(x spaceMember) bool { return x.ID == hostID && bytes.Equal(x.Pub, hostPub) }) {
				return nil, errors.New("пространство: ПК, отдавший состав, в нём не числится")
			}
			// свежесть первого M (исключённый P может отдать старый подлинный M) — сверка с остальными после (spaceFresh)
			if slices.ContainsFunc(m.Members, func(x spaceMember) bool { return x.ID == id && bytes.Equal(x.Pub, pub) }) {
				joined, ch.Already = m, true // полу-вступление (С1): P уже сохранил нас — принять его M как есть
				return b, nil
			}
			n, err := spaceAdd(m, phrase, id, pub)
			if err != nil {
				return nil, err
			}
			joined = n
			return n.marshal()
		}})
	if err != nil {
		return ch, err
	}
	if joined == nil {
		return ch, errors.New("пространство: нет подписанного состава") // SpaceJoin без Sign — не бывает
	}
	if mb, _ := joined.marshal(); !bytes.Equal(mb, out) {
		return ch, errors.New("пространство: принятый состав — не подписанный здесь")
	}
	step, _ := totp.Check(joined.TOTP, code, time.Now(), 0) // этот код уже вошёл на P — здесь он повтор
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	if len(c.Space) > 0 || c.ID != id || !bytes.Equal(c.Key, key) {
		return ch, errSpaceChange
	}
	c.Space, c.SpaceHeads, c.SpaceClock, c.SpaceOver = out, nil, nil, ""
	u := &c.Users[0]
	ch.Password = !bytes.Equal(u.Salt, joined.PSalt) || !bytes.Equal(u.Hash, joined.PHash)
	ch.TOTP = u.TOTP != joined.TOTP
	ch.Trusted, ch.KeyLogin = len(u.Trusted), len(u.KeyLogin)
	u.Salt, u.Hash, u.TOTP, u.TOTPStep = bytes.Clone(joined.PSalt), bytes.Clone(joined.PHash), joined.TOTP, step
	u.Trusted, u.KeyLogin = nil, nil // новый пароль — доверие ключам заново (как setAccount); гостей не трогаем
	ch.Ask = c.codeModeLocked()
	c.SpaceWait = hostID // пропусков нет до сверки с другим членом (spaceSyncer.one)
	if !slices.ContainsFunc(joined.Members, func(x spaceMember) bool { return x.ID != id && x.ID != hostID }) {
		c.SpaceWait = "" // других членов нет — сверять не с кем
	}
	if err := c.save(); err != nil {
		return ch, err
	}
	c.mu.Unlock()
	ch.Fresh = c.spaceFresh(ctx)
	c.mu.Lock()
	log.Printf("пространство: этот ПК вступил через %s (%s)", hostID, ch)
	return ch, nil
}
