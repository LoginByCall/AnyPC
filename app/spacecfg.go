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

// spaceLocked — разобранный Space (под c.mu); nil — пространства нет или запись испорчена (в журнал — без секретов:
// ошибки разбора их не содержат).
func (c *config) spaceLocked() *space {
	if len(c.Space) == 0 {
		c.sp, c.spRaw = nil, nil
		return nil
	}
	if c.spRaw != nil && bytes.Equal(c.spRaw, c.Space) {
		return c.sp
	}
	m, err := spaceParse(c.Space)
	if err != nil {
		log.Printf("пространство в настройках не читается: %v", err)
		m = nil
	}
	c.sp, c.spRaw = m, bytes.Clone(c.Space)
	return m
}

// spaceCreate — новое пространство с этим ПК (Э2, п. 2): пароль записи по умолчанию (сверяется с её хэшем в
// spaceNew), её секрет TOTP и ключ хоста. Нужен режим «пароль + TOTP» (не «Спрашивать»).
func (c *config) spaceCreate(password string) error {
	c.mu.Lock()
	c.reload()
	if len(c.Space) > 0 {
		c.mu.Unlock()
		return errSpaceIn
	}
	if c.codeModeLocked() || len(c.Users[0].Hash) == 0 {
		c.mu.Unlock()
		return errors.New("пространство: сначала пароль этого ПК и TOTP (вход без подтверждения)")
	}
	u := c.Users[0]
	salt, hash, sec, id, key := bytes.Clone(u.Salt), bytes.Clone(u.Hash), u.TOTP, c.ID, bytes.Clone(c.Key)
	c.mu.Unlock()
	m, err := spaceNew(password, salt, hash, sec, id, ed25519.PrivateKey(key).Public().(ed25519.PublicKey)) // Argon2 — без c.mu
	if err != nil {
		return err
	}
	b, err := m.marshal()
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	if len(c.Space) > 0 || !bytes.Equal(c.Users[0].Salt, salt) || c.Users[0].TOTP != sec || c.ID != id || !bytes.Equal(c.Key, key) {
		return errSpaceChange
	}
	c.Space = b
	return c.save()
}

// spaceGet — agent.Agent.SpaceGet (на ПК P): запись M для сессии, вошедшей записью по умолчанию с солью salt. Только
// если запись по умолчанию — запись владельца из M (те же соль, хэш и секрет TOTP) и режим не «Спрашивать».
func (c *config) spaceGet(salt []byte) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	if c.spaceOwnerLocked(salt) == nil {
		return nil
	}
	return bytes.Clone(c.Space)
}

// spaceOwnerLocked — состав (под c.mu), если вход с солью salt — запись владельца из него: запись по умолчанию с теми
// же солью, хэшем и секретом TOTP, режим не «Спрашивать». Иначе nil.
// TODO(Э4/Э5): смена пароля (setPassword), включение «Спрашивать» и новый TOTP записи по умолчанию молча выключают
// пространство на этом ПК (С6 приёмки Э2) — нужны тексты окна и решение о смене пароля владельца.
func (c *config) spaceOwnerLocked(salt []byte) *space {
	m := c.spaceLocked()
	if m == nil || c.codeModeLocked() {
		return nil
	}
	u := c.Users[0]
	if !bytes.Equal(salt, m.PSalt) || !bytes.Equal(u.Salt, m.PSalt) || !bytes.Equal(u.Hash, m.PHash) || u.TOTP != m.TOTP {
		return nil
	}
	return m
}

// spaceJoin — agent.Agent.SpaceJoin (на ПК P): принять M, который новый ПК подписал паролем владельца. Годен только
// «текущий состав + ровно один ПК с ключом pub» (ключ, которым новый ПК доказал себя в канале), эпоха +1, остальное
// без изменений; подпись — закреплённым opub (spaceAccept). Сессия — записи владельца (salt, как в spaceGet): сверка
// под тем же c.mu, что и запись.
// TODO(Э4): ID нового ПК не сверяется с соединением (С4 приёмки Э2): у клиента на хабе ID нет, его заявляет N под
// подписью владельца; чужой ID закроет вступление настоящему ПК — нужна проверка ID при сверке членов.
func (c *config) spaceJoin(salt, b []byte, pub ed25519.PublicKey) error {
	in, err := spaceParse(b)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	cur := c.spaceOwnerLocked(salt)
	if cur == nil {
		return errSpaceNotIn
	}
	if err := spaceAccept(cur, in); err != nil {
		return err
	}
	want, err := cur.next()
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
	c.Space = bytes.Clone(b)
	return c.save()
}

// spaceOwnerCheck — Н1 приёмки Э1: первому составу из сети верят, только если ключ владельца из введённого пароля и
// osalt состава равен его opub; и хэш пароля записи в составе — от того же пароля (им будет входить владелец).
func spaceOwnerCheck(m *space, password string) error {
	key := spaceOwnerKey(password, m.OSalt)
	defer clear(key)
	if subtle.ConstantTimeCompare(key.Public().(ed25519.PublicKey), m.OPub) != 1 {
		return fmt.Errorf("%w: ключ владельца из пароля не совпал", errSpaceForeign)
	}
	if subtle.ConstantTimeCompare(pake.KDF(password, m.PSalt), m.PHash) != 1 {
		return errSpacePassword
	}
	return nil
}

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
}

func (s spaceChanges) String() string {
	return fmt.Sprintf("пароль заменён: %v, код заменён: %v, сброшено ключей: %d+%d, «Спрашивать» остался: %v, уже в составе: %v",
		s.Password, s.TOTP, s.Trusted, s.KeyLogin, s.Ask, s.Already)
}

// spaceEnter — вступить этим ПК в пространство через его ПК hostID (Э2, п. 3–4): владелец ввёл здесь ID, пароль и
// код. После успеха запись по умолчанию этого ПК — запись владельца из M (тот же пароль и код). Режим подтверждения
// и записи гостей не меняются (С3 приёмки Э2: иначе ожили бы спящие гостевые записи режима «Спрашивать»). Пароль в
// сеть не уходит: M подписывается здесь.
func (c *config) spaceEnter(ctx context.Context, hostID, password, code string) (spaceChanges, error) {
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
	pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	var joined *space
	out, err := spaceDial(ctx, agent.SpaceDial{Server: server, ID: hostID, Key: key, Password: password, Code: code, Known: known,
		Sign: func(b []byte, hostPub ed25519.PublicKey) ([]byte, error) {
			m, err := spaceParse(b)
			if err != nil {
				return nil, err
			}
			if err := spaceOwnerCheck(m, password); err != nil {
				return nil, err
			}
			if !slices.ContainsFunc(m.Members, func(x spaceMember) bool { return x.ID == hostID && bytes.Equal(x.Pub, hostPub) }) {
				return nil, errors.New("пространство: ПК, отдавший состав, в нём не числится")
			}
			// TODO(Э4): свежесть первого M — исключённый P может отдать старый подлинный M (подпись владельца верна).
			// Сразу после вступления сверить состав с остальными членами (UI-REDESIGN.md, «Открыто», требования к Э4).
			if slices.ContainsFunc(m.Members, func(x spaceMember) bool { return x.ID == id && bytes.Equal(x.Pub, pub) }) {
				joined, ch.Already = m, true // полу-вступление (С1): P уже сохранил нас — принять его M как есть
				return b, nil
			}
			n, err := spaceAdd(m, password, id, pub)
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
	c.Space = out
	u := &c.Users[0]
	ch.Password = !bytes.Equal(u.Salt, joined.PSalt) || !bytes.Equal(u.Hash, joined.PHash)
	ch.TOTP = u.TOTP != joined.TOTP
	ch.Trusted, ch.KeyLogin = len(u.Trusted), len(u.KeyLogin)
	u.Salt, u.Hash, u.TOTP, u.TOTPStep = bytes.Clone(joined.PSalt), bytes.Clone(joined.PHash), joined.TOTP, step
	u.Trusted, u.KeyLogin = nil, nil // новый пароль — доверие ключам заново (как setAccount); гостей не трогаем
	ch.Ask = c.codeModeLocked()
	if err := c.save(); err != nil {
		return ch, err
	}
	log.Printf("пространство: этот ПК вступил через %s (%s)", hostID, ch)
	return ch, nil
}
