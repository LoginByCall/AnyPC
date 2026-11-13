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
	m := c.spaceLocked()
	if m == nil || c.codeModeLocked() {
		return nil
	}
	u := c.Users[0]
	if !bytes.Equal(salt, m.PSalt) || !bytes.Equal(u.Salt, m.PSalt) || !bytes.Equal(u.Hash, m.PHash) || u.TOTP != m.TOTP {
		return nil
	}
	return bytes.Clone(c.Space)
}

// spaceJoin — agent.Agent.SpaceJoin (на ПК P): принять M, который новый ПК подписал паролем владельца. Годен только
// «текущий состав + ровно один ПК с ключом pub» (ключ, которым новый ПК доказал себя в канале), эпоха +1, остальное
// без изменений; подпись — закреплённым opub (spaceAccept).
func (c *config) spaceJoin(b []byte, pub ed25519.PublicKey) error {
	in, err := spaceParse(b)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	cur := c.spaceLocked()
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

// spaceEnter — вступить этим ПК в пространство через его ПК hostID (Э2, п. 3–4): владелец ввёл здесь ID, пароль и
// код. После успеха запись по умолчанию этого ПК — запись владельца из M (тот же пароль и код), вход — без
// подтверждения с TOTP. Пароль в сеть не уходит: M подписывается здесь.
func (c *config) spaceEnter(ctx context.Context, hostID, password, code string) error {
	c.mu.Lock()
	c.reload()
	in := len(c.Space) > 0
	id, key, server := c.ID, bytes.Clone(c.Key), c.Server
	c.mu.Unlock()
	switch {
	case in:
		return errSpaceIn // переход в другое пространство и слияние — не Э2
	case !hub.IsHostID(hostID) || hostID == id:
		return errors.New("пространство: неверный ID ПК")
	}
	pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	var joined *space
	out, err := spaceDial(ctx, agent.SpaceDial{Server: server, ID: hostID, Key: key, Password: password, Code: code,
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
			n, err := spaceAdd(m, password, id, pub)
			if err != nil {
				return nil, err
			}
			joined = n
			return n.marshal()
		}})
	if err != nil {
		return err
	}
	if joined == nil {
		return errors.New("пространство: нет подписанного состава") // SpaceJoin без Sign — не бывает
	}
	if mb, _ := joined.marshal(); !bytes.Equal(mb, out) {
		return errors.New("пространство: принятый состав — не подписанный здесь")
	}
	step, _ := totp.Check(joined.TOTP, code, time.Now(), 0) // этот код уже вошёл на P — здесь он повтор
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	if len(c.Space) > 0 || c.ID != id || !bytes.Equal(c.Key, key) {
		return errSpaceChange // P уже принял: повтор вступления ответит дублем ПК — нужна сверка (Э4)
	}
	c.Space = out
	u := &c.Users[0]
	u.Salt, u.Hash, u.TOTP, u.TOTPStep = bytes.Clone(joined.PSalt), bytes.Clone(joined.PHash), joined.TOTP, step
	u.Trusted, u.KeyLogin = nil, nil // новый пароль — доверие ключам заново (как setAccount)
	off := false
	c.Confirm = &off // вход паролем и кодом без подтверждения, как на остальных ПК пространства
	return c.save()
}
