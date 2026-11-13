package main

// «Моё пространство», этап Э1: состав пространства M и его подпись (UI-REDESIGN.md, «Проект ядра пространства»).
// Только формат и правила — без сети, без диска, без окна. ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (CLAUDE.md A13: ключевой материал).
//
// Ключ владельца — Ed25519 с зерном Argon2id(пароль, osalt) (pake.KDF, те же параметры, что у паролей). Закрытая
// часть живёт только на время одной подписи: не хранится, не пишется в журнал; на диск и в сеть идут opub и osalt.
//
// Запись M (версия 1), все числа — big-endian, длины полей постоянные, кроме секрета TOTP и двух списков:
//
//	"AnyPC space M\x00" | ver=1 | sid[16] | epoch u64 | osalt[16] | opub[32] | psalt[16] | phash[32]
//	| u8 len, totp | u8 n, n×{id[9], pub[32]} | u16 k, k×pub[32]            ← эти байты подписываются
//	| sig[64]                                                                 ← подпись владельца
//
// Запись однозначна: члены и исключённые идут по возрастанию открытого ключа без повторов, иной порядок — ошибка
// разбора. Поэтому одинаковый состав — одинаковые байты на любой ОС и версии.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"anypc/hub"
	"anypc/pake"
	"anypc/totp"
)

const (
	spaceDomain     = "AnyPC space M\x00" // доменный префикс: подпись состава не сойдёт за подпись чего-то другого
	spaceVer        = 1
	spaceIDLen      = 9  // ID хоста (hub.IsHostID)
	spaceSaltLen    = 16 // sid, osalt, psalt
	spaceHashLen    = 32 // pake.KDF
	spaceMaxMembers = 32
	spaceMaxGone    = 256 // исключённые не забываются никогда; после 256 исключений — новое пространство
	spaceMaxTOTP    = 64
	// spaceMaxBytes — потолок записи с подписью: больше не разбираем вовсе.
	spaceMaxBytes = len(spaceDomain) + 1 + spaceSaltLen + 8 + spaceSaltLen + ed25519.PublicKeySize + spaceSaltLen + spaceHashLen +
		1 + spaceMaxTOTP + 1 + spaceMaxMembers*(spaceIDLen+ed25519.PublicKeySize) + 2 + spaceMaxGone*ed25519.PublicKeySize +
		ed25519.SignatureSize
)

var (
	errSpaceFormat     = errors.New("пространство: запись состава испорчена")
	errSpaceVersion    = errors.New("пространство: неизвестная версия записи состава")
	errSpaceLimit      = errors.New("пространство: превышен предел размера состава")
	errSpaceSig        = errors.New("пространство: подпись владельца неверна")
	errSpacePassword   = errors.New("пространство: неверный пароль владельца")
	errSpaceForeign    = errors.New("пространство: состав другого пространства или другого владельца")
	errSpaceStale      = errors.New("пространство: состав не новее текущего")
	errSpaceGoneShrunk = errors.New("пространство: из списка исключённых пропал ключ")
	errSpaceGoneMember = errors.New("пространство: исключённый ПК числится членом")
	errSpaceDup        = errors.New("пространство: такой ПК уже в составе")
	errSpaceNoMember   = errors.New("пространство: такого ПК в составе нет")
	errSpaceLast       = errors.New("пространство: нельзя исключить последний ПК")
)

// spaceMember — ПК пространства: ID на хабе и открытая часть ключа хоста (config.Key).
type spaceMember struct {
	ID  string
	Pub ed25519.PublicKey
}

// space — состав M с подписью владельца. Значение не меняется после подписи: правки дают новый состав.
type space struct {
	SID     []byte            // случайный идентификатор пространства
	Epoch   uint64            // растёт на 1 с каждой правкой; с 1
	OSalt   []byte            // соль ключа владельца (не соль пароля записи: иначе зерно ключа равнялось бы PHash)
	OPub    ed25519.PublicKey // открытая часть ключа владельца
	PSalt   []byte            // соль и хэш пароля записи владельца (account.Salt / account.Hash)
	PHash   []byte            //
	TOTP    string            // секрет кода пространства, base32 без '='
	Members []spaceMember     // по возрастанию Pub
	Gone    [][]byte          // открытые ключи исключённых ПК, по возрастанию; только растёт
	Sig     []byte
}

// spaceOwnerKey — закрытый ключ владельца из пароля. Вызывающий затирает его после подписи (clear).
func spaceOwnerKey(password string, osalt []byte) ed25519.PrivateKey {
	seed := pake.KDF(password, osalt)
	key := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	return key
}

// spaceNew — новое пространство с одним ПК (id, pub): свежие sid и osalt, эпоха 1. psalt/phash/totpSecret — из
// записи владельца на этом ПК; пароль сверяется с phash, чтобы ключ владельца и запись были от одного пароля.
func spaceNew(password string, psalt, phash []byte, totpSecret, id string, pub ed25519.PublicKey) (*space, error) {
	if len(psalt) != spaceSaltLen || len(phash) != spaceHashLen {
		return nil, fmt.Errorf("%w: соль или хэш пароля", errSpaceFormat)
	}
	if subtle.ConstantTimeCompare(pake.KDF(password, psalt), phash) != 1 {
		return nil, errSpacePassword
	}
	m := &space{
		SID: make([]byte, spaceSaltLen), Epoch: 1, OSalt: make([]byte, spaceSaltLen),
		PSalt: bytes.Clone(psalt), PHash: bytes.Clone(phash), TOTP: totpSecret,
		Members: []spaceMember{{ID: id, Pub: bytes.Clone(pub)}},
	}
	rand.Read(m.SID)
	rand.Read(m.OSalt)
	key := spaceOwnerKey(password, m.OSalt)
	defer clear(key)
	m.OPub = bytes.Clone(key.Public().(ed25519.PublicKey))
	if err := m.seal(key); err != nil {
		return nil, err
	}
	return m, nil
}

// spaceAdd — состав следующей эпохи с новым ПК. Только с паролем владельца; m не меняется.
func spaceAdd(m *space, password, id string, pub ed25519.PublicKey) (*space, error) {
	n, err := m.next()
	if err != nil {
		return nil, err
	}
	if !hub.IsHostID(id) || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: ID или ключ ПК", errSpaceFormat)
	}
	if slices.ContainsFunc(n.Gone, func(g []byte) bool { return bytes.Equal(g, pub) }) {
		return nil, errSpaceGoneMember
	}
	if slices.ContainsFunc(n.Members, func(x spaceMember) bool { return x.ID == id || bytes.Equal(x.Pub, pub) }) {
		return nil, errSpaceDup
	}
	if len(n.Members) >= spaceMaxMembers {
		return nil, fmt.Errorf("%w: не больше %d ПК", errSpaceLimit, spaceMaxMembers)
	}
	n.Members = append(n.Members, spaceMember{ID: id, Pub: bytes.Clone(pub)})
	slices.SortFunc(n.Members, func(a, b spaceMember) int { return bytes.Compare(a.Pub, b.Pub) })
	return n, n.sign(password)
}

// spaceRemove — состав следующей эпохи без ПК pub: ключ уходит в исключённые навсегда, секрет TOTP новый
// (исключённый ПК знал старый). Только с паролем владельца; m не меняется.
func spaceRemove(m *space, password string, pub ed25519.PublicKey) (*space, error) {
	n, err := m.next()
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(n.Members, func(x spaceMember) bool { return bytes.Equal(x.Pub, pub) })
	switch {
	case i < 0:
		return nil, errSpaceNoMember
	case len(n.Members) == 1:
		return nil, errSpaceLast
	case len(n.Gone) >= spaceMaxGone:
		return nil, fmt.Errorf("%w: не больше %d исключённых", errSpaceLimit, spaceMaxGone)
	}
	n.Members = slices.Delete(n.Members, i, i+1)
	n.Gone = append(n.Gone, bytes.Clone(pub))
	slices.SortFunc(n.Gone, bytes.Compare)
	n.TOTP = totp.NewSecret()
	return n, n.sign(password)
}

// spaceAccept — можно ли заменить текущий состав пришедшим: то же пространство и тот же владелец, подпись верна,
// эпоха строго больше, исключённые только прибавляются (иначе украденный ПК вернул бы старый список).
// Равная эпоха — тоже отказ (errSpaceStale): одинаковый состав принимать незачем, разный — подмена.
func spaceAccept(cur, in *space) error {
	if cur == nil || in == nil {
		return errSpaceFormat
	}
	if err := in.verify(); err != nil {
		return err
	}
	if !bytes.Equal(cur.SID, in.SID) || !bytes.Equal(cur.OPub, in.OPub) || !bytes.Equal(cur.OSalt, in.OSalt) {
		return errSpaceForeign
	}
	if in.Epoch <= cur.Epoch {
		return errSpaceStale
	}
	for _, g := range cur.Gone {
		if _, ok := slices.BinarySearchFunc(in.Gone, g, bytes.Compare); !ok {
			return errSpaceGoneShrunk
		}
	}
	return nil
}

// verify — состав цел (check) и подписан ключом OPub. Чей это OPub — решает spaceAccept или тот, кто вводил пароль.
func (m *space) verify() error {
	if err := m.check(); err != nil {
		return err
	}
	if len(m.Sig) != ed25519.SignatureSize || !ed25519.Verify(m.OPub, m.signBytes(), m.Sig) {
		return errSpaceSig
	}
	return nil
}

// sign — подписать паролем владельца: ключ из пароля обязан совпасть с OPub, иначе errSpacePassword.
func (m *space) sign(password string) error {
	if len(m.OSalt) != spaceSaltLen {
		return errSpaceFormat
	}
	key := spaceOwnerKey(password, m.OSalt)
	defer clear(key)
	return m.seal(key)
}

// seal — подпись готовым ключом владельца (он же — сверка ключа с OPub).
func (m *space) seal(key ed25519.PrivateKey) error {
	if subtle.ConstantTimeCompare(key.Public().(ed25519.PublicKey), m.OPub) != 1 {
		return errSpacePassword
	}
	if err := m.check(); err != nil {
		return err
	}
	m.Sig = ed25519.Sign(key, m.signBytes())
	return nil
}

// next — копия проверенного состава для правки: эпоха +1, без подписи.
func (m *space) next() (*space, error) {
	if m == nil {
		return nil, errSpaceFormat
	}
	if err := m.verify(); err != nil {
		return nil, err
	}
	if m.Epoch == math.MaxUint64 {
		return nil, fmt.Errorf("%w: эпоха", errSpaceLimit)
	}
	n := &space{
		SID: bytes.Clone(m.SID), Epoch: m.Epoch + 1, OSalt: bytes.Clone(m.OSalt), OPub: bytes.Clone(m.OPub),
		PSalt: bytes.Clone(m.PSalt), PHash: bytes.Clone(m.PHash), TOTP: m.TOTP,
	}
	for _, x := range m.Members {
		n.Members = append(n.Members, spaceMember{ID: x.ID, Pub: bytes.Clone(x.Pub)})
	}
	for _, g := range m.Gone {
		n.Gone = append(n.Gone, bytes.Clone(g))
	}
	return n, nil
}

// check — все правила состава, кроме подписи: длины, пределы, порядок, никто из членов не исключён.
func (m *space) check() error {
	bad := func(what string) error { return fmt.Errorf("%w: %s", errSpaceFormat, what) }
	switch {
	case len(m.Members) > spaceMaxMembers || len(m.Gone) > spaceMaxGone || len(m.TOTP) > spaceMaxTOTP:
		return errSpaceLimit
	case len(m.SID) != spaceSaltLen || len(m.OSalt) != spaceSaltLen || len(m.PSalt) != spaceSaltLen:
		return bad("длина sid или соли")
	case len(m.OPub) != ed25519.PublicKeySize || len(m.PHash) != spaceHashLen:
		return bad("длина ключа владельца или хэша")
	case m.Epoch == 0:
		return bad("эпоха 0")
	case bytes.Equal(m.OSalt, m.PSalt): // зерно ключа владельца совпало бы с PHash, а он в составе открыт
		return bad("соль ключа владельца равна соли пароля")
	case !totp.Valid(m.TOTP) || strings.ContainsFunc(m.TOTP, func(r rune) bool { return r == '=' || r >= 'a' && r <= 'z' }):
		return bad("секрет TOTP")
	case len(m.Members) == 0:
		return bad("нет ни одного ПК")
	}
	ids := make(map[string]bool, len(m.Members))
	for i, x := range m.Members {
		if !hub.IsHostID(x.ID) || len(x.Pub) != ed25519.PublicKeySize || ids[x.ID] {
			return bad("ID или ключ ПК")
		}
		ids[x.ID] = true
		if i > 0 && bytes.Compare(m.Members[i-1].Pub, x.Pub) >= 0 {
			return bad("порядок ПК")
		}
	}
	for i, g := range m.Gone {
		if len(g) != ed25519.PublicKeySize || i > 0 && bytes.Compare(m.Gone[i-1], g) >= 0 {
			return bad("список исключённых")
		}
	}
	for _, x := range m.Members {
		if _, ok := slices.BinarySearchFunc(m.Gone, []byte(x.Pub), bytes.Compare); ok {
			return errSpaceGoneMember
		}
	}
	return nil
}

// signBytes — подписываемые байты (формат — в начале файла). Только для состава, прошедшего check.
func (m *space) signBytes() []byte {
	b := make([]byte, 0, spaceMaxBytes)
	b = append(b, spaceDomain...)
	b = append(b, spaceVer)
	b = append(b, m.SID...)
	b = binary.BigEndian.AppendUint64(b, m.Epoch)
	b = append(b, m.OSalt...)
	b = append(b, m.OPub...)
	b = append(b, m.PSalt...)
	b = append(b, m.PHash...)
	b = append(b, byte(len(m.TOTP)))
	b = append(b, m.TOTP...)
	b = append(b, byte(len(m.Members)))
	for _, x := range m.Members {
		b = append(b, x.ID...)
		b = append(b, x.Pub...)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(m.Gone)))
	for _, g := range m.Gone {
		b = append(b, g...)
	}
	return b
}

// marshal — запись состава с подписью: для диска и сети (следующие этапы).
func (m *space) marshal() ([]byte, error) {
	if err := m.check(); err != nil {
		return nil, err
	}
	if len(m.Sig) != ed25519.SignatureSize {
		return nil, errSpaceSig
	}
	return append(m.signBytes(), m.Sig...), nil
}

// spaceParse — разбор записи из недоверенного источника: пределы размера и все правила check; подпись проверяет
// verify / spaceAccept. Результат не ссылается на b.
func spaceParse(b []byte) (*space, error) {
	if len(b) > spaceMaxBytes {
		return nil, errSpaceLimit
	}
	short := false
	take := func(n int) []byte {
		if short || len(b) < n {
			short = true
			return make([]byte, n) // нули: разбор дойдёт до конца и вернёт errSpaceFormat
		}
		v := bytes.Clone(b[:n])
		b = b[n:]
		return v
	}
	if string(take(len(spaceDomain))) != spaceDomain {
		return nil, errSpaceFormat
	}
	if v := take(1)[0]; short {
		return nil, errSpaceFormat
	} else if v != spaceVer {
		return nil, errSpaceVersion
	}
	m := &space{SID: take(spaceSaltLen)}
	m.Epoch = binary.BigEndian.Uint64(take(8))
	m.OSalt, m.OPub = take(spaceSaltLen), take(ed25519.PublicKeySize)
	m.PSalt, m.PHash = take(spaceSaltLen), take(spaceHashLen)
	n := int(take(1)[0])
	if n > spaceMaxTOTP {
		return nil, errSpaceLimit
	}
	m.TOTP = string(take(n))
	if n = int(take(1)[0]); n > spaceMaxMembers {
		return nil, errSpaceLimit
	}
	for range n {
		m.Members = append(m.Members, spaceMember{ID: string(take(spaceIDLen)), Pub: take(ed25519.PublicKeySize)})
	}
	if n = int(binary.BigEndian.Uint16(take(2))); n > spaceMaxGone {
		return nil, errSpaceLimit
	}
	for range n {
		m.Gone = append(m.Gone, take(ed25519.PublicKeySize))
	}
	m.Sig = take(ed25519.SignatureSize)
	if short || len(b) != 0 {
		return nil, errSpaceFormat
	}
	if err := m.check(); err != nil {
		return nil, err
	}
	return m, nil
}
