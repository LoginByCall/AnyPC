package main

// «Моё пространство», этап Э1: состав пространства M и его подпись (UI-REDESIGN.md, «Проект ядра пространства»).
// Только формат и правила — без сети, без диска, без окна. ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (CLAUDE.md A13: ключевой материал).
//
// Ключ владельца — Ed25519 с зерном Argon2id(spaceOwnerDomain+пароль, osalt) (pake.KDF, те же параметры, что у
// паролей). Доменный префикс обязателен: без него зерно совпало бы с хэшем пароля Argon2id(пароль, psalt), который
// лежит в составе открыто, — знающий хэш собрал бы состав с osalt = psalt и подписывал бы за владельца.
// Закрытая часть не хранится и не передаётся: пересчитывается из пароля на время одной подписи; на диск и в сеть
// идут только opub и osalt. Затирание памяти (clear) — по возможности: Go не гарантирует, что копий не осталось.
//
// Доверие к составу — только через ключ владельца: первому составу, пришедшему из сети, верят, лишь если ключ,
// выведенный из введённого пароля, равен его opub (spaceAdd/sign это и сверяют), или по закреплённому ранее opub
// (spaceAccept сверяет с текущим). Сама по себе верная подпись ничего не доказывает: подписать может кто угодно
// своим ключом.
//
// Запись M (версия 1), все числа — big-endian, длины полей постоянные, кроме секрета TOTP и двух списков:
//
//	"AnyPC space M\x00" | ver=1 | sid[16] | epoch u64 | osalt[16] | opub[32] | psalt[16] | phash[32]
//	| u8 len, totp | u8 n, n×{id[9], pub[32]} | u16 k, k×pub[32]            ← эти байты подписываются
//	| sig[64]                                                                 ← подпись владельца
//
// Запись однозначна: члены и исключённые идут по возрастанию открытого ключа без повторов, секрет TOTP — только
// [A-Z2-7] в каноническом base32; иное — ошибка разбора. Поэтому одинаковый состав — одинаковые байты на любой ОС
// и версии.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"

	"anypc/hub"
	"anypc/pake"
	"anypc/totp"
)

const (
	spaceDomain      = "AnyPC space M\x00"            // доменный префикс подписи: она не сойдёт за подпись чего-то другого
	spaceOwnerDomain = "AnyPC space owner key v1\x00" // доменный префикс пароля в Argon2id ключа владельца
	spaceVer         = 1
	spaceIDLen       = 9  // ID хоста (hub.IsHostID)
	spaceSaltLen     = 16 // sid, osalt, psalt
	spaceHashLen     = 32 // pake.KDF
	spaceMaxMembers  = 32
	spaceMaxGone     = 256 // исключённые не забываются никогда; после 256 исключений — новое пространство
	spaceMaxTOTP     = 64
	// spaceMaxJump — наибольший шаг эпохи за один приём. Честные правки дают +1; больший скачок (до MaxUint64)
	// заморозил бы пространство — следующая правка стала бы невозможна.
	spaceMaxJump = 1 << 20
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
	errSpaceStale      = errors.New("пространство: состав старее текущего")
	errSpaceSame       = errors.New("пространство: этот состав уже есть") // не раскол: менять нечего
	errSpaceFork       = errors.New("пространство: раскол состава — нужно слияние (spaceMerge)")
	errSpaceJump       = errors.New("пространство: слишком большой скачок эпохи")
	errSpaceGoneMember = errors.New("пространство: исключённый ПК числится членом")
	errSpaceDup        = errors.New("пространство: такой ПК уже в составе")
	errSpaceNoMember   = errors.New("пространство: такого ПК в составе нет")
	errSpaceLast       = errors.New("пространство: нельзя исключить последний ПК")
)

var spaceB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// spaceSmallOrder — координаты y (старший бит — знак x — снят) восьми точек малого порядка Ed25519 и их
// неканонических записей (y ≥ p). Для такого открытого ключа подпись (R, 0) сходится на любом сообщении.
// Список — как у libsodium (ge25519_has_small_order); y8 и p−y8 сверены с уравнением кривой в тесте.
var spaceSmallOrder = func() [][]byte {
	var l [][]byte
	for _, h := range []string{
		"0000000000000000000000000000000000000000000000000000000000000000", // y = 0, порядок 4
		"0100000000000000000000000000000000000000000000000000000000000000", // y = 1, единица
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // y8, порядок 8
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // p − y8, порядок 8
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p − 1, порядок 2
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p (≡ 0)
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p + 1 (≡ 1)
	} {
		b, _ := hex.DecodeString(h)
		l = append(l, b)
	}
	return l
}()

// spaceWeakKey — ключ малого порядка (в том числе нулевой): такому ключу подпись не доказывает ничего.
func spaceWeakKey(pub []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return true
	}
	y := bytes.Clone(pub)
	y[31] &= 0x7f
	return slices.ContainsFunc(spaceSmallOrder, func(s []byte) bool { return bytes.Equal(s, y) })
}

// spaceMember — ПК пространства: ID на хабе и открытая часть ключа хоста (config.Key).
type spaceMember struct {
	ID  string
	Pub ed25519.PublicKey
}

// space — состав M с подписью владельца. Значение не меняется после подписи: правки дают новый состав.
// Печать (%v, %+v, %s, %#v) вымарывает секрет TOTP и хэш пароля — см. Format.
type space struct {
	SID     []byte            // случайный идентификатор пространства
	Epoch   uint64            // растёт на 1 с каждой правкой; с 1
	OSalt   []byte            // соль ключа владельца; не равна PSalt (вторая защита к доменному префиксу)
	OPub    ed25519.PublicKey // открытая часть ключа владельца
	PSalt   []byte            // соль и хэш пароля записи владельца (account.Salt / account.Hash)
	PHash   []byte            //
	TOTP    string            // секрет кода пространства, канонический base32 без '='
	Members []spaceMember     // по возрастанию Pub
	Gone    [][]byte          // открытые ключи исключённых ПК, по возрастанию; только растёт
	Sig     []byte
}

// String — состав без секретов: TOTP и хэш пароля не печатаются никогда.
func (m space) String() string {
	ids := make([]string, len(m.Members))
	for i, x := range m.Members {
		ids[i] = x.ID
	}
	return fmt.Sprintf("space{sid=%x epoch=%d opub=%x members=%v gone=%d totp=<скрыт> phash=<скрыт> sig=%d}",
		m.SID, m.Epoch, m.OPub, ids, len(m.Gone), len(m.Sig))
}

// Format — любая печать через fmt идёт через String: %+v и %#v не выдадут поля с секретами.
func (m space) Format(f fmt.State, _ rune) { fmt.Fprint(f, m.String()) }

// spaceOwnerKey — закрытый ключ владельца из пароля; вызывающий не хранит его дольше одной подписи.
func spaceOwnerKey(password string, osalt []byte) ed25519.PrivateKey {
	seed := pake.KDF(spaceOwnerDomain+password, osalt)
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
	for rand.Read(m.OSalt); bytes.Equal(m.OSalt, m.PSalt); rand.Read(m.OSalt) {
	}
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
	if !hub.IsHostID(id) || spaceWeakKey(pub) {
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
	if err := n.sign(password); err != nil {
		return nil, err
	}
	return n, nil
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
	if err := n.sign(password); err != nil {
		return nil, err
	}
	return n, nil
}

// spaceAccept — можно ли заменить текущий (своего, проверенного) состав пришедшим. nil — да. Иначе:
//   - errSpaceForeign — другое пространство или другой владелец (sid, opub, osalt);
//   - errSpaceStale — эпоха меньше (откат: украденный ПК вернул бы старый список);
//   - errSpaceSame — тот же состав, менять нечего;
//   - errSpaceFork — две правки от одной эпохи (равная эпоха с другими байтами; большая эпоха, где пропал
//     исключённый или член, не попавший в исключённые). Честная история так не идёт: исключение — это перенос
//     в gone, а не удаление. Лечится слиянием spaceMerge с паролем владельца;
//   - errSpaceJump — скачок эпохи больше spaceMaxJump.
func spaceAccept(cur, in *space) error {
	if cur == nil || in == nil {
		return errSpaceFormat
	}
	if err := cur.verify(); err != nil {
		return err
	}
	if err := in.verify(); err != nil {
		return err
	}
	if !cur.sameSpace(in) {
		return errSpaceForeign
	}
	switch {
	case in.Epoch < cur.Epoch:
		return errSpaceStale
	case in.Epoch == cur.Epoch && bytes.Equal(cur.signBytes(), in.signBytes()):
		return errSpaceSame
	case in.Epoch == cur.Epoch:
		return errSpaceFork
	case in.Epoch-cur.Epoch > spaceMaxJump:
		return errSpaceJump
	}
	for _, g := range cur.Gone {
		if !in.gone(g) {
			return fmt.Errorf("%w: пропал исключённый", errSpaceFork)
		}
	}
	for _, x := range cur.Members {
		if !in.member(x.Pub) && !in.gone(x.Pub) {
			return fmt.Errorf("%w: пропал член", errSpaceFork)
		}
	}
	return nil
}

// spaceMerge — слияние двух ветвей одного пространства (раскол, errSpaceFork): эпоха max+1, исключённые —
// объединение, члены — объединение без исключённых. Секрет TOTP новый, если хоть одна ветвь не знала о каком-то
// исключении (исключённый знает её секрет) или ветви разошлись в секрете. Только с паролем владельца.
// Результат принимает каждая ветвь (spaceAccept).
func spaceMerge(a, b *space, password string) (*space, error) {
	if a == nil || b == nil {
		return nil, errSpaceFormat
	}
	if err := a.verify(); err != nil {
		return nil, err
	}
	if err := b.verify(); err != nil {
		return nil, err
	}
	if !a.sameSpace(b) {
		return nil, errSpaceForeign
	}
	if !bytes.Equal(a.PSalt, b.PSalt) || !bytes.Equal(a.PHash, b.PHash) {
		return nil, fmt.Errorf("%w: ветви разошлись в пароле записи", errSpaceFork) // смена пароля — не Э1
	}
	top := a
	if b.Epoch > a.Epoch {
		top = b
	}
	n, err := top.next()
	if err != nil {
		return nil, err
	}
	n.Gone = slices.Clone(a.Gone)
	for _, g := range b.Gone {
		if !a.gone(g) {
			n.Gone = append(n.Gone, bytes.Clone(g))
		}
	}
	slices.SortFunc(n.Gone, bytes.Compare)
	if len(n.Gone) > spaceMaxGone {
		return nil, fmt.Errorf("%w: не больше %d исключённых", errSpaceLimit, spaceMaxGone)
	}
	n.Members = nil
	for _, x := range slices.Concat(a.Members, b.Members) {
		if n.gone(x.Pub) || slices.ContainsFunc(n.Members, func(y spaceMember) bool { return y.ID == x.ID && bytes.Equal(y.Pub, x.Pub) }) {
			continue // исключён или уже взят из другой ветви
		}
		if slices.ContainsFunc(n.Members, func(y spaceMember) bool { return y.ID == x.ID || bytes.Equal(y.Pub, x.Pub) }) {
			return nil, fmt.Errorf("%w: ветви разошлись в ID или ключе ПК %s", errSpaceDup, x.ID)
		}
		n.Members = append(n.Members, spaceMember{ID: x.ID, Pub: bytes.Clone(x.Pub)})
	}
	switch {
	case len(n.Members) == 0:
		return nil, errSpaceLast
	case len(n.Members) > spaceMaxMembers:
		return nil, fmt.Errorf("%w: не больше %d ПК", errSpaceLimit, spaceMaxMembers)
	}
	slices.SortFunc(n.Members, func(x, y spaceMember) int { return bytes.Compare(x.Pub, y.Pub) })
	n.TOTP = a.TOTP
	if len(n.Gone) > len(a.Gone) || len(n.Gone) > len(b.Gone) || a.TOTP != b.TOTP {
		n.TOTP = totp.NewSecret()
	}
	if err := n.sign(password); err != nil {
		return nil, err
	}
	return n, nil
}

func (m *space) sameSpace(o *space) bool {
	return bytes.Equal(m.SID, o.SID) && bytes.Equal(m.OPub, o.OPub) && bytes.Equal(m.OSalt, o.OSalt)
}

// gone и member — по проверенному составу (Gone отсортирован).
func (m *space) gone(pub []byte) bool {
	_, ok := slices.BinarySearchFunc(m.Gone, pub, bytes.Compare)
	return ok
}

func (m *space) member(pub []byte) bool {
	return slices.ContainsFunc(m.Members, func(x spaceMember) bool { return bytes.Equal(x.Pub, pub) })
}

// verify — состав цел (check) и подписан ключом OPub. Чей это OPub — решает spaceAccept или тот, кто вводил пароль.
func (m *space) verify() error {
	if m == nil {
		return errSpaceFormat
	}
	if err := m.check(); err != nil {
		return err
	}
	if len(m.Sig) != ed25519.SignatureSize || !ed25519.Verify(m.OPub, m.signBytes(), m.Sig) {
		return errSpaceSig
	}
	return nil
}

// sign — подписать паролем владельца: ключ из пароля обязан совпасть с OPub, иначе errSpacePassword. При ошибке
// m не годен (без подписи) — вызывающий его выбрасывает.
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

// spaceTOTPOK — секрет годен (totp.Valid) и записан канонически: только [A-Z2-7], без '=' и пробелов, и обратное
// кодирование байтов секрета даёт ту же строку (лишние хвостовые биты не прячут второе написание).
func spaceTOTPOK(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'A' && c <= 'Z' || c >= '2' && c <= '7') {
			return false
		}
	}
	k, err := spaceB32.DecodeString(s)
	return err == nil && spaceB32.EncodeToString(k) == s && totp.Valid(s)
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
	case spaceWeakKey(m.OPub):
		return bad("ключ владельца малого порядка")
	case m.Epoch == 0:
		return bad("эпоха 0")
	case bytes.Equal(m.OSalt, m.PSalt):
		return bad("соль ключа владельца равна соли пароля")
	case !spaceTOTPOK(m.TOTP):
		return bad("секрет TOTP")
	case len(m.Members) == 0:
		return bad("нет ни одного ПК")
	}
	ids := make(map[string]bool, len(m.Members))
	for i, x := range m.Members {
		if !hub.IsHostID(x.ID) || spaceWeakKey(x.Pub) || ids[x.ID] {
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
		if m.gone(x.Pub) {
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

// marshal — запись состава с подписью (для диска и сети в следующих этапах). Только целый и подписанный состав.
func (m *space) marshal() ([]byte, error) {
	if err := m.verify(); err != nil {
		return nil, err
	}
	return append(m.signBytes(), m.Sig...), nil
}

// spaceParse — разбор записи из недоверенного источника: пределы размера, все правила check и подпись по opub
// записи. Чей это opub — решает вызывающий (см. начало файла). Результат не ссылается на b.
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
	if err := m.verify(); err != nil {
		return nil, err
	}
	return m, nil
}
