package main

// «Моё пространство», этап Э1: состав пространства M и его подпись (UI-REDESIGN.md, «Проект ядра пространства»).
// Только формат и правила — без сети, без диска, без окна. ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (CLAUDE.md A13: ключевой материал).
//
// Ключ владельца (решение 8 владельца, вариант B) — Ed25519 с зерном Argon2id(spaceOwnerDomain+фраза, osalt)
// (pake.KDF, те же параметры, что у паролей). Фраза пространства — отдельный от пароля входа секрет: пароль входа
// (psalt/phash записи владельца) и секрет TOTP — обычные поля M, меняются правкой M(epoch+1) под тем же ключом;
// знающий пароль входа (и phash) состав не подписывает. Доменный префикс и запрет osalt = psalt сохранены (Н1
// приёмки Э1): зерно не совпадёт с хэшем Argon2id(пароль, psalt), который лежит в составе открыто, даже если фраза
// равна паролю (это запрещено отдельно — spacePhraseLoginOK). Префикс v2: в v1 в KDF шёл пароль входа (составы v1
// нигде не созданы: spaceCreate не вызывался вне тестов); новый префикс разводит обе производные при равных строках.
// Закрытая часть не хранится и не передаётся: пересчитывается из фразы на время одной подписи; на диск и в сеть
// идут только opub и osalt. Затирание памяти (clear) — по возможности: Go не гарантирует, что копий не осталось.
//
// Доверие к составу — только через ключ владельца: первому составу, пришедшему из сети, верят, лишь если ключ,
// выведенный из введённой фразы, равен его opub (spaceAdd/sign это и сверяют), или по закреплённому ранее opub
// (spaceHeads сверяет sid, opub и osalt с текущими). Сама по себе верная подпись ничего не доказывает: подписать может кто угодно
// своим ключом.
//
// Фраза (С3/С4 приёмки Э1b): ровно 10 слов словаря spaceWords (80 бит), только ASCII; при создании — только фраза
// генератора.
//
// Состав — объединение (решение 10 A владельца, FINDINGS «Готовые решения для состава группы»). Украденный ПК фразы
// не знает и M не подпишет: каждый подписанный M — подлинная правка владельца. Поэтому ПК держит не «последний» M, а
// все подлинные M, которые ничем не перекрыты (верхушки, spaceHeads), и состав — их объединение как 2P-Set:
// gone = ∪ gone, members = ∪ members − gone (spaceView). Объединение коммутативно, ассоциативно и идемпотентно:
// порядок доставки, повторы и старые M ничего не ломают, расколов по составу нет, подпись слияния не нужна;
// исключённый не возвращается никогда. Вход (пароль входа и секрет TOTP) — регистр: lgen (номер), lex (сколько
// исключённых было, когда вход задан), lprev (хэш прежнего входа). Из разных входов побеждает один по правилу
// развилки Tailnet Lock (spaceLoginCmp): больше исключений → больший lgen → меньший хэш. Вход, чей секрет мог видеть
// исключённый ПК, — «скомпрометирован» (Compromised): в объединении исключённых больше, чем lex победившего входа.
// Исключённые при задании входа (lex штук) его секрета не видели; любой другой исключённый тогда исключён не был и
// мог получить секрет сверкой (член любой ветви, даже не числившийся ни в одной M с этим входом). Пропусков нет,
// вступлений нет, правки — только с новым секретом кода (новый вход фразой: lex = все исключённые объединения).
// Следующая правка фразой делается от объединения и перекрывает все верхушки.
//
// Запись M (версия 2; составы не выпущены — формат менялся без совместимости), все числа — big-endian, длины полей
// постоянные, кроме секрета TOTP и двух списков:
//
//	"AnyPC space M\x00" | ver=2 | sid[16] | epoch u64 | osalt[16] | opub[32] | psalt[16] | phash[32]
//	| u8 len, totp | lgen u32 | lex u16 | lprev[32]
//	| u8 n, n×{id[9], pub[32]} | u16 k, k×pub[32]                            ← эти байты подписываются
//	| sig[64]                                                                 ← подпись владельца
//
// lgen — с 1, растёт при каждой смене psalt/phash/totp; lex — число исключённых в M, где вход задан (0 при lgen 1);
// lprev — loginHash прежнего входа (нули при lgen 1). Эпоха — с 1, правка от объединения — наибольшая эпоха + 1.
//
// Запись однозначна: члены и исключённые идут по возрастанию открытого ключа без повторов, секрет TOTP — только
// [A-Z2-7] в каноническом base32; иное — ошибка разбора. Поэтому одинаковый состав — одинаковые байты на любой ОС
// и версии.

import (
	"bytes"
	"cmp"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
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
	spaceDomain      = "AnyPC space M\x00"            // доменный префикс подписи: она не сойдёт за подпись чего-то другого
	spaceOwnerDomain = "AnyPC space owner key v2\x00" // доменный префикс фразы в Argon2id ключа владельца
	spaceLoginDomain = "AnyPC space login v2\x00"     // доменный префикс хэша входа (lprev, развилка)
	spacePhraseWords = 10                             // слов во фразе: 10 × 8 бит = 80 бит
	spaceVer         = 2
	spaceIDLen       = 9   // ID хоста (hub.IsHostID)
	spaceSaltLen     = 16  // sid, osalt, psalt
	spaceHashLen     = 32  // pake.KDF
	spaceMaxMembers  = 32  // добавить ПК можно, пока в объединении их меньше (spaceAdd)
	spaceMaxListed   = 255 // предел формата (u8): объединение параллельных добавлений бывает больше spaceMaxMembers,
	// и исключение (уменьшает состав) должно оставаться возможным
	spaceMaxGone = 256 // исключённые не забываются никогда; после 256 исключений — новое пространство
	spaceMaxTOTP = 64
	// spaceMaxHeads — сколько неперекрытых M держит ПК: столько параллельных правок фразой на разных ПК, не
	// узнавших друг о друге; любая следующая правка фразой сводит верхушки к одной.
	spaceMaxHeads = 16
	// spaceMaxPend — сколько непринятых сверх spaceMaxHeads M держит ПК (SpacePend); дальше пришедшие сверх не
	// запоминаются (ПК и так закрыт; их владелец пришлёт снова).
	spaceMaxPend = 32
	// spaceMaxBytes — потолок записи с подписью: больше не разбираем вовсе.
	spaceMaxBytes = len(spaceDomain) + 1 + spaceSaltLen + 8 + spaceSaltLen + ed25519.PublicKeySize + spaceSaltLen + spaceHashLen +
		1 + spaceMaxTOTP + 4 + 2 + sha256.Size + 1 + spaceMaxListed*(spaceIDLen+ed25519.PublicKeySize) + 2 + spaceMaxGone*ed25519.PublicKeySize +
		ed25519.SignatureSize
)

var (
	errSpaceFormat      = errors.New("пространство: запись состава испорчена")
	errSpaceVersion     = errors.New("пространство: неизвестная версия записи состава")
	errSpaceLimit       = errors.New("пространство: превышен предел размера состава")
	errSpaceSig         = errors.New("пространство: подпись владельца неверна")
	errSpacePassword    = errors.New("пространство: неверный пароль входа")
	errSpacePhrase      = errors.New("пространство: неверная фраза пространства")
	errSpacePhraseCount = errors.New("пространство: во фразе должно быть ровно 10 слов")
	errSpacePhraseASCII = errors.New("пространство: во фразе только латинские буквы и пробелы — проверьте раскладку")
	errSpacePhraseWord  = errors.New("пространство: слово фразы не из словаря")
	errSpacePhraseLogin = errors.New("пространство: пароль входа не должен совпадать с фразой пространства")
	errSpaceNoChange    = errors.New("пространство: менять нечего")
	errSpaceForeign     = errors.New("пространство: состав другого пространства или другого владельца")
	errSpaceHeads       = errors.New("пространство: слишком много параллельных правок — сделайте правку фразой")
	// errSpaceDamaged — лечение без кода (у записи нет TOTP; решение владельца B, 2026-11-14): переустановка config.json
	// не трогает, поэтому — убрать "space" руками (путь — main_unix.go/main_windows.go loadConfig).
	errSpaceDamaged = errors.New("пространство: записи состава на этом ПК испорчены — выйдите из пространства (пароль и код) и вступите снова. " +
		"Если кода нет: закройте AnyPC, удалите поле \"space\" из config.json (Linux: ~/.config/AnyPC, macOS: ~/Library/Application Support/AnyPC, " +
		"Windows: %APPDATA%\\AnyPC) или весь файл настроек и запустите AnyPC заново")
	errSpaceCompromised = errors.New("пространство: секрет кода видел исключённый ПК — задайте новый код (фраза)")
	errSpaceGoneMember  = errors.New("пространство: исключённый ПК числится членом")
	errSpaceDup         = errors.New("пространство: такой ПК уже в составе")
	errSpaceNoMember    = errors.New("пространство: такого ПК в составе нет")
	errSpaceLast        = errors.New("пространство: нельзя исключить последний ПК")
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
	LGen    uint32            // номер входа (PSalt, PHash, TOTP): с 1, +1 при каждой смене
	LEx     uint16            // число исключённых в M, где задан этот вход (развилка входа: больше — сильнее)
	LPrev   []byte            // loginHash прежнего входа; нули при LGen 1
	Members []spaceMember     // по возрастанию Pub
	Gone    [][]byte          // открытые ключи исключённых ПК, по возрастанию; только растёт
	Sig     []byte
	// Только у объединения (spaceView, без подписи): секрет кода победившего входа видел исключённый ПК.
	Compromised bool
}

// String — состав без секретов: TOTP и хэш пароля не печатаются никогда.
func (m space) String() string {
	ids := make([]string, len(m.Members))
	for i, x := range m.Members {
		ids[i] = x.ID
	}
	return fmt.Sprintf("space{sid=%x epoch=%d opub=%x members=%v gone=%d lgen=%d totp=<скрыт> phash=<скрыт> sig=%d compromised=%v}",
		m.SID, m.Epoch, m.OPub, ids, len(m.Gone), m.LGen, len(m.Sig), m.Compromised)
}

// Format — любая печать через fmt идёт через String: %+v и %#v не выдадут поля с секретами.
func (m space) Format(f fmt.State, _ rune) { fmt.Fprint(f, m.String()) }

// spaceOwnerKey — закрытый ключ владельца из фразы (spacePhraseNorm); вызывающий не хранит его дольше одной подписи.
func spaceOwnerKey(phrase string, osalt []byte) ed25519.PrivateKey {
	seed := pake.KDF(spaceOwnerDomain+spacePhraseNorm(phrase), osalt)
	key := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	return key
}

// spacePhraseNorm — фраза как её вводит человек на любом ПК: строчные буквы, слова через один пробел, без пробелов
// по краям. Только для фразы, прошедшей spacePhraseOK (ASCII).
func spacePhraseNorm(phrase string) string {
	return strings.ToLower(strings.Join(strings.Fields(phrase), " "))
}

// spacePhraseWordError — слово N (с 1) фразы не из словаря: окно подсветит опечатку.
type spacePhraseWordError struct{ N int }

func (e spacePhraseWordError) Error() string {
	return fmt.Sprintf("%v: слово %d", errSpacePhraseWord, e.N)
}
func (e spacePhraseWordError) Is(t error) bool { return t == errSpacePhraseWord }

var spaceWordSet = func() map[string]bool {
	m := make(map[string]bool, len(spaceWords))
	for _, w := range spaceWords {
		m[w] = true
	}
	return m
}()

// spacePhraseOK — правило фразы при каждом вводе: только ASCII (NBSP и прочие Юникод-пробелы — тоже отказ), после
// spacePhraseNorm ровно spacePhraseWords слов, каждое из словаря. Проверяется до Argon2.
func spacePhraseOK(phrase string) error {
	for i := 0; i < len(phrase); i++ {
		if phrase[i] >= 0x80 {
			return errSpacePhraseASCII
		}
	}
	w := strings.Fields(strings.ToLower(phrase))
	for i, x := range w {
		if !spaceWordSet[x] {
			return spacePhraseWordError{i + 1}
		}
	}
	if len(w) != spacePhraseWords {
		return errSpacePhraseCount
	}
	return nil
}

// spacePhraseLoginOK — пароль входа открытым текстом не равен фразе с точностью до нормализации (С1): иначе знающий
// пароль входа (его вводят на каждом «Работаю тут») подписывал бы состав. Окно вызывает до смены пароля; правки
// состава с новым паролем (setLogin) сверяют сами.
func spacePhraseLoginOK(phrase, password string) error {
	if spacePhraseOK(password) == nil && spacePhraseNorm(password) == spacePhraseNorm(phrase) {
		return errSpacePhraseLogin
	}
	return nil
}

// spacePhraseNew — случайная фраза: spacePhraseWords слов из spaceWords (256 слов — один байт crypto/rand на слово,
// без смещения). Итог перепроверяется правилом: испорченный словарь — паника, а не слабая фраза.
func spacePhraseNew() string {
	b := make([]byte, spacePhraseWords)
	rand.Read(b)
	w := make([]string, len(b))
	for i, x := range b {
		w[i] = spaceWords[x]
	}
	p := strings.Join(w, " ")
	if err := spacePhraseOK(p); err != nil {
		panic(err)
	}
	return p
}

// spaceNew — новое пространство с одним ПК (id, pub): свежие sid и osalt, эпоха 1, вход 1 и новая фраза генератора
// (своя фраза при создании не принимается — С3); фраза возвращается один раз — окно показывает её для записи.
// psalt/phash/totpSecret — из записи владельца на этом ПК (пароль входа сверяет вызывающий).
func spaceNew(psalt, phash []byte, totpSecret, id string, pub ed25519.PublicKey) (*space, string, error) {
	if len(psalt) != spaceSaltLen || len(phash) != spaceHashLen {
		return nil, "", fmt.Errorf("%w: соль или хэш пароля", errSpaceFormat)
	}
	phrase := spacePhraseNew()
	m := &space{
		SID: make([]byte, spaceSaltLen), Epoch: 1, OSalt: make([]byte, spaceSaltLen),
		PSalt: bytes.Clone(psalt), PHash: bytes.Clone(phash), TOTP: totpSecret,
		LGen: 1, LPrev: make([]byte, sha256.Size),
		Members: []spaceMember{{ID: id, Pub: bytes.Clone(pub)}},
	}
	rand.Read(m.SID)
	for rand.Read(m.OSalt); bytes.Equal(m.OSalt, m.PSalt); rand.Read(m.OSalt) {
	}
	key := spaceOwnerKey(phrase, m.OSalt)
	defer clear(key)
	m.OPub = bytes.Clone(key.Public().(ed25519.PublicKey))
	if err := m.seal(key); err != nil {
		return nil, "", err
	}
	return m, phrase, nil
}

// loginHash — хэш входа (lgen, lex, psalt, phash, totp): lprev следующего входа и последнее правило развилки.
func (m *space) loginHash() []byte {
	b := binary.BigEndian.AppendUint32([]byte(spaceLoginDomain), m.LGen)
	b = binary.BigEndian.AppendUint16(b, m.LEx)
	b = append(append(append(b, m.PSalt...), m.PHash...), byte(len(m.TOTP)))
	h := sha256.Sum256(append(b, m.TOTP...))
	return h[:]
}

// spaceLoginCmp — развилка входа (правило Tailnet Lock pickNextAUM): > 0 — вход a сильнее b, 0 — тот же вход.
// Больше исключений (lex) → больший lgen → меньший хэш. Продолжение входа всегда сильнее: lex не убывает (gone только
// растёт), lgen растёт. Порядок полный и одинаков на всех ПК.
func spaceLoginCmp(a, b *space) int {
	if c := cmp.Compare(a.LEx, b.LEx); c != 0 {
		return c
	}
	if c := cmp.Compare(a.LGen, b.LGen); c != 0 {
		return c
	}
	return bytes.Compare(b.loginHash(), a.loginHash())
}

// setLogin — новый пароль входа (открытым текстом; "" — прежний; соль новая) и секрет TOTP ("" — прежний) в
// неподписанной правке; вход сменился — lgen+1, lprev — прежний вход. Пароль, равный фразе, — отказ (С1).
func (m *space) setLogin(phrase, password, totpSecret string) error {
	prev := m.loginHash()
	if password != "" {
		if err := spacePhraseLoginOK(phrase, password); err != nil {
			return err
		}
		psalt := make([]byte, spaceSaltLen)
		for rand.Read(psalt); bytes.Equal(psalt, m.OSalt); rand.Read(psalt) {
		}
		m.PSalt, m.PHash = psalt, pake.KDF(password, psalt)
	}
	if totpSecret != "" {
		m.TOTP = totpSecret
	}
	if password == "" && totpSecret == "" || bytes.Equal(prev, m.loginHash()) {
		return nil
	}
	if m.LGen == math.MaxUint32 {
		return fmt.Errorf("%w: номер входа", errSpaceLimit)
	}
	m.LGen++
	m.LEx, m.LPrev = uint16(len(m.Gone)), prev
	return nil
}

// spaceAdd — состав следующей эпохи с новым ПК. Только с фразой пространства; m не меняется.
func spaceAdd(m *space, phrase, id string, pub ed25519.PublicKey) (*space, error) {
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
	if err := n.sign(phrase); err != nil {
		return nil, err
	}
	return n, nil
}

// spaceSetLogin — состав следующей эпохи с новым паролем входа записи владельца (открытым текстом, "" — прежний)
// и/или новым секретом TOTP ("" — прежний). Только с фразой; ключ владельца тот же, члены принимают правку по
// закреплённому opub (spaceHeads) без фразы у них. Новые соль и хэш — в результате (для записи по умолчанию).
func spaceSetLogin(m *space, phrase, password, totpSecret string) (*space, error) {
	n, err := m.next()
	if err != nil {
		return nil, err
	}
	if password == "" && (totpSecret == "" || totpSecret == n.TOTP) {
		return nil, errSpaceNoChange
	}
	if err := n.signLogin(phrase, password, totpSecret); err != nil {
		return nil, err
	}
	return n, nil
}

// spaceRemove — состав следующей эпохи без ПК pub: ключ уходит в исключённые навсегда, секрет TOTP новый
// (исключённый ПК знал старый). Только с фразой; m не меняется.
func spaceRemove(m *space, phrase string, pub ed25519.PublicKey) (*space, error) {
	return spaceRemoveLogin(m, phrase, pub, "")
}

// spaceRemoveLogin — исключение ПК pub и смена пароля входа ("" — прежний) одной правкой, одной эпохой: исключённый
// знал и хэш пароля, и секрет TOTP (решение 5 владельца: окно просит сменить пароль).
func spaceRemoveLogin(m *space, phrase string, pub ed25519.PublicKey, password string) (*space, error) {
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
	if err := n.signLogin(phrase, password, totp.NewSecret()); err != nil {
		return nil, err
	}
	return n, nil
}

// spaceUnder — a ничего не добавляет к b (её можно забыть, объединение не изменится): исключённые a — в b; вход a
// не сильнее; каждый член a — член b или исключён в b. Compromised от этого не зависит: он — от всех исключённых
// объединения и lex победившего входа, а они при забывании a не меняются. Только для составов одного пространства.
func spaceUnder(a, b *space) bool {
	c := spaceLoginCmp(a, b)
	if c > 0 {
		return false
	}
	for _, g := range a.Gone {
		if !b.gone(g) {
			return false
		}
	}
	for _, x := range a.Members {
		if !b.has(x) && !b.gone(x.Pub) {
			return false
		}
	}
	return true
}

// spaceOrder — порядок верхушек: сильнейший вход, затем большая эпоха, затем меньший хэш записи. Первая — «главная»:
// её отдают вступающему (spaceGet) и сверяют в подтверждении.
func spaceOrder(a, b *space) int {
	if c := spaceLoginCmp(b, a); c != 0 {
		return c
	}
	if c := cmp.Compare(b.Epoch, a.Epoch); c != 0 {
		return c
	}
	ha, hb := sha256.Sum256(a.signBytes()), sha256.Sum256(b.signBytes())
	return bytes.Compare(ha[:], hb[:])
}

// spaceHeads — верхушки множества подлинных составов одного пространства: те, что ничем не перекрыты (spaceUnder);
// из взаимно перекрытых — первая по spaceOrder. Итог по spaceOrder; зависит только от множества (не от порядка и
// повторов): heads(heads(A) ∪ B) = heads(A ∪ B). Каждый состав проверяется (verify); чужое пространство —
// errSpaceForeign; больше spaceMaxHeads верхушек — errSpaceHeads (ничего не принято).
func spaceHeads(ms []*space) ([]*space, error) {
	out, err := spaceHeadsAll(ms)
	if err == nil && len(out) > spaceMaxHeads {
		return nil, fmt.Errorf("%w (%d)", errSpaceHeads, len(out))
	}
	return out, err
}

// spaceHeadsAll — spaceHeads без предела числа верхушек (состав ПК с непринятыми правками, SpacePend).
func spaceHeadsAll(ms []*space) ([]*space, error) {
	if len(ms) == 0 {
		return nil, errSpaceFormat
	}
	for _, m := range ms {
		if err := m.verify(); err != nil {
			return nil, err
		}
		if !ms[0].sameSpace(m) {
			return nil, errSpaceForeign
		}
	}
	l := slices.Clone(ms)
	slices.SortFunc(l, spaceOrder)
	var out []*space
	for i, m := range l {
		if i > 0 && spaceOrder(l[i-1], m) == 0 {
			continue // та же запись
		}
		if slices.ContainsFunc(out, func(h *space) bool { return spaceUnder(m, h) }) {
			continue // перекрыт уже взятой (взятые раньше по порядку — из равных побеждают они)
		}
		if slices.ContainsFunc(l, func(h *space) bool { return spaceUnder(m, h) && !spaceUnder(h, m) }) {
			continue // перекрыт строго (тот, кто перекрывает, — сам верхушка или перекрыт верхушкой)
		}
		out = append(out, m)
	}
	return out, nil
}

// spaceView — объединение верхушек (по spaceHeads, первая — главная) как 2P-Set, без подписи: gone — объединение;
// members — объединение пар (ID, ключ) без исключённых, при споре ID или ключа — пара из верхушки раньше по порядку
// (такое даёт лишь ПК, назвавшийся чужим ID, С4); вход — главной верхушки (сильнейший); эпоха — наибольшая.
// Compromised — исключённых в объединении больше, чем lex победившего входа (см. начало файла): секрет кода мог
// видеть исключённый ПК. Одна верхушка — объединение и есть она (копия с подписью: её можно записать).
func spaceView(heads []*space) *space {
	top := heads[0]
	v := top.clone()
	if len(heads) == 1 {
		v.Compromised = len(v.Gone) > int(top.LEx)
		return v
	}
	v.Sig = nil
	for _, h := range heads[1:] {
		v.Epoch = max(v.Epoch, h.Epoch)
		for _, g := range h.Gone {
			if !v.gone(g) {
				v.Gone = append(v.Gone, bytes.Clone(g))
				slices.SortFunc(v.Gone, bytes.Compare)
			}
		}
	}
	v.Members = nil
	for _, h := range heads {
		for _, x := range h.Members {
			if v.gone(x.Pub) || slices.ContainsFunc(v.Members, func(y spaceMember) bool { return y.ID == x.ID || bytes.Equal(y.Pub, x.Pub) }) {
				continue
			}
			v.Members = append(v.Members, spaceMember{ID: x.ID, Pub: bytes.Clone(x.Pub)})
		}
	}
	slices.SortFunc(v.Members, func(x, y spaceMember) int { return bytes.Compare(x.Pub, y.Pub) })
	v.Compromised = len(v.Gone) > int(top.LEx)
	return v
}

// spaceJoin — объединение подлинных составов одного пространства (spaceHeads + spaceView).
func spaceJoin(ms ...*space) (*space, error) {
	h, err := spaceHeads(ms)
	if err != nil {
		return nil, err
	}
	return spaceView(h), nil
}

// has — пара (ID, ключ) — член m.
func (m *space) has(x spaceMember) bool {
	return slices.ContainsFunc(m.Members, func(y spaceMember) bool { return y.ID == x.ID && bytes.Equal(y.Pub, x.Pub) })
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

// verify — состав цел (check) и подписан ключом OPub. Чей это OPub — решает spaceHeads (закреплённый) или тот, кто вводил фразу.
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

// sign — подписать фразой: ключ из фразы обязан совпасть с OPub, иначе errSpacePhrase. При ошибке m не годен (без
// подписи) — вызывающий его выбрасывает.
func (m *space) sign(phrase string) error { return m.signLogin(phrase, "", "") }

// ownerKey — ключ владельца из фразы (правило spacePhraseOK — до Argon2), равный OPub, иначе errSpacePhrase.
func (m *space) ownerKey(phrase string) (ed25519.PrivateKey, error) {
	if err := spacePhraseOK(phrase); err != nil {
		return nil, err
	}
	if len(m.OSalt) != spaceSaltLen {
		return nil, errSpaceFormat
	}
	key := spaceOwnerKey(phrase, m.OSalt)
	if subtle.ConstantTimeCompare(key.Public().(ed25519.PublicKey), m.OPub) != 1 {
		clear(key)
		return nil, errSpacePhrase
	}
	return key, nil
}

// signLogin — sign с правкой входа (setLogin): сперва фраза (errSpacePhrase), потом правка и подпись.
func (m *space) signLogin(phrase, password, totpSecret string) error {
	key, err := m.ownerKey(phrase)
	if err != nil {
		return err
	}
	defer clear(key)
	if err := m.setLogin(phrase, password, totpSecret); err != nil {
		return err
	}
	return m.seal(key)
}

// seal — подпись готовым ключом владельца (он же — сверка ключа с OPub).
func (m *space) seal(key ed25519.PrivateKey) error {
	if subtle.ConstantTimeCompare(key.Public().(ed25519.PublicKey), m.OPub) != 1 {
		return errSpacePhrase
	}
	if err := m.check(); err != nil {
		return err
	}
	m.Sig = ed25519.Sign(key, m.signBytes())
	return nil
}

// next — копия состава для правки: эпоха +1, без подписи. m — подписанный M (verify) или объединение подлинных
// (spaceView: подписи нет, правила check — те же); объединение со скомпрометированным входом правится только со
// сменой секрета кода (это сверяет spaceEdit).
func (m *space) next() (*space, error) {
	if m == nil {
		return nil, errSpaceFormat
	}
	if err := m.check(); err != nil {
		return nil, err
	}
	if m.Sig != nil {
		if err := m.verify(); err != nil {
			return nil, err
		}
	}
	if m.Epoch == math.MaxUint64 {
		return nil, fmt.Errorf("%w: эпоха", errSpaceLimit)
	}
	n := m.clone()
	n.Epoch, n.Sig = m.Epoch+1, nil
	return n, nil
}

// clone — глубокая копия.
func (m *space) clone() *space {
	n := &space{
		SID: bytes.Clone(m.SID), Epoch: m.Epoch, OSalt: bytes.Clone(m.OSalt), OPub: bytes.Clone(m.OPub),
		PSalt: bytes.Clone(m.PSalt), PHash: bytes.Clone(m.PHash), TOTP: m.TOTP,
		LGen: m.LGen, LEx: m.LEx, LPrev: bytes.Clone(m.LPrev), Sig: bytes.Clone(m.Sig), Compromised: m.Compromised,
	}
	for _, x := range m.Members {
		n.Members = append(n.Members, spaceMember{ID: x.ID, Pub: bytes.Clone(x.Pub)})
	}
	for _, g := range m.Gone {
		n.Gone = append(n.Gone, bytes.Clone(g))
	}
	return n
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
	case len(m.Members) > spaceMaxListed || len(m.Gone) > spaceMaxGone || len(m.TOTP) > spaceMaxTOTP:
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
	case len(m.LPrev) != sha256.Size || m.LGen == 0:
		return bad("номер или история входа")
	case (m.LGen == 1) != bytes.Equal(m.LPrev, make([]byte, sha256.Size)), m.LGen == 1 && m.LEx != 0, int(m.LEx) > len(m.Gone):
		return bad("история входа")
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
	b = binary.BigEndian.AppendUint32(b, m.LGen)
	b = binary.BigEndian.AppendUint16(b, m.LEx)
	b = append(b, m.LPrev...)
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
	m.LGen = binary.BigEndian.Uint32(take(4))
	m.LEx = binary.BigEndian.Uint16(take(2))
	m.LPrev = take(sha256.Size)
	n = int(take(1)[0]) // ≤ spaceMaxListed: u8
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
