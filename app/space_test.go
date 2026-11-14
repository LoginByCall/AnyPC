package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"testing"

	"anypc/pake"
	"anypc/totp"
)

const (
	spaceTestPhrase = "ant bat bear bee bird boar bull cat cow crab" // 10 слов словаря
	spaceTestWrong  = "crab cow cat bull boar bird bee bear bat ant" // годная по правилу, но чужая фраза
	spaceTestLogin  = "space-test-login"
	spaceTestTOTP   = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
)

var (
	spaceTestOSalt = bytes.Repeat([]byte{0x01}, 16)
	spaceTestPSalt = bytes.Repeat([]byte{0x02}, 16)
	spaceTestSID   = bytes.Repeat([]byte{0x03}, 16)
	// Argon2id — 64 МБ на вызов: ключ владельца для всех тестов считается один раз.
	spaceTestKey = sync.OnceValue(func() ed25519.PrivateKey { return spaceOwnerKey(spaceTestPhrase, spaceTestOSalt) })
)

func spacePub(n byte) ed25519.PublicKey { return bytes.Repeat([]byte{n}, ed25519.PublicKeySize) }

// spaceFixture — подписанный состав эпохи 1 с двумя ПК (ключи 0x10 и 0x20), постоянный до байта.
func spaceFixture(t *testing.T) *space {
	t.Helper()
	m := &space{
		SID: bytes.Clone(spaceTestSID), Epoch: 1, OSalt: bytes.Clone(spaceTestOSalt),
		OPub:  bytes.Clone(spaceTestKey().Public().(ed25519.PublicKey)),
		PSalt: bytes.Clone(spaceTestPSalt), PHash: bytes.Repeat([]byte{0x04}, 32), TOTP: spaceTestTOTP,
		LGen: 1, LPrev: make([]byte, 32),
		Members: []spaceMember{{"100000001", spacePub(0x10)}, {"100000002", spacePub(0x20)}},
	}
	if err := m.seal(spaceTestKey()); err != nil {
		t.Fatal(err)
	}
	return m
}

// spaceEdit — копия состава с правкой и свежей подписью владельца в обход check: так проверяются правила приёма
// на составах, которые честный код не выпустит.
func spaceEdit(t *testing.T, m *space, edit func(*space)) *space {
	t.Helper()
	b, err := m.marshal()
	if err != nil {
		t.Fatal(err)
	}
	n, err := spaceParse(b)
	if err != nil {
		t.Fatal(err)
	}
	edit(n)
	n.Sig = ed25519.Sign(spaceTestKey(), n.signBytes())
	return n
}

func spaceWant(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("ошибка %v, ждали %v", err, want)
	}
}

func TestSpaceNewVerify(t *testing.T) {
	phash := pake.KDF(spaceTestLogin, spaceTestPSalt)
	m, ph, err := spaceNew(spaceTestPSalt, phash, spaceTestTOTP, "100000001", spacePub(0x10))
	if err != nil {
		t.Fatal(err)
	}
	if spacePhraseOK(ph) != nil || m.LGen != 1 {
		t.Fatalf("фраза генератора %q, вход %d", ph, m.LGen)
	}
	if err := m.verify(); err != nil {
		t.Fatal(err)
	}
	if m.Epoch != 1 || len(m.Members) != 1 || m.Members[0].ID != "100000001" || len(m.Gone) != 0 {
		t.Fatalf("состав: %+v", m)
	}
	if bytes.Equal(m.SID, make([]byte, 16)) || bytes.Equal(m.OSalt, make([]byte, 16)) || bytes.Equal(m.OSalt, m.PSalt) {
		t.Fatal("sid и osalt должны быть случайными")
	}
	b, err := m.marshal()
	if err != nil {
		t.Fatal(err)
	}
	key := spaceOwnerKey(ph, m.OSalt)
	if !bytes.Equal(key.Public().(ed25519.PublicKey), m.OPub) {
		t.Fatal("opub не от фразы")
	}
	if bytes.Contains(b, key.Seed()) {
		t.Fatal("закрытая часть ключа владельца попала в запись")
	}
	p, err := spaceParse(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.verify(); err != nil {
		t.Fatal(err)
	}
	if b2, _ := p.marshal(); !bytes.Equal(b, b2) {
		t.Fatal("разбор и запись дали другие байты")
	}

	// другое пространство той же записи — другие sid, соль, фраза и ключ владельца
	m2, ph2, err := spaceNew(spaceTestPSalt, phash, spaceTestTOTP, "100000001", spacePub(0x10))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(m.SID, m2.SID) || bytes.Equal(m.OPub, m2.OPub) || ph == ph2 {
		t.Fatal("два пространства совпали")
	}

	_, _, err = spaceNew(spaceTestPSalt[:8], phash, spaceTestTOTP, "100000001", spacePub(0x10))
	spaceWant(t, err, errSpaceFormat)
	_, _, err = spaceNew(spaceTestPSalt, phash, spaceTestTOTP, "12345", spacePub(0x10))
	spaceWant(t, err, errSpaceFormat)
	_, _, err = spaceNew(spaceTestPSalt, phash, "", "100000001", spacePub(0x10))
	spaceWant(t, err, errSpaceFormat)
}

func TestSpaceWrongPassword(t *testing.T) {
	m := spaceFixture(t)
	before, _ := m.marshal()
	_, err := spaceAdd(m, spaceTestWrong, "100000003", spacePub(0x30))
	spaceWant(t, err, errSpacePhrase)
	_, err = spaceRemove(m, spaceTestWrong, spacePub(0x20))
	spaceWant(t, err, errSpacePhrase)
	spaceWant(t, m.sign(spaceTestWrong), errSpacePhrase)
	spaceWant(t, m.sign("not-the-password"), errSpacePhraseWord) // не по правилу — до Argon2
	if after, _ := m.marshal(); !bytes.Equal(before, after) {
		t.Fatal("состав изменился при неверном пароле")
	}
	if err := m.verify(); err != nil {
		t.Fatal(err)
	}
}

func TestSpaceAddRemove(t *testing.T) {
	m1 := spaceFixture(t)
	before, _ := m1.marshal()

	m2, err := spaceAdd(m1, spaceTestPhrase, "100000003", spacePub(0x05)) // меньший ключ встаёт первым
	if err != nil {
		t.Fatal(err)
	}
	if m2.Epoch != 2 || len(m2.Members) != 3 || m2.Members[0].ID != "100000003" || m2.TOTP != m1.TOTP {
		t.Fatalf("после добавления: %+v", m2)
	}
	if v := spaceJoinT(t, m1, m2); len(v.Members) != 3 || v.Epoch != 2 {
		t.Fatalf("объединение с добавлением: %v", v)
	}

	m3, err := spaceRemove(m2, spaceTestPhrase, spacePub(0x20))
	if err != nil {
		t.Fatal(err)
	}
	if m3.Epoch != 3 || len(m3.Members) != 2 || len(m3.Gone) != 1 || !bytes.Equal(m3.Gone[0], spacePub(0x20)) {
		t.Fatalf("после исключения: %+v", m3)
	}
	if slices.ContainsFunc(m3.Members, func(x spaceMember) bool { return bytes.Equal(x.Pub, spacePub(0x20)) }) {
		t.Fatal("исключённый ПК остался в составе")
	}
	if m3.TOTP == m2.TOTP || m3.TOTP == "" {
		t.Fatal("исключение не сменило секрет TOTP")
	}
	for _, v := range []*space{spaceJoinT(t, m2, m3), spaceJoinT(t, m1, m3), spaceJoinT(t, m3, m2, m1)} { // пропущенная эпоха — не помеха;
		if v.member(spacePub(0x20)) || !v.gone(spacePub(0x20)) || !sameLogin(v, m3) { // украденный возвращает старый список
			t.Fatalf("исключённый вернулся: %v", v)
		}
	}

	if after, _ := m1.marshal(); !bytes.Equal(before, after) {
		t.Fatal("правка изменила исходный состав")
	}

	// отказы до всякой подписи — пароль не нужен, Argon2 не считается
	_, err = spaceAdd(m3, "", "100000009", spacePub(0x20))
	spaceWant(t, err, errSpaceGoneMember) // исключённого назад не вернуть
	_, err = spaceAdd(m3, "", "100000009", spacePub(0x10))
	spaceWant(t, err, errSpaceDup)
	_, err = spaceAdd(m3, "", "100000001", spacePub(0x77))
	spaceWant(t, err, errSpaceDup)
	_, err = spaceAdd(m3, "", "bad-id", spacePub(0x77))
	spaceWant(t, err, errSpaceFormat)
	_, err = spaceAdd(m3, "", "100000009", spacePub(0x77)[:31])
	spaceWant(t, err, errSpaceFormat)
	_, err = spaceRemove(m3, "", spacePub(0x77))
	spaceWant(t, err, errSpaceNoMember)

	one := spaceEdit(t, m1, func(s *space) { s.Members = s.Members[:1] })
	_, err = spaceRemove(one, "", spacePub(0x10))
	spaceWant(t, err, errSpaceLast)

	full := spaceEdit(t, m1, func(s *space) {
		for i := len(s.Members); i < spaceMaxMembers; i++ {
			s.Members = append(s.Members, spaceMember{ID: "2000000" + string(rune('0'+i/10)) + string(rune('0'+i%10)), Pub: spacePub(byte(0x40 + i))})
		}
	})
	if err := full.verify(); err != nil {
		t.Fatal(err)
	}
	_, err = spaceAdd(full, "", "300000001", spacePub(0xF0))
	spaceWant(t, err, errSpaceLimit)

	forged := spaceFixture(t)
	forged.Epoch = 9 // правка без подписи: менять такой состав нельзя
	_, err = spaceAdd(forged, spaceTestPhrase, "100000003", spacePub(0x30))
	spaceWant(t, err, errSpaceSig)
}

func TestSpaceTamper(t *testing.T) {
	m := spaceFixture(t)
	b, _ := m.marshal()
	for i := range b { // любой байт записи, включая подпись
		for _, bit := range []byte{0x01, 0x80} {
			c := bytes.Clone(b)
			c[i] ^= bit
			p, err := spaceParse(c)
			if err == nil {
				err = p.verify()
			}
			if err == nil {
				t.Fatalf("байт %d ^ %#x: подделка принята", i, bit)
			}
		}
	}
	for name, edit := range map[string]func(*space){
		"sid":        func(s *space) { s.SID[0] ^= 1 },
		"epoch":      func(s *space) { s.Epoch++ },
		"osalt":      func(s *space) { s.OSalt[0] ^= 1 },
		"psalt":      func(s *space) { s.PSalt[0] ^= 1 },
		"phash":      func(s *space) { s.PHash[0] ^= 1 },
		"totp":       func(s *space) { s.TOTP = "KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU" },
		"member id":  func(s *space) { s.Members[0].ID = "100000009" },
		"member pub": func(s *space) { s.Members[0].Pub[31] ^= 1 },
		"member add": func(s *space) { s.Members = append(s.Members, spaceMember{"100000003", spacePub(0x30)}) },
		"member del": func(s *space) { s.Members = s.Members[:1] },
		"gone add":   func(s *space) { s.Gone = append(s.Gone, spacePub(0x30)) },
		"sig":        func(s *space) { s.Sig[0] ^= 1 },
	} {
		s := spaceFixture(t)
		edit(s)
		if err := s.verify(); !errors.Is(err, errSpaceSig) {
			t.Errorf("%s: ошибка %v, ждали %v", name, err, errSpaceSig)
		}
		if _, err := spaceJoin(m, s); err == nil {
			t.Errorf("%s: подделка принята", name)
		}
	}
	other, _, _ := ed25519.GenerateKey(nil)
	s := spaceFixture(t)
	s.OPub = other
	spaceWant(t, s.verify(), errSpaceSig)
}

// Приём в объединение: любой подлинный M того же пространства; откат и повтор ничего не меняют; чужое, неподписанное
// и «исключённый — член» — отказ.
func TestSpaceJoinAccept(t *testing.T) {
	cur := spaceEdit(t, spaceFixture(t), func(s *space) { s.Epoch, s.Gone = 5, [][]byte{spacePub(0x30), spacePub(0x50)} })
	if err := cur.verify(); err != nil {
		t.Fatal(err)
	}
	next := func(edit func(*space)) *space {
		return spaceEdit(t, cur, func(s *space) { s.Epoch = 6; edit(s) })
	}
	if v := spaceJoinT(t, cur, next(func(s *space) { s.Gone = append(s.Gone, spacePub(0x60)) })); len(v.Gone) != 3 {
		t.Fatalf("новый исключённый: %v", v)
	}
	for name, old := range map[string]*space{
		"откат эпохи":        next(func(s *space) { s.Epoch = 4; s.Gone = nil }),
		"тот же":             cur,
		"пропал исключённый": next(func(s *space) { s.Gone = s.Gone[:1] }),
		"пропал член":        next(func(s *space) { s.Members = s.Members[:1] }),
	} {
		v := spaceJoinT(t, cur, old)
		if len(v.Gone) != 2 || len(v.Members) != 2 || !v.gone(spacePub(0x50)) {
			t.Errorf("%s: объединение потеряло: %v", name, v)
		}
		if h, _ := spaceHeads([]*space{cur, old}); len(h) != 1 {
			t.Errorf("%s: %d верхушек", name, len(h))
		}
	}
	for name, f := range map[string]*space{
		"sid":   next(func(s *space) { s.SID[0] ^= 1 }),
		"osalt": next(func(s *space) { s.OSalt[0] ^= 1 }),
	} {
		if _, err := spaceJoin(cur, f); !errors.Is(err, errSpaceForeign) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// чужой владелец: состав с тем же sid, честно подписанный другим ключом
	_, otherKey, _ := ed25519.GenerateKey(nil)
	foreign := next(func(*space) {})
	foreign.OPub = otherKey.Public().(ed25519.PublicKey)
	foreign.Sig = ed25519.Sign(otherKey, foreign.signBytes())
	if err := foreign.verify(); err != nil {
		t.Fatal(err)
	}
	_, err := spaceJoin(cur, foreign)
	spaceWant(t, err, errSpaceForeign)

	// исключённый ПК числится членом — даже с подписью владельца
	bad := next(func(s *space) { s.Gone = [][]byte{spacePub(0x10), spacePub(0x30), spacePub(0x50)} })
	_, err = spaceJoin(cur, bad)
	spaceWant(t, err, errSpaceGoneMember)
	spaceWant(t, bad.verify(), errSpaceGoneMember)
	_, err = spaceParse(append(bad.signBytes(), bad.Sig...))
	spaceWant(t, err, errSpaceGoneMember)

	unsigned := next(func(*space) {})
	unsigned.Sig = nil
	_, err = spaceJoin(cur, unsigned)
	spaceWant(t, err, errSpaceSig)
	_, err = spaceJoin(cur, nil)
	spaceWant(t, err, errSpaceFormat)
	_, err = spaceJoin()
	spaceWant(t, err, errSpaceFormat)
}

// Постоянный вектор: байты записи собраны здесь вручную по описанию формата, а хэш записи с подписью закреплён —
// он же закрепляет параметры Argon2id и вывод ключа владельца. Изменился — формат или ключи сломаны для уже
// работающих пространств.
func TestSpaceVector(t *testing.T) {
	m := spaceEdit(t, spaceFixture(t), func(s *space) { s.Epoch, s.Gone = 0x0102030405060708, [][]byte{spacePub(0x30)} })

	var w []byte
	w = append(w, "AnyPC space M\x00"...)
	w = append(w, 2)                                     // версия
	w = append(w, bytes.Repeat([]byte{0x03}, 16)...)     // sid
	w = append(w, 1, 2, 3, 4, 5, 6, 7, 8)                // эпоха, big-endian
	w = append(w, bytes.Repeat([]byte{0x01}, 16)...)     // osalt
	w = append(w, m.OPub...)                             // opub
	w = append(w, bytes.Repeat([]byte{0x02}, 16)...)     // psalt
	w = append(w, bytes.Repeat([]byte{0x04}, 32)...)     // phash
	w = append(w, 32)                                    // длина секрета TOTP
	w = append(w, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"...) //
	w = append(w, 0, 0, 0, 1)                            // номер входа lgen, u32
	w = append(w, 0, 0)                                  // lex, u16: 0 при lgen 1
	w = append(w, make([]byte, 32)...)                   // lprev: нули при lgen 1
	w = append(w, 2)                                     // число ПК
	w = append(w, "100000001"...)                        //
	w = append(w, bytes.Repeat([]byte{0x10}, 32)...)     //
	w = append(w, "100000002"...)                        //
	w = append(w, bytes.Repeat([]byte{0x20}, 32)...)     //
	w = append(w, 0, 1)                                  // число исключённых, u16
	w = append(w, bytes.Repeat([]byte{0x30}, 32)...)     //
	if got := m.signBytes(); !bytes.Equal(got, w) {
		t.Fatalf("подписываемые байты:\n%x\nждали:\n%x", got, w)
	}

	const wantOPub = "35b94481ee24b3672e176b6f76716b3a5bb9f0bcd3e411fd860f4e93efe7ff1d"
	if got := hex.EncodeToString(m.OPub); got != wantOPub {
		t.Fatalf("opub %s, ждали %s", got, wantOPub)
	}
	// вывод ключа владельца по описанию (решение 8 B): Argon2id("AnyPC space owner key v2\0" + фраза, osalt) → зерно
	seed := pake.KDF("AnyPC space owner key v2\x00ant bat bear bee bird boar bull cat cow crab", bytes.Repeat([]byte{0x01}, 16))
	if pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey); !bytes.Equal(pub, m.OPub) {
		t.Fatal("opub — не по описанию вывода из фразы")
	}
	b, err := m.marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != len(w)+ed25519.SignatureSize || !bytes.Equal(b[:len(w)], w) {
		t.Fatal("запись — не подписываемые байты плюс подпись")
	}
	const wantSum = "9d1eb439df07d41e9c57d9b00a508bacec0f8b6aca96bdb454ed2f504eee8066"
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != wantSum {
		t.Fatalf("sha256 записи %s, ждали %s", got, wantSum)
	}
	for range 3 { // повтор даёт те же байты
		if b2, _ := m.marshal(); !bytes.Equal(b, b2) {
			t.Fatal("запись не детерминирована")
		}
	}
}

// Запись однозначна: тот же состав в другом порядке или с повтором — не другая запись, а ошибка.
func TestSpaceCanonical(t *testing.T) {
	m := spaceFixture(t)
	for name, edit := range map[string]func(*space){
		"порядок ПК":          func(s *space) { slices.Reverse(s.Members) },
		"повтор ключа ПК":     func(s *space) { s.Members[1].Pub = spacePub(0x10) },
		"повтор ID":           func(s *space) { s.Members[1].ID = "100000001" },
		"порядок исключённых": func(s *space) { s.Gone = [][]byte{spacePub(0x50), spacePub(0x30)} },
		"повтор исключённого": func(s *space) { s.Gone = [][]byte{spacePub(0x30), spacePub(0x30)} },
		"ID не хоста":         func(s *space) { s.Members[0].ID = "c00000001" },
		"нет ПК":              func(s *space) { s.Members = nil },
		"эпоха 0":             func(s *space) { s.Epoch = 0 },
		"osalt = psalt":       func(s *space) { s.PSalt = bytes.Clone(s.OSalt) },
		"TOTP строчными":      func(s *space) { s.TOTP = "jbswy3dpehpk3pxpjbswy3dpehpk3pxp" },
		"TOTP с дополнением":  func(s *space) { s.TOTP = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP======" },
		"TOTP короткий":       func(s *space) { s.TOTP = "JBSWY3DP" },
		"TOTP пустой":         func(s *space) { s.TOTP = "" },
	} {
		s := spaceEdit(t, m, edit)
		if err := s.verify(); !errors.Is(err, errSpaceFormat) {
			t.Errorf("%s: verify — %v, ждали %v", name, err, errSpaceFormat)
		}
		if _, err := spaceParse(append(s.signBytes(), s.Sig...)); !errors.Is(err, errSpaceFormat) {
			t.Errorf("%s: разбор — %v, ждали %v", name, err, errSpaceFormat)
		}
		if _, err := s.marshal(); !errors.Is(err, errSpaceFormat) {
			t.Errorf("%s: запись — %v, ждали %v", name, err, errSpaceFormat)
		}
	}
}

func TestSpaceParseLimits(t *testing.T) {
	m := spaceFixture(t)
	b, _ := m.marshal()
	const (
		offVer  = len(spaceDomain)
		offTOTP = offVer + 1 + 16 + 8 + 16 + 32 + 16 + 32       // байт длины секрета
		offN    = offTOTP + 1 + len(spaceTestTOTP) + 4 + 2 + 32 // байт числа ПК (после lgen, lex, lprev)
		offK    = offN + 1 + 2*(9+32)                           // u16 числа исключённых
	)
	if b[offVer] != 2 || b[offTOTP] != 32 || b[offN] != 2 || b[offK] != 0 || b[offK+1] != 0 || len(b) != offK+2+64 {
		t.Fatal("смещения теста разошлись с форматом")
	}
	with := func(edit func([]byte) []byte) []byte { return edit(bytes.Clone(b)) }
	pad := func(n int) []byte { return make([]byte, n) }

	for name, c := range map[string]struct {
		b    []byte
		want error
	}{
		"пусто":               {nil, errSpaceFormat},
		"только префикс":      {[]byte(spaceDomain), errSpaceFormat},
		"чужой префикс":       {with(func(c []byte) []byte { c[0] = 'a'; return c }), errSpaceFormat},
		"версия 3":            {with(func(c []byte) []byte { c[offVer] = 3; return c }), errSpaceVersion},
		"версия 0":            {with(func(c []byte) []byte { c[offVer] = 0; return c }), errSpaceVersion},
		"обрезана на байт":    {b[:len(b)-1], errSpaceFormat},
		"обрезана в списке":   {b[:offN+5], errSpaceFormat},
		"лишний байт":         {append(bytes.Clone(b), 0), errSpaceFormat},
		"больше потолка":      {pad(spaceMaxBytes + 1), errSpaceLimit},
		"мегабайт":            {append(bytes.Clone(b), pad(1<<20)...), errSpaceLimit},
		"секрет TOTP длиннее": {with(func(c []byte) []byte { c[offTOTP] = spaceMaxTOTP + 1; return c }), errSpaceLimit},
		"секрет TOTP 255":     {with(func(c []byte) []byte { c[offTOTP] = 255; return c }), errSpaceLimit},
		"ПК сверх предела":    {with(func(c []byte) []byte { c[offN] = spaceMaxMembers + 1; return c }), errSpaceLimit},
		"ПК 255":              {with(func(c []byte) []byte { c[offN] = 255; return c }), errSpaceLimit},
		"исключённых сверх предела": {with(func(c []byte) []byte {
			binary.BigEndian.PutUint16(c[offK:], spaceMaxGone+1)
			return c
		}), errSpaceLimit},
		"исключённых 65535":   {with(func(c []byte) []byte { c[offK], c[offK+1] = 0xFF, 0xFF; return c }), errSpaceLimit},
		"ПК больше, чем байт": {with(func(c []byte) []byte { c[offN] = spaceMaxMembers; return c }), errSpaceFormat},
	} {
		if _, err := spaceParse(c.b); !errors.Is(err, c.want) {
			t.Errorf("%s: ошибка %v, ждали %v", name, err, c.want)
		}
	}

	// ровно на пределах — разбирается и проверяется
	max := spaceEdit(t, m, func(s *space) {
		s.Members, s.Gone = nil, nil
		for i := range spaceMaxMembers {
			id := []byte("500000000")
			id[7], id[8] = byte('0'+i/10), byte('0'+i%10)
			s.Members = append(s.Members, spaceMember{ID: string(id), Pub: append([]byte{0x05, byte(i)}, pad(30)...)})
		}
		for i := range spaceMaxGone {
			s.Gone = append(s.Gone, append([]byte{0x02, byte(i)}, pad(30)...))
		}
		s.TOTP = spaceTestTOTP + spaceTestTOTP
	})
	mb, err := max.marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(mb) != spaceMaxBytes {
		t.Fatalf("запись на пределах %d байт, потолок %d", len(mb), spaceMaxBytes)
	}
	p, err := spaceParse(mb)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.verify(); err != nil {
		t.Fatal(err)
	}
	_, err = spaceRemove(p, "", p.Members[0].Pub) // список исключённых полон
	spaceWant(t, err, errSpaceLimit)

	// сверх пределов в памяти (в обход разбора) — тоже отказ
	over := spaceEdit(t, max, func(s *space) { s.Gone = append(s.Gone, append([]byte{0x03}, pad(31)...)) })
	spaceWant(t, over.verify(), errSpaceLimit)
	_, err = spaceJoin(m, over)
	spaceWant(t, err, errSpaceLimit)

	// разобранный состав не держит ссылок на входной буфер
	c := bytes.Clone(b)
	p, err = spaceParse(c)
	if err != nil {
		t.Fatal(err)
	}
	clear(c)
	if err := p.verify(); err != nil {
		t.Fatal("разобранный состав ссылается на входной буфер")
	}
}

// Регрессия приёмки Э1 (Н1): знающий phash (он в составе и в config.json каждого члена) собирал состав с
// osalt' = psalt — зерно ключа владельца без доменного префикса равнялось phash, и новый ПК с настоящим паролем (теперь — фразой)
// вступал в поддельный состав.
func TestSpaceForgeOwnerKeyFromPHash(t *testing.T) {
	const realPw = "owner-real-password"
	psalt := bytes.Repeat([]byte{0xA1}, 16)
	phash := pake.KDF(realPw, psalt)
	real, realPhrase, err := spaceNew(psalt, phash, spaceTestTOTP, "100000001", spacePub(0x10))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(spaceOwnerKey(realPw, psalt).Seed(), phash) {
		t.Fatal("зерно ключа владельца равно хэшу пароля")
	}

	evilKey := ed25519.NewKeyFromSeed(real.PHash)
	evilPSalt := bytes.Repeat([]byte{0xEE}, 16)
	evil := &space{
		SID: bytes.Clone(real.SID), Epoch: real.Epoch + 100, OSalt: bytes.Clone(real.PSalt),
		OPub:  bytes.Clone(evilKey.Public().(ed25519.PublicKey)),
		PSalt: evilPSalt, PHash: pake.KDF("attacker-password", evilPSalt), TOTP: "KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU",
		LGen: 1, LPrev: make([]byte, 32),
		Members: []spaceMember{{"666000001", spacePub(0x66)}},
	}
	if err := evil.seal(evilKey); err != nil {
		t.Fatal(err)
	}
	wire, err := evil.marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := spaceParse(wire) // подпись верна — но своим ключом, это ещё не владелец
	if err != nil {
		t.Fatal(err)
	}
	joined, err := spaceAdd(got, realPhrase, "100000007", spacePub(0x77))
	spaceWant(t, err, errSpacePhrase)
	if joined != nil {
		t.Fatal("новый ПК подписал состав атакующего")
	}
	_, err = spaceJoin(real, got)
	spaceWant(t, err, errSpaceForeign)
}

// Н3: секрет TOTP записан ровно одним способом.
func TestSpaceTOTPCanon(t *testing.T) {
	m := spaceFixture(t)
	for name, s := range map[string]string{
		"перевод строки":   "JBSWY3DPEHPK3PXP\nJBSWY3DPEHPK3PXP",
		"CRLF":             "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\r\n",
		"пробел":           "JBSWY3DPEHPK3PXP JBSWY3DPEHPK3PX",
		"длинная s":        "JBſWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
		"i без точки":      "ıBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
		"хвостовые биты":   "JBSWY3DPEHPK3PXPJBSWY3DPEB",
		"хвостовые биты 3": "JBSWY3DPEHPK3PXPJBSWY3DPED",
		"длина 27":         "JBSWY3DPEHPK3PXPJBSWY3DPEAA",
		"цифра 1":          "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PX1",
		"нулевой байт":     "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PX\x00",
	} {
		n := spaceEdit(t, m, func(x *space) { x.TOTP = s })
		if err := n.verify(); !errors.Is(err, errSpaceFormat) {
			t.Errorf("%s: verify — %v", name, err)
		}
		if _, err := n.marshal(); !errors.Is(err, errSpaceFormat) {
			t.Errorf("%s: запись — %v", name, err)
		}
		if _, err := spaceParse(append(n.signBytes(), n.Sig...)); err == nil {
			t.Errorf("%s: разбор принял", name)
		}
	}
	for _, s := range []string{spaceTestTOTP, "JBSWY3DPEHPK3PXPJBSWY3DPEA", "JBSWY3DPEHPK3PXPJBSWY3DPEE", totp.NewSecret()} { // A, E: два хвостовых бита — нули
		if !spaceTOTPOK(s) {
			t.Errorf("канонический секрет %q отвергнут", s)
		}
	}
}

// Н5: при ошибке правки — nil, а не неподписанный состав.
func TestSpaceErrorReturnsNil(t *testing.T) {
	m := spaceFixture(t)
	n, err := spaceAdd(m, spaceTestWrong, "100000003", spacePub(0x30))
	spaceWant(t, err, errSpacePhrase)
	if n != nil {
		t.Fatal("spaceAdd вернул состав при неверной фразе")
	}
	n, err = spaceRemove(m, spaceTestWrong, spacePub(0x20))
	spaceWant(t, err, errSpacePhrase)
	if n != nil {
		t.Fatal("spaceRemove вернул состав при неверной фразе")
	}
	n, err = spaceSetLogin(spaceJoinT(t, m), spaceTestWrong, "", spaceTestSec2)
	spaceWant(t, err, errSpacePhrase)
	if n != nil {
		t.Fatal("spaceSetLogin вернул состав при неверной фразе")
	}
}

// Н6: правка на эпохе MaxUint64 — отказ (такую эпоху честный код не выпустит; объединение её не теряет).
func TestSpaceEpochMax(t *testing.T) {
	m := spaceFixture(t)
	mx := spaceEdit(t, m, func(x *space) { x.Epoch = math.MaxUint64 })
	v := spaceJoinT(t, m, mx)
	if v.Epoch != math.MaxUint64 {
		t.Fatalf("эпоха объединения: %d", v.Epoch)
	}
	_, err := spaceAdd(mx, "", "100000003", spacePub(0x30))
	spaceWant(t, err, errSpaceLimit)
	_, err = spaceRemove(mx, "", spacePub(0x20))
	spaceWant(t, err, errSpaceLimit)
	_, err = spaceAdd(v, "", "100000003", spacePub(0x30))
	spaceWant(t, err, errSpaceLimit)
}

// Н2 и решение 10 A: две правки владельца от одной эпохи (A добавил ПК, B исключил украденный) — не раскол, а
// объединение: добавленные в A остаются, исключённый в B не возвращается, вход — исключения (его секрет украденный
// не видел). Подписи слияния нет.
func TestSpaceFork(t *testing.T) {
	m1 := spaceFixture(t)
	a, err := spaceAdd(m1, spaceTestPhrase, "100000003", spacePub(0x30))
	if err != nil {
		t.Fatal(err)
	}
	b, err := spaceRemove(m1, spaceTestPhrase, spacePub(0x20)) // 0x20 украден
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := spaceAdd(a, spaceTestPhrase, "100000004", spacePub(0x40)) // на ветви A украденный — член
	b2, _ := spaceAdd(b, spaceTestPhrase, "100000005", spacePub(0x50))
	var first []byte
	for _, order := range [][]*space{{a2, b2}, {b2, a2}, {a, b, a2, b2, m1}, {m1, b2, a, a2, b, b2}} {
		h, err := spaceHeads(order)
		if err != nil {
			t.Fatal(err)
		}
		v := spaceView(h)
		if v.Epoch != 3 || len(v.Gone) != 1 || !v.gone(spacePub(0x20)) || v.member(spacePub(0x20)) || len(v.Members) != 4 ||
			!sameLogin(v, b) || v.Compromised || len(h) != 2 {
			t.Fatalf("объединение: %d верхушек, %v", len(h), v)
		}
		for _, p := range []byte{0x10, 0x30, 0x40, 0x50} {
			if !v.member(spacePub(p)) {
				t.Errorf("в объединении нет ПК %#x", p)
			}
		}
		var bs []byte
		for _, x := range h {
			x, _ := x.marshal()
			bs = append(bs, x...)
		}
		if first == nil {
			first = bs
		} else if !bytes.Equal(first, bs) {
			t.Fatal("верхушки зависят от порядка")
		}
	}

	// каждая ветвь исключила другой ПК — никого не осталось, вход скомпрометирован
	r1, _ := spaceRemove(m1, spaceTestPhrase, spacePub(0x10))
	r2, _ := spaceRemove(m1, spaceTestPhrase, spacePub(0x20))
	if v := spaceJoinT(t, r1, r2); len(v.Members) != 0 || !v.Compromised {
		t.Fatalf("взаимное исключение: %v", v)
	}

	// объединение сверх пределов: виден, но не правится
	grow := func(base byte, n int) *space {
		return spaceEdit(t, m1, func(s *space) {
			s.Epoch = 2
			for i := range n {
				id := []byte("70000000" + string(rune('0'+int(base)%10)))
				id[5], id[6] = byte('0'+i/10), byte('0'+i%10)
				s.Members = append(s.Members, spaceMember{ID: string(id), Pub: append([]byte{base, byte(i)}, make([]byte, 30)...)})
				s.Gone = append(s.Gone, append([]byte{base + 1, byte(i)}, make([]byte, 30)...))
			}
			for i := range 200 - n {
				s.Gone = append(s.Gone, append([]byte{base + 2, byte(i)}, make([]byte, 30)...))
			}
			slices.SortFunc(s.Members, func(x, y spaceMember) int { return bytes.Compare(x.Pub, y.Pub) })
			slices.SortFunc(s.Gone, bytes.Compare)
		})
	}
	big := spaceJoinT(t, grow(0x81, 20), grow(0x91, 20))
	if len(big.Gone) != 400 {
		t.Fatalf("исключённых %d", len(big.Gone))
	}
	_, err = spaceAdd(big, "", "100000009", spacePub(0x09))
	spaceWant(t, err, errSpaceLimit)

	// один ID с разными ключами (ПК назвался чужим ID, С4): одна пара, одинаково при любом порядке
	d, _ := spaceAdd(m1, spaceTestPhrase, "100000003", spacePub(0x31))
	v1, v2 := spaceJoinT(t, a, d), spaceJoinT(t, d, a)
	if len(v1.Members) != 3 || v1.member(spacePub(0x30)) == v1.member(spacePub(0x31)) ||
		v1.member(spacePub(0x30)) != v2.member(spacePub(0x30)) {
		t.Fatalf("спор ID: %v / %v", v1, v2)
	}
	if h, _ := spaceHeads([]*space{a, d}); len(h) != 2 {
		t.Fatal("спорная пара потеряна из верхушек")
	}

	_, err = spaceJoin(a, spaceEdit(t, b, func(s *space) { s.SID[0] ^= 1 }))
	spaceWant(t, err, errSpaceForeign)
	bad := spaceFixture(t)
	bad.Epoch = 7
	_, err = spaceJoin(a, bad)
	spaceWant(t, err, errSpaceSig)
	_, err = spaceJoin(bad, a)
	spaceWant(t, err, errSpaceSig)
}

// spaceGen — случайная история правок владельца на разных ПК: каждая правка — от объединения случайного
// подмножества уже выпущенных M (добавить ПК, исключить члена с новым кодом, новый код); подпись — без Argon2.
func spaceGen(t *testing.T, rnd *rand.Rand, n int) []*space {
	t.Helper()
	all := []*space{spaceFixture(t)}
	pc := 0
	for len(all) < n {
		var base []*space
		for _, m := range all {
			if rnd.IntN(3) == 0 {
				base = append(base, m)
			}
		}
		if len(base) == 0 {
			base = []*space{all[rnd.IntN(len(all))]}
		}
		v, err := spaceJoin(base...)
		if err != nil {
			t.Fatal(err)
		}
		x, err := v.next()
		if err != nil {
			continue // объединение без членов или сверх пределов не правится
		}
		switch op := rnd.IntN(3); {
		case op == 0 || len(x.Members) < 2:
			pc++
			x.Members = append(x.Members, spaceMember{ID: fmt.Sprintf("5%08d", pc), Pub: append([]byte{0x60, byte(pc)}, bytes.Repeat([]byte{7}, 30)...)})
			slices.SortFunc(x.Members, func(a, b spaceMember) int { return bytes.Compare(a.Pub, b.Pub) })
		case op == 1:
			i := rnd.IntN(len(x.Members))
			x.Gone = append(x.Gone, x.Members[i].Pub)
			slices.SortFunc(x.Gone, bytes.Compare)
			x.Members = slices.Delete(x.Members, i, i+1)
			fallthrough
		default:
			if err := x.setLogin(spaceTestPhrase, "", totp.NewSecret()); err != nil {
				t.Fatal(err)
			}
		}
		if err := x.seal(spaceTestKey()); err != nil {
			t.Fatal(err)
		}
		all = append(all, x)
	}
	return all
}

// headsBytes — верхушки множества одной строкой байтов (для сравнения).
func headsBytes(t *testing.T, ms []*space) string {
	t.Helper()
	h, err := spaceHeads(ms)
	if err != nil {
		t.Fatal(err)
	}
	var b []byte
	for _, x := range h {
		r, _ := x.marshal()
		b = append(b, r...)
	}
	return string(b)
}

// Свойства объединения (2P-Set) на случайных историях: коммутативность, ассоциативность, идемпотентность;
// gone = ∪ gone, members = ∪ members − gone; исключённый не возвращается; вход — сильнейший по развилке, одинаково
// при любом порядке доставки.
func TestSpaceJoinProps(t *testing.T) {
	for seed := range uint64(12) {
		rnd := rand.New(rand.NewPCG(seed, 7))
		all := spaceGen(t, rnd, 24)
		pick := func() []*space {
			var l []*space
			for _, m := range all {
				if rnd.IntN(2) == 0 {
					l = append(l, m)
				}
			}
			if len(l) == 0 {
				l = append(l, all[0])
			}
			return l
		}
		heads := func(ms []*space) []*space {
			h, err := spaceHeads(ms)
			if err != nil {
				t.Fatal(err)
			}
			return h
		}
		for range 20 {
			a, b, c := pick(), pick(), pick()
			ab, ba := slices.Concat(a, b), slices.Concat(b, a)
			if headsBytes(t, ab) != headsBytes(t, ba) {
				t.Fatalf("seed %d: не коммутативно", seed)
			}
			if headsBytes(t, slices.Concat(heads(slices.Concat(a, b)), c)) != headsBytes(t, slices.Concat(a, heads(slices.Concat(b, c)))) {
				t.Fatalf("seed %d: не ассоциативно", seed)
			}
			if headsBytes(t, slices.Concat(a, a, heads(a))) != headsBytes(t, a) {
				t.Fatalf("seed %d: не идемпотентно", seed)
			}
			sh := slices.Clone(ab)
			rnd.Shuffle(len(sh), func(i, j int) { sh[i], sh[j] = sh[j], sh[i] })
			if headsBytes(t, sh) != headsBytes(t, ab) {
				t.Fatalf("seed %d: зависит от порядка", seed)
			}
			hs := heads(ab)
			for i, x := range hs { // верхушки — антицепь: ни одна не перекрыта другой
				for j, y := range hs {
					if i != j && spaceUnder(x, y) {
						t.Fatalf("seed %d: верхушка %d перекрыта верхушкой %d", seed, i, j)
					}
				}
			}
			v := spaceView(hs)
			var gone [][]byte
			best := ab[0]
			for _, m := range ab {
				for _, g := range m.Gone {
					if !slices.ContainsFunc(gone, func(x []byte) bool { return bytes.Equal(x, g) }) {
						gone = append(gone, g)
					}
				}
				if spaceLoginCmp(m, best) > 0 {
					best = m
				}
			}
			if len(v.Gone) != len(gone) {
				t.Fatalf("seed %d: gone %d, ждали %d", seed, len(v.Gone), len(gone))
			}
			for _, m := range ab {
				for _, x := range m.Members {
					if v.gone(x.Pub) == v.member(x.Pub) { // не исключён — член; исключён — не член
						t.Fatalf("seed %d: ПК %s: член %v, исключён %v", seed, x.ID, v.member(x.Pub), v.gone(x.Pub))
					}
				}
			}
			for _, x := range v.Members {
				if !slices.ContainsFunc(ab, func(m *space) bool { return m.has(x) }) {
					t.Fatalf("seed %d: ПК %s взялся ниоткуда", seed, x.ID)
				}
			}
			if !sameLogin(v, best) {
				t.Fatalf("seed %d: вход объединения — не сильнейший", seed)
			}
			comp := slices.ContainsFunc(ab, func(m *space) bool {
				return bytes.Equal(m.loginHash(), best.loginHash()) && slices.ContainsFunc(m.Members, func(x spaceMember) bool { return v.gone(x.Pub) })
			})
			if v.Compromised != comp {
				t.Fatalf("seed %d: скомпрометирован %v, ждали %v (по всем M, а не только верхушкам)", seed, v.Compromised, comp)
			}
		}
	}
}

// Взаимно перекрытые M (тот же вход и те же члены, разные эпохи: правка от объединения и правка по одной ветви) —
// одна верхушка, с большей эпохой; объединение то же. Мутант h2 приёмки 2P-Set.
func TestSpaceHeadsMutual(t *testing.T) {
	m1 := spaceFixture(t)
	w, n, x := spacePub(0x30), spacePub(0x40), spacePub(0x50)
	a2, _ := spaceAdd(m1, spaceTestPhrase, "100000003", w)
	a3, _ := spaceAdd(a2, spaceTestPhrase, "100000004", n)
	a4, err := spaceAdd(a3, spaceTestPhrase, "100000005", x) // эпоха 4: +W, +N, +X по одной ветви
	if err != nil {
		t.Fatal(err)
	}
	bw, _ := spaceAdd(m1, spaceTestPhrase, "100000003", w)
	bn, _ := spaceAdd(m1, spaceTestPhrase, "100000004", n)
	d, err := spaceAdd(spaceJoinT(t, bw, bn), spaceTestPhrase, "100000005", x) // эпоха 3: +X от объединения
	if err != nil {
		t.Fatal(err)
	}
	if d.Epoch == a4.Epoch || !spaceUnder(d, a4) || !spaceUnder(a4, d) {
		t.Fatalf("сценарий: эпохи %d/%d, взаимное перекрытие %v/%v", d.Epoch, a4.Epoch, spaceUnder(d, a4), spaceUnder(a4, d))
	}
	for _, l := range [][]*space{{a4, d}, {d, a4}, {d, bw, a4, bn, m1}} {
		h, err := spaceHeads(l)
		if err != nil {
			t.Fatal(err)
		}
		if len(h) != 1 || h[0].Epoch != a4.Epoch {
			t.Fatalf("верхушек %d, ждали одну с эпохой %d", len(h), a4.Epoch)
		}
	}
}

// Н4: ключ владельца малого порядка — подпись (R, 0) сходится на любом сообщении.
func TestSpaceSmallOrder(t *testing.T) {
	ident := make([]byte, 32)
	ident[0] = 1
	if !ed25519.Verify(ident, []byte("любое сообщение"), append(bytes.Clone(ident), make([]byte, 32)...)) {
		t.Fatal("ожидали: стандартная библиотека принимает такую подпись — проверка нужна")
	}
	m := spaceFixture(t)
	m.OPub = ident
	m.Sig = append(bytes.Clone(ident), make([]byte, 32)...)
	m.Epoch = 777
	spaceWant(t, m.verify(), errSpaceFormat)
	_, err := m.marshal()
	spaceWant(t, err, errSpaceFormat)
	_, err = spaceParse(append(m.signBytes(), m.Sig...))
	spaceWant(t, err, errSpaceFormat)

	// y8 и p−y8 — корни d·y⁴ + 2y² − 1 = 0 (у 2P координата y = 0 — порядок 4); остальные — y ∈ {0, 1, p−1}
	// и неканонические p, p+1
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	d := new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), p))
	le := func(b []byte) *big.Int { r := slices.Clone(b); slices.Reverse(r); return new(big.Int).SetBytes(r) }
	want := []*big.Int{big.NewInt(0), big.NewInt(1), nil, nil, new(big.Int).Sub(p, big.NewInt(1)), p, new(big.Int).Add(p, big.NewInt(1))}
	if len(spaceSmallOrder) != len(want) {
		t.Fatal("в списке не 7 записей")
	}
	for i, e := range spaceSmallOrder {
		y := le(e)
		if want[i] != nil {
			if y.Cmp(want[i]) != 0 {
				t.Errorf("запись %d: %x", i, e)
			}
			continue
		}
		y2 := new(big.Int).Mul(y, y)
		v := new(big.Int).Mul(d, new(big.Int).Mul(y2, y2))
		v.Add(v, new(big.Int).Lsh(y2, 1)).Sub(v, big.NewInt(1)).Mod(v, p)
		if v.Sign() != 0 {
			t.Errorf("запись %d — не точка порядка 8", i)
		}
	}
	if new(big.Int).Add(le(spaceSmallOrder[2]), le(spaceSmallOrder[3])).Cmp(p) != 0 {
		t.Error("y8 + (p − y8) ≠ p")
	}
	for _, e := range spaceSmallOrder {
		neg := bytes.Clone(e)
		neg[31] |= 0x80
		if !spaceWeakKey(e) || !spaceWeakKey(neg) {
			t.Errorf("%x не отвергнут", e)
		}
	}
	if spaceWeakKey(spacePub(0x10)) || spaceWeakKey(spaceTestKey().Public().(ed25519.PublicKey)) || !spaceWeakKey(ident[:31]) {
		t.Error("обычный ключ сочтён слабым или короткий — нет")
	}

	_, err = spaceAdd(spaceFixture(t), "", "100000003", ident) // ключ хоста малого порядка
	spaceWant(t, err, errSpaceFormat)
	weak := spaceEdit(t, spaceFixture(t), func(s *space) { s.Members[0].Pub = make([]byte, 32) })
	spaceWant(t, weak.verify(), errSpaceFormat)
}

// Н4: запись и разбор проверяют подпись.
func TestSpaceMarshalParseVerify(t *testing.T) {
	m := spaceFixture(t)
	m.Members = m.Members[:1] // правка без переподписи
	_, err := m.marshal()
	spaceWant(t, err, errSpaceSig)
	m.Sig = nil
	_, err = m.marshal()
	spaceWant(t, err, errSpaceSig)

	m = spaceFixture(t)
	b, _ := m.marshal()
	b[len(b)-1] ^= 1
	_, err = spaceParse(b)
	spaceWant(t, err, errSpaceSig)
}

// Н7: печать состава не выдаёт секрет TOTP и хэш пароля.
func TestSpaceFormat(t *testing.T) {
	m := spaceFixture(t)
	for _, f := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q"} {
		for _, v := range []any{m, *m, []*space{m}} {
			s := fmt.Sprintf(f, v)
			if strings.Contains(s, m.TOTP) || strings.Contains(s, hex.EncodeToString(m.PHash)) ||
				strings.Contains(s, string(m.PHash)) || strings.Contains(s, "4 4 4 4") {
				t.Errorf("%s %T: секрет в выводе: %s", f, v, s)
			}
			if !strings.Contains(s, "epoch=1") {
				t.Errorf("%s %T: нет эпохи: %s", f, v, s)
			}
		}
	}
	var nilSpace *space
	_ = fmt.Sprintf("%v", nilSpace) // без паники
	spaceWant(t, nilSpace.verify(), errSpaceFormat)
}

// Ветви, не покрытые остальными тестами: длины полей, правка непроверенного состава, подпись без соли.
func TestSpaceGuards(t *testing.T) {
	m := spaceFixture(t)
	for name, edit := range map[string]func(*space){
		"sid":   func(s *space) { s.SID = s.SID[:15] },
		"osalt": func(s *space) { s.OSalt = s.OSalt[:15] },
		"psalt": func(s *space) { s.PSalt = append(s.PSalt, 0) },
		"opub":  func(s *space) { s.OPub = s.OPub[:31] },
		"phash": func(s *space) { s.PHash = s.PHash[:31] },
	} {
		s := spaceEdit(t, m, edit)
		if err := s.verify(); !errors.Is(err, errSpaceFormat) {
			t.Errorf("%s: verify — %v", name, err)
		}
		if _, err := s.marshal(); !errors.Is(err, errSpaceFormat) {
			t.Errorf("%s: запись — %v", name, err)
		}
	}

	forged := spaceFixture(t)
	forged.Epoch = 9
	_, err := spaceRemove(forged, spaceTestPhrase, spacePub(0x20))
	spaceWant(t, err, errSpaceSig)
	_, err = spaceAdd(nil, spaceTestPhrase, "100000003", spacePub(0x30))
	spaceWant(t, err, errSpaceFormat)
	_, err = spaceRemove(nil, spaceTestPhrase, spacePub(0x20))
	spaceWant(t, err, errSpaceFormat)

	s := spaceFixture(t)
	s.OSalt = s.OSalt[:8]
	spaceWant(t, s.sign(spaceTestPhrase), errSpaceFormat)

	// член, пропавший без исключения, — не тихая потеря: объединение его держит
	lost := spaceEdit(t, m, func(s *space) { s.Epoch, s.Members = 2, s.Members[:1] })
	if v := spaceJoinT(t, m, lost); len(v.Members) != 2 {
		t.Fatalf("пропавший член: %v", v)
	}
}
