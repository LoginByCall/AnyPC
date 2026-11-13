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
	"slices"
	"strings"
	"sync"
	"testing"

	"anypc/pake"
	"anypc/totp"
)

const (
	spaceTestPw   = "space-test-password"
	spaceTestTOTP = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
)

var (
	spaceTestOSalt = bytes.Repeat([]byte{0x01}, 16)
	spaceTestPSalt = bytes.Repeat([]byte{0x02}, 16)
	spaceTestSID   = bytes.Repeat([]byte{0x03}, 16)
	// Argon2id — 64 МБ на вызов: ключ владельца для всех тестов считается один раз.
	spaceTestKey = sync.OnceValue(func() ed25519.PrivateKey { return spaceOwnerKey(spaceTestPw, spaceTestOSalt) })
)

func spacePub(n byte) ed25519.PublicKey { return bytes.Repeat([]byte{n}, ed25519.PublicKeySize) }

// spaceFixture — подписанный состав эпохи 1 с двумя ПК (ключи 0x10 и 0x20), постоянный до байта.
func spaceFixture(t *testing.T) *space {
	t.Helper()
	m := &space{
		SID: bytes.Clone(spaceTestSID), Epoch: 1, OSalt: bytes.Clone(spaceTestOSalt),
		OPub:  bytes.Clone(spaceTestKey().Public().(ed25519.PublicKey)),
		PSalt: bytes.Clone(spaceTestPSalt), PHash: bytes.Repeat([]byte{0x04}, 32), TOTP: spaceTestTOTP,
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
	phash := pake.KDF(spaceTestPw, spaceTestPSalt)
	m, err := spaceNew(spaceTestPw, spaceTestPSalt, phash, spaceTestTOTP, "100000001", spacePub(0x10))
	if err != nil {
		t.Fatal(err)
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
	key := spaceOwnerKey(spaceTestPw, m.OSalt)
	if !bytes.Equal(key.Public().(ed25519.PublicKey), m.OPub) {
		t.Fatal("opub не от пароля владельца")
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

	// другое пространство того же пароля — другие sid, соль и ключ владельца
	m2, err := spaceNew(spaceTestPw, spaceTestPSalt, phash, spaceTestTOTP, "100000001", spacePub(0x10))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(m.SID, m2.SID) || bytes.Equal(m.OPub, m2.OPub) {
		t.Fatal("два пространства совпали")
	}

	_, err = spaceNew("not-the-password", spaceTestPSalt, phash, spaceTestTOTP, "100000001", spacePub(0x10))
	spaceWant(t, err, errSpacePassword)
	_, err = spaceNew(spaceTestPw, spaceTestPSalt[:8], phash, spaceTestTOTP, "100000001", spacePub(0x10))
	spaceWant(t, err, errSpaceFormat)
	_, err = spaceNew(spaceTestPw, spaceTestPSalt, phash, spaceTestTOTP, "12345", spacePub(0x10))
	spaceWant(t, err, errSpaceFormat)
	_, err = spaceNew(spaceTestPw, spaceTestPSalt, phash, "", "100000001", spacePub(0x10))
	spaceWant(t, err, errSpaceFormat)
}

func TestSpaceWrongPassword(t *testing.T) {
	m := spaceFixture(t)
	before, _ := m.marshal()
	_, err := spaceAdd(m, "not-the-password", "100000003", spacePub(0x30))
	spaceWant(t, err, errSpacePassword)
	_, err = spaceRemove(m, "not-the-password", spacePub(0x20))
	spaceWant(t, err, errSpacePassword)
	spaceWant(t, m.sign("not-the-password"), errSpacePassword)
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

	m2, err := spaceAdd(m1, spaceTestPw, "100000003", spacePub(0x05)) // меньший ключ встаёт первым
	if err != nil {
		t.Fatal(err)
	}
	if m2.Epoch != 2 || len(m2.Members) != 3 || m2.Members[0].ID != "100000003" || m2.TOTP != m1.TOTP {
		t.Fatalf("после добавления: %+v", m2)
	}
	if err := spaceAccept(m1, m2); err != nil {
		t.Fatal(err)
	}

	m3, err := spaceRemove(m2, spaceTestPw, spacePub(0x20))
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
	if err := spaceAccept(m2, m3); err != nil {
		t.Fatal(err)
	}
	if err := spaceAccept(m1, m3); err != nil { // пропущенная эпоха — не помеха
		t.Fatal(err)
	}
	spaceWant(t, spaceAccept(m3, m2), errSpaceStale) // украденный ПК возвращает старый список
	spaceWant(t, spaceAccept(m3, m1), errSpaceStale)

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
	_, err = spaceAdd(forged, spaceTestPw, "100000003", spacePub(0x30))
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
		if err := spaceAccept(m, s); err == nil {
			t.Errorf("%s: подделка принята", name)
		}
	}
	other, _, _ := ed25519.GenerateKey(nil)
	s := spaceFixture(t)
	s.OPub = other
	spaceWant(t, s.verify(), errSpaceSig)
}

func TestSpaceAccept(t *testing.T) {
	cur := spaceEdit(t, spaceFixture(t), func(s *space) { s.Epoch, s.Gone = 5, [][]byte{spacePub(0x30), spacePub(0x50)} })
	if err := cur.verify(); err != nil {
		t.Fatal(err)
	}
	next := func(edit func(*space)) *space {
		return spaceEdit(t, cur, func(s *space) { s.Epoch = 6; edit(s) })
	}

	if err := spaceAccept(cur, next(func(*space) {})); err != nil {
		t.Fatal(err)
	}
	if err := spaceAccept(cur, next(func(s *space) { s.Gone = append(s.Gone, spacePub(0x60)) })); err != nil {
		t.Fatal(err)
	}

	spaceWant(t, spaceAccept(cur, next(func(s *space) { s.Epoch = 4 })), errSpaceStale) // откат
	spaceWant(t, spaceAccept(cur, next(func(s *space) { s.Epoch = 5 })), errSpaceSame)  // равная эпоха, те же байты
	spaceWant(t, spaceAccept(cur, cur), errSpaceSame)
	spaceWant(t, spaceAccept(cur, next(func(s *space) { s.Epoch = 5; s.TOTP = "KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU" })), errSpaceFork)

	spaceWant(t, spaceAccept(cur, next(func(s *space) { s.Gone = s.Gone[:1] })), errSpaceFork)
	spaceWant(t, spaceAccept(cur, next(func(s *space) { s.Gone = nil })), errSpaceFork)
	spaceWant(t, spaceAccept(cur, next(func(s *space) { s.Gone = [][]byte{spacePub(0x30), spacePub(0x51)} })), errSpaceFork)

	spaceWant(t, spaceAccept(cur, next(func(s *space) { s.SID[0] ^= 1 })), errSpaceForeign)
	spaceWant(t, spaceAccept(cur, next(func(s *space) { s.OSalt[0] ^= 1 })), errSpaceForeign)

	// чужой владелец: состав с тем же sid, честно подписанный другим ключом
	_, otherKey, _ := ed25519.GenerateKey(nil)
	foreign := next(func(*space) {})
	foreign.OPub = otherKey.Public().(ed25519.PublicKey)
	foreign.Sig = ed25519.Sign(otherKey, foreign.signBytes())
	if err := foreign.verify(); err != nil {
		t.Fatal(err)
	}
	spaceWant(t, spaceAccept(cur, foreign), errSpaceForeign)

	// исключённый ПК числится членом — даже с подписью владельца
	spaceWant(t, spaceAccept(cur, next(func(s *space) { s.Gone = [][]byte{spacePub(0x20), spacePub(0x30), spacePub(0x50)} })), errSpaceGoneMember)
	bad := next(func(s *space) { s.Gone = [][]byte{spacePub(0x10), spacePub(0x30), spacePub(0x50)} })
	spaceWant(t, spaceAccept(cur, bad), errSpaceGoneMember)
	spaceWant(t, bad.verify(), errSpaceGoneMember)
	_, err := spaceParse(append(bad.signBytes(), bad.Sig...))
	spaceWant(t, err, errSpaceGoneMember)

	unsigned := next(func(*space) {})
	unsigned.Sig = nil
	spaceWant(t, spaceAccept(cur, unsigned), errSpaceSig)
	spaceWant(t, spaceAccept(cur, nil), errSpaceFormat)
	spaceWant(t, spaceAccept(nil, cur), errSpaceFormat)
}

// Постоянный вектор: байты записи собраны здесь вручную по описанию формата, а хэш записи с подписью закреплён —
// он же закрепляет параметры Argon2id и вывод ключа владельца. Изменился — формат или ключи сломаны для уже
// работающих пространств.
func TestSpaceVector(t *testing.T) {
	m := spaceEdit(t, spaceFixture(t), func(s *space) { s.Epoch, s.Gone = 0x0102030405060708, [][]byte{spacePub(0x30)} })

	var w []byte
	w = append(w, "AnyPC space M\x00"...)
	w = append(w, 1)                                     // версия
	w = append(w, bytes.Repeat([]byte{0x03}, 16)...)     // sid
	w = append(w, 1, 2, 3, 4, 5, 6, 7, 8)                // эпоха, big-endian
	w = append(w, bytes.Repeat([]byte{0x01}, 16)...)     // osalt
	w = append(w, m.OPub...)                             // opub
	w = append(w, bytes.Repeat([]byte{0x02}, 16)...)     // psalt
	w = append(w, bytes.Repeat([]byte{0x04}, 32)...)     // phash
	w = append(w, 32)                                    // длина секрета TOTP
	w = append(w, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"...) //
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

	const wantOPub = "1a3e44d5d0a4e47282106bf99605790f7bcd12ff42dcdfca0562222eb64db3fe"
	if got := hex.EncodeToString(m.OPub); got != wantOPub {
		t.Fatalf("opub %s, ждали %s", got, wantOPub)
	}
	b, err := m.marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != len(w)+ed25519.SignatureSize || !bytes.Equal(b[:len(w)], w) {
		t.Fatal("запись — не подписываемые байты плюс подпись")
	}
	const wantSum = "164afe31eeb3a1ae2e7e20c89ca36ef30d07cea28a4b490756c58f57478d645b"
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
		offTOTP = offVer + 1 + 16 + 8 + 16 + 32 + 16 + 32 // байт длины секрета
		offN    = offTOTP + 1 + len(spaceTestTOTP)        // байт числа ПК
		offK    = offN + 1 + 2*(9+32)                     // u16 числа исключённых
	)
	if b[offVer] != 1 || b[offTOTP] != 32 || b[offN] != 2 || b[offK] != 0 || b[offK+1] != 0 || len(b) != offK+2+64 {
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
		"версия 2":            {with(func(c []byte) []byte { c[offVer] = 2; return c }), errSpaceVersion},
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
	spaceWant(t, spaceAccept(m, over), errSpaceLimit)

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
// osalt' = psalt — зерно ключа владельца без доменного префикса равнялось phash, и новый ПК с настоящим паролем
// вступал в поддельный состав.
func TestSpaceForgeOwnerKeyFromPHash(t *testing.T) {
	const realPw = "owner-real-password"
	psalt := bytes.Repeat([]byte{0xA1}, 16)
	phash := pake.KDF(realPw, psalt)
	real, err := spaceNew(realPw, psalt, phash, spaceTestTOTP, "100000001", spacePub(0x10))
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
	joined, err := spaceAdd(got, realPw, "100000007", spacePub(0x77))
	spaceWant(t, err, errSpacePassword)
	if joined != nil {
		t.Fatal("новый ПК подписал состав атакующего")
	}
	spaceWant(t, spaceAccept(real, got), errSpaceForeign)
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
	n, err := spaceAdd(m, "wrong", "100000003", spacePub(0x30))
	spaceWant(t, err, errSpacePassword)
	if n != nil {
		t.Fatal("spaceAdd вернул состав при неверном пароле")
	}
	n, err = spaceRemove(m, "wrong", spacePub(0x20))
	spaceWant(t, err, errSpacePassword)
	if n != nil {
		t.Fatal("spaceRemove вернул состав при неверном пароле")
	}
	b := spaceEdit(t, m, func(s *space) { s.Epoch = 2 })
	n, err = spaceMerge(m, b, "wrong")
	spaceWant(t, err, errSpacePassword)
	if n != nil {
		t.Fatal("spaceMerge вернул состав при неверном пароле")
	}
}

// Н6: эпоха MaxUint64 не замораживает пространство — такой скачок не принимается, а правка на ней — отказ.
func TestSpaceEpochMax(t *testing.T) {
	m := spaceFixture(t)
	mx := spaceEdit(t, m, func(x *space) { x.Epoch = math.MaxUint64 })
	spaceWant(t, spaceAccept(m, mx), errSpaceJump)
	_, err := spaceAdd(mx, "", "100000003", spacePub(0x30))
	spaceWant(t, err, errSpaceLimit)
	_, err = spaceRemove(mx, "", spacePub(0x20))
	spaceWant(t, err, errSpaceLimit)
	_, err = spaceMerge(mx, m, "")
	spaceWant(t, err, errSpaceLimit)

	ok := spaceEdit(t, m, func(x *space) { x.Epoch = 1 + spaceMaxJump })
	if err := spaceAccept(m, ok); err != nil {
		t.Fatal(err)
	}
	far := spaceEdit(t, m, func(x *space) { x.Epoch = 2 + spaceMaxJump })
	spaceWant(t, spaceAccept(m, far), errSpaceJump)
}

// Н2: две правки владельца от одной эпохи (A добавил ПК, B исключил украденный) — раскол виден, а не тих.
func TestSpaceFork(t *testing.T) {
	m1 := spaceFixture(t)
	a, err := spaceAdd(m1, spaceTestPw, "100000003", spacePub(0x30))
	if err != nil {
		t.Fatal(err)
	}
	b, err := spaceRemove(m1, spaceTestPw, spacePub(0x20)) // 0x20 украден
	if err != nil {
		t.Fatal(err)
	}
	spaceWant(t, spaceAccept(a, b), errSpaceFork)
	spaceWant(t, spaceAccept(b, a), errSpaceFork)
	a2, err := spaceAdd(a, spaceTestPw, "100000004", spacePub(0x40))
	if err != nil {
		t.Fatal(err)
	}
	spaceWant(t, spaceAccept(b, a2), errSpaceFork) // на ветви A украденный — снова член
	b2, err := spaceAdd(b, spaceTestPw, "100000005", spacePub(0x50))
	if err != nil {
		t.Fatal(err)
	}
	spaceWant(t, spaceAccept(a, b2), errSpaceFork) // на ветви B пропал добавленный в A
	spaceWant(t, spaceAccept(a2, b2), errSpaceFork)

	m, err := spaceMerge(a2, b2, spaceTestPw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Epoch != 4 || len(m.Gone) != 1 || !m.gone(spacePub(0x20)) || m.member(spacePub(0x20)) || len(m.Members) != 4 {
		t.Fatalf("слияние: %v", m)
	}
	for _, p := range []byte{0x10, 0x30, 0x40, 0x50} {
		if !m.member(spacePub(p)) {
			t.Errorf("после слияния нет ПК %#x", p)
		}
	}
	if m.TOTP == a2.TOTP || m.TOTP == b2.TOTP { // ветвь A не знала об исключении — её секрет знает украденный
		t.Fatal("слияние с новым исключённым не сменило секрет TOTP")
	}
	for name, cur := range map[string]*space{"m1": m1, "a": a, "b": b, "a2": a2, "b2": b2} {
		if err := spaceAccept(cur, m); err != nil {
			t.Errorf("ветвь %s не принимает слияние: %v", name, err)
		}
	}
	m2, err := spaceMerge(b2, a2, spaceTestPw) // порядок входов: тот же состав, кроме нового секрета
	if err != nil {
		t.Fatal(err)
	}
	if m2.Epoch != m.Epoch || len(m2.Members) != len(m.Members) || len(m2.Gone) != len(m.Gone) {
		t.Fatalf("слияние зависит от порядка входов: %v / %v", m, m2)
	}
	spaceWant(t, spaceAccept(m, m2), errSpaceFork) // два слияния одной эпохи с разными секретами — снова раскол

	// без новых исключений секрет прежний
	c, err := spaceAdd(m1, spaceTestPw, "100000006", spacePub(0x60))
	if err != nil {
		t.Fatal(err)
	}
	mc, err := spaceMerge(a, c, spaceTestPw)
	if err != nil {
		t.Fatal(err)
	}
	if mc.TOTP != m1.TOTP || len(mc.Members) != 4 || mc.Epoch != 3 {
		t.Fatalf("слияние двух добавлений: %v", mc)
	}

	// каждая ветвь исключила другой ПК — никого не осталось
	r1, _ := spaceRemove(m1, spaceTestPw, spacePub(0x10))
	r2, _ := spaceRemove(m1, spaceTestPw, spacePub(0x20))
	_, err = spaceMerge(r1, r2, "")
	spaceWant(t, err, errSpaceLast)

	// объединение сверх пределов
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
	_, err = spaceMerge(grow(0x81, 20), grow(0x91, 20), "")
	spaceWant(t, err, errSpaceLimit) // 400 исключённых
	_, err = spaceMerge(grow(0x81, 20), spaceEdit(t, grow(0x91, 20), func(s *space) { s.Gone = nil }), "")
	spaceWant(t, err, errSpaceLimit) // 42 члена

	// один ID с разными ключами
	d, _ := spaceAdd(m1, spaceTestPw, "100000003", spacePub(0x31))
	_, err = spaceMerge(a, d, "")
	spaceWant(t, err, errSpaceDup)

	_, err = spaceMerge(a, spaceEdit(t, b, func(s *space) { s.PHash[0] ^= 1 }), "")
	spaceWant(t, err, errSpaceFork)
	_, err = spaceMerge(a, spaceEdit(t, b, func(s *space) { s.SID[0] ^= 1 }), "")
	spaceWant(t, err, errSpaceForeign)
	_, err = spaceMerge(a, nil, "")
	spaceWant(t, err, errSpaceFormat)
	bad := spaceFixture(t)
	bad.Epoch = 7
	_, err = spaceMerge(a, bad, "")
	spaceWant(t, err, errSpaceSig)
	_, err = spaceMerge(bad, a, "")
	spaceWant(t, err, errSpaceSig)
	spaceWant(t, spaceAccept(bad, a), errSpaceSig) // текущий тоже проверяется
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
	_, err := spaceRemove(forged, spaceTestPw, spacePub(0x20))
	spaceWant(t, err, errSpaceSig)
	_, err = spaceAdd(nil, spaceTestPw, "100000003", spacePub(0x30))
	spaceWant(t, err, errSpaceFormat)
	_, err = spaceRemove(nil, spaceTestPw, spacePub(0x20))
	spaceWant(t, err, errSpaceFormat)

	s := spaceFixture(t)
	s.OSalt = s.OSalt[:8]
	spaceWant(t, s.sign(spaceTestPw), errSpaceFormat)

	// член, пропавший без исключения, при большей эпохе — раскол, а не тихая потеря
	lost := spaceEdit(t, m, func(s *space) { s.Epoch, s.Members = 2, s.Members[:1] })
	spaceWant(t, spaceAccept(m, lost), errSpaceFork)
}
