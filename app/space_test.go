package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"slices"
	"sync"
	"testing"

	"anypc/pake"
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
	spaceWant(t, spaceAccept(cur, next(func(s *space) { s.Epoch = 5 })), errSpaceStale) // равная эпоха
	spaceWant(t, spaceAccept(cur, cur), errSpaceStale)
	spaceWant(t, spaceAccept(cur, next(func(s *space) { s.Epoch = 5; s.TOTP = "KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU" })), errSpaceStale)

	spaceWant(t, spaceAccept(cur, next(func(s *space) { s.Gone = s.Gone[:1] })), errSpaceGoneShrunk)
	spaceWant(t, spaceAccept(cur, next(func(s *space) { s.Gone = nil })), errSpaceGoneShrunk)
	spaceWant(t, spaceAccept(cur, next(func(s *space) { s.Gone = [][]byte{spacePub(0x30), spacePub(0x51)} })), errSpaceGoneShrunk)

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

	const wantOPub = "34608260b8e15201e4aac24578433f2beddf85e8615cf3ad22791c41415c4c87"
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
	const wantSum = "3510f405939ddfbd286c126c5e7d1f0ffddaf6a237be0a3e1d90d5f59d3fade1"
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
			s.Members = append(s.Members, spaceMember{ID: string(id), Pub: append([]byte{0x01, byte(i)}, pad(30)...)})
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
