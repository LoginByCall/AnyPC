package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"
	"testing"

	"anypc/agent"
	"anypc/pake"
	"anypc/totp"
)

const spaceTestSec2 = "KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU"

// spaceJoinT — объединение подлинных составов (2P-Set) или провал теста.
func spaceJoinT(t *testing.T, ms ...*space) *space {
	t.Helper()
	v, err := spaceJoin(ms...)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// sameLogin — у объединения v вход состава m.
func sameLogin(v, m *space) bool {
	return bytes.Equal(v.loginHash(), m.loginHash()) && v.LGen == m.LGen
}

// Решение 8 B: пароль входа и секрет TOTP меняются правкой под тем же ключом владельца; члены принимают её по
// закреплённому opub без фразы у них. Без фразы (паролем входа, его хэшем) состав не подписать.
func TestSpaceSetLogin(t *testing.T) {
	m := spaceFixture(t)
	n, err := spaceSetLogin(m, spaceTestPhrase, "new-login-pass", "")
	if err != nil {
		t.Fatal(err)
	}
	if n.Epoch != m.Epoch+1 || bytes.Equal(n.PSalt, m.PSalt) || bytes.Equal(n.PSalt, n.OSalt) ||
		!bytes.Equal(n.PHash, pake.KDF("new-login-pass", n.PSalt)) || n.TOTP != m.TOTP || !bytes.Equal(n.OPub, m.OPub) ||
		n.LGen != 2 || n.LEx != 0 || !bytes.Equal(n.LPrev, m.loginHash()) ||
		!slices.EqualFunc(n.Members, m.Members, func(a, b spaceMember) bool { return a.ID == b.ID }) {
		t.Fatalf("смена пароля входа: %v", n)
	}
	if v := spaceJoinT(t, m, n); !sameLogin(v, n) { // член знает только свой M — фразы у него нет
		t.Fatalf("объединение — не новый вход: %v", v)
	}
	n2, err := spaceSetLogin(n, "  ANT bat\tbear bee bird boar bull cat cow CRAB ", "", spaceTestSec2) // только TOTP; норма
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(n2.PHash, n.PHash) || n2.TOTP != spaceTestSec2 || n2.LGen != 3 || !sameLogin(spaceJoinT(t, n, n2), n2) {
		t.Fatalf("смена TOTP: %v", n2)
	}
	// две смены входа за раз: отставшему цепочка не нужна — побеждает сильнейший вход
	if v := spaceJoinT(t, m, n2); !sameLogin(v, n2) || v.Compromised {
		t.Fatalf("две ступени входа: %v", v)
	}

	_, err = spaceSetLogin(m, spaceTestWrong, "new-login-pass", "") // чужая фраза
	spaceWant(t, err, errSpacePhrase)
	_, err = spaceSetLogin(m, "new-login-pass", "x-login-pass", "") // пароль входа вместо фразы — до Argon2
	spaceWant(t, err, errSpacePhraseWord)
	_, err = spaceSetLogin(m, spaceTestPhrase, "", "")
	spaceWant(t, err, errSpaceNoChange)
	_, err = spaceSetLogin(m, spaceTestPhrase, "", m.TOTP)
	spaceWant(t, err, errSpaceNoChange)
	_, err = spaceSetLogin(m, spaceTestPhrase, "", "bad totp")
	spaceWant(t, err, errSpaceFormat)

	// Знающий пароль входа и phash (они в M и config.json каждого члена) подписывает чем угодно, кроме ключа из фразы:
	// объединение не принимает ни подпись ключом из пароля, ни ключом из хэша, ни состав с подменённым opub.
	for name, key := range map[string]ed25519.PrivateKey{
		"ключ из пароля входа":       spaceOwnerKey("new-login-pass", n.OSalt),
		"ключ из phash":              ed25519.NewKeyFromSeed(n.PHash),
		"ключ из пароля, соль psalt": spaceOwnerKey("new-login-pass", n.PSalt),
	} {
		f, _ := n.next()
		f.Members = append(f.Members, spaceMember{"100000009", spacePub(0x99)})
		f.Sig = ed25519.Sign(key, f.signBytes())
		if _, err := spaceJoin(n, f); !errors.Is(err, errSpaceSig) {
			t.Errorf("%s: %v", name, err)
		}
		f.OPub = bytes.Clone(key.Public().(ed25519.PublicKey))
		f.Sig = ed25519.Sign(key, f.signBytes())
		if _, err := spaceJoin(n, f); !errors.Is(err, errSpaceForeign) {
			t.Errorf("%s: подмена opub — %v", name, err)
		}
	}
}

// С1 приёмки Э1b: пароль входа, равный фразе с точностью до регистра и пробелов, — отказ во всех правках с новым
// паролем (иначе знающий пароль входа подписывал бы состав: ключ выводится из нормализованной фразы).
func TestSpacePhraseLoginVariants(t *testing.T) {
	m := spaceFixture(t)
	for _, pw := range []string{spaceTestPhrase, "Ant Bat Bear Bee Bird Boar Bull Cat Cow Crab", " ant  bat bear bee bird boar bull cat cow crab\t"} {
		spaceWant(t, spacePhraseLoginOK(spaceTestPhrase, pw), errSpacePhraseLogin)
		_, err := spaceSetLogin(m, spaceTestPhrase, pw, "")
		spaceWant(t, err, errSpacePhraseLogin)
		_, err = spaceRemoveLogin(m, spaceTestPhrase, spacePub(0x20), pw)
		spaceWant(t, err, errSpacePhraseLogin)
	}
	for _, pw := range []string{spaceTestWrong, "antbat bear bee bird boar bull cat cow crab", "ant bat bear bee bird boar bull cat cow"} {
		if err := spacePhraseLoginOK(spaceTestPhrase, pw); err != nil {
			t.Errorf("%q: %v", pw, err)
		}
	}
}

// Исключение и смена пароля входа — одна правка, одна эпоха; секрет TOTP новый, вход +1, lex — число исключённых.
func TestSpaceRemoveLogin(t *testing.T) {
	m := spaceFixture(t)
	n, err := spaceRemoveLogin(m, spaceTestPhrase, spacePub(0x20), "after-theft-pass")
	if err != nil {
		t.Fatal(err)
	}
	if n.Epoch != 2 || n.member(spacePub(0x20)) || !n.gone(spacePub(0x20)) || n.TOTP == m.TOTP || n.LGen != 2 || n.LEx != 1 ||
		!bytes.Equal(n.PHash, pake.KDF("after-theft-pass", n.PSalt)) || !sameLogin(spaceJoinT(t, m, n), n) {
		t.Fatalf("исключение со сменой пароля: %v", n)
	}
	r, err := spaceRemove(m, spaceTestPhrase, spacePub(0x20)) // без смены пароля
	if err != nil || !bytes.Equal(r.PHash, m.PHash) || r.TOTP == m.TOTP || r.LGen != 2 || r.LEx != 1 {
		t.Fatalf("исключение: %v %v", r, err)
	}
	_, err = spaceRemoveLogin(m, spaceTestWrong, spacePub(0x20), "after-theft-pass")
	spaceWant(t, err, errSpacePhrase)
}

// Вход — регистр: смена входа в ветви A не теряется, когда ветвь B ушла дальше по эпохам (С2 приёмки Э1b), и
// состав B не теряется (2P-Set). Ни раскола, ни слияния фразой.
func TestSpaceLoginRegister(t *testing.T) {
	m1 := spaceFixture(t)
	b, _ := spaceAdd(m1, spaceTestPhrase, "100000003", spacePub(0x30))
	b2, err := spaceAdd(b, spaceTestPhrase, "100000004", spacePub(0x40))
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string][2]string{"пароль": {"new-after-leak", ""}, "TOTP": {"", spaceTestSec2}} {
		t.Run(name, func(t *testing.T) {
			a, err := spaceSetLogin(m1, spaceTestPhrase, edit[0], edit[1]) // эпоха 2
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range []*space{spaceJoinT(t, a, b2), spaceJoinT(t, b2, a), spaceJoinT(t, b, a, b2, m1)} {
				if !sameLogin(v, a) || !v.member(spacePub(0x30)) || !v.member(spacePub(0x40)) || v.Epoch != 3 || v.Compromised {
					t.Fatalf("объединение: %v", v)
				}
			}
			a2, _ := spaceSetLogin(a, spaceTestPhrase, "second-change", "") // эпоха 3, вход 3
			if v := spaceJoinT(t, b, a2); !sameLogin(v, a2) || !v.member(spacePub(0x30)) {
				t.Fatalf("вход 3: %v", v)
			}
			// правка фразой от объединения перекрывает обе ветви
			n, err := spaceAdd(spaceJoinT(t, a, b2), spaceTestPhrase, "100000005", spacePub(0x50))
			if err != nil {
				t.Fatal(err)
			}
			if h, _ := spaceHeads([]*space{a, b2, n}); len(h) != 1 || h[0] != n || n.Epoch != 4 || !sameLogin(n, a) {
				t.Fatalf("правка от объединения: %d верхушек, %v", len(h), n)
			}
		})
	}
}

// Развилка входа (TKA): больше исключений → больший lgen → меньший хэш; одинаково при любом порядке. Вход, чей
// секрет видел исключённый ПК, — скомпрометирован, пока правка фразой не задаст новый код.
func TestSpaceLoginFork(t *testing.T) {
	m1 := spaceFixture(t)
	m2, _ := spaceAdd(m1, spaceTestPhrase, "100000003", spacePub(0x30))
	a, err := spaceSetLogin(m2, spaceTestPhrase, "branch-a-pass", "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := spaceSetLogin(m2, spaceTestPhrase, "", spaceTestSec2)
	if err != nil {
		t.Fatal(err)
	}
	win := a // равные lex и lgen — меньший хэш входа
	if bytes.Compare(b.loginHash(), a.loginHash()) < 0 {
		win = b
	}
	if v1, v2 := spaceJoinT(t, a, b), spaceJoinT(t, b, a); !sameLogin(v1, win) || !sameLogin(v2, win) || v1.Compromised {
		t.Fatalf("равные входы: %v %v", v1, v2)
	}
	// больший lgen без исключений проигрывает исключению
	d, _ := spaceSetLogin(a, spaceTestPhrase, "third-pass", "") // lgen 3, lex 0
	x, err := spaceRemove(m2, spaceTestPhrase, spacePub(0x30))  // lgen 2, lex 1
	if err != nil {
		t.Fatal(err)
	}
	v := spaceJoinT(t, d, x)
	if !sameLogin(v, x) || v.member(spacePub(0x30)) || !v.gone(spacePub(0x30)) {
		t.Fatalf("исключение должно победить: %v", v)
	}
	// вход d видел 0x30 (член d), но победил вход x — его 0x30 не видел: не скомпрометирован
	if v.Compromised {
		t.Fatal("вход исключения скомпрометирован без причины")
	}
	// два исключения в разных ветвях: каждый новый секрет видел ПК, исключённый в другой ветви
	y, _ := spaceRemove(m2, spaceTestPhrase, spacePub(0x20))
	v = spaceJoinT(t, x, y)
	if !v.Compromised || v.member(spacePub(0x20)) || v.member(spacePub(0x30)) || len(v.Members) != 1 {
		t.Fatalf("встречные исключения: %v", v)
	}
	if v2 := spaceJoinT(t, y, x, m1, d); !v2.Compromised || !bytes.Equal(v2.loginHash(), v.loginHash()) {
		t.Fatalf("порядок: %v / %v", v2, v)
	}
	// новый код фразой от объединения — вход чист и перекрывает обе ветви
	n, err := spaceSetLogin(v, spaceTestPhrase, "", totp.NewSecret())
	if err != nil {
		t.Fatal(err)
	}
	if w := spaceJoinT(t, x, y, n); w.Compromised || !sameLogin(w, n) || n.LEx != 2 || n.LGen != 3 {
		t.Fatalf("новый вход: %v", w)
	}
}

// История входа однозначна: lgen 1 — lprev нули, lex 0; lgen > 1 — lprev не нули; lex не больше исключённых.
func TestSpaceLoginCanon(t *testing.T) {
	m := spaceFixture(t)
	n, _ := spaceSetLogin(m, spaceTestPhrase, "", spaceTestSec2)
	for name, e := range map[string]func(*space){
		"lgen 0":            func(s *space) { s.LGen = 0 },
		"lgen 1, lprev":     func(s *space) { s.LGen = 1 },
		"lgen 2, без lprev": func(s *space) { s.LPrev = make([]byte, 32) },
		"lex больше gone":   func(s *space) { s.LEx = 1 },
	} {
		b, _ := n.marshal()
		x, _ := spaceParse(b)
		e(x)
		if err := x.check(); !errors.Is(err, errSpaceFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	x := spaceEdit(t, m, func(s *space) { s.Gone = [][]byte{spacePub(0x50)}; s.LEx = 1 })
	if err := x.check(); !errors.Is(err, errSpaceFormat) {
		t.Errorf("lgen 1, lex 1: %v", err)
	}
}

// С3/С4: фраза — ровно 10 слов словаря, только ASCII; генератор — 10 слов, проходит правило; словарь — 256 разных
// слов [a-z]{3,6}.
func TestSpacePhraseRule(t *testing.T) {
	seen := map[string]bool{}
	for _, w := range spaceWords {
		if seen[w] || len(w) < 3 || len(w) > 6 || strings.Trim(w, "abcdefghijklmnopqrstuvwxyz") != "" {
			t.Errorf("слово %q: повтор или не [a-z]{3,6}", w)
		}
		seen[w] = true
	}
	p1, p2 := spacePhraseNew(), spacePhraseNew()
	if p1 == p2 || spacePhraseOK(p1) != nil || spacePhraseNorm(p1) != p1 || len(strings.Fields(p1)) != 10 {
		t.Fatalf("фразы %q %q", p1, p2)
	}
	for _, w := range strings.Fields(p1) {
		if !seen[w] {
			t.Fatalf("слово %q не из словаря", w)
		}
	}
	for p, want := range map[string]error{
		spaceTestPhrase: nil,
		"  ANT bat\tbear bee\nbird boar bull cat cow Crab ": nil,
		"ant bat bear bee bird boar bull cat cow":           errSpacePhraseCount,
		"ant bat bear bee bird boar bull cat cow crab crow": errSpacePhraseCount,
		"": errSpacePhraseCount,
		"ant bat bear bee bird boar bull cat cow crab":      errSpacePhraseASCII, // NBSP
		"ant bat bear bee bird boar bull cat cow crаb":      errSpacePhraseASCII, // кириллическая «а»
		"муравей bat bear bee bird boar bull cat cow crab":  errSpacePhraseASCII,
		"ant bat bear bee bird boar bull cat cow crab\x00":  errSpacePhraseWord,
		"ant bat bear bee bird boar bul cat cow crab":       errSpacePhraseWord,
		"aaaa bbbb cccc dddd eeee ffff gggg hhhh iiii jjjj": errSpacePhraseWord,
		"correct horse battery staple":                      errSpacePhraseWord,
	} {
		if err := spacePhraseOK(p); want == nil && err != nil || want != nil && !errors.Is(err, want) {
			t.Errorf("%q: %v, ждали %v", p, err, want)
		}
	}
	var we spacePhraseWordError
	if err := spacePhraseOK("ant bat bear bee bird boar bul cat cow crab"); !errors.As(err, &we) || we.N != 7 {
		t.Errorf("номер слова с опечаткой: %v", err)
	}
	k1, k2 := spaceOwnerKey(spaceTestPhrase, spaceTestOSalt), spaceOwnerKey("  ANT bat\tbear bee\nbird boar bull cat cow Crab ", spaceTestOSalt)
	if !bytes.Equal(k1, k2) {
		t.Error("нормализация: другой ключ")
	}
}

// С5: N сверяет пароль входа с phash пришедшего M (spaceLoginCheck): подлинный M владельца, но с другим паролем
// входа (P отстал или подсовывает чужую правку) — отказ, N не вступает и записи не меняет.
func TestSpaceEnterLoginMismatch(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	p.mu.Lock()
	real := p.spaceLocked()
	p.mu.Unlock()
	other, err := spaceSetLogin(real, ph, "other-login-pass", "")
	if err != nil {
		t.Fatal(err)
	}
	ob, _ := other.marshal()
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	withSpaceNet(t, spaceNet(p, func([]byte) []byte { return ob }))
	_, err = n.spaceEnter(context.Background(), p.id(), spacePass, spaceCode(p, sec), ph)
	spaceWant(t, err, errSpacePassword)
	n.mu.Lock()
	in := len(n.Space) > 0
	n.mu.Unlock()
	if in {
		t.Fatal("N вступил в состав с чужим паролем входа")
	}
}

// Опечатка во фразе при вступлении — отказ до сети (код TOTP не тратится), с номером слова.
func TestSpaceEnterPhraseTypo(t *testing.T) {
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	calls := 0
	withSpaceNet(t, func(context.Context, agent.SpaceDial) ([]byte, error) { calls++; return nil, agent.ErrSpaceOffline })
	var we spacePhraseWordError
	_, err := n.spaceEnter(context.Background(), "123456789", spacePass, "000000", "ant bat bear bee bird boar bul cat cow crab")
	if !errors.As(err, &we) || we.N != 7 || calls != 0 {
		t.Fatalf("опечатка: %v, вызовов сети %d", err, calls)
	}
	_, err = n.spaceEnter(context.Background(), "123456789", spacePass, "000000", "ant bat bear bee bird boar bull cat cow")
	if !errors.Is(err, errSpacePhraseCount) || calls != 0 {
		t.Fatalf("9 слов: %v, вызовов сети %d", err, calls)
	}
}
