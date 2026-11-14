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
		n.LGen != 2 || !bytes.Equal(n.LPrev, m.loginHash()) ||
		!slices.EqualFunc(n.Members, m.Members, func(a, b spaceMember) bool { return a.ID == b.ID }) {
		t.Fatalf("смена пароля входа: %v", n)
	}
	if err := spaceAccept(m, n); err != nil { // член знает только свой M — фразы у него нет
		t.Fatal(err)
	}
	n2, err := spaceSetLogin(n, "  ANT bat\tbear bee bird boar bull cat cow CRAB ", "", spaceTestSec2) // только TOTP; норма
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(n2.PHash, n.PHash) || n2.TOTP != spaceTestSec2 || n2.LGen != 3 || spaceAccept(n, n2) != nil {
		t.Fatalf("смена TOTP: %v", n2)
	}
	spaceWant(t, spaceAccept(m, n2), errSpaceFork) // две ступени входа за раз — не прямое продолжение

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
	// члены не принимают ни подпись ключом из пароля, ни ключом из хэша, ни состав с подменённым opub.
	for name, key := range map[string]ed25519.PrivateKey{
		"ключ из пароля входа":       spaceOwnerKey("new-login-pass", n.OSalt),
		"ключ из phash":              ed25519.NewKeyFromSeed(n.PHash),
		"ключ из пароля, соль psalt": spaceOwnerKey("new-login-pass", n.PSalt),
	} {
		f, _ := n.next()
		f.Members = append(f.Members, spaceMember{"100000009", spacePub(0x99)})
		f.Sig = ed25519.Sign(key, f.signBytes())
		if err := spaceAccept(n, f); !errors.Is(err, errSpaceSig) {
			t.Errorf("%s: %v", name, err)
		}
		f.OPub = bytes.Clone(key.Public().(ed25519.PublicKey))
		f.Sig = ed25519.Sign(key, f.signBytes())
		if err := spaceAccept(n, f); !errors.Is(err, errSpaceForeign) {
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
		_, err = spaceMerge(m, spaceEdit(t, m, func(s *space) { s.Epoch = 2; s.PHash[0] ^= 1 }), spaceTestPhrase, pw)
		spaceWant(t, err, errSpacePhraseLogin)
	}
	for _, pw := range []string{spaceTestWrong, "antbat bear bee bird boar bull cat cow crab", "ant bat bear bee bird boar bull cat cow"} {
		if err := spacePhraseLoginOK(spaceTestPhrase, pw); err != nil {
			t.Errorf("%q: %v", pw, err)
		}
	}
}

// Исключение и смена пароля входа — одна правка, одна эпоха; секрет TOTP новый, вход +1.
func TestSpaceRemoveLogin(t *testing.T) {
	m := spaceFixture(t)
	n, err := spaceRemoveLogin(m, spaceTestPhrase, spacePub(0x20), "after-theft-pass")
	if err != nil {
		t.Fatal(err)
	}
	if n.Epoch != 2 || n.member(spacePub(0x20)) || !n.gone(spacePub(0x20)) || n.TOTP == m.TOTP || n.LGen != 2 ||
		!bytes.Equal(n.PHash, pake.KDF("after-theft-pass", n.PSalt)) || spaceAccept(m, n) != nil {
		t.Fatalf("исключение со сменой пароля: %v", n)
	}
	r, err := spaceRemove(m, spaceTestPhrase, spacePub(0x20)) // без смены пароля
	if err != nil || !bytes.Equal(r.PHash, m.PHash) || r.TOTP == m.TOTP || r.LGen != 2 {
		t.Fatalf("исключение: %v %v", r, err)
	}
	_, err = spaceRemoveLogin(m, spaceTestWrong, spacePub(0x20), "after-theft-pass")
	spaceWant(t, err, errSpacePhrase)
}

// С2 приёмки Э1b: смена входа в ветви A не теряется, когда ветвь B ушла дальше по эпохам.
func TestSpaceLoginFork(t *testing.T) {
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
			spaceWant(t, spaceAccept(a, b), errSpaceFork)  // равная эпоха
			spaceWant(t, spaceAccept(a, b2), errSpaceFork) // эпоха больше, вход старый — не молча
			spaceWant(t, spaceAccept(b2, a), errSpaceStale)
			a2, _ := spaceSetLogin(a, spaceTestPhrase, "second-change", "") // эпоха 3, вход 3
			spaceWant(t, spaceAccept(b, a2), errSpaceFork)                  // вход не продолжает вход B
			// слияние без нового пароля: вход B2 — предок входа A, берётся вход A
			m, err := spaceMerge(a, b2, spaceTestPhrase, "")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(m.PHash, a.PHash) || m.TOTP != a.TOTP || !m.member(spacePub(0x40)) ||
				spaceAccept(a, m) != nil || spaceAccept(b2, m) != nil {
				t.Fatalf("слияние: %v", m)
			}
		})
	}
}

// Ветви, обе сменившие вход, молча не сливаются: пароль задаётся заново, итог принимают обе ветви.
func TestSpaceMergeLogin(t *testing.T) {
	m1 := spaceFixture(t)
	a, err := spaceSetLogin(m1, spaceTestPhrase, "branch-a-pass", "")
	if err != nil {
		t.Fatal(err)
	}
	b0, _ := spaceAdd(m1, spaceTestPhrase, "100000003", spacePub(0x30))
	b, err := spaceSetLogin(b0, spaceTestPhrase, "", spaceTestSec2)
	if err != nil {
		t.Fatal(err)
	}
	_, err = spaceMerge(a, b, spaceTestPhrase, "")
	spaceWant(t, err, errSpaceFork)
	m, err := spaceMerge(a, b, spaceTestPhrase, "merged-pass")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.PHash, pake.KDF("merged-pass", m.PSalt)) || !m.member(spacePub(0x30)) || m.LGen != 3 ||
		m.TOTP == a.TOTP || m.TOTP == b.TOTP || spaceAccept(a, m) != nil || spaceAccept(b, m) != nil {
		t.Fatalf("слияние: %v", m)
	}
	spaceWant(t, spaceAccept(m1, m), errSpaceFork) // предок обеих ветвей — не прямой родитель нового входа
}

// История входа однозначна: lgen 1 — нули; lgen > 1 — lprev не нули и не равен lmerge.
func TestSpaceLoginCanon(t *testing.T) {
	m := spaceFixture(t)
	n, _ := spaceSetLogin(m, spaceTestPhrase, "", spaceTestSec2)
	for name, e := range map[string]func(*space){
		"lgen 0":            func(s *space) { s.LGen = 0 },
		"lgen 1, lprev":     func(s *space) { s.LGen = 1 },
		"lgen 2, без lprev": func(s *space) { s.LPrev = make([]byte, 32) },
		"lmerge = lprev":    func(s *space) { s.LMerge = bytes.Clone(s.LPrev) },
	} {
		b, _ := n.marshal()
		x, _ := spaceParse(b)
		e(x)
		if err := x.check(); !errors.Is(err, errSpaceFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	x := spaceEdit(t, m, func(s *space) { s.LMerge[0] = 1 })
	if err := x.check(); !errors.Is(err, errSpaceFormat) {
		t.Errorf("lgen 1, lmerge: %v", err)
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
