package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"
	"testing"

	"anypc/pake"
)

// Решение 8 B: пароль входа и секрет TOTP меняются правкой под тем же ключом владельца; члены принимают её по
// закреплённому opub без фразы у них. Без фразы (паролем входа, его хэшем) состав не подписать.
func TestSpaceSetLogin(t *testing.T) {
	m := spaceFixture(t)
	psalt := bytes.Repeat([]byte{0x05}, 16)
	phash := pake.KDF("new-login-pass", psalt)
	n, err := spaceSetLogin(m, spaceTestPhrase, psalt, phash, "")
	if err != nil {
		t.Fatal(err)
	}
	if n.Epoch != m.Epoch+1 || !bytes.Equal(n.PSalt, psalt) || !bytes.Equal(n.PHash, phash) || n.TOTP != m.TOTP ||
		!bytes.Equal(n.OPub, m.OPub) || !slices.EqualFunc(n.Members, m.Members, func(a, b spaceMember) bool { return a.ID == b.ID }) {
		t.Fatalf("смена пароля входа: %v", n)
	}
	if err := spaceAccept(m, n); err != nil { // член знает только свой M — фразы у него нет
		t.Fatal(err)
	}
	const sec2 = "KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU"
	n2, err := spaceSetLogin(n, "  SPACE test phrase   Vectors ", nil, nil, sec2) // только TOTP; фраза нормализуется
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(n2.PHash, phash) || n2.TOTP != sec2 || spaceAccept(n, n2) != nil {
		t.Fatalf("смена TOTP: %v", n2)
	}

	_, err = spaceSetLogin(m, "new-login-pass", psalt, phash, "") // пароль входа — не фраза
	spaceWant(t, err, errSpacePhrase)
	_, err = spaceSetLogin(m, spaceTestPhrase, nil, nil, "")
	spaceWant(t, err, errSpaceNoChange)
	_, err = spaceSetLogin(m, spaceTestPhrase, m.PSalt, m.PHash, m.TOTP)
	spaceWant(t, err, errSpaceNoChange)
	_, err = spaceSetLogin(m, spaceTestPhrase, m.OSalt, pake.KDF("x-login", m.OSalt), "") // psalt = osalt
	spaceWant(t, err, errSpaceFormat)
	_, err = spaceSetLogin(m, spaceTestPhrase, psalt, pake.KDF(spaceTestPhrase, psalt), "") // пароль входа = фраза
	spaceWant(t, err, errSpacePhraseLogin)
	_, err = spaceSetLogin(m, spaceTestPhrase, psalt, phash[:8], "")
	spaceWant(t, err, errSpaceFormat)
	_, err = spaceSetLogin(m, spaceTestPhrase, nil, nil, "bad totp")
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
	_, err = spaceAdd(n, "new-login-pass", "100000009", spacePub(0x99))
	spaceWant(t, err, errSpacePhrase)
}

// Исключение и смена пароля входа — одна правка, одна эпоха; секрет TOTP новый.
func TestSpaceRemoveLogin(t *testing.T) {
	m := spaceFixture(t)
	psalt := bytes.Repeat([]byte{0x06}, 16)
	phash := pake.KDF("after-theft-pass", psalt)
	n, err := spaceRemoveLogin(m, spaceTestPhrase, spacePub(0x20), psalt, phash)
	if err != nil {
		t.Fatal(err)
	}
	if n.Epoch != 2 || n.member(spacePub(0x20)) || !n.gone(spacePub(0x20)) || n.TOTP == m.TOTP ||
		!bytes.Equal(n.PSalt, psalt) || !bytes.Equal(n.PHash, phash) || spaceAccept(m, n) != nil {
		t.Fatalf("исключение со сменой пароля: %v", n)
	}
	r, err := spaceRemove(m, spaceTestPhrase, spacePub(0x20)) // без смены пароля
	if err != nil || !bytes.Equal(r.PHash, m.PHash) || r.TOTP == m.TOTP {
		t.Fatalf("исключение: %v %v", r, err)
	}
	_, err = spaceRemoveLogin(m, spaceTestPhrase, spacePub(0x20), psalt, pake.KDF(spaceTestPhrase, psalt))
	spaceWant(t, err, errSpacePhraseLogin)
	_, err = spaceRemoveLogin(m, "after-theft-pass", spacePub(0x20), psalt, phash)
	spaceWant(t, err, errSpacePhrase)
}

// Ветви, разошедшиеся в пароле входа, молча не сливаются: пароль задаётся заново, итог принимают обе ветви.
func TestSpaceMergeLogin(t *testing.T) {
	m1 := spaceFixture(t)
	psalt := bytes.Repeat([]byte{0x07}, 16)
	a, err := spaceSetLogin(m1, spaceTestPhrase, psalt, pake.KDF("branch-a-pass", psalt), "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := spaceAdd(m1, spaceTestPhrase, "100000003", spacePub(0x30))
	if err != nil {
		t.Fatal(err)
	}
	_, err = spaceMerge(a, b, spaceTestPhrase, nil, nil)
	spaceWant(t, err, errSpaceFork)
	qsalt := bytes.Repeat([]byte{0x08}, 16)
	m, err := spaceMerge(a, b, spaceTestPhrase, qsalt, pake.KDF("merged-pass", qsalt))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.PSalt, qsalt) || !m.member(spacePub(0x30)) || spaceAccept(a, m) != nil || spaceAccept(b, m) != nil {
		t.Fatalf("слияние: %v", m)
	}
}

// Генератор фразы: 8 слов словаря, проходит правило; словарь — 256 разных слов [a-z]{3,6}.
func TestSpacePhraseNew(t *testing.T) {
	seen := map[string]bool{}
	for _, w := range spaceWords {
		if seen[w] || len(w) < 3 || len(w) > 6 || strings.Trim(w, "abcdefghijklmnopqrstuvwxyz") != "" {
			t.Errorf("слово %q: повтор или не [a-z]{3,6}", w)
		}
		seen[w] = true
	}
	p1, p2 := spacePhraseNew(), spacePhraseNew()
	if p1 == p2 || spacePhraseOK(p1) != nil || spacePhraseNorm(p1) != p1 || len(strings.Fields(p1)) != 8 {
		t.Fatalf("фразы %q %q", p1, p2)
	}
	for _, w := range strings.Fields(p1) {
		if !seen[w] {
			t.Fatalf("слово %q не из словаря", w)
		}
	}
}
