package pake

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

// TestXKey — X25519 из ключа хоста: открытый из Ed25519 совпадает с открытым из закрытого, общий секрет у двух сторон
// один; негодный ключ — ошибка.
func TestXKey(t *testing.T) {
	for range 50 {
		pa, ka, _ := ed25519.GenerateKey(nil)
		pb, kb, _ := ed25519.GenerateKey(nil)
		xa, err := XPriv(ka)
		if err != nil {
			t.Fatal(err)
		}
		ua, err := XPub(pa)
		if err != nil || !bytes.Equal(ua.Bytes(), xa.PublicKey().Bytes()) {
			t.Fatalf("открытый X25519 из Ed25519 не тот: %v", err)
		}
		xb, _ := XPriv(kb)
		ub, _ := XPub(pb)
		s1, err1 := xa.ECDH(ub)
		s2, err2 := xb.ECDH(ua)
		if err1 != nil || err2 != nil || !bytes.Equal(s1, s2) {
			t.Fatalf("общий секрет: %v %v", err1, err2)
		}
	}
	one := make([]byte, 32)
	one[0] = 1 // y = 1
	if _, err := XPub(one); err == nil {
		t.Error("нейтральная точка принята")
	}
	if _, err := XPub(make([]byte, 31)); err == nil {
		t.Error("короткий ключ принят")
	}
}

func TestHostKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sig := HostSign(priv, "123456789", fpC, fpH)
	if err := HostVerify(pub, sig, "123456789", fpC, fpH); err != nil {
		t.Fatal(err)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	for name, err := range map[string]error{
		"MITM: другой отпечаток": HostVerify(pub, sig, "123456789", "sha-256 EE:FF", fpH),
		"другой ID":              HostVerify(pub, sig, "987654321", fpC, fpH),
		"другой ключ":            HostVerify(other, sig, "123456789", fpC, fpH),
		"мусорный ключ":          HostVerify(pub[:5], sig, "123456789", fpC, fpH),
	} {
		if err == nil {
			t.Errorf("%s: подпись принята", name)
		}
	}
	b := base64.StdEncoding.EncodeToString
	fp, err := HostVerifyB64(b(pub), b(sig), "123456789", "a=fingerprint:sha-256 aa:bb\r\n", "a=fingerprint:sha-256 cc:dd\r\n")
	if err != nil || fp != KeyFingerprint(pub) || len(strings.Fields(fp)) != 8 {
		t.Fatalf("%q %v", fp, err)
	}
}

// TestSpaceJoinProof — Ч12б: доказательство фразы годится только для своего соединения, ID поручителя и ключа
// клиента; подпись другого домена тем же ключом (clientMsg, identityMsg) — не доказательство.
func TestSpaceJoinProof(t *testing.T) {
	_, owner, _ := ed25519.GenerateKey(nil)
	opub := owner.Public().(ed25519.PublicKey)
	cpub, _, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	const id, fc, fh = "123456789", "sha-256 AA:BB", "sha-256 CC:DD"
	sig := SpaceJoinSign(owner, id, fc, fh, cpub)
	if !SpaceJoinVerify(opub, sig, id, fc, fh, cpub) {
		t.Fatal("верное доказательство не принято")
	}
	for name, ok := range map[string]bool{
		"чужое соединение (клиент)": SpaceJoinVerify(opub, sig, id, "sha-256 AA:BC", fh, cpub),
		"чужое соединение (хост)":   SpaceJoinVerify(opub, sig, id, fc, "sha-256 CC:DE", cpub),
		"отпечатки местами":         SpaceJoinVerify(opub, sig, id, fh, fc, cpub),
		"другой поручитель":         SpaceJoinVerify(opub, sig, "123456780", fc, fh, cpub),
		"другой ключ клиента":       SpaceJoinVerify(opub, sig, id, fc, fh, other),
		"другой ключ владельца":     SpaceJoinVerify(cpub, sig, id, fc, fh, cpub),
		"без отпечатков":            SpaceJoinVerify(opub, SpaceJoinSign(owner, id, "", "", cpub), id, "", "", cpub),
		"домен clientMsg":           SpaceJoinVerify(opub, ed25519.Sign(owner, clientMsg(id, fc, fh)), id, fc, fh, cpub),
		"домен identityMsg":         SpaceJoinVerify(opub, HostSign(owner, id, fc, fh), id, fc, fh, cpub),
		"пустая подпись":            SpaceJoinVerify(opub, nil, id, fc, fh, cpub),
	} {
		if ok {
			t.Errorf("%s: принято", name)
		}
	}
	if ClientVerify(opub, sig, id, fc, fh) || HostVerify(opub, sig, id, fc, fh) == nil {
		t.Error("доказательство фразы сошло за подпись клиента или хоста")
	}
}
