package pake

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

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
