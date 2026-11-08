package pake

import (
	"bytes"
	"encoding/base64"
	"testing"
)

const (
	fpC = "sha-256 AA:BB"
	fpH = "sha-256 CC:DD"
)

func run(t *testing.T, hostPass, clientPass, hostID, clientHostID, cC, cH string) error {
	t.Helper()
	salt := []byte("0123456789abcdef")
	msgA, st, err := HostStart(KDF(hostPass, salt), hostID, fpC, fpH)
	if err != nil {
		t.Fatal(err)
	}
	msgB, cConf, wantH, err := ClientRespond(clientPass, salt, msgA, clientHostID, cC, cH)
	if err != nil {
		return err
	}
	hConf, err := HostFinish(st, msgB, cConf)
	if err == nil && !bytes.Equal(hConf, wantH) {
		t.Fatal("клиент не узнал хост при верном пароле")
	}
	return err
}

func TestPAKE(t *testing.T) {
	if err := run(t, "пароль-123", "пароль-123", "123456789", "123456789", fpC, fpH); err != nil {
		t.Fatalf("верный пароль: %v", err)
	}
	cases := map[string][4]string{
		"неверный пароль":         {"пароль-124", "123456789", fpC, fpH},
		"MITM: подмена отпечатка": {"пароль-123", "123456789", "sha-256 EE:FF", fpH}, // REQ-S-02: клиент видит отпечаток атакующего
		"другой хост":             {"пароль-123", "987654321", fpC, fpH},
	}
	for name, c := range cases {
		if err := run(t, "пароль-123", c[0], "123456789", c[1], c[2], c[3]); err == nil {
			t.Errorf("%s: вход принят", name)
		}
	}
	if _, _, err := HostStart(nil, "1", fpC, fpH); err == nil {
		t.Error("пустой секрет принят")
	}
}

func TestFingerprint(t *testing.T) {
	sdp := "v=0\r\na=group:BUNDLE 0\r\na=fingerprint:SHA-256 ab:cd:EF\r\nm=video 9\r\n"
	if got := Fingerprint(sdp); got != "sha-256 AB:CD:EF" {
		t.Fatalf("%q", got)
	}
	if Fingerprint("v=0\r\n") != "" {
		t.Fatal("нет отпечатка → пусто")
	}
	two := "a=fingerprint:sha-256 AB:CD\r\nm=video 9\r\na=fingerprint:sha-256 ab:cd\r\nm=application 9\r\n"
	if got := Fingerprint(two); got != "sha-256 AB:CD" { // по строке на m-секцию, одинаковые — норма браузеров
		t.Fatalf("одинаковые отпечатки: %q", got)
	}
	// Д-3: разные отпечатки по секциям или неразборчивая строка — подмена, вход к ним не привязывается
	for _, bad := range []string{
		"a=fingerprint:sha-256 AB:CD\r\na=fingerprint:sha-256 EE:FF\r\n",
		"a=fingerprint:sha-256 AB:CD\r\na=fingerprint:sha-256 zz\r\n",
	} {
		if got := Fingerprint(bad); got != "" {
			t.Errorf("%q → %q, ждали пусто", bad, got)
		}
	}
}

// TestClientKey — подпись клиента привязана к ID хоста и к обоим DTLS-отпечаткам; seed сохраняет ключ.
func TestClientKey(t *testing.T) {
	sdp := func(fp string) string { return "a=fingerprint:sha-256 " + fp + "\r\n" }
	k, err := ClientSignB64("", "123456789", sdp("AA"), sdp("BB"))
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := ClientSignB64(k["seed"], "123456789", sdp("AA"), sdp("BB"))
	if k2["pub"] != k["pub"] {
		t.Fatal("seed не восстановил ключ")
	}
	pub, _ := base64.StdEncoding.DecodeString(k["pub"])
	sig, _ := base64.StdEncoding.DecodeString(k["sig"])
	fa, fb := Fingerprint(sdp("AA")), Fingerprint(sdp("BB"))
	if !ClientVerify(pub, sig, "123456789", fa, fb) {
		t.Fatal("верная подпись не прошла")
	}
	if ClientVerify(pub, sig, "987654321", fa, fb) || ClientVerify(pub, sig, "123456789", fb, fa) || ClientVerify(pub, sig, "123456789", "", "") {
		t.Fatal("подпись прошла для чужого хоста, обмена отпечатками или пустых отпечатков")
	}
	if HostVerify(pub, sig, "123456789", fa, fb) == nil {
		t.Fatal("подпись клиента принята как подпись хоста")
	}
}
