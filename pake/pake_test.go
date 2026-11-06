package pake

import (
	"bytes"
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
}
