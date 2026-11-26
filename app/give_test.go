package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"anypc/pake"
	"anypc/totp"
)

// «Разрешить управление» (требование владельца 2026-11-15): переключатель управляет только входом по одноразовому
// коду. После запуска — выкл (в файле не хранится); выкл — кода нет и он не действует; вкл — новый код.

// TestGiveSwitch — состояние переключателя в настройках: по умолчанию выкл, вкл — новый код (повторное вкл — снова
// новый), выкл — код не виден и не входит, соль та же (идущую сессию не рвёт), конец сессии нового кода не выдаёт.
func TestGiveSwitch(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	c, _ := loadConfig(p)
	c.mu.Lock()
	stored, salt0 := c.Code, bytes.Clone(c.CodeSalt)
	c.mu.Unlock()
	// после запуска — выкл: кода нет, код из файла не входит, но запись есть (не «nopass»: выключено не выдать)
	s, h := c.oneTimeSecret()
	if c.giving() || c.code() != "" || len(stored) != 6 {
		t.Fatalf("после запуска: вкл %v, код %q", c.giving(), c.code())
	}
	if len(h) == 0 || !bytes.Equal(s, salt0) || bytes.Equal(h, pake.KDF(stored, s)) {
		t.Fatal("выкл: код из файла действует или запись по умолчанию пуста")
	}
	if _, err := c.newCode(); !errors.Is(err, errGiveOff) || c.code() != "" { // ↻ при выкл кода не выдаёт
		t.Fatalf("↻ при выкл: %v, код %q", err, c.code())
	}
	c.codeUsed() // конец сессии / блокировка при выкл — нового кода нет
	if c.code() != "" {
		t.Fatal("codeUsed при выкл выдал код")
	}
	// вкл — новый код, он и входит; соль та же
	code1, err := c.setGive(true)
	if s, h := c.oneTimeSecret(); err != nil || len(code1) != 6 || code1 != c.code() || code1 == stored || !bytes.Equal(s, salt0) || !bytes.Equal(h, pake.KDF(code1, s)) {
		t.Fatalf("вкл: %v, код %q (был %q)", err, code1, stored)
	}
	// повторное вкл (выкл → вкл) — новый код, старый не входит
	c.setGive(false)
	code2, _ := c.setGive(true)
	if s, h := c.oneTimeSecret(); code2 == code1 || bytes.Equal(h, pake.KDF(code1, s)) || !bytes.Equal(h, pake.KDF(code2, s)) {
		t.Fatalf("повторное вкл: %q → %q", code1, code2)
	}
	// конец сессии при вкл — новый код (как раньше)
	c.codeUsed()
	if code3 := c.code(); code3 == code2 || len(code3) != 6 {
		t.Fatalf("codeUsed при вкл: %q → %q", code2, code3)
	}
	// выкл во время сессии: соль та же и секрет не пуст (agent.revoked не рвёт), код не входит и не виден
	cur := c.code()
	c.setGive(false)
	s, h = c.oneTimeSecret()
	if c.code() != "" || !bytes.Equal(s, salt0) || len(h) == 0 || bytes.Equal(h, pake.KDF(cur, s)) {
		t.Fatal("выкл: код виден или действует, либо сменилась соль")
	}
	c.setGive(true)
	_, h1 := c.oneTimeSecret()
	c.setGive(false)
	_, hOff1 := c.oneTimeSecret()
	c.setGive(true)
	c.setGive(false)
	_, hOff2 := c.oneTimeSecret()
	if bytes.Equal(hOff1, hOff2) || bytes.Equal(hOff1, h1) {
		t.Fatal("секрет выкл не меняется между выключениями")
	}
	// не хранится между запусками: включили, перечитали — выкл
	c.setGive(true)
	if c2, _ := loadConfig(p); c2.giving() || c2.code() != "" {
		t.Fatal("переключатель пережил перезапуск")
	}
}

// TestGiveOtherLogins — permanent-пароль, именные записи и ключи не зависят от одноразового кода.
func TestGiveOtherLogins(t *testing.T) {
	c, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	c.setPassword("пароль-123")
	passwordMode(t, c)
	c.setUser("ivan", "пароль-ивана", "full")
	sec := totp.NewSecret()
	now, _ := totp.Code(sec, time.Now())
	if err := c.otpEnable(sec, now, "ivan"); err != nil {
		t.Fatal(err)
	}
	_, k, _ := ed25519.GenerateKey(nil)
	pub := k.Public().(ed25519.PublicKey)
	c.mu.Lock()
	s0 := c.Users[0].Salt
	c.mu.Unlock()
	c.keyTrust(pub, "", s0)
	check := func(what string) {
		t.Helper()
		if s, h, _ := c.secret(""); !bytes.Equal(h, pake.KDF("пароль-123", s)) {
			t.Fatalf("%s: пароль по умолчанию не действует", what)
		}
		if s, h, _ := c.secret("ivan"); !bytes.Equal(h, pake.KDF("пароль-ивана", s)) {
			t.Fatalf("%s: запись по имени не действует", what)
		}
		if in, on := c.keyLogin(pub, ""); !in || !on {
			t.Fatalf("%s: вход ключом %v %v", what, in, on)
		}
	}
	check("one-time выключен")
	code, err := c.setGive(true)
	if err != nil || len(code) != 6 {
		t.Fatalf("включение one-time при active permanent: %v", err)
	}
	check("one-time включен")
	if s, h := c.oneTimeSecret(); !bytes.Equal(h, pake.KDF(code, s)) {
		t.Fatal("одноразовый код не действует")
	}
	c.setGive(false)
	check("one-time снова выключен")
}
