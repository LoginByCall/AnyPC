package main

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"anypc/agent"
	"anypc/totp"
)

// Регрессия повторной приёмки otc (Д1, Д2): закрепление ключей и переключение режимов туда-обратно.
func TestCodeTrustModes(t *testing.T) {
	c, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	kc, kp := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 32)
	st := func(when string) {
		t.Logf("%-46s режим кода %-5v | ключ эпохи кода: закреплён %-5v | ключ эпохи пароля: закреплён %-5v (за любой %v) | в файле ключей %d",
			when, c.codeMode(), c.trusted(kc, ""), c.trusted(kp, ""), c.trusted(kp, agent.AnyUser), len(c.Users[0].Trusted))
	}
	c.trust(kc, "") // вход кодом + «Разрешить»
	st("новая установка, вход кодом:")
	if c.trusted(kc, "") || c.trusted(kc, agent.AnyUser) || len(c.Users[0].Trusted) != 0 {
		t.Fatal("в режиме кода ключ закреплён")
	}
	c.setPassword("пароль-123")
	sec := totp.NewSecret()
	code, _ := totp.Code(sec, time.Now())
	if err := c.otpEnable(sec, code, ""); err != nil { // → режим пароля
		t.Fatal(err)
	}
	st("включили TOTP (режим пароля):")
	if c.trusted(kc, "") {
		t.Fatal("ключ эпохи кода закреплён в режиме пароля")
	}
	c.trust(kp, "") // вход постоянным паролем
	st("вход постоянным паролем:")
	for i := range 3 { // туда-обратно
		c.setConfirm(true)
		c.trust(kc, "")
		c.codeUsed()
		st("«Спрашивать» включили, вход кодом, смена кода:")
		if c.trusted(kc, "") || c.trusted(kp, "") || c.trusted(kp, agent.AnyUser) || c.trusted(kc, agent.AnyUser) {
			t.Fatalf("круг %d: в режиме кода действует закрепление", i)
		}
		code, _ = totp.Code(sec, time.Now().Add(time.Duration(i+1)*90*time.Second))
		c.mu.Lock()
		c.Users[0].TOTP, c.Confirm = sec, new(bool) // обратно в режим пароля (как otpEnable, без ожидания шага)
		c.save()
		c.mu.Unlock()
		st("обратно в режим пароля:")
		if c.trusted(kc, "") || !c.trusted(kp, "") {
			t.Fatalf("круг %d: ключ эпохи кода закрепился либо ключ эпохи пароля потерян", i)
		}
	}
	// файл: закрепления кода не сохранены, перечитывание не возвращает
	c2, _ := loadConfig(c.path)
	c2.setConfirm(true)
	if c2.trusted(kp, "") || c2.trusted(kc, "") {
		t.Fatal("после перечитывания в режиме кода действует закрепление")
	}
	// запуск программы: новый код
	before := c2.code()
	c3, _ := loadConfig(c.path)
	c3.codeUsed()
	t.Logf("код до запуска %s, после %s", before, c3.code())
	if c3.code() == before || c3.code() == "" {
		t.Fatal("код при запуске не сменился")
	}
}
