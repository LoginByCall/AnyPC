package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anypc/hub"
	"anypc/pake"
	"anypc/totp"
)

func TestConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "AnyPC", "config.json")
	c, err := loadConfig(p)
	if err != nil || !hub.IsHostID(c.ID) {
		t.Fatalf("первый запуск: %v %+v", err, c)
	}
	if _, h := c.secret(); len(h) != 0 || c.hasPass() {
		t.Fatal("без пароля вход должен быть запрещён")
	}
	if c.setPassword("short") == nil {
		t.Fatal("короткий пароль принят")
	}
	if err := c.setPassword("пароль-123"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if strings.Contains(string(b), "пароль-123") {
		t.Fatal("пароль в открытом виде в конфиге")
	}
	c2, err := loadConfig(p)                                                                    // ID и пароль переживают перезапуск
	if !bytes.Equal(c2.Key, c.Key) || len(c.Key) != 64 || c2.fingerprint() != c.fingerprint() { // ключ хоста постоянный
		t.Fatal("ключ хоста не сохранился")
	}
	if c2.knownSet("123456789", "abcd") != nil || c2.knownGet("123456789") != "abcd" || c2.knownSet("../x", "a") == nil {
		t.Fatal("известные хосты")
	}
	salt, h := c2.secret()
	if err != nil || c2.ID != c.ID || !bytes.Equal(h, pake.KDF("пароль-123", salt)) || bytes.Equal(h, pake.KDF("пароль-124", salt)) {
		t.Fatalf("перезагрузка: %v %+v", err, c2)
	}
}

// TestConfirmSetting — REQ-F-03: новая установка спрашивает; старая с паролем (без поля) — нет, чтобы не запереть
// ПК без человека рядом после обновления; выбор сохраняется.
func TestConfirmSetting(t *testing.T) {
	dir := t.TempDir()
	c, _ := loadConfig(filepath.Join(dir, "new.json"))
	if !c.confirm() {
		t.Fatal("новая установка должна спрашивать")
	}
	old := filepath.Join(dir, "old.json")
	os.WriteFile(old, []byte(`{"id":"123456789","salt":"AAAA","hash":"AAAA"}`), 0o600)
	if c, _ = loadConfig(old); c.confirm() {
		t.Fatal("старая установка с паролем стала спрашивать — удалённый ПК без человека будет недоступен")
	}
	if err := c.setConfirm(true); err != nil {
		t.Fatal(err)
	}
	if c, _ = loadConfig(old); !c.confirm() {
		t.Fatal("выбор не сохранился")
	}
}

// TestServerRename — старый адрес any. переводится на новый; свой адрес пользователя не трогается.
func TestServerRename(t *testing.T) {
	for in, want := range map[string]string{oldServers[0]: DefaultServer, oldServers[1]: DefaultServer, oldServers[2]: DefaultServer, "wss://my.example/ws": "wss://my.example/ws"} {
		p := filepath.Join(t.TempDir(), "config.json")
		os.WriteFile(p, []byte(`{"server":"`+in+`"}`), 0o600)
		c, err := loadConfig(p)
		if err != nil || c.Server != want {
			t.Fatalf("%s → %s, ждали %s (%v)", in, c.Server, want, err)
		}
		if c2, _ := loadConfig(p); c2.Server != want {
			t.Fatal("не сохранилось")
		}
	}
}

// TestTrusted — ключи клиентов: не больше maxTrusted (уходят давние), повтор не дублирует, смена пароля сбрасывает.
func TestTrusted(t *testing.T) {
	c, err := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	key := func(i int) []byte { return bytes.Repeat([]byte{byte(i)}, 32) }
	for i := range maxTrusted + 2 {
		c.trust(key(i))
	}
	c.trust(key(5))
	if len(c.Trusted) != maxTrusted || c.trusted(key(0)) || c.trusted(key(1)) || !c.trusted(key(2)) || !c.trusted(key(5)) {
		t.Fatalf("доверенных %d", len(c.Trusted))
	}
	c2, _ := loadConfig(c.path)
	if !c2.trusted(key(5)) {
		t.Fatal("не сохранилось")
	}
	c.setPassword("новый-пароль")
	if c.trusted(key(5)) {
		t.Fatal("смена пароля не сбросила доверие")
	}
}

// TestOTPConfig — TOTP (PLAN.md): секрет сохраняется только с верным кодом и переживает перезапуск; выключить
// подтверждение без TOTP нельзя; включить подтверждение — отключить TOTP; повтор принятого кода — отказ.
func TestOTPConfig(t *testing.T) {
	c, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	if c.setConfirm(false) == nil || !c.confirm() {
		t.Fatal("подтверждение выключено без TOTP")
	}
	r, err := c.otpNew()
	if err != nil || !strings.HasPrefix(r["svg"], "<svg") || r["uri"] != totp.URI(c.ID, r["secret"]) {
		t.Fatalf("otpNew: %v %v", err, r["uri"])
	}
	sec := r["secret"]
	if c.otpEnable(sec, "000000") == nil && c.otpEnable(sec, "111111") == nil {
		t.Fatal("неверный код принят")
	}
	if c.otpSet() || !c.confirm() {
		t.Fatal("TOTP сохранён без верного кода")
	}
	code, _ := totp.Code(sec, time.Now())
	if err := c.otpEnable(sec, code); err != nil || c.confirm() || !c.otpSet() {
		t.Fatalf("верный код: %v", err)
	}
	b, _ := os.ReadFile(c.path)
	if !strings.Contains(string(b), sec) {
		t.Fatal("секрет не в настройках")
	}
	c2, _ := loadConfig(c.path)
	if set, ok := c2.otp(code); !set || ok { // код настройки уже принят — повтор
		t.Fatalf("после перезапуска: задан %v, повтор принят %v", set, ok)
	}
	if set, ok := c2.otp(""); !set || ok {
		t.Fatal("пустой код")
	}
	if err := c2.setConfirm(true); err != nil || c2.otpSet() {
		t.Fatal("включение подтверждения не отключило TOTP")
	}
	if set, _ := c2.otp(code); set {
		t.Fatal("TOTP остался")
	}
}

// TestSaved — запомненные пароли: сохраняются, "" — забыть, чужой ID — отказ.
func TestSaved(t *testing.T) {
	c, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	if c.savedSet("123456789", "пароль-1") != nil || c.savedSet("../x", "a") == nil {
		t.Fatal("savedSet")
	}
	if c2, _ := loadConfig(c.path); c2.savedGet("123456789") != "пароль-1" {
		t.Fatal("не сохранился")
	}
	if c.savedSet("123456789", "") != nil || c.savedGet("123456789") != "" {
		t.Fatal("не забылся")
	}
}
