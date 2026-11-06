package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"anypc/hub"
	"anypc/pake"
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
