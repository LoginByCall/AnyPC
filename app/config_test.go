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
	c2, err := loadConfig(p) // ID и пароль переживают перезапуск
	salt, h := c2.secret()
	if err != nil || c2.ID != c.ID || !bytes.Equal(h, pake.KDF("пароль-123", salt)) || bytes.Equal(h, pake.KDF("пароль-124", salt)) {
		t.Fatalf("перезагрузка: %v %+v", err, c2)
	}
}
