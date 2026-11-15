package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRecvPins — Ч10.1: закрепление чужого отправителя в config.json: заявленные ID и имя — только годные; повтор
// обновляет запись; не больше maxRecvPins (уходят давние); негодные записи из файла не действуют; откреплённый
// ключ — снова незнакомый (и для другого процесса — через файл).
func TestRecvPins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	pub := func() []byte { p, _, _ := ed25519.GenerateKey(nil); return p }
	k1 := pub()
	if _, ok := c.recvPinned(k1); ok {
		t.Fatal("закреплён до закрепления")
	}
	c.recvPin(k1, "555666777", "Друг")
	if l, ok := c.recvPinned(k1); !ok || l != "Друг" {
		t.Fatalf("%q %v", l, ok)
	}
	c.recvPin(k1, "12345", "<b>злой</b>") // негодные ID и имя не сохраняются, запись одна
	if l := c.recvPinList(); len(l) != 1 || l[0].ID != "" || l[0].Name != "" {
		t.Fatalf("%+v", l)
	}
	c.recvPin(k1, "555666777", "")
	if l, ok := c.recvPinned(k1); !ok || l != "555666777" {
		t.Fatalf("подпись по ID: %q", l)
	}
	c.recvPin([]byte("short"), "555666777", "x")
	for range maxRecvPins + 3 {
		c.recvPin(pub(), "", "")
	}
	if n := len(c.recvPinList()); n != maxRecvPins {
		t.Fatalf("закреплено %d", n)
	}
	if _, ok := c.recvPinned(k1); ok {
		t.Fatal("давний не ушёл")
	}
	// другой процесс (окно, CLI) закрепил и открепил — запущенная программа видит файл
	other, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	k2 := pub()
	other.recvPin(k2, "", "ПК 2")
	if _, ok := c.recvPinned(k2); !ok {
		t.Fatal("закрепление другого процесса не видно")
	}
	if ok, err := other.recvUnpin(k2); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if _, ok := c.recvPinned(k2); ok {
		t.Fatal("откреплённый действует")
	}
	if ok, _ := c.recvUnpin(k2); ok {
		t.Fatal("открепил несуществующий")
	}
	// правленный руками файл: негодные записи не действуют
	b, _ := os.ReadFile(path)
	var raw map[string]any
	json.Unmarshal(b, &raw)
	k3 := pub()
	raw["recv_pins"] = []map[string]any{{"id": "x", "pub": k3}, {"pub": []byte("short")}, {"name": "a/b", "pub": k3}}
	b, _ = json.Marshal(raw)
	os.WriteFile(path, b, 0o600)
	if _, ok := c.recvPinned(k3); ok || len(c.recvPinList()) != 0 {
		t.Fatal("негодная запись действует")
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "recv_pins") {
		t.Fatal("поле не в файле")
	}
}
