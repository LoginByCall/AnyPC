package main

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Вторая копия в том же каталоге настроек — отказ (errRunning), в другом — своя блокировка; после выхода первой — снова можно.
func TestLockInstance(t *testing.T) {
	dir, other := filepath.Join(t.TempDir(), "AnyPC"), t.TempDir() // dir ещё нет — lockInstance создаёт
	unlock, err := lockInstance(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockInstance(dir); !errors.Is(err, errRunning) {
		t.Fatalf("вторая копия в том же каталоге: %v, нужен errRunning", err)
	}
	u2, err := lockInstance(other)
	if err != nil {
		t.Fatalf("другой пользователь (каталог): %v", err)
	}
	u2()
	unlock()
	u3, err := lockInstance(dir)
	if err != nil {
		t.Fatalf("после выхода первой: %v", err)
	}
	u3()
}

// singleInstance: занято — running, окно первой показано; блокировку не взять (каталог не создаётся) — запуск
// с записью в журнал, а не падение.
func TestSingleInstance(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	dir := t.TempDir()
	unlock, running := singleInstance(dir, nil)
	if running {
		t.Fatal("первая копия: running")
	}
	defer unlock()
	shown := false
	if u, running := singleInstance(dir, func() error { shown = true; return errors.New("нет окна") }); !running || u != nil || !shown {
		t.Fatalf("вторая копия: running=%v shown=%v", running, shown)
	}
	if s := buf.String(); !strings.Contains(s, "AnyPC уже запущен") || !strings.Contains(s, "нет окна") {
		t.Fatalf("журнал второй копии: %q", s)
	}

	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, nil, 0o600)
	buf.Reset()
	u, running := singleInstance(filepath.Join(file, "AnyPC"), func() error { t.Fatal("show без второй копии"); return nil })
	if running || u == nil {
		t.Fatalf("каталог не создаётся: running=%v unlock=%v — нужно запускаться", running, u != nil)
	}
	u()
	if !strings.Contains(buf.String(), "проверка второй копии не удалась") {
		t.Fatalf("журнал: %q", buf.String())
	}
}
