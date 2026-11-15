//go:build linux

package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// spawnedPID — PID следующего процесса gjs (plaqueSpawned); после теста он убит, если ещё жив.
func spawnedPID(t *testing.T) *int {
	pid := new(int)
	plaqueSpawned = func(p int) { *pid = p }
	t.Cleanup(func() {
		plaqueSpawned = func(int) {}
		if *pid != 0 && pidAlive(*pid) {
			syscall.Kill(*pid, syscall.SIGKILL)
		}
	})
	return pid
}

// pidAlive — процесс есть и не зомби.
func pidAlive(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if pid <= 0 || err != nil {
		return false
	}
	i := strings.LastIndexByte(string(b), ')')
	return i > 0 && i+2 < len(b) && b[i+2] != 'Z'
}

// waitClosed — ждать onUserClose до d.
func waitClosed(n *atomic.Int32, d time.Duration) {
	for t0 := time.Now(); n.Load() == 0 && time.Since(t0) < d; {
		time.Sleep(50 * time.Millisecond)
	}
}

// TestGjsPlaqueProbe — настоящее окно (broadway): «Разорвать» и закрытие окна рвут сессию; кнопка и окно не берут
// фокус (иначе проба выходит); stop убивает процесс gjs.
func TestGjsPlaqueProbe(t *testing.T) {
	base := broadwayEnv(t, ":39")
	defer func() { plaqueEnv = nil }()
	for _, c := range []struct {
		probe string
		close bool
	}{{"click", true}, {"close", true}, {"focus", false}} {
		plaqueEnv = append(append([]string{}, base...), "ANYPC_PLAQUE_PROBE="+c.probe)
		var closed atomic.Int32
		pid := spawnedPID(t)
		stop, err := gjsPlaque("ru", "c-probe-"+c.probe, 0, func() { closed.Add(1) })
		if err != nil {
			t.Fatalf("%s: %v", c.probe, err)
		}
		waitClosed(&closed, 2*time.Second)
		if got := closed.Load() == 1; got != c.close {
			t.Errorf("%s: onUserClose %v, ждали %v", c.probe, got, c.close)
		}
		stop()
		time.Sleep(300 * time.Millisecond)
		if pidAlive(*pid) {
			syscall.Kill(*pid, syscall.SIGKILL)
			t.Errorf("%s: после stop gjs жив (PID %d)", c.probe, *pid)
		}
	}
}

// fakeBin — каталог для PATH с исполняемыми скриптами name → тело.
func fakeBin(t *testing.T, files map[string]string) string {
	d := t.TempDir()
	for _, b := range []string{"sleep", "touch"} { // PATH подменён — свои утилиты тестов
		if p, err := exec.LookPath(b); err == nil {
			files[b] = `exec "` + p + `" "$@"`
		}
	}
	for n, body := range files {
		if err := os.WriteFile(filepath.Join(d, n), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// TestShowIndicatorGjs — showIndicator идёт в gjs, zenity не зовёт (zenity подменён — на экран человека ничего).
func TestShowIndicatorGjs(t *testing.T) {
	gjs, err := exec.LookPath("gjs")
	if err != nil {
		t.Skip("нет gjs")
	}
	env := broadwayEnv(t, ":40")
	mark := filepath.Join(t.TempDir(), "zenity-called")
	dir := fakeBin(t, map[string]string{"zenity": "touch " + mark + "; exec sleep 30", "gjs": `exec "` + gjs + `" "$@"`})
	t.Setenv("PATH", dir)
	plaqueEnv = append(env, "PATH="+dir)
	fd := fakeDesktop
	fakeDesktop = false
	defer func() { plaqueEnv, fakeDesktop = nil, fd }()
	pid := spawnedPID(t)
	stop, err := showIndicator("c-show", 0, func() {})
	if err != nil {
		t.Fatalf("плашка: %v", err)
	}
	defer stop()
	time.Sleep(500 * time.Millisecond) // запасной zenity успел бы отметиться
	if _, err := os.Stat(mark); err == nil {
		t.Errorf("при работающем gjs позвали zenity")
	}
	if cmd, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", *pid)); *pid == 0 || !pidAlive(*pid) || !strings.Contains(string(cmd), "c-show") {
		t.Errorf("плашка gjs не запущена (PID %d)", *pid)
	}
}

// TestGjsPlaqueHang — gjs не дал «ready» за plaqueReady: ошибка и процесс убит (не висит невидимым).
func TestGjsPlaqueHang(t *testing.T) {
	dir := fakeBin(t, map[string]string{"gjs": "exec sleep 6007"})
	t.Setenv("PATH", dir)
	r := plaqueReady
	plaqueReady = 300 * time.Millisecond
	defer func() { plaqueReady = r }()
	pid := spawnedPID(t)
	if _, err := gjsPlaque("en", "c-hang", 0, func() {}); err == nil {
		t.Fatal("без ready — ждали ошибку")
	}
	if pidAlive(*pid) {
		syscall.Kill(*pid, syscall.SIGKILL)
		t.Errorf("зависший gjs не убит (PID %d)", *pid)
	}
}
