//go:build linux

package agent

import (
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// broadwayEnv — своё окно GTK broadway (не экран человека): окружение для gjs; нет broadwayd или gjs — пропуск.
func broadwayEnv(t *testing.T, display string) []string {
	t.Helper()
	for _, b := range []string{"gjs", "broadwayd"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skip("нет " + b)
		}
	}
	srv := exec.Command("broadwayd", display)
	srv.Env = scrubDisplay(nil)
	if err := srv.Start(); err != nil {
		t.Skip("broadwayd: ", err)
	}
	t.Cleanup(func() { srv.Process.Kill(); srv.Wait() })
	time.Sleep(300 * time.Millisecond)
	return scrubDisplay([]string{"GDK_BACKEND=broadway", "BROADWAY_DISPLAY=" + display})
}

func scrubDisplay(env []string) []string {
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "DISPLAY=") && !strings.HasPrefix(e, "WAYLAND_DISPLAY=") && !strings.HasPrefix(e, "GDK_BACKEND=") {
			env = append(env, e)
		}
	}
	return env
}

// TestGjsPlaque — плашка-полоса на настоящем gjs + GTK 3 в broadway: окно появилось («ready»); закрыли мы — сессию
// не рвём; окно закрыли не мы (человек, WM) — onUserClose; GTK не запустился — ошибка сразу (запасной путь zenity).
func TestGjsPlaque(t *testing.T) {
	plaqueEnv = broadwayEnv(t, ":37")
	defer func() { plaqueEnv = nil }()
	var closed atomic.Int32
	stop, err := gjsPlaque("ru", "c-test-a", plaqueView|plaqueMic, func() { closed.Add(1) })
	if err != nil {
		t.Fatalf("плашка: %v", err)
	}
	stop()
	time.Sleep(300 * time.Millisecond)
	if closed.Load() != 0 {
		t.Errorf("закрыли мы — onUserClose не нужен")
	}

	pid := spawnedPID(t)
	if _, err := gjsPlaque("en", "c-test-c", 0, func() { closed.Add(1) }); err != nil {
		t.Fatalf("плашка: %v", err)
	}
	syscall.Kill(*pid, syscall.SIGTERM) // «закрыл человек»
	for i := 0; i < 30 && closed.Load() == 0; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if closed.Load() != 1 {
		t.Errorf("окно закрыто не нами — ждали onUserClose, было %d", closed.Load())
	}

	plaqueEnv = scrubDisplay([]string{"GDK_BACKEND=broadway", "BROADWAY_DISPLAY=:93"}) // сервера нет
	t0 := time.Now()
	if _, err := gjsPlaque("en", "c-test-b", 0, func() { closed.Add(1) }); err == nil || time.Since(t0) > plaqueReady {
		t.Errorf("без дисплея: %v за %v — ждали ошибку сразу", err, time.Since(t0))
	}
}
