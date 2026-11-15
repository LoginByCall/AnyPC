//go:build linux

package agent

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func acceptCount(pat string) int {
	out, _ := exec.Command("pgrep", "-fc", pat).Output()
	n := 0
	fmt.Sscan(strings.TrimSpace(string(out)), &n)
	return n
}

// AnyPC убит (SIGKILL) — плашка gjs не остаётся сиротой.
func TestAcceptPlaqueOrphan(t *testing.T) {
	if os.Getenv("ACCEPT_HELPER") == "1" {
		plaqueEnv = scrubDisplay([]string{"GDK_BACKEND=broadway", "BROADWAY_DISPLAY=:41"})
		if _, err := gjsPlaque("ru", os.Getenv("ACCEPT_CID"), 0, func() {}); err != nil {
			fmt.Println("err", err)
			return
		}
		fmt.Println("up")
		time.Sleep(time.Minute)
		return
	}
	env := broadwayEnv(t, ":41")
	cid := fmt.Sprintf("c-accept-%d", os.Getpid())
	h := exec.Command(os.Args[0], "-test.run=TestAcceptPlaqueOrphan")
	h.Env = append(env, "ACCEPT_HELPER=1", "ACCEPT_CID="+cid)
	out, _ := h.StdoutPipe()
	if err := h.Start(); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(out)
	if !sc.Scan() || sc.Text() != "up" {
		t.Fatalf("помощник: %q", sc.Text())
	}
	pat := "gjs -c .* " + cid
	if n := acceptCount(pat); n != 1 {
		t.Fatalf("gjs до убийства: %d", n)
	}
	h.Process.Signal(syscall.SIGKILL)
	h.Wait()
	time.Sleep(500 * time.Millisecond)
	if n := acceptCount(pat); n != 0 {
		exec.Command("pkill", "-f", pat).Run()
		t.Errorf("AnyPC убит, а gjs жив: %d", n)
	}
}

// Текст клиента — данные, не код: кавычки, обратные кавычки, перевод строки, «опции» gjs не исполняются и окно живёт.
func TestAcceptPlaqueHostile(t *testing.T) {
	plaqueEnv = broadwayEnv(t, ":42")
	defer func() { plaqueEnv = nil }()
	mark := fmt.Sprintf("%s/accept-pwn-%d", os.TempDir(), os.Getpid())
	os.Remove(mark)
	evil := "x'); imports.gi.GLib.file_set_contents('" + mark + "', 'p'); ('\n\"`${imports.gi.GLib.file_set_contents('" + mark + "', 'p')}` --version -c print(1) <b>&amp;"
	var closed atomic.Int32
	stop, err := gjsPlaque("ru", evil, plaqueView|plaqueMic, func() { closed.Add(1) })
	if err != nil {
		t.Fatalf("плашка: %v", err)
	}
	time.Sleep(700 * time.Millisecond)
	if _, err := os.Stat(mark); err == nil {
		os.Remove(mark)
		t.Errorf("текст клиента исполнен как код")
	}
	if closed.Load() != 0 {
		t.Errorf("окно закрылось само")
	}
	stop()
	time.Sleep(300 * time.Millisecond)
	if closed.Load() != 0 {
		t.Errorf("закрыли мы — onUserClose не нужен")
	}
}
