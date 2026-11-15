//go:build linux || darwin

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestSendPlanFIFO — M2: FIFO в отправляемой папке пропущен (открытие FIFO вешает отправку до писателя); FIFO,
// подложенный после плана, — отказ «не обычный файл» сразу (O_NONBLOCK), а не зависание.
func TestSendPlanFIFO(t *testing.T) {
	d := filepath.Join(t.TempDir(), "P")
	tree(t, d, map[string]string{"a.txt": "A"})
	if err := syscall.Mkfifo(filepath.Join(d, "fifo"), 0o644); err != nil {
		t.Skip(err)
	}
	p, err := makePlan(nil, []string{d}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	if len(p.items) != 1 || strings.Join(p.skipped, ",") != "P/fifo" {
		t.Fatalf("уходит %d, пропущено %q", len(p.items), p.skipped)
	}
	os.Remove(filepath.Join(d, "a.txt"))
	syscall.Mkfifo(filepath.Join(d, "a.txt"), 0o644)
	done := make(chan error, 1)
	go func() {
		f, _, err := p.items[0].open()
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO открыт как файл")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("открытие FIFO повисло")
	}
}
