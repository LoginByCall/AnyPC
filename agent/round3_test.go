//go:build linux

package agent

import (
	"slices"
	"sync/atomic"
	"testing"
)

// TestGjsEnv — приёмка M1: Wayland с XWayland (есть DISPLAY) — gjs с GDK_BACKEND=x11; без DISPLAY или на X11 —
// окружение AnyPC (nil); окружение тестов (plaqueEnv) — как есть.
func TestGjsEnv(t *testing.T) {
	if e := gjsEnv(true, ":0"); !slices.Contains(e, "GDK_BACKEND=x11") || e[len(e)-1] != "GDK_BACKEND=x11" {
		t.Errorf("Wayland + DISPLAY: GDK_BACKEND=x11 не последним: %v", e)
	}
	if e := gjsEnv(true, ""); e != nil {
		t.Errorf("Wayland без DISPLAY: %v", e)
	}
	if e := gjsEnv(false, ":0"); e != nil {
		t.Errorf("X11: %v", e)
	}
	plaqueEnv = []string{"A=1"}
	defer func() { plaqueEnv = nil }()
	if e := gjsEnv(true, ":0"); !slices.Equal(e, []string{"A=1"}) {
		t.Errorf("plaqueEnv: %v", e)
	}
}

// TestEndInputOnBye — приёмка круга 2: конец настоящей сессии (bye клиента) зовёт endInput (сброс опоры портала).
func TestEndInputOnBye(t *testing.T) {
	var n atomic.Int32
	defer func(f func()) { endInput = f }(endInput)
	endInput = func() { n.Add(1) }
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}), "secret123")
	if n.Load() == 0 {
		t.Error("сессия закончилась, а endInput не позван")
	}
}

// TestEndInputIsForget — связка: endInput на Linux — forgetPointer (init в linux.go).
func TestEndInputIsForget(t *testing.T) {
	p := &portal{ptr: ptrMap{w: 1536, h: 960, k: 2, known: true, held: 1}}
	deskMu.Lock()
	old := desk
	desk = p
	deskMu.Unlock()
	defer func() { deskMu.Lock(); desk = old; deskMu.Unlock() }()
	endInput()
	if p.ptr.known || p.ptr.held != 0 {
		t.Errorf("endInput не забыл опору: known %v held %d", p.ptr.known, p.ptr.held)
	}
}
