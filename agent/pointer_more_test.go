//go:build linux

package agent

import (
	"math"
	"testing"
)

// TestPtrLim — граница check_position строгая: lim < size, и ни одно абсолютное движение у края зоны не равно size.
func TestPtrLim(t *testing.T) {
	if l := lim(1536); l >= 1536 || l < 1535.99 {
		t.Errorf("lim(1536) = %v", l)
	}
	pm := &ptrMap{w: 1536, h: 960, k: 5.0 / 3}
	for x := int32(39000); x < 39700; x++ {
		pm.forget()
		if st := pm.move(x, 0); st.abs && st.ax >= 1536 {
			t.Fatalf("x=%d: abs %.4f ≥ 1536", x, st.ax)
		}
	}
}

// TestPtrForget — конец сессии: следующее движение вне зоны — снова якорь (abs к краю зоны + довод), кнопки отпущены.
func TestPtrForget(t *testing.T) {
	pm := &ptrMap{w: 1536, h: 960, k: 5.0 / 3}
	pm.move(60000, 60000)
	pm.held = 1
	pm.forget()
	if pm.known || pm.held != 0 {
		t.Fatalf("forget: known %v held %d", pm.known, pm.held)
	}
	if st := pm.move(60100, 60100); !st.abs || !st.rel {
		t.Errorf("после forget без якоря: %+v", st)
	}
}

// TestPtrMapEnv — ручки: ANYPC_POINTER_SCALE заменяет масштаб mutter (негодное значение — нет), без неё — масштаб mutter.
func TestPtrMapEnv(t *testing.T) {
	t.Setenv("ANYPC_POINTER_SCALE", "")
	t.Setenv("ANYPC_POINTER_LOG", "")
	if m := newPtrMap(1536, 960, 5.0/3); m.k != 5.0/3 || m.w != 1536 || m.h != 960 || m.trace {
		t.Errorf("без ручек: %+v", m)
	}
	t.Setenv("ANYPC_POINTER_SCALE", "1.25")
	t.Setenv("ANYPC_POINTER_LOG", "1")
	if m := newPtrMap(1536, 960, 5.0/3); m.k != 1.25 || !m.trace {
		t.Errorf("ANYPC_POINTER_SCALE=1.25: %+v", m)
	}
	for _, bad := range []string{"0", "-2", "x"} {
		t.Setenv("ANYPC_POINTER_SCALE", bad)
		if m := newPtrMap(1536, 960, 2); m.k != 2 {
			t.Errorf("ANYPC_POINTER_SCALE=%s: k %v", bad, m.k)
		}
	}
}

// TestPortalInputPointer — связка portal.input → вызовы портала: узел и (x, y) абсолютного, (dx, dy) относительного по
// порядку, кнопки ведут held (в перетаскивании после паузы — только относительное).
func TestPortalInputPointer(t *testing.T) {
	var calls [][]any
	p := &portal{node: 77, w: 1536, h: 960, ptr: ptrMap{w: 1536, h: 960, k: 5.0 / 3}}
	p.call = func(m string, a ...any) error { calls = append(calls, append([]any{m}, a...)); return nil }
	k := p.ptr.k
	p.input(event{flags: mMove, x: 16384, y: 8192}, nil) // зона абсолютных
	ax, ay := float64(16384)*(1536*k-1)/65535, float64(8192)*(960*k-1)/65535
	if len(calls) != 1 || calls[0][0] != "NotifyPointerMotionAbsolute" || calls[0][1] != uint32(77) ||
		math.Abs(calls[0][2].(float64)-ax) > 1e-9 || math.Abs(calls[0][3].(float64)-ay) > 1e-9 {
		t.Fatalf("абсолютное: %v, ждали (77, %.3f, %.3f)", calls, ax, ay)
	}
	calls = nil
	p.input(event{flags: mMove, x: 65535, y: 49152}, nil) // вне зоны сразу после — только относительное
	tx0, ty0 := p.ptr.target(16384, 8192)
	tx1, ty1 := p.ptr.target(65535, 49152)
	if len(calls) != 1 || calls[0][0] != "NotifyPointerMotion" ||
		math.Abs(calls[0][1].(float64)-(tx1-tx0)) > 1e-9 || math.Abs(calls[0][2].(float64)-(ty1-ty0)) > 1e-9 {
		t.Fatalf("относительное: %v, ждали (%.3f, %.3f)", calls, tx1-tx0, ty1-ty0)
	}
	p.input(event{flags: btnFlags[0][1]}, nil)
	if p.ptr.held != 1 {
		t.Errorf("кнопка нажата — held %d", p.ptr.held)
	}
	acceptPause(&p.ptr)
	calls = nil
	p.input(event{flags: mMove, x: 65000, y: 49000}, nil)
	if len(calls) != 1 || calls[0][0] != "NotifyPointerMotion" {
		t.Errorf("перетаскивание после паузы: %v", calls)
	}
	p.input(event{flags: btnFlags[0][0]}, nil)
	if p.ptr.held != 0 {
		t.Errorf("кнопка отпущена — held %d", p.ptr.held)
	}
}
