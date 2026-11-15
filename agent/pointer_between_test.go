//go:build linux

package agent

import (
	"math"
	"testing"
)

// Приёмка, круг 2: «между сессиями» через настоящую связку — endInput (конец сессии) сбрасывает опору портала desk,
// даже без паузы и с «залипшей» кнопкой; следующее движение вне зоны приходит в цель.
func TestAccept2BetweenSessions(t *testing.T) {
	k := 5.0 / 3
	f := &fakeMutter{w: 1536, h: 960, scale: k, mw: 1536, mh: 960}
	p := &portal{node: 5, w: 1536, h: 960, ptr: ptrMap{w: 1536, h: 960, k: k}}
	p.call = func(m string, a ...any) error {
		switch m {
		case "NotifyPointerMotionAbsolute":
			f.abs(a[1].(float64), a[2].(float64))
		case "NotifyPointerMotion":
			f.rel(a[0].(float64), a[1].(float64))
		}
		return nil
	}
	deskMu.Lock()
	old := desk
	desk = p
	deskMu.Unlock()
	defer func() { deskMu.Lock(); desk = old; deskMu.Unlock() }()

	p.input(event{flags: mMove, x: 60000, y: 60000}, nil)
	p.input(event{flags: btnFlags[0][1]}, nil) // сессия оборвалась с зажатой кнопкой
	endInput()                                 // конец сессии 1
	f.x, f.y = 300, 300                        // человек поработал мышью
	for _, c := range [][2]int32{{61000, 61000}, {50000, 62000}} {
		p.input(event{flags: mMove, x: c[0], y: c[1]}, nil)
		wx, wy := p.ptr.target(c[0], c[1])
		if math.Abs(f.x-wx) > 0.05 || math.Abs(f.y-wy) > 0.05 {
			t.Errorf("(%d,%d): курсор (%.1f, %.1f), цель (%.1f, %.1f)", c[0], c[1], f.x, f.y, wx, wy)
		}
	}
	if f.reject != 0 || p.ptr.held != 0 {
		t.Errorf("отказов %d, held %d", f.reject, p.ptr.held)
	}
}
