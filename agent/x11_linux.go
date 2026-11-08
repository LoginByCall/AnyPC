//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"

	"github.com/jezek/xgb"
	"github.com/jezek/xgb/randr"
	"github.com/jezek/xgb/xproto"
	"github.com/jezek/xgb/xtest"
)

// x11 — захват ffmpeg x11grab (весь экран), ввод — расширение XTest (без root и без /dev/uinput).
type x11 struct {
	mu     sync.Mutex
	c      *xgb.Conn
	root   xproto.Window
	w, h   int
	wheelV int32 // остаток прокрутки меньше одного щелчка
	wheelH int32
}

func newX11() (desktop, error) {
	c, err := xgb.NewConn()
	if err != nil {
		return nil, err
	}
	if err := xtest.Init(c); err != nil {
		c.Close()
		return nil, errors.New("нет расширения XTest")
	}
	s := xproto.Setup(c).DefaultScreen(c)
	return &x11{c: c, root: s.Root, w: int(s.WidthInPixels), h: int(s.HeightInPixels)}, nil
}

func (x *x11) alive() bool { return true }

func (x *x11) capture(ctx context.Context, fps int, bitrate, enc string, m *Monitor) (*exec.Cmd, error) {
	disp := os.Getenv("DISPLAY")
	if disp == "" {
		disp = ":0"
	}
	src := "x11:" + disp
	if m != nil { // один монитор: размер и смещение в общем экране X
		src = fmt.Sprintf("x11:%dx%d@%s+%d,%d", m.W&^1, m.H&^1, disp, m.X, m.Y) // libx264: чётные размеры
	}
	return exec.CommandContext(ctx, "ffmpeg", FFArgs(src, enc, fps, bitrate)...), nil
}

// monitors — мониторы по RandR 1.5 (основной отмечен); нет RandR — nil (весь экран).
func (x *x11) monitors() []Monitor {
	if err := randr.Init(x.c); err != nil {
		return nil
	}
	r, err := randr.GetMonitors(x.c, x.root, true).Reply()
	if err != nil {
		return nil
	}
	var out []Monitor
	for _, mi := range r.Monitors {
		name := ""
		if a, err := xproto.GetAtomName(x.c, mi.Name).Reply(); err == nil {
			name = a.Name
		}
		out = append(out, Monitor{Name: name, X: int(mi.X), Y: int(mi.Y), W: int(mi.Width), H: int(mi.Height), Primary: mi.Primary})
	}
	return out
}

const (
	xKeyPress, xKeyRelease, xButtonPress, xButtonRelease, xMotion = 2, 3, 4, 5, 6
)

func (x *x11) fake(typ, detail byte, rx, ry int16) {
	xtest.FakeInput(x.c, typ, detail, 0, x.root, rx, ry, 0)
}

func (x *x11) click(button byte, n int32) {
	for ; n > 0; n-- {
		x.fake(xButtonPress, button, 0, 0)
		x.fake(xButtonRelease, button, 0, 0)
	}
}

func (x *x11) input(e event, m *Monitor) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if e.key {
		code := evdevCode(e)
		if code == 0 {
			return errors.New("клавиша без кода evdev")
		}
		typ := byte(xKeyPress)
		if e.flags&kUp != 0 {
			typ = xKeyRelease
		}
		x.fake(typ, byte(code+8), 0, 0) // код X11 = evdev + 8
		return nil
	}
	switch f := e.flags; {
	case f&mMove != 0:
		if m == nil {
			m = &Monitor{W: x.w, H: x.h}
		}
		px, py := monPoint(m, e.x, e.y)
		x.fake(xMotion, 0, int16(px), int16(py))
	case f&mWheel != 0: // кнопки 4/5 — щелчок вверх/вниз (WHEEL_DELTA = 120)
		n := notches(&x.wheelV, e.data)
		x.click(4, n)
		x.click(5, -n)
	case f&mHWheel != 0: // 6/7 — влево/вправо
		n := notches(&x.wheelH, e.data)
		x.click(7, n)
		x.click(6, -n)
	default:
		for i, b := range []byte{1, 2, 3} { // левая, средняя, правая — как btnFlags
			if f&btnFlags[i][1] != 0 {
				x.fake(xButtonPress, b, 0, 0)
			}
			if f&btnFlags[i][0] != 0 {
				x.fake(xButtonRelease, b, 0, 0)
			}
		}
	}
	return nil
}
