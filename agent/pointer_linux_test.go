//go:build linux

package agent

import (
	"math"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

// fakeMutter — цепочка портал → mutter по исходникам (pointer_linux.go): check_position фронтенда по размеру потока,
// transform_position mutter (деление на масштаб), относительное движение в логических точках (float32, как в mutter)
// и удержание курсора внутри монитора.
type fakeMutter struct {
	w, h   float64 // размер потока по порталу
	scale  float64 // делитель mutter (1 при layout-mode physical)
	mw, mh float64 // логический размер монитора
	x, y   float64
	reject int // абсолютные, отвергнутые check_position
}

func (f *fakeMutter) abs(sx, sy float64) {
	if !(sx >= 0 && sx < f.w && sy >= 0 && sy < f.h) {
		f.reject++
		return
	}
	f.x, f.y = sx/f.scale, sy/f.scale
}

func (f *fakeMutter) rel(dx, dy float64) {
	f.x = math.Max(0, math.Min(f.mw-1e-3, f.x+float64(float32(dx))))
	f.y = math.Max(0, math.Min(f.mh-1e-3, f.y+float64(float32(dy))))
}

func (f *fakeMutter) apply(st ptrStep) {
	if st.abs {
		f.abs(st.ax, st.ay)
	}
	if st.rel {
		f.rel(st.dx, st.dy)
	}
}

// TestPtrMap — регрессия «мышь не доходит до края» (Linux-хост, 2026-11-15): при масштабе > 1 любой угол, край и
// путь туда-обратно приходят в нужную точку монитора; масштабы 1…2, поток логический (GNOME, layout logical) и
// физический (layout physical), несколько мониторов с разным масштабом (масштаб берётся у монитора потока).
func TestPtrMap(t *testing.T) {
	type mon struct{ x, y, pw, ph int32 } // положение (лог.) и физический размер
	cases := []struct {
		name    string
		m       mon
		k       float64
		logical bool
	}{
		{"1", mon{0, 0, 1920, 1080}, 1, true},
		{"1.25", mon{0, 0, 2560, 1440}, 1.25, true},
		{"1.333", mon{0, 0, 2048, 1152}, 4.0 / 3, true},
		{"1.5", mon{0, 0, 3840, 2160}, 1.5, true},
		{"1.667 ноутбук владельца", mon{0, 0, 2560, 1600}, 5.0 / 3, true},
		{"2", mon{0, 0, 3840, 2160}, 2, true},
		{"второй монитор 1.5 справа от 1.667", mon{1536, 0, 3840, 2160}, 1.5, true},
		{"физический поток 2", mon{0, 0, 3840, 2160}, 2, false},
	}
	for _, c := range cases {
		// ответ DisplayConfig: ноутбук 1536×960 @ 5/3 в (0,0) и монитор потока; масштаб — у монитора потока
		lw, lh := math.Round(float64(c.m.pw)/c.k), math.Round(float64(c.m.ph)/c.k)
		mode := uint32(1)
		pw, ph, div := lw, lh, c.k // logical: портал сообщает логический размер, mutter делит на масштаб
		if !c.logical {
			mode, pw, ph, div = 2, float64(c.m.pw), float64(c.m.ph), 1
			lw, lh = pw, ph
		}
		lm := func(x, y int32, k float64) []any {
			return []any{x, y, k, uint32(0), true, [][]any{}, map[string]dbus.Variant{}}
		}
		body := []any{uint32(1), [][]any{}, [][]any{lm(0, 0, 5.0/3), lm(c.m.x, c.m.y, c.k)}, map[string]dbus.Variant{"layout-mode": dbus.MakeVariant(mode)}}
		if c.m.x == 0 {
			body[2] = [][]any{lm(0, 0, c.k)}
		}
		k := scaleFrom(body, c.m.x, c.m.y)
		pm := &ptrMap{w: pw, h: ph, k: k}
		f := &fakeMutter{w: pw, h: ph, scale: div, mw: lw, mh: lh}

		check := func(x, y int32) {
			t.Helper()
			f.apply(pm.move(x, y))
			wx, wy := float64(x)*(pw*k-1)/65535/k, float64(y)*(ph*k-1)/65535/k // 65535 — последняя точка кадра
			if math.Abs(f.x-wx) > 0.05 || math.Abs(f.y-wy) > 0.05 {
				t.Errorf("%s: (%d,%d) → курсор (%.2f, %.2f), ждали (%.2f, %.2f)", c.name, x, y, f.x, f.y, wx, wy)
			}
			if f.x >= lw || f.y >= lh {
				t.Errorf("%s: (%d,%d) вне монитора %.0f×%.0f", c.name, x, y, lw, lh)
			}
		}
		// углы и края в разном порядке: из центра, из угла в угол, вдоль края
		for _, p := range [][2]int32{{32768, 32768}, {65535, 65535}, {0, 0}, {65535, 0}, {0, 65535}, {65535, 32768}, {32768, 65535}, {0, 0}} {
			check(p[0], p[1])
		}
		// плавный путь из левого верхнего угла в правый нижний и обратно (зона абсолютных → относительные → назад)
		for i := int32(0); i <= 200; i++ {
			check(i*65535/200, i*65535/200)
		}
		for i := int32(200); i >= 0; i-- {
			check(i*65535/200, 65535-i*65535/200)
		}
		if f.reject != 0 {
			t.Errorf("%s: портал отверг %d абсолютных (check_position)", c.name, f.reject)
		}
		if math.Abs(f.x-0) > 0.05 || math.Abs(f.y-(ph*k-1)/k) > 0.05 {
			t.Errorf("%s: конец пути (%.2f, %.2f)", c.name, f.x, f.y)
		}
	}
}

// TestPtrMapOldWay — почему понадобился довод: одним абсолютным (как до 2026-11-15) при 166 % курсор не уходит дальше 60 %.
func TestPtrMapOldWay(t *testing.T) {
	f := &fakeMutter{w: 1536, h: 960, scale: 5.0 / 3, mw: 1536, mh: 960}
	for i := int32(0); i <= 100; i++ {
		f.abs(float64(i*65535/100)*2560/65535, float64(i*65535/100)*1600/65535)
	}
	if f.x > 922 || f.reject == 0 {
		t.Errorf("модель портала: курсор (%.0f, %.0f), отвергнуто %d — ждали упор в 921", f.x, f.y, f.reject)
	}
}

// TestPtrMapDescribe — строка журнала для владельца: край мыши у монитора 2560×1600 @ 166 % — (1535.4, 959.4) лог.
func TestPtrMapDescribe(t *testing.T) {
	s := (&ptrMap{w: 1536, h: 960, k: 5.0 / 3}).describe("mutter")
	for _, want := range []string{"1536×960", "2560×1600", "(1535.4, 959.4)", "абсолютно до (922, 576)"} {
		if !strings.Contains(s, want) {
			t.Errorf("нет %q в %q", want, s)
		}
	}
	if s := (&ptrMap{w: 1920, h: 1080, k: 1}).describe("mutter"); strings.Contains(s, "относительным") {
		t.Errorf("масштаб 1 — без довода: %q", s)
	}
}
