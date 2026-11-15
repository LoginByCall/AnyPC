//go:build linux

package agent

import (
	"math"
	"testing"
	"time"
)

// Приёмка: портал (и ptrMap) живёт между сессиями (getDesktop кеширует desk). Человек за хостом сдвинул мышь
// (между сессиями или в паузе оператора) — следующее движение оператора вне абсолютной зоны должно прийти в цель.
func TestAcceptPtrMapStale(t *testing.T) {
	k := 5.0 / 3
	pm := &ptrMap{w: 1536, h: 960, k: k}
	f := &fakeMutter{w: 1536, h: 960, scale: k, mw: 1536, mh: 960}
	f.apply(pm.move(60000, 60000)) // сессия 1: курсор в правом нижнем углу
	f.x, f.y = 300, 300            // человек за хостом поработал мышью
	acceptPause(pm)                // пауза / новая сессия
	for _, p := range [][2]int32{{61000, 61000}, {62000, 50000}, {50000, 62000}} {
		f.apply(pm.move(p[0], p[1]))
		wx, wy := pm.target(p[0], p[1])
		if math.Abs(f.x-wx) > 0.05 || math.Abs(f.y-wy) > 0.05 {
			t.Errorf("(%d,%d): курсор (%.1f, %.1f), цель (%.1f, %.1f) — ошибка (%.0f, %.0f) точек", p[0], p[1], f.x, f.y, wx, wy, f.x-wx, f.y-wy)
		}
	}
	if f.reject != 0 {
		t.Errorf("портал отверг %d", f.reject)
	}
}

// первое движение сеанса вне абсолютной зоны (ветка default): к краю зоны + довод
func TestAcceptPtrMapFirstOutside(t *testing.T) {
	for _, k := range []float64{1.25, 5.0 / 3, 2} {
		for _, p := range [][2]int32{{65535, 65535}, {65535, 100}, {100, 65535}, {50000, 60000}} {
			pm := &ptrMap{w: 1536, h: 960, k: k}
			f := &fakeMutter{w: 1536, h: 960, scale: k, mw: 1536, mh: 960, x: 700, y: 20}
			f.apply(pm.move(p[0], p[1]))
			wx, wy := pm.target(p[0], p[1])
			if math.Abs(f.x-wx) > 0.05 || math.Abs(f.y-wy) > 0.05 || f.reject != 0 {
				t.Errorf("k=%.3f (%d,%d): курсор (%.1f, %.1f), цель (%.1f, %.1f), отказов %d", k, p[0], p[1], f.x, f.y, wx, wy, f.reject)
			}
		}
	}
}

func acceptPause(m *ptrMap) { m.at = m.at.Add(-time.Second) }

// без паузы и в перетаскивании — только относительное (лишней точки у края зоны нет)
func TestAcceptPtrMapNoHop(t *testing.T) {
	pm := &ptrMap{w: 1536, h: 960, k: 5.0 / 3}
	pm.move(60000, 60000)
	if st := pm.move(60100, 60100); st.abs || !st.rel {
		t.Errorf("подряд: %+v", st)
	}
	pm.held = 1
	acceptPause(pm)
	if st := pm.move(60200, 60200); st.abs || !st.rel {
		t.Errorf("перетаскивание после паузы: %+v", st)
	}
	pm.held = 0
	acceptPause(pm)
	if st := pm.move(60300, 60300); !st.abs || !st.rel {
		t.Errorf("после паузы без кнопок — якорь: %+v", st)
	}
}
