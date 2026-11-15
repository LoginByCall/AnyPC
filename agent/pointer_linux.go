//go:build linux

package agent

import (
	"fmt"
	"log"
	"math"
)

// ptrMap — точка мыши клиента (0..65535 по картинке монитора) → вызовы портала RemoteDesktop.
//
// Почему не одним NotifyPointerMotionAbsolute (Linux-хост, «мышь не доходит до края», 2026-11-15; FINDINGS):
//   - фронтенд xdg-desktop-portal пропускает абсолютные координаты только внутри размера потока, который сообщил
//     бэкенд: 0 ≤ x < size.w, 0 ≤ y < size.h, иначе «Invalid position» [xdg-desktop-portal 1.21.1,
//     src/remote-desktop.c: check_position];
//   - бэкенд GNOME передаёт их mutter как есть [xdg-desktop-portal-gnome gnome-50, src/remotedesktop.c];
//   - size у GNOME — логический размер монитора [mutter gnome-50, meta-screen-cast-monitor-stream.c: set_parameters],
//     а mutter при включённом масштабировании делит координаты потока на масштаб [там же, transform_position].
//
// При масштабе k абсолютно достижим только угол [0, w/k) × [0, h/k) логических точек: при 166 % — 60 % ширины и высоты.
// Остаток пути — относительным NotifyPointerMotion в логических точках (виртуальная мышь mutter без ускорения:
// dx_unaccel = dx [mutter gnome-50, native/meta-virtual-input-device-native.c], фильтр масштаба при «views scaled»
// не применяется [native/meta-seat-impl.c: filter_relative_motion]).
type ptrMap struct {
	w, h  float64 // размер потока по порталу (граница check_position)
	k     float64 // координаты потока = логические точки × k (mutterScale; 1 — портал и mutter в одних единицах)
	trace bool    // ANYPC_POINTER_LOG: каждое движение в журнал (для калибровки у владельца)

	lx, ly float64 // где курсор хоста по нашим расчётам, логические точки от угла монитора
	known  bool    // lx, ly известны (было хоть одно движение)
	relLog bool    // строка «довод относительным» уже в журнале
}

// ptrStep — что отправить порталу: абсолютное движение (координаты потока) и/или относительное (логические точки).
type ptrStep struct {
	abs, rel bool
	ax, ay   float64
	dx, dy   float64
}

// lim — наибольшая координата, которую пропускает check_position (строго меньше размера).
func lim(size float64) float64 { return size - 1.0/1024 }

// target — точка 0..65535 → логические точки внутри монитора: 65535 — последняя физическая точка кадра (как virtualDesk).
func (m *ptrMap) target(x, y int32) (tx, ty float64) {
	return float64(x) * (m.w*m.k - 1) / 65535 / m.k, float64(y) * (m.h*m.k - 1) / 65535 / m.k
}

// move — шаги для точки (x, y). Внутри абсолютной зоны — только абсолютное (якорь, без накопления ошибки). Вне её —
// относительное от прошлой точки; без прошлой точки — абсолютное к краю зоны и довод относительным.
// ponytail: курсор, сдвинутый человеком за хостом, пока оператор вне абсолютной зоны, сбивает довод до возврата в зону.
func (m *ptrMap) move(x, y int32) (st ptrStep) {
	tx, ty := m.target(x, y)
	sx, sy := tx*m.k, ty*m.k
	switch lx, ly := lim(m.w), lim(m.h); {
	case sx <= lx && sy <= ly:
		st = ptrStep{abs: true, ax: sx, ay: sy}
	case m.known:
		st = ptrStep{rel: true, dx: tx - m.lx, dy: ty - m.ly}
	default:
		ax, ay := math.Min(sx, lx), math.Min(sy, ly)
		st = ptrStep{abs: true, ax: ax, ay: ay, rel: true, dx: tx - ax/m.k, dy: ty - ay/m.k}
	}
	if st.rel && !m.relLog {
		m.relLog = true
		log.Printf("мышь: точка (%.0f, %.0f) лог. вне абсолютной зоны портала — довод относительным движением", tx, ty)
	}
	if m.trace {
		log.Printf("мышь: цель (%.1f, %.1f) лог. → abs %v (%.1f, %.1f) rel %v (%.2f, %.2f)", tx, ty, st.abs, st.ax, st.ay, st.rel, st.dx, st.dy)
	}
	m.lx, m.ly, m.known = tx, ty, true
	return st
}

// describe — строка журнала при открытии сеанса: по ней видно, верен ли пересчёт (FINDINGS, ИЗМЕРЕНИЕ).
func (m *ptrMap) describe(src string) string {
	s := fmt.Sprintf("поток %.0f×%.0f по порталу, масштаб %.4f (%s) → кадр %.0f×%.0f, край мыши (%.1f, %.1f) лог.",
		m.w, m.h, m.k, src, m.w*m.k, m.h*m.k, (m.w*m.k-1)/m.k, (m.h*m.k-1)/m.k)
	if m.k > 1 {
		s += fmt.Sprintf("; абсолютно до (%.0f, %.0f) лог., дальше — относительным", lim(m.w)/m.k, lim(m.h)/m.k)
	}
	return s
}
