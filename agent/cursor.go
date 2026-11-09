package agent

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// cursorInfo — курсор хоста: позиция (пиксели виртуального экрана, у Мака — точки, как Monitor) и форма именем CSS
// (default, text, pointer, …); ok=false — скрыт или неизвестен. nil — платформа не умеет, курсор рисуется в кадр
// (Cap.Cursor). Назначают платформенные файлы: Windows — GetCursorInfo, macOS — CGEvent (только позиция),
// X11 — XFixes; Wayland — nil (портал рисует курсор сам).
var cursorInfo func() (x, y int, shape string, ok bool)

// cursorMsg — {"t":"cur"}: точка 0..65535 внутри монитора m (обратно monPoint) и форма; скрыт, вне монитора
// или мониторы неизвестны — {"t":"cur","c":"none"}.
func cursorMsg(m *Monitor, x, y int, shape string, ok bool) ctlMsg {
	if !ok || m == nil || m.W < 2 || m.H < 2 || x < m.X || y < m.Y || x >= m.X+m.W || y >= m.Y+m.H {
		return ctlMsg{T: "cur", C: "none"}
	}
	return ctlMsg{T: "cur", X: (x - m.X) * 65535 / (m.W - 1), Y: (y - m.Y) * 65535 / (m.H - 1), C: shape}
}

// watchCursor — после входа шлёт курсор клиенту до 30 раз/с и только при изменении: курсора нет в кадре, поэтому
// при движении одной мыши видео статично (считанные байты на кадр), а курсор у клиента не привязан к к/с видео.
func (s *session) watchCursor(ctx context.Context, send func([]byte)) {
	if cursorInfo == nil {
		return
	}
	t := time.NewTicker(33 * time.Millisecond)
	defer t.Stop()
	var last ctlMsg
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !s.authed.Load() {
			continue
		}
		x, y, shape, ok := cursorInfo()
		m := cursorMsg(s.monitor(), x, y, shape, ok)
		if m.X != last.X || m.Y != last.Y || m.C != last.C {
			last = m
			b, _ := json.Marshal(m)
			send(b)
		}
	}
}

// cssCursor — имя курсора X11 (тема: left_ptr, xterm, hand2, sb_h_double_arrow, …; freedesktop: text, pointer,
// ew-resize, …) → имя CSS. Неизвестное — default.
func cssCursor(name string) string {
	switch {
	case name == "xterm", name == "text", name == "ibeam":
		return "text"
	case strings.HasPrefix(name, "hand"), name == "pointer", name == "pointing_hand":
		return "pointer"
	case name == "X_cursor", name == "not-allowed", name == "crossed_circle", name == "forbidden":
		return "not-allowed"
	case name == "watch", name == "wait":
		return "wait"
	case strings.Contains(name, "watch"), name == "progress": // left_ptr_watch
		return "progress"
	case strings.Contains(name, "h_double_arrow"), name == "ew-resize", name == "col-resize", name == "size_hor":
		return "ew-resize"
	case strings.Contains(name, "v_double_arrow"), name == "ns-resize", name == "row-resize", name == "size_ver":
		return "ns-resize"
	case strings.Contains(name, "bd_double_arrow"), name == "nwse-resize", name == "size_fdiag":
		return "nwse-resize"
	case strings.Contains(name, "fd_double_arrow"), name == "nesw-resize", name == "size_bdiag":
		return "nesw-resize"
	case name == "fleur", name == "move", name == "all-scroll", name == "grabbing", name == "size_all":
		return "move"
	case strings.Contains(name, "cross"), name == "tcross":
		return "crosshair"
	case name == "question_arrow", name == "help", name == "whats_this":
		return "help"
	}
	return "default"
}
