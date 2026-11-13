//go:build linux

package agent

import (
	"testing"

	"github.com/godbus/dbus/v5"
)

// TestScaleFrom — регрессия (канбан 2026-11-13, «указатели расползлись»): при layout-mode logical координаты мыши
// портала умножаются на масштаб монитора в позиции потока; physical или монитор не найден — 1.
func TestScaleFrom(t *testing.T) {
	lm := func(x, y int32, k float64) []any { return []any{x, y, k, uint32(0), true, [][]any{}, map[string]dbus.Variant{}} }
	body := func(mode uint32, lms ...[]any) []any {
		return []any{uint32(1), [][]any{}, lms, map[string]dbus.Variant{"layout-mode": dbus.MakeVariant(mode)}}
	}
	for _, c := range []struct {
		name string
		b    []any
		x, y int32
		want float64
	}{
		{"ноутбук 166 %", body(1, lm(0, 0, 5.0/3)), 0, 0, 5.0 / 3},
		{"второй монитор справа", body(1, lm(0, 0, 1), lm(1536, 0, 2)), 1536, 0, 2},
		{"physical — mutter не делит", body(2, lm(0, 0, 2)), 0, 0, 1},
		{"монитор не найден", body(1, lm(0, 0, 2)), 99, 0, 1},
		{"пустой ответ", nil, 0, 0, 1},
	} {
		if got := scaleFrom(c.b, c.x, c.y); got != c.want {
			t.Errorf("%s: %v, ждали %v", c.name, got, c.want)
		}
	}
}

// TestMutterScaleLive — тот же разбор на настоящем ответе mutter (только чтение DisplayConfig); не GNOME — пропуск.
func TestMutterScaleLive(t *testing.T) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Skip("нет сессионной шины")
	}
	defer conn.Close()
	if c := conn.Object("org.gnome.Mutter.DisplayConfig", "/org/gnome/Mutter/DisplayConfig").Call("org.gnome.Mutter.DisplayConfig.GetCurrentState", 0); c.Err != nil {
		t.Skip("не GNOME")
	}
	t.Logf("масштаб mutter в (0,0): %.4f", mutterScale(conn, 0, 0))
}
