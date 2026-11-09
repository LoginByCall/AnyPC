package agent

import (
	"os"
	"slices"
	"testing"
)

// Тесты не трогают рабочий стол того, кто их запускает: ввод, окна, буфер обмена — заглушки.
func TestMain(m *testing.M) {
	fakeDesktop = true
	os.Exit(m.Run())
}

// TestMacKeys — у каждой клавиши веб-клиента есть код macOS, кроме тех, у которых нет аналога.
func TestMacKeys(t *testing.T) {
	for in, want := range map[string]uint16{`{"t":"k","c":"KeyA","d":true}`: 0x00, `{"t":"k","c":"ArrowUp","d":true}`: 0x7E,
		`{"t":"k","c":"MetaLeft","d":true}`: 0x37, `{"t":"k","c":"Enter","d":true}`: 0x24, `{"t":"k","c":"NumpadEnter","d":true}`: 0x4C,
		`{"t":"k","c":"Delete","d":true}`: 0x75, `{"t":"k","c":"AltRight","d":true}`: 0x3D} {
		e, err := decode([]byte(in))
		sc := e.scan
		if e.flags&kExtended != 0 {
			sc |= 0xE000
		}
		if got, ok := macKeys[sc]; err != nil || !ok || got != want {
			t.Errorf("%s → %#x (%v), ждали %#x", in, got, err, want)
		}
	}
	for name, sc := range scancodes {
		if _, ok := macKeys[sc]; !ok && !slices.Contains([]string{"ContextMenu", "PrintScreen", "ScrollLock"}, name) {
			t.Errorf("нет кода macOS для %s", name)
		}
	}
}

// TestMacArgs — захват экрана N через avfoundation с курсором; частота — фильтром fps (регрессия: тысячи кадров/с, серый экран).
func TestMacArgs(t *testing.T) {
	a := FFArgs("avf:1", "libx264", Cap{FPS: 30, Kbps: 4000, Cursor: true})
	if i := slices.Index(a, "-i"); i < 0 || a[i+1] != "Capture screen 1:none" || !slices.Contains(a, "avfoundation") || !slices.Contains(a, "fps=30") {
		t.Fatal(a)
	}
}
