package agent

import (
	"strings"
	"testing"
)

// Плашка REQ-F-15: на каждом языке есть подпись с ID клиента и кнопка «Разорвать»; неизвестный язык — английский.
func TestPlaqueBar(t *testing.T) {
	for lang, pl := range plaques {
		for i, s := range pl {
			if s == "" {
				t.Errorf("%s: пустая строка %d", lang, i)
			}
		}
		if l, b := plaqueBar(lang, "c123456789012", false); !strings.Contains(l, "c123456789012") || b != pl[3] {
			t.Errorf("%s: %q %q", lang, l, b)
		}
	}
	if _, b := plaqueBar("xx", "c1", false); b != "Disconnect" {
		t.Errorf("запасной язык: %q", b)
	}
}
