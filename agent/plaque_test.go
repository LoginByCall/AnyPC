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
		if l, b := plaqueBar(lang, "c123456789012", 0); !strings.Contains(l, "c123456789012") || b != pl[3] {
			t.Errorf("%s: %q %q", lang, l, b)
		}
	}
	// REQ-F-22: включённый микрофон хоста виден на плашке (и вместе с «только просмотр»)
	if l, _ := plaqueBar("ru", "c1", plaqueView|plaqueMic); !strings.Contains(l, "только просмотр") || !strings.Contains(l, "🎤 микрофон этого ПК включён") {
		t.Errorf("пометки: %q", l)
	}
	if _, txt := plaqueText("en", "c1", plaqueMic); !strings.Contains(txt, "microphone is on") {
		t.Errorf("plaqueText: %q", txt)
	}
	if _, b := plaqueBar("xx", "c1", 0); b != "Disconnect" {
		t.Errorf("запасной язык: %q", b)
	}
}
