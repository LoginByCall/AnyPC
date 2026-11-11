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

// TestAskText — окно «Разрешить» (REQ-F-03): на каждом языке все поля непустые, в тексте есть ID, IP и
// предупреждение о мошенниках (F3); неизвестный язык — английский.
func TestAskText(t *testing.T) {
	for _, lang := range []string{"en", "ru", "zh", "es", "de", "fr", "it"} {
		if _, ok := asks[lang]; !ok {
			t.Errorf("нет языка %s", lang)
		}
	}
	for lang, q := range asks {
		for i, s := range q {
			if strings.TrimSpace(s) == "" {
				t.Errorf("%s: пустая строка %d", lang, i)
			}
		}
		_, text, yes, no, view := askText(lang, "c123456789012", "203.0.113.7", false)
		for _, want := range []string{"ID: c123456789012", "IP: 203.0.113.7", q[1], q[7]} {
			if !strings.Contains(text, want) {
				t.Errorf("%s: в тексте нет %q:\n%s", lang, want, text)
			}
		}
		if yes != q[3] || no != q[4] || view != q[5] || winAskHint(lang) != q[6] {
			t.Errorf("%s: кнопки %q %q %q", lang, yes, no, view)
		}
		if _, loop, _, _, _ := askText(lang, "c1", "ip", true); !strings.Contains(text, q[8]) || !strings.Contains(loop, q[9]) || strings.Contains(loop, q[8]) {
			t.Errorf("%s: задержка — TaskDialog 3 с, окна askLoop 5 с", lang)
		}
	}
	if _, text, _, _, _ := askText("xx", "c1", "ip", true); !strings.Contains(text, "stranger") {
		t.Errorf("запасной язык: %q", text)
	}
}
