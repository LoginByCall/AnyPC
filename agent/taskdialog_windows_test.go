package agent

import (
	"testing"
	"time"
)

// TestTaskDialog — окно «Разрешить»: каждая кнопка даёт свой ответ, без ответа — отказ по таймеру (REQ-F-03).
// Нужен рабочий стол Windows (раннер GitHub Actions windows-latest его даёт).
func TestTaskDialog(t *testing.T) {
	for click, want := range map[int]Answer{tdAllow: Allow, tdView: ViewOnly, tdDeny: Deny} {
		got, err := askTaskDialog("AnyPC — test", "text", "Allow", "Deny", "View only", AskTimeout, 0, click)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("кнопка %d: %v, ждали %v", click, got, want)
		}
	}
	start := time.Now()
	got, err := askTaskDialog("AnyPC — test", "timeout", "Allow", "Deny", "View only", 500*time.Millisecond, 0, 0)
	if err != nil || got != Deny {
		t.Errorf("таймаут: %v %v", got, err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("таймаут 0,5 с сработал за %v", d)
	}
}

// TestTaskDialogDelay — «Разрешить» выключена первые delay: нажатие сразу не срабатывает, окно уходит по таймеру — отказ.
func TestTaskDialogDelay(t *testing.T) {
	got, err := askTaskDialog("AnyPC — test", "delay", "Allow", "Deny", "View only", 1500*time.Millisecond, 3*time.Second, tdAllow)
	if err != nil || got != Deny {
		t.Errorf("нажатие выключенной «Разрешить»: %v %v", got, err)
	}
}
