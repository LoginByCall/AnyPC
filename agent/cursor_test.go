package agent

import (
	"testing"
	"time"
)

func TestCursorMsg(t *testing.T) {
	m := &Monitor{X: 1920, Y: 0, W: 1280, H: 720}
	if c := cursorMsg(m, 1920, 0, "text", true); c.X != 0 || c.Y != 0 || c.C != "text" {
		t.Errorf("левый верх: %+v", c)
	}
	if c := cursorMsg(m, 1920+1279, 719, "default", true); c.X != 65535 || c.Y != 65535 {
		t.Errorf("правый низ: %+v", c)
	}
	for _, c := range []ctlMsg{cursorMsg(m, 100, 100, "default", true), cursorMsg(m, 2000, 100, "default", false), cursorMsg(nil, 0, 0, "default", true), cursorMsg(m, 1920+1280, 0, "default", true)} {
		if c.C != "none" || c.X != 0 || c.Y != 0 {
			t.Errorf("вне монитора/скрыт: %+v", c)
		}
	}
	for name, want := range map[string]string{"left_ptr": "default", "xterm": "text", "hand2": "pointer", "sb_h_double_arrow": "ew-resize", "left_ptr_watch": "progress", "watch": "wait", "crossed_circle": "not-allowed", "crosshair": "crosshair", "fleur": "move", "": "default"} {
		if got := cssCursor(name); got != want {
			t.Errorf("%q: %s, ждали %s", name, got, want)
		}
	}
}

// TestRateVideo — профиль «видео»: частота кадров не снижается с битрейтом; смена профиля перезапускает захват один раз.
func TestRateVideo(t *testing.T) {
	r := rate{max: 4000, cur: 4000, fpsMax: 30, video: true}
	r.report(time.Unix(1000, 0), 0.5, 0)
	if r.cur != 2400 || r.fps() != 30 {
		t.Fatalf("видео: %d кбит/с %d к/с, ждали 2400/30", r.cur, r.fps())
	}
	n := 0
	s := &session{capCancel: func() { n++ }}
	if !s.setVideo(true) || s.setVideo(true) || n != 1 || !s.switched.Load() || !s.rate.video {
		t.Errorf("setVideo: перезапусков %d", n)
	}
	if !s.setVideo(false) || n != 2 || s.rate.video {
		t.Errorf("обратно в текст: перезапусков %d", n)
	}
}
