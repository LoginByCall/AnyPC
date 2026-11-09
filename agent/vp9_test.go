//go:build vp9

package agent

import (
	"testing"
	"time"
)

// TestVP9 — кодер в процессе: первый кадр ключевой, дальше нет; смена битрейта без ключевого; ключевой по запросу.
func TestVP9(t *testing.T) {
	w, h := 320, 240
	e, err := newVP9(w, h, 500)
	if err != nil {
		t.Fatal(err)
	}
	defer e.close()
	frame := make([]byte, w*h*3/2)
	for i := range frame {
		frame[i] = byte(i)
	}
	var sizes []int
	for i := range 10 {
		frame[i*64] ^= 0xff // немного движения
		out, key, err := e.encode(frame, 33*time.Millisecond, false)
		if err != nil || len(out) == 0 || key != (i == 0) {
			t.Fatalf("кадр %d: %v, %d байт, key=%v", i, err, len(out), key)
		}
		sizes = append(sizes, len(out))
	}
	if err := e.setBitrate(200); err != nil {
		t.Fatal(err)
	}
	if _, key, err := e.encode(frame, 33*time.Millisecond, false); err != nil || key {
		t.Fatalf("после смены битрейта: %v key=%v", err, key)
	}
	if _, key, err := e.encode(frame, 33*time.Millisecond, true); err != nil || !key {
		t.Fatalf("принудительный ключевой: %v key=%v", err, key)
	}
	if _, _, err := e.encode(frame[:10], 33*time.Millisecond, false); err == nil {
		t.Fatal("кадр неверного размера принят")
	}
	t.Logf("размеры кадров: %v", sizes)
}

// BenchmarkVP9 — 1080p, синтетическое движение (бегущая полоса на шуме): CPU на кадр при настройках хоста.
func BenchmarkVP9(b *testing.B) {
	w, h := 1920, 1080
	e, err := newVP9(w, h, 4000)
	if err != nil {
		b.Fatal(err)
	}
	defer e.close()
	frame := make([]byte, w*h*3/2)
	for i := range frame {
		frame[i] = byte(i * 7)
	}
	b.ResetTimer()
	total := 0
	for i := 0; b.Loop(); i++ {
		x := (i * 16) % w
		for y := 0; y < h; y++ {
			frame[y*w+x] = 0xff
		}
		out, _, err := e.encode(frame, 33*time.Millisecond, false)
		if err != nil {
			b.Fatal(err)
		}
		total += len(out)
	}
	b.ReportMetric(float64(total)*8/1000/float64(b.N)*30, "kbit/s")
}
