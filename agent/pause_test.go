package agent

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// fakeVP9 — кодер-заглушка для TestPause (без libvpx): считает вызовы encode, то есть выдачу кадров кодером.
type fakeVP9 struct{ n *atomic.Int64 }

func (fakeVP9) setRate(int, int) error { return nil }
func (f fakeVP9) encode([]byte, time.Duration, bool) ([]byte, bool, error) {
	f.n.Add(1)
	return []byte{1}, false, nil // непустой кадр: идёт в WriteSample (трек не привязан — no-op)
}
func (fakeVP9) close() {}

// y4mFeed — бесконечный поток YUV4MPEG2 w×h в пайп (кадр каждые 2 мс, пока жив ctx): вход для streamVP9.
func y4mFeed(ctx context.Context, w, h int) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		fmt.Fprintf(pw, "YUV4MPEG2 W%d H%d F30:1 C420\n", w, h)
		buf := make([]byte, w*h+2*((w+1)/2)*((h+1)/2))
		for ctx.Err() == nil {
			if _, err := pw.Write([]byte("FRAME\n")); err != nil {
				return
			}
			if _, err := pw.Write(buf); err != nil {
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
		pw.Close()
	}()
	return pr
}

// TestPause — REQ-F-27: пауза останавливает выдачу кадров кодером, возобновление — снова запускает; пауза не закрывает
// плашку (REQ-F-15: сессия жива). Кодер VP9 подменён заглушкой (без libvpx), считаем вызовы encode.
func TestPause(t *testing.T) {
	old := newVP9Enc
	var n atomic.Int64
	newVP9Enc = func(int, int, int) (vp9Encoder, error) { return fakeVP9{&n}, nil }
	defer func() { newVP9Enc = old }()

	a := newAgent("", "123456789", nil)
	s := &session{cid: "c1"}
	s.authed.Store(true)
	s.vp9 = true
	s.rate = rate{max: 1000, cur: 1000, fpsMax: 30}
	var closed atomic.Int32
	s.closeInd = func() { closed.Add(1) } // плашка: пауза её закрывать не должна
	track, err := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP9}, "v", "s")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.streamVP9(ctx, s, y4mFeed(ctx, 16, 16), track, Cap{Kbps: 1000}, func() {})

	grew := func(from int64, what string) {
		for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
			if n.Load() > from {
				return
			}
		}
		t.Fatalf("%s: кодер не выдал кадр (кадров %d)", what, n.Load())
	}
	grew(0, "старт") // поток пошёл

	s.setPaused(true)                  // фоновая вкладка
	time.Sleep(150 * time.Millisecond) // дать уйти кадру «в полёте»
	a1 := n.Load()
	time.Sleep(300 * time.Millisecond)
	if b := n.Load(); b != a1 {
		t.Errorf("в паузе кодер выдал ещё %d кадров (с %d до %d)", b-a1, a1, b)
	}
	if closed.Load() != 0 {
		t.Errorf("пауза закрыла плашку (закрытий %d)", closed.Load())
	}

	paused := n.Load()
	s.setPaused(false) // вернулись в активную вкладку
	grew(paused, "возобновление")
	if closed.Load() != 0 {
		t.Errorf("возобновление закрыло плашку (закрытий %d)", closed.Load())
	}
}

// TestPauseIDR — возобновление: H.264/ffmpeg запрашивает IDR перезапуском захвата (путь PLI), VP9 в процессе — нет
// (следующий разностный кадр кодируется от сохранённой опорной). Пауза захват не трогает.
func TestPauseIDR(t *testing.T) {
	s := &session{cid: "h"} // H.264/ffmpeg: inproc=false
	var cancels atomic.Int32
	s.capCancel = func() { cancels.Add(1) }
	s.capStart = time.Now().Add(-time.Hour)
	s.setPaused(true)
	if cancels.Load() != 0 {
		t.Errorf("пауза перезапустила захват (%d)", cancels.Load())
	}
	s.setPaused(false)
	if cancels.Load() != 1 {
		t.Errorf("возобновление H.264 не запросило IDR: перезапусков %d, ждали 1", cancels.Load())
	}

	s2 := &session{cid: "v"} // VP9 в процессе
	var c2 atomic.Int32
	s2.capCancel = func() { c2.Add(1) }
	s2.inproc.Store(true)
	s2.setPaused(true)
	s2.setPaused(false)
	if c2.Load() != 0 {
		t.Errorf("VP9: возобновление перезапустило захват (%d), ждали 0 — хватает разностного кадра", c2.Load())
	}
}
