package agent

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/jezek/xgb/xproto"
)

// Тесты не трогают рабочий стол того, кто их запускает: ввод, плашка, буфер обмена — заглушки.
func TestMain(m *testing.M) {
	fakeDesktop = true
	os.Exit(m.Run())
}

func TestEvdevAndBitrate(t *testing.T) {
	for in, want := range map[string]uint16{`{"t":"k","c":"KeyA","d":true}`: 30, `{"t":"k","c":"ArrowUp","d":true}`: 103,
		`{"t":"k","c":"MetaLeft","d":true}`: 125, `{"t":"k","c":"NumLock","d":true}`: 69, `{"t":"k","c":"ControlRight","d":true}`: 97, `{"t":"k","c":"F12","d":true}`: 88} {
		e, _ := decode([]byte(in))
		if got := evdevCode(e); got != want {
			t.Errorf("%s → evdev %d, ждали %d", in, got, want)
		}
	}
	for in, want := range map[string]int{"4M": 4000, "1500k": 1500, "800": 800, "x": 4000} {
		if Kbps(in) != want {
			t.Errorf("Kbps(%q) = %d", in, Kbps(in))
		}
	}
	for c := range scancodes { // у каждой клавиши таблицы есть код evdev
		e, _ := decode([]byte(`{"t":"k","c":"` + c + `","d":true}`))
		if evdevCode(e) == 0 {
			t.Errorf("%s: нет кода evdev", c)
		}
	}
}

// TestX11 — бэкенд X11 на виртуальном дисплее Xvfb :97 (не на рабочем столе того, кто запускает).
func TestX11(t *testing.T) {
	xvfb, err := exec.LookPath("Xvfb")
	if err != nil {
		t.Skip("нет Xvfb (sudo apt install xvfb)")
	}
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("нет ffmpeg")
	}
	srv := exec.Command(xvfb, ":97", "-screen", "0", "1280x720x24", "-nolisten", "tcp")
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { srv.Process.Kill(); srv.Wait() }()
	for i := 0; i < 50; i++ {
		if _, err := os.Stat("/tmp/.X11-unix/X97"); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Setenv("DISPLAY", ":97")
	d, err := newX11()
	if err != nil {
		t.Fatal(err)
	}
	x := d.(*x11)
	defer x.c.Close()

	// курсор в центр: 32767/65535 от 1280×720
	e, _ := decode([]byte(`{"t":"m","x":32767,"y":32767}`))
	d.input(e, nil)
	x.c.Sync()
	ptr, err := xproto.QueryPointer(x.c, x.root).Reply()
	if err != nil || ptr.RootX != 639 || ptr.RootY != 359 {
		t.Fatalf("курсор: %+v %v", ptr, err)
	}
	// клавиша: нажата → в карте клавиш бит keycode = evdev+8 установлен
	e, _ = decode([]byte(`{"t":"k","c":"KeyA","d":true}`))
	d.input(e, nil)
	x.c.Sync()
	km, _ := xproto.QueryKeymap(x.c).Reply()
	if km == nil || km.Keys[(30+8)/8]&(1<<((30+8)%8)) == 0 {
		t.Fatal("клавиша A не нажата на X-сервере")
	}
	e, _ = decode([]byte(`{"t":"k","c":"KeyA","d":false}`))
	d.input(e, nil)

	// захват: ffmpeg x11grab отдаёт H.264 Annex-B
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd, _ := d.capture(ctx, 30, "1M", "libx264", nil)
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(out, head); err != nil || !bytes.Equal(head, []byte{0, 0, 0, 1}) {
		t.Fatalf("захват X11: %x %v", head, err)
	}
	cancel()
	cmd.Wait()
}
