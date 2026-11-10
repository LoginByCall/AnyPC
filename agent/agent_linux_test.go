package agent

import (
	"bytes"
	"context"
	"errors"
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
	cmd, _ := d.capture(ctx, Cap{FPS: 30, Kbps: 1000, Cursor: true}, "libx264", nil)
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

type stubDesk struct{ live bool }

func (stubDesk) capture(context.Context, Cap, string, *Monitor) (*exec.Cmd, error) { return nil, nil }
func (stubDesk) input(event, *Monitor) error                                       { return nil }
func (d stubDesk) alive() bool                                                     { return d.live }

// TestInputNoPortal — N5: ввод на Wayland не открывает сеанс портала (окно согласия), только берёт живой.
// Раньше sendInput звал getDesktop: клавиша клиента, ждавшая, пока открыто первое окно, после «Отмена»
// открывала второе. Захват (getDesktop) открывает по-прежнему.
func TestInputNoPortal(t *testing.T) {
	oldW, oldOpen, oldDesk := Wayland, openPortal, desk
	t.Cleanup(func() { Wayland, openPortal, desk = oldW, oldOpen, oldDesk })
	Wayland = true
	opened := 0
	openPortal = func() (desktop, error) { opened++; return nil, errors.New("заглушка портала") }
	for _, d := range []desktop{nil, stubDesk{false}} { // нет сеанса; сеанс закрыт («Отмена», закрыл человек)
		desk = d
		if got, err := inputDesktop(); err == nil || got != nil || opened != 0 {
			t.Fatalf("ввод при %v: %v, %v, окон портала %d", d, got, err, opened)
		}
	}
	desk = stubDesk{true}
	if got, err := inputDesktop(); err != nil || got != desk || opened != 0 {
		t.Fatalf("живой сеанс: %v, %v, окон портала %d", got, err, opened)
	}
	desk = nil
	if getDesktop(); opened != 1 {
		t.Fatalf("захват открыл окон портала: %d", opened)
	}
}
