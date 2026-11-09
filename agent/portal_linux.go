//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"anypc/hub"

	"github.com/godbus/dbus/v5"
)

// portal — Wayland: xdg-desktop-portal RemoteDesktop + ScreenCast (один сеанс на захват и ввод).
// Первое подключение показывает на хосте диалог согласия; restore_token (persist_mode=2) избавляет
// от него в следующие разы. Захват — gst-launch-1.0 pipewiresrc из выданного порталом PipeWire-fd.
// Не проверено автоматически: нужна живая Wayland-сессия (V3).
type portal struct {
	mu      sync.Mutex
	conn    *dbus.Conn
	obj     dbus.BusObject
	session dbus.ObjectPath
	node    uint32
	w, h    float64
	fd      int
	closed  atomic.Bool
	wheelV  int32
	wheelH  int32
}

const (
	pDest = "org.freedesktop.portal.Desktop"
	pPath = dbus.ObjectPath("/org/freedesktop/portal/desktop")
	pRD   = "org.freedesktop.portal.RemoteDesktop"
	pSC   = "org.freedesktop.portal.ScreenCast"
)

type vmap = map[string]dbus.Variant

func tokenFile() string {
	d, _ := os.UserConfigDir()
	return filepath.Join(d, "AnyPC", "portal-token")
}

func newPortal() (desktop, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, err
	}
	p := &portal{conn: conn, obj: conn.Object(pDest, pPath)}
	if err := p.start(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("портал Wayland: %w", err)
	}
	return p, nil
}

// request вызывает метод портала и ждёт сигнала Request.Response (там может быть диалог с человеком).
func (p *portal) request(method string, args ...any) (vmap, error) {
	token := "anypc" + hub.RandDigits(10)
	sender := strings.ReplaceAll(strings.TrimPrefix(p.conn.Names()[0], ":"), ".", "_")
	path := dbus.ObjectPath("/org/freedesktop/portal/desktop/request/" + sender + "/" + token)
	match := []dbus.MatchOption{dbus.WithMatchObjectPath(path), dbus.WithMatchInterface("org.freedesktop.portal.Request"), dbus.WithMatchMember("Response")}
	if err := p.conn.AddMatchSignal(match...); err != nil {
		return nil, err
	}
	defer p.conn.RemoveMatchSignal(match...)
	ch := make(chan *dbus.Signal, 8)
	p.conn.Signal(ch)
	defer p.conn.RemoveSignal(ch)

	args[len(args)-1].(vmap)["handle_token"] = dbus.MakeVariant(token) // опции — последний аргумент
	if c := p.obj.Call(method, 0, args...); c.Err != nil {
		return nil, c.Err
	}
	timeout := time.After(3 * time.Minute) // человек отвечает на диалог согласия
	for {
		select {
		case s := <-ch:
			if s.Path != path || len(s.Body) < 2 {
				continue
			}
			if code, _ := s.Body[0].(uint32); code != 0 {
				return nil, fmt.Errorf("%s: отказ или отмена (%d)", method, code)
			}
			res, _ := s.Body[1].(map[string]dbus.Variant)
			return res, nil
		case <-timeout:
			return nil, fmt.Errorf("%s: нет ответа", method)
		}
	}
}

func (p *portal) start() error {
	res, err := p.request(pRD+".CreateSession", vmap{"session_handle_token": dbus.MakeVariant("anypc" + hub.RandDigits(10))})
	if err != nil {
		return err
	}
	sh, _ := res["session_handle"].Value().(string)
	if sh == "" {
		if op, ok := res["session_handle"].Value().(dbus.ObjectPath); ok {
			sh = string(op)
		}
	}
	if sh == "" {
		return errors.New("нет session_handle")
	}
	p.session = dbus.ObjectPath(sh)

	dev := vmap{"types": dbus.MakeVariant(uint32(1 | 2)), "persist_mode": dbus.MakeVariant(uint32(2))} // клавиатура | мышь
	if b, err := os.ReadFile(tokenFile()); err == nil && len(b) > 0 {
		dev["restore_token"] = dbus.MakeVariant(strings.TrimSpace(string(b)))
	}
	if _, err := p.request(pRD+".SelectDevices", p.session, dev); err != nil {
		return err
	}
	src := vmap{"types": dbus.MakeVariant(uint32(1)), "multiple": dbus.MakeVariant(false), "cursor_mode": dbus.MakeVariant(uint32(2))} // монитор, курсор в кадре
	if _, err := p.request(pSC+".SelectSources", p.session, src); err != nil {
		return err
	}
	res, err = p.request(pRD+".Start", p.session, "", vmap{})
	if err != nil {
		return err
	}
	if tok, ok := res["restore_token"].Value().(string); ok && tok != "" {
		os.MkdirAll(filepath.Dir(tokenFile()), 0o700)
		os.WriteFile(tokenFile(), []byte(tok), 0o600)
	}
	if err := p.parseStream(res["streams"].Value()); err != nil {
		return err
	}
	var fd dbus.UnixFD
	if err := p.obj.Call(pSC+".OpenPipeWireRemote", 0, p.session, vmap{}).Store(&fd); err != nil {
		return err
	}
	p.fd = int(fd)

	// Пользователь остановил показ экрана (значок в панели GNOME) → сеанс пересоздаётся при следующем захвате.
	closed := []dbus.MatchOption{dbus.WithMatchObjectPath(p.session), dbus.WithMatchInterface("org.freedesktop.portal.Session"), dbus.WithMatchMember("Closed")}
	if err := p.conn.AddMatchSignal(closed...); err == nil {
		ch := make(chan *dbus.Signal, 1)
		p.conn.Signal(ch)
		go func() {
			for s := range ch {
				if s.Path == p.session && s.Name == "org.freedesktop.portal.Session.Closed" {
					p.closed.Store(true)
					return
				}
			}
		}()
	}
	return nil
}

// parseStream: streams — a(ua{sv}); берём первый поток: PipeWire node и логический размер (ii).
func (p *portal) parseStream(v any) error {
	list, ok := v.([][]any)
	if !ok || len(list) == 0 || len(list[0]) < 2 {
		return fmt.Errorf("нет потоков экрана (%T)", v)
	}
	p.node, _ = list[0][0].(uint32)
	props, _ := list[0][1].(map[string]dbus.Variant)
	if sz, ok := props["size"].Value().([]any); ok && len(sz) == 2 {
		w, _ := sz[0].(int32)
		h, _ := sz[1].(int32)
		p.w, p.h = float64(w), float64(h)
	}
	if p.node == 0 || p.w <= 0 || p.h <= 0 {
		return fmt.Errorf("поток без node или размера: %v", list[0])
	}
	return nil
}

func (p *portal) alive() bool { return !p.closed.Load() }

// ponytail: профиль «видео» (масштаб 720p) в конвейере GStreamer не реализован — только к/с из c.
func (p *portal) capture(ctx context.Context, c Cap, _ string, _ *Monitor) (*exec.Cmd, error) {
	fps := c.FPS
	deskMu.Lock()                 // getDesktop закрывает fd мёртвого портала — номер не должен уйти чужому сокету до Dup
	dup, err := syscall.Dup(p.fd) // свой экземпляр fd на каждый запуск захвата
	deskMu.Unlock()
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dup), "pipewire")
	go func() { <-ctx.Done(); f.Close() }()
	pipeline := fmt.Sprintf("pipewiresrc fd=3 path=%d do-timestamp=true keepalive-time=1000 ! videoconvert ! videorate"+
		" ! video/x-raw,format=I420,framerate=%d/1 ! x264enc tune=zerolatency speed-preset=ultrafast bitrate=%d key-int-max=%d bframes=0 byte-stream=true"+
		" ! video/x-h264,profile=constrained-baseline,stream-format=byte-stream ! fdsink fd=1", p.node, fps, c.Kbps, fps)
	cmd := exec.CommandContext(ctx, "gst-launch-1.0", append([]string{"-q"}, strings.Fields(pipeline)...)...)
	cmd.ExtraFiles = []*os.File{f} // станет fd 3 в дочернем процессе
	return cmd, nil
}

// notify — ввод через портал; без ожидания ответа, порядок сохраняется соединением D-Bus.
func (p *portal) notify(method string, args ...any) error {
	return p.obj.Call(pRD+"."+method, dbus.FlagNoReplyExpected, append([]any{p.session, vmap{}}, args...)...).Err
}

func (p *portal) input(e event, _ *Monitor) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e.key {
		code := evdevCode(e)
		if code == 0 {
			return errors.New("клавиша без кода evdev")
		}
		state := uint32(1)
		if e.flags&kUp != 0 {
			state = 0
		}
		return p.notify("NotifyKeyboardKeycode", int32(code), state)
	}
	switch f := e.flags; {
	case f&mMove != 0:
		return p.notify("NotifyPointerMotionAbsolute", p.node, float64(e.x)*p.w/65535, float64(e.y)*p.h/65535)
	case f&mWheel != 0: // ось 0; положительные шаги — вниз, а у нас +120 — вверх
		if steps := notches(&p.wheelV, e.data); steps != 0 {
			return p.notify("NotifyPointerAxisDiscrete", uint32(0), -steps)
		}
	case f&mHWheel != 0:
		if steps := notches(&p.wheelH, e.data); steps != 0 {
			return p.notify("NotifyPointerAxisDiscrete", uint32(1), steps)
		}
	default:
		for i, btn := range []int32{0x110, 0x112, 0x111} { // BTN_LEFT, BTN_MIDDLE, BTN_RIGHT — как btnFlags
			if f&btnFlags[i][1] != 0 {
				return p.notify("NotifyPointerButton", btn, uint32(1))
			}
			if f&btnFlags[i][0] != 0 {
				return p.notify("NotifyPointerButton", btn, uint32(0))
			}
		}
	}
	return nil
}
