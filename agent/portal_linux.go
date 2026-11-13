//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
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
	w, h    float64 // размер потока для NotifyPointerMotionAbsolute (логический × масштаб mutter, mutterScale)
	x, y    int32   // логическое положение потока (props position) — по нему ищем монитор в mutterScale
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
			if code, _ := s.Body[0].(uint32); code == 1 { // 1 — человек нажал «Отмена», 2 — прервано иначе
				return nil, fmt.Errorf("%s: %w", method, ErrCaptureDenied)
			} else if code != 0 {
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
	if k := mutterScale(p.conn, p.x, p.y); k != 1 {
		log.Printf("портал: поток %.0f×%.0f логических, масштаб mutter %.3f — координаты мыши в %.0f×%.0f", p.w, p.h, k, p.w*k, p.h*k)
		p.w, p.h = p.w*k, p.h*k
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
	if pos, ok := props["position"].Value().([]any); ok && len(pos) == 2 {
		p.x, _ = pos[0].(int32)
		p.y, _ = pos[1].(int32)
	}
	if p.node == 0 || p.w <= 0 || p.h <= 0 {
		return fmt.Errorf("поток без node или размера: %v", list[0])
	}
	return nil
}

// mutterScale — масштаб монитора GNOME в точке (x, y) логических координат, если mutter делит абсолютные координаты
// потока на масштаб (layout-mode «logical», по умолчанию в Wayland): портал сообщает логический размер потока
// (1536×960), а NotifyPointerMotionAbsolute mutter считает в точках кадра (2560×1600 при 166 %) — без поправки курсор
// хоста уходил к 60 % пути (канбан 2026-11-13, «указатели расползлись»; FINDINGS). Не GNOME (KDE) или ошибка — 1.
func mutterScale(conn *dbus.Conn, x, y int32) float64 {
	c := conn.Object("org.gnome.Mutter.DisplayConfig", "/org/gnome/Mutter/DisplayConfig").Call("org.gnome.Mutter.DisplayConfig.GetCurrentState", 0)
	if c.Err != nil {
		return 1
	}
	return scaleFrom(c.Body, x, y)
}

// scaleFrom — разбор ответа GetCurrentState: (serial, monitors, logical_monitors a(iiduba(ssss)a{sv}), properties).
func scaleFrom(body []any, x, y int32) float64 {
	if len(body) < 4 {
		return 1
	}
	if props, ok := body[3].(map[string]dbus.Variant); ok {
		if m, ok := props["layout-mode"].Value().(uint32); ok && m != 1 { // 2 — physical: mutter не делит на масштаб
			return 1
		}
	}
	lms, _ := body[2].([][]any)
	for _, lm := range lms {
		if len(lm) < 3 {
			continue
		}
		lx, _ := lm[0].(int32)
		ly, _ := lm[1].(int32)
		if k, ok := lm[2].(float64); ok && lx == x && ly == y && k > 0 {
			return k
		}
	}
	return 1
}

func (p *portal) alive() bool { return !p.closed.Load() }

// ponytail: профиль «видео» (масштаб 720p) в конвейере GStreamer не реализован — только к/с из c.
func (p *portal) capture(ctx context.Context, c Cap, _ string, _ *Monitor) (*exec.Cmd, error) {
	deskMu.Lock()                 // getDesktop закрывает fd мёртвого портала — номер не должен уйти чужому сокету до Dup
	dup, err := syscall.Dup(p.fd) // свой экземпляр fd на каждый запуск захвата
	deskMu.Unlock()
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dup), "pipewire")
	go func() { <-ctx.Done(); f.Close() }()
	pipeline := fmt.Sprintf("pipewiresrc fd=3 path=%d do-timestamp=true keepalive-time=1000 ! videoconvert ! videorate ! ", p.node) + gstTail(c)
	cmd := exec.CommandContext(ctx, "gst-launch-1.0", append([]string{"-q"}, strings.Fields(pipeline)...)...)
	cmd.ExtraFiles = []*os.File{f} // станет fd 3 в дочернем процессе
	return cmd, nil
}

// gstTail — кодирование после videorate: H.264 Annex-B или (c.VP9) Y4M для кодера в процессе — как у ffmpeg (FFArgs).
// sliced-threads=false: tune=zerolatency режет кадр на слайсы по числу потоков, а длительность сэмпла ставится на слайс —
// браузер видел каждый слайс отдельным кадром: цела верхняя полоса, ниже вертикальные полосы (Ubuntu, 3440×1440, 2026-11-10).
// ponytail: нечётные размеры экрана для Y4M не выравниваются (ffmpeg-ветка делает scale) — мониторы чётные.
func gstTail(c Cap) string {
	if c.VP9 {
		return fmt.Sprintf("video/x-raw,format=I420,framerate=%d/1 ! y4menc ! fdsink fd=1", c.FPS)
	}
	return fmt.Sprintf("video/x-raw,format=I420,framerate=%d/1 ! x264enc tune=zerolatency sliced-threads=false speed-preset=ultrafast"+
		" bitrate=%d key-int-max=%d bframes=0 byte-stream=true ! video/x-h264,profile=constrained-baseline,stream-format=byte-stream ! fdsink fd=1",
		c.FPS, c.Kbps, c.FPS)
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
