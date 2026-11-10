//go:build linux

package agent

// Хост на Linux: X11 (ffmpeg x11grab + XTest) или Wayland (портал RemoteDesktop/ScreenCast + PipeWire).
// Плашка и выбор файла — zenity; буфер обмена — xclip (X11) или wl-clipboard (Wayland).

import (
	"context"
	"errors"
	"hash/crc32"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Wayland — сессия Wayland: захват и ввод только через портал (XWayland не видит чужие окна).
var Wayland = os.Getenv("XDG_SESSION_TYPE") == "wayland" || (os.Getenv("WAYLAND_DISPLAY") != "" && os.Getenv("DISPLAY") == "")

// fakeDesktop — только для тестов (agent_linux_test.go): не трогать настоящий рабочий стол,
// буфер обмена и не открывать окна у человека, на чьей машине идут тесты.
var fakeDesktop bool

type desktop interface {
	capture(ctx context.Context, c Cap, enc string, m *Monitor) (*exec.Cmd, error)
	input(e event, m *Monitor) error
	alive() bool
}

var (
	deskMu     sync.Mutex
	desk       desktop
	openPortal = newPortal // в тестах подменяется: не открывать окно портала у того, кто их запускает
)

// getDesktop создаёт бэкенд лениво: на Wayland это диалог согласия портала, он должен появиться
// при подключении, а не при запуске. Закрытый пользователем сеанс портала пересоздаётся.
func getDesktop() (desktop, error) {
	deskMu.Lock()
	defer deskMu.Unlock()
	if desk != nil && desk.alive() {
		return desk, nil
	}
	if p, ok := desk.(*portal); ok { // закрытый сеанс: dbus-соединение и fd PipeWire иначе висят до выхода
		p.conn.Close()
		syscall.Close(p.fd)
	}
	var err error
	if Wayland {
		desk, err = openPortal()
	} else {
		desk, err = newX11()
	}
	if err != nil {
		desk = nil
	}
	return desk, err
}

// LinuxCapture — Agent.Capture для Linux.
func LinuxCapture(enc string) func(ctx context.Context, c Cap) (*exec.Cmd, error) {
	return func(ctx context.Context, c Cap) (*exec.Cmd, error) {
		d, err := getDesktop()
		if err != nil {
			return nil, err
		}
		var m *Monitor
		if ms := monitors(); c.Mon >= 0 && c.Mon < len(ms) {
			m = &ms[c.Mon]
		}
		return d.capture(ctx, c, enc, m)
	}
}

func init() {
	if !Wayland { // Wayland: курсор рисует портал (cursor_mode 2), отдельно его не отдать
		cursorInfo = x11Cursor
	}
}

func x11Cursor() (int, int, string, bool) {
	if fakeDesktop {
		return 0, 0, "", false
	}
	d, err := getDesktop()
	if err != nil {
		return 0, 0, "", false
	}
	return d.(*x11).cursor()
}

func sendInput(e event, m *Monitor) error {
	if fakeDesktop {
		return nil
	}
	d, err := inputDesktop()
	if err != nil {
		return err
	}
	return d.input(e, m)
}

var errNoPortal = errors.New("нет сеанса портала (его открывает захват экрана)")

// inputDesktop — бэкенд для ввода (N5). На Wayland сеанс портала (окно согласия) открывает только захват: ввод,
// ждавший deskMu, пока окно было на экране, после «Отмена» иначе открывал второе окно; то же — отпускание
// зажатых клавиш при закрытии сессии. На X11 бэкенд без окон — создаётся лениво, как раньше.
func inputDesktop() (desktop, error) {
	if !Wayland {
		return getDesktop()
	}
	deskMu.Lock()
	defer deskMu.Unlock()
	if desk != nil && desk.alive() {
		return desk, nil
	}
	return nil, errNoPortal
}

// monitors — X11: RandR; Wayland: nil (монитор выбирает человек в диалоге портала).
func monitors() []Monitor {
	if fakeDesktop || Wayland {
		return nil
	}
	d, err := getDesktop()
	if err != nil {
		return nil
	}
	return d.(*x11).monitors()
}

func hideWindow(*exec.Cmd) {}

func sysLang() string {
	for _, v := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if l := os.Getenv(v); len(l) >= 2 && l != "C" && l != "POSIX" {
			return strings.ToLower(l[:2])
		}
	}
	return "en"
}

func pangoEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// showIndicator — плашка REQ-F-15: окно zenity; закрыл человек → разорвать сессию.
func showIndicator(cid string, mode plaqueMode, onUserClose func()) (func(), error) {
	if fakeDesktop {
		return func() {}, nil
	}
	bin, err := exec.LookPath("zenity")
	if err != nil {
		return nil, errors.New("нет zenity — установите пакет zenity")
	}
	title, text := plaqueText(sysLang(), cid, mode)
	cmd := exec.Command(bin, "--warning", "--no-wrap", "--title="+title, "--text="+pangoEscape(text))
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	var byUs atomic.Bool
	go func() {
		cmd.Wait()
		if !byUs.Load() {
			onUserClose()
		}
	}()
	return func() { byUs.Store(true); cmd.Process.Kill() }, nil
}

// pickFile — окно выбора файла на хосте (zenity работает и в X11, и в Wayland).
func pickFile() (string, bool) {
	if fakeDesktop {
		return "", false
	}
	out, err := exec.Command("zenity", "--file-selection", "--title=AnyPC").Output()
	p := strings.TrimRight(string(out), "\n")
	return p, err == nil && p != ""
}

func clipCmds() (get, set []string) {
	if Wayland {
		return []string{"wl-paste", "--no-newline", "--type", "text/plain"}, []string{"wl-copy", "--type", "text/plain"}
	}
	return []string{"xclip", "-selection", "clipboard", "-o"}, []string{"xclip", "-selection", "clipboard", "-i"}
}

// ClipText — текст буфера обмена ("" — нет текста или нет утилиты).
func ClipText() (string, error) {
	if fakeDesktop {
		return "", nil
	}
	g, _ := clipCmds()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, g[0], g[1:]...).Output()
	if err != nil {
		return "", nil // пусто или не текст
	}
	return string(out), nil
}

func SetClipText(s string) error {
	if fakeDesktop {
		return nil
	}
	_, set := clipCmds()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, set[0], set[1:]...)
	cmd.Stdin = strings.NewReader(s)
	if err := cmd.Run(); err != nil { // xclip/wl-copy уходят в фон и держат выделение сами
		log.Printf("буфер обмена: %v", err)
		return err
	}
	return nil
}

// ClipSeq — признак изменения буфера: на Linux нет счётчика, поэтому контрольная сумма текста.
// ponytail: опрос утилитой раз в 0,5 с во время сессии; события XFixes/Wayland — если начнёт мешать.
func ClipSeq() uint32 {
	t, _ := ClipText()
	return crc32.ChecksumIEEE([]byte(t))
}

// AskAccept — окно «Разрешить / Отклонить» (REQ-F-03); без ответа AskTimeout или без zenity → отказ.
func AskAccept(cid, peer string) Answer {
	if fakeDesktop {
		return Allow
	}
	title, text, yes, no, view := askText(sysLang(), cid, peer)
	// дополнительная кнопка: zenity печатает её подпись и выходит с кодом 1, как «Отклонить»;
	// --default-cancel — Enter = «Отклонить»; перенос строк по ширине вместо --no-wrap (длинное предупреждение)
	out, err := exec.Command("zenity", "--question", "--default-cancel", "--width=460", "--title="+title, "--text="+pangoEscape(text),
		"--ok-label="+yes, "--cancel-label="+no, "--extra-button="+view, "--timeout="+strconv.Itoa(int(AskTimeout.Seconds()))).Output()
	switch {
	case err == nil:
		return Allow
	case strings.TrimSpace(string(out)) == view:
		return ViewOnly
	}
	return Deny
}
