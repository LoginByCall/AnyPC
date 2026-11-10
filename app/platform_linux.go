package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"anypc/agent"
)

const openCmd = "xdg-open"

func hostCapture(enc string) func(ctx context.Context, c agent.Cap) (*exec.Cmd, error) {
	return agent.LinuxCapture(enc)
}

// hostLocked — на Linux не проверяется: экран блокировки X11 — обычное окно, захват идёт; отказ портала Wayland
// ловит общий признак «захват без кадров» (F7).
var hostLocked func() bool

func platformKind() string {
	if agent.Wayland {
		return "Wayland"
	}
	return "X11"
}

// downloads — папка загрузок по XDG (на русской Ubuntu это ~/Загрузки).
func downloads() string {
	if out, err := exec.Command("xdg-user-dir", "DOWNLOAD").Output(); err == nil {
		if d := strings.TrimSpace(string(out)); d != "" {
			return d
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Downloads")
}

var hint = map[string]string{
	"zenity":         "без него нет плашки сессии, и подключения отклоняются (sudo apt install zenity)",
	"ffmpeg":         "нужен для захвата экрана X11 (sudo apt install ffmpeg)",
	"xclip":          "без него не работает буфер обмена (sudo apt install xclip)",
	"gst-launch-1.0": "нужен для захвата экрана Wayland (sudo apt install gstreamer1.0-tools gstreamer1.0-pipewire gstreamer1.0-plugins-ugly)",
	"wl-paste":       "без него не работает буфер обмена (sudo apt install wl-clipboard)",
}

func deps() []string {
	if agent.Wayland {
		return []string{"zenity", "gst-launch-1.0", "wl-paste"}
	}
	return []string{"zenity", "ffmpeg", "xclip"}
}

// serviceUnit — пользовательская служба systemd: старт с графическим сеансом (нужны DISPLAY/WAYLAND_DISPLAY и D-Bus
// сеанса — их импортирует сам сеанс), окно в браузере не открывается (адрес окна — в журнале).
func serviceUnit(exe string) string {
	return "[Unit]\nDescription=AnyPC remote access host\nAfter=graphical-session.target\nPartOf=graphical-session.target\n\n" +
		"[Service]\nExecStart=" + unitQuote(exe) + " --no-browser\nRestart=on-failure\nRestartSec=5\n\n" +
		"[Install]\nWantedBy=graphical-session.target\n"
}

// unitQuote — путь в кавычках по правилам systemd: \\ и \" внутри кавычек, %% — спецификаторы, $$ — подстановка переменных;
// Юникод (~/Загрузки) — как есть.
func unitQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$").Replace(s) + `"`
}

func unitPath() string {
	d, _ := os.UserConfigDir()
	return filepath.Join(d, "systemd", "user", "anypc.service")
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", append([]string{"--user"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl --user %s: %v %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func installService(exe string) error {
	p := unitPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(serviceUnit(exe)), 0o644); err != nil {
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	return systemctl("enable", "--now", "anypc.service")
}

func uninstallService() error {
	systemctl("disable", "--now", "anypc.service") // нет службы — не ошибка
	if err := os.Remove(unitPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return systemctl("daemon-reload")
}

func serviceState() string {
	if _, err := os.Stat(unitPath()); err != nil {
		return "нет"
	}
	out, _ := exec.Command("systemctl", "--user", "is-active", "anypc.service").Output()
	return "включён, служба " + strings.TrimSpace(string(out))
}
