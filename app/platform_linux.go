package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"anypc/agent"
)

// openWindow — окно AnyPC: Chrome/Chromium/Edge отдельным приложением (--app: без вкладок; в полноэкранном режиме
// Esc, Alt+Tab и Win уходят на удалённый ПК — Keyboard Lock, а в Firefox, браузере Ubuntu по умолчанию, его нет:
// Alt+Tab срабатывал на этом ПК, владелец 2026-11-11). Нет такого браузера — браузер по умолчанию.
func openWindow(u string) {
	for _, b := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge"} {
		if p, err := exec.LookPath(b); err == nil && launch(p, "--app="+u) == nil {
			return
		}
	}
	launch("xdg-open", u)
}

// launch — запустить и не ждать (Wait в горутине — без зомби). Под systemd (служба: INVOCATION_ID) — в своём scope:
// иначе браузер попадёт в cgroup anypc.service, и остановка или обновление службы убьёт его окна.
// systemd-run быстро вышел с ошибкой (нет менеджера пользователя) — браузер напрямую, как без службы.
func launch(name string, args ...string) error {
	c, scoped := launchCmd(name, args...)
	if err := c.Start(); err != nil {
		return err
	}
	if !scoped {
		go c.Wait()
		return nil
	}
	go func() {
		done := make(chan error, 1)
		go func() { done <- c.Wait() }()
		select {
		case err := <-done:
			if err == nil {
				return
			}
			log.Printf("окно: systemd-run --scope не сработал (%v) — запускаю браузер напрямую", err) // без аргументов: в них код
			if d := exec.Command(name, args...); d.Start() == nil {
				go d.Wait()
			}
		case <-time.After(launchGrace):
		}
	}()
	return nil
}

var launchGrace = 2 * time.Second // сколько ждать отказа systemd-run

// launchCmd — команда запуска и признак «через systemd-run». --description: иначе scope назван командной строкой,
// и код окна из аргументов попадает в журнал systemd (измерено).
func launchCmd(name string, args ...string) (*exec.Cmd, bool) {
	if os.Getenv("INVOCATION_ID") != "" {
		if sr, err := exec.LookPath("systemd-run"); err == nil {
			return exec.Command(sr, append([]string{"--user", "--scope", "--quiet", "--description=AnyPC window", "--", name}, args...)...), true
		}
	}
	return exec.Command(name, args...), false
}

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

// serviceHint — что сказать после --install-service.
const serviceHint = "Журнал: journalctl --user -u anypc"

func serviceState() string {
	if _, err := os.Stat(unitPath()); err != nil {
		return "нет"
	}
	out, _ := exec.Command("systemctl", "--user", "is-active", "anypc.service").Output()
	return "включён, служба " + strings.TrimSpace(string(out))
}
