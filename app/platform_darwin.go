package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"anypc/agent"
)

const openCmd = "open"

// Из launchd (автозапуск) и Finder PATH урезан до /usr/bin:/bin:/usr/sbin:/sbin — ffmpeg из Homebrew не находится.
func init() { os.Setenv("PATH", brewPath(os.Getenv("PATH"))) }

// brewPath — PATH с каталогами Homebrew (Intel /usr/local/bin, Apple Silicon /opt/homebrew/bin), если их там нет.
func brewPath(path string) string {
	for _, d := range []string{"/usr/local/bin", "/opt/homebrew/bin"} {
		if !slices.Contains(filepath.SplitList(path), d) {
			path += string(filepath.ListSeparator) + d
		}
	}
	return strings.TrimPrefix(path, string(filepath.ListSeparator))
}

// hostCapture — захват на macOS; заодно один раз просит у системы разрешения (окна появляются у человека).
func hostCapture(enc string) func(ctx context.Context, c agent.Cap) (*exec.Cmd, error) {
	if s, i := agent.Permissions(true); !s || !i {
		log.Printf("ВНИМАНИЕ: выдайте разрешения в «Системные настройки → Конфиденциальность и безопасность»: «Запись экрана» (%v) и «Универсальный доступ» (%v) — приложению, из которого запущен AnyPC (Терминал; при автозапуске — самому AnyPC); затем перезапустите AnyPC", s, i)
	}
	return agent.MacCapture(enc)
}

// hostLocked — заблокированный экран Мака: захват ждёт разблокировки (F7).
var hostLocked = agent.ScreenLocked

func platformKind() string { return "macOS" }

func downloads() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Downloads")
}

var hint = map[string]string{"ffmpeg": "нужен для захвата экрана (brew install ffmpeg)"}

func deps() []string { return []string{"ffmpeg"} }

// Автозапуск на macOS — LaunchAgent пользователя: старт при входе в графический сеанс (Aqua), перезапуск при падении.
// Процесс от launchd сам отвечает за свои разрешения TCC: «Запись экрана» и «Универсальный доступ» нужны самому AnyPC,
// а не Терминалу. Выпускной файл подписан своим сертификатом (deploy/mac.sh), требование подписи у сборок одно —
// после обновления на том же месте разрешения сохраняются; спросит заново, если файл перенесли или он подписан
// иначе (ad-hoc — сборка без связки подписи).
const launchLabel = "org.anypc.host"

func launchPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", launchLabel+".plist")
}

func launchPlist(exe string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(exe))
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>` + launchLabel + `</string>
	<key>ProgramArguments</key><array><string>` + b.String() + `</string><string>--no-browser</string></array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
	<key>LimitLoadToSessionType</key><string>Aqua</string>
	<key>ProcessType</key><string>Interactive</string>
	<key>ThrottleInterval</key><integer>10</integer>
</dict>
</plist>
`
}

// launchctl — вызов launchctl; в тестах подменяется.
var launchctl = func(args ...string) error {
	out, err := exec.Command("launchctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %v %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func guiDomain() string { return "gui/" + strconv.Itoa(os.Getuid()) }

func installService(exe string) error {
	p := launchPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(launchPlist(exe)), 0o644); err != nil {
		return err
	}
	svc := guiDomain() + "/" + launchLabel
	launchctl("bootout", svc) // прежняя копия (другой путь) — не ошибка, если её нет
	// bootout завершает службу асинхронно: bootstrap сразу за ним launchd отвергает «Bootstrap failed: 5:
	// Input/output error» (N4, повтор --install-service при работающей службе). Ждём, пока print перестанет
	// её находить (до ~5 с), и на всякий случай повторяем bootstrap.
	for i := 0; i < 50 && launchctl("print", svc) == nil; i++ {
		time.Sleep(launchWait)
	}
	var err error
	for i := range 3 {
		if i > 0 {
			time.Sleep(10 * launchWait)
		}
		if err = launchctl("bootstrap", guiDomain(), p); err == nil {
			return nil
		}
	}
	return err
}

var launchWait = 100 * time.Millisecond // шаг ожидания launchd; в тестах меньше

func uninstallService() error {
	launchctl("bootout", guiDomain()+"/"+launchLabel) // не загружен — не ошибка
	if err := os.Remove(launchPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func serviceState() string {
	if _, err := os.Stat(launchPath()); err != nil {
		return "нет"
	}
	out, _ := exec.Command("launchctl", "print", guiDomain()+"/"+launchLabel).Output()
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "state = ") {
			return "включён, " + l
		}
	}
	return "включён, не загружен"
}

// serviceHint — что сказать после --install-service.
const serviceHint = "Журнал: ~/Library/Caches/AnyPC/anypc.log. Выдайте «Запись экрана» и «Универсальный доступ» самому AnyPC (не Терминалу) в «Настройки → Конфиденциальность и безопасность»; после обновления выпускной сборки на том же месте разрешения сохраняются, после переноса файла — выдать заново"
