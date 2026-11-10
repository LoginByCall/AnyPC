package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"anypc/agent"
)

const openCmd = "open"

// hostCapture — захват на macOS; заодно один раз просит у системы разрешения (окна появляются у человека).
func hostCapture(enc string) func(ctx context.Context, c agent.Cap) (*exec.Cmd, error) {
	if s, i := agent.Permissions(true); !s || !i {
		log.Printf("ВНИМАНИЕ: выдайте разрешения в «Системные настройки → Конфиденциальность и безопасность»: «Запись экрана» (%v) и «Универсальный доступ» (%v) — приложению, из которого запущен AnyPC (Терминал); затем перезапустите AnyPC", s, i)
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

// ponytail: автозапуск на macOS (LaunchAgent) — когда понадобится; пока — «Объекты входа» в Настройках системы.
var errNoService = errors.New("на macOS пока нет — добавьте AnyPC в «Объекты входа» (Настройки → Основные)")

func installService(string) error { return errNoService }
func uninstallService() error     { return errNoService }
func serviceState() string        { return "— (macOS)" }
