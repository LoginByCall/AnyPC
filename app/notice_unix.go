//go:build linux || darwin

package main

import (
	"context"
	"html"
	"log"
	"os/exec"
	"runtime"
	"time"
)

// noticeOS — уведомление рабочего стола: Linux — notify-send (нет — только журнал), Мак — osascript «display
// notification» (текст — аргументом, не в тексте скрипта: кавычки в имени файла не ломают и не исполняются).
func noticeOS(title, body string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.CommandContext(ctx, "/usr/bin/osascript", "-e", "on run argv", "-e",
			"display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run", title, body) // аргументы после скрипта — argv (title — всегда «AnyPC»)
	} else if p, err := exec.LookPath("notify-send"); err == nil {
		// тело — разметка у части серверов уведомлений (KDE, dunst): & < > — сущностями, иначе имя файла «a<b» ломает текст
		cmd = exec.CommandContext(ctx, p, "--", title, noticeEsc(body))
	} else {
		log.Printf("уведомление: нет notify-send")
		return
	}
	if err := cmd.Run(); err != nil {
		log.Printf("уведомление: %v", err)
	}
}

// noticeEsc — тело для notify-send: & < > (и кавычки) — сущностями разметки.
func noticeEsc(s string) string { return html.EscapeString(s) }
