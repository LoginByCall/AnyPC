//go:build !windows

package agent

import (
	"log"
	"os/exec"
)

// STUB: вне Windows ввод только логируется — для тестов на Linux.
func sendInput(e event) error { return nil }

func showIndicator(cid string, _ func()) func() {
	log.Printf("плашка: идёт удалённая сессия %s", cid)
	return func() {}
}

func hideWindow(*exec.Cmd) {}

// STUB: буфер обмена вне Windows не поддерживается.
func ClipSeq() uint32           { return 0 }
func ClipText() (string, error) { return "", nil }
func SetClipText(string) error  { return nil }

// STUB: окна выбора файла вне Windows нет.
func pickFile() (string, bool) { return "", false }
