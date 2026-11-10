//go:build !windows

package agent

import (
	"os"
	"path/filepath"
)

// DownloadsDir — ~/Downloads (Linux-приложение задаёт FileDir само, через xdg-user-dir).
func DownloadsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Downloads")
}
