package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"anypc/agent"
)

const openCmd = "xdg-open"

func hostCapture(enc string) func(ctx context.Context, mon, kbps, fps int) (*exec.Cmd, error) {
	return agent.LinuxCapture(enc)
}

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
