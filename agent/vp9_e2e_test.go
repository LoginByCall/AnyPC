//go:build vp9

package agent

import (
	"testing"

	"github.com/pion/webrtc/v4"
)

// TestE2EVP9 — клиент просит VP9 в connect: ffmpeg отдаёт Y4M, кодер VP9 в процессе, клиент получает трек VP9.
func TestE2EVP9(t *testing.T) {
	e2eVP9, e2eMime = true, webrtc.MimeTypeVP9
	defer func() { e2eVP9, e2eMime = false, webrtc.MimeTypeH264 }()
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000, VP9: true}), "secret123")
}
