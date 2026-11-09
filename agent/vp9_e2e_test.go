//go:build vp9

package agent

import (
	"testing"

	"github.com/pion/webrtc/v4"
)

// TestE2EVP9 — ffmpeg отдаёт Y4M, кодер VP9 в процессе, клиент получает трек VP9.
func TestE2EVP9(t *testing.T) {
	e2eAgent = func(a *Agent) { a.VP9 = func() bool { return true } }
	e2eMime = webrtc.MimeTypeVP9
	defer func() { e2eAgent, e2eMime = nil, webrtc.MimeTypeH264 }()
	e2e(t, local(t), "123456789", false, FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000, VP9: true}), "secret123")
}
