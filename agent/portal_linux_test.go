package agent

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/pion/webrtc/v4/pkg/media/h264reader"
)

// TestGstTail — хвост конвейера Wayland на настоящем GStreamer (videotestsrc вместо PipeWire):
// H.264 — ровно один слайс на кадр (иначе браузер показывает верхнюю полосу и вертикальные полосы ниже);
// VP9 — Y4M нужного размера, а не H.264 (иначе кодер в процессе не получает ни кадра — чёрный экран).
func TestGstTail(t *testing.T) {
	if _, err := exec.LookPath("gst-launch-1.0"); err != nil {
		t.Skip("нет gst-launch-1.0")
	}
	run := func(c Cap) []byte {
		pl := "videotestsrc num-buffers=10 pattern=ball ! video/x-raw,width=1920,height=1080 ! videoconvert ! videorate ! " + gstTail(c)
		out, err := exec.Command("gst-launch-1.0", append([]string{"-q"}, strings.Fields(pl)...)...).Output()
		if err != nil {
			t.Skipf("gst-launch (нет плагина?): %v", err)
		}
		return out
	}
	r, _ := h264reader.NewReader(bytes.NewReader(run(Cap{FPS: 30, Kbps: 4000})))
	slices := 0
	for {
		nal, err := r.NextNAL()
		if err != nil {
			break
		}
		if nal.UnitType == h264reader.NalUnitTypeCodedSliceIdr || nal.UnitType == h264reader.NalUnitTypeCodedSliceNonIdr {
			slices++
		}
	}
	if slices < 10 || slices > 11 { // videorate на EOS может добавить кадр; слайсы по потокам дали бы ×N
		t.Errorf("H.264: %d слайсов на 10 кадров", slices)
	}

	y, err := newY4M(bytes.NewReader(run(Cap{FPS: 30, VP9: true})))
	if err != nil {
		t.Fatalf("VP9: %v", err)
	}
	n := 0
	for ; ; n++ {
		if _, err := y.next(); err != nil {
			break
		}
	}
	if y.w != 1920 || y.h != 1080 || n < 10 { // videorate на EOS может добавить кадр
		t.Errorf("VP9: Y4M %d×%d, кадров %d", y.w, y.h, n)
	}
}
