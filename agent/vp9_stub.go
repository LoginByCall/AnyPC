//go:build !vp9

package agent

import (
	"errors"
	"time"
)

// VP9Built — программа собрана без кодера VP9 (нет -tags vp9 и libvpx): enc "vp9" в настройках → H.264 через ffmpeg.
const VP9Built = false

type vp9 struct{}

func newVP9(int, int, int) (*vp9, error) { return nil, errors.New("собрано без VP9") }
func (*vp9) setRate(int, int) error      { return nil }
func (*vp9) encode([]byte, time.Duration, bool) ([]byte, bool, error) {
	return nil, false, errors.New("собрано без VP9")
}
func (*vp9) close() {}
