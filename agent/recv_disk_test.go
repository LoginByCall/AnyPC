package agent

import (
	"sync/atomic"
	"testing"
)

// TestFileDiskWrite — запас места проверяется и во время записи (M4 приёмки Ч10.1): диск заняли после Open — приём
// останавливается на следующем мегабайте, а не заполняет диск.
func TestFileDiskWrite(t *testing.T) {
	var free atomic.Uint64
	free.Store(10 << 30)
	defer func(f func(string) (uint64, error)) { freeSpace = f }(freeSpace)
	freeSpace = func(string) (uint64, error) { return free.Load(), nil }
	r := NewReceiver(t.TempDir())
	if _, err := r.Open("a.bin", 4<<20, ""); err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 64<<10)
	for range 16 { // 1 МБ — место ещё есть
		if err := r.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	free.Store(diskReserve - 1) // диск заняли
	var err error
	for i := 0; i < 32 && err == nil; i++ {
		err = r.Write(chunk)
	}
	if err == nil || r.got > 2<<20 {
		t.Fatalf("запись при заполненном диске: err=%v, принято %d", err, r.got)
	}
	r.Abort(false)
}
