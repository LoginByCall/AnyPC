package agent

import (
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Б1 приёмки Ч10.5 (регрессия): после долгой копии части (placing) окно скорости rxWatch остаётся прежним — первая же проверка
// после копии делит байты на время вместе с копией. Контроль: та же передача без медленной копии проходит.
func TestRecvPlaceThenRate(t *testing.T) {
	defer func(a, b, c, d int64) { rxIdle.Store(a); rxLife.Store(b); rxSlowWin.Store(c); rxMinRate.Store(d) }(rxIdle.Load(), rxLife.Load(), rxSlowWin.Load(), rxMinRate.Load())
	defer func() { rootLink = func(r *os.Root, o, n string) error { return r.Link(o, n) } }()
	rxIdle.Store(int64(10 * time.Second))
	rxLife.Store(int64(100 * time.Millisecond))
	rxSlowWin.Store(int64(400 * time.Millisecond))
	rxMinRate.Store(1)
	big := make([]byte, 48<<20)
	run := func(slow bool) (time.Duration, error) {
		var n atomic.Int32
		rootLink = func(r *os.Root, o, nw string) error {
			if slow && n.Add(1) == 1 {
				time.Sleep(1500 * time.Millisecond)
				return syscall.EPERM
			}
			return r.Link(o, nw)
		}
		url := local(t)
		r := recvHost(t, url)
		t0 := time.Now()
		err := sendT(t, r.own(url, []string{srcFile(t, "small.bin", []byte("payload")), srcFile(t, "big.bin", big)}, ""))
		return time.Since(t0), err
	}
	d, err := run(false)
	if err != nil {
		t.Fatalf("замер: %v", err)
	}
	v := float64(len(big)) / d.Seconds()
	t.Logf("замер: %v, %.1f МБ/с", d, v/1e6)
	rxMinRate.Store(int64(v / 8))
	if d, err := run(false); err != nil {
		t.Fatalf("контроль (без медленной копии, порог v/8) не прошёл: %v за %v", err, d)
	}
	if d, err := run(true); err != nil {
		t.Fatalf("ДЕФЕКТ: после копии 1,5 с первого файла сессия закрыта по скорости, хотя второй файл шёл: %v за %v", err, d)
	}
}
