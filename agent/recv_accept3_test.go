package agent

import (
	"fmt"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// Регрессионные тесты приёмки Ч10.1, круг 3 (R1).

// круг 3: много мелких файлов подряд (папка, канал через TURN) — честная передача, байт мало, окно скорости её рвать не должно
func TestAccR3SmallFiles(t *testing.T) {
	defer rxSlowWin.Store(rxSlowWin.Load())
	rxSlowWin.Store(int64(time.Second)) // 2 мин в масштабе
	url := local(t)
	r := recvHost(t, url)
	n, bad := 0, ""
	recvTestPC = func(pc *webrtc.PeerConnection) error {
		for i := range 40 { // 40 файлов по 100 байт, по 100 мс на файл (обмены meta/resume/end/done через ретранслятор)
			if err := rawFile(pc, fmt.Sprintf("f%02d.txt", i), make([]byte, 100)); err != nil {
				bad = err.Error()
				return nil
			}
			n++
			time.Sleep(100 * time.Millisecond)
		}
		return nil
	}
	defer func() { recvTestPC = nil }()
	sendT(t, r.own(url, nil, ""))
	t.Logf("принято %d из 40: %s", n, bad)
	if n != 40 {
		t.Fatalf("сессия с мелкими файлами закрыта по скорости: принято %d из 40 (%s)", n, bad)
	}
}

// круг 3: по капле с нулевыми окнами — держится не дольше срока
func TestAccR3ZeroHold(t *testing.T) {
	defer func(i, l, w int64) { rxIdle.Store(i); rxLife.Store(l); rxSlowWin.Store(w) }(rxIdle.Load(), rxLife.Load(), rxSlowWin.Load())
	rxIdle.Store(int64(800 * time.Millisecond))
	rxSlowWin.Store(int64(800 * time.Millisecond))
	rxLife.Store(int64(2 * time.Second))
	url := local(t)
	r := recvHost(t, url)
	fkey := accPinned(t, r)
	alive := 0
	recvTestPC = func(pc *webrtc.PeerConnection) error {
		t0 := time.Now()
		for time.Since(t0) < 5*time.Second { // сообщения без байт: каждый раз новый канал "text" с негодным началом
			dc, err := pc.CreateDataChannel("text", nil)
			if err != nil {
				return nil
			}
			open := make(chan struct{})
			dc.OnOpen(func() { close(open) })
			select {
			case <-open:
			case <-time.After(time.Second):
				return nil
			}
			dc.SendText(`{"t":"zzz"}`)
			time.Sleep(200 * time.Millisecond)
			r.a.mu.Lock()
			if len(r.a.recvs) == 1 {
				alive = int(time.Since(t0) / time.Millisecond)
			}
			r.a.mu.Unlock()
		}
		return nil
	}
	defer func() { recvTestPC = nil }()
	sendT(t, foreign(url, fkey, "", nil, ""))
	t.Logf("без байт сессия жила %d мс при сроке 2000, окон %d", alive, r.askN())
	if alive > 3200 {
		t.Fatalf("сессия без байт пережила срок: %d мс", alive)
	}
}

// круг 3: после срока — по капле (медленнее rxMinRate) держаться нельзя; быстрый файл после срока идёт
func TestAccR3AfterLife(t *testing.T) {
	defer func(l, w int64) { rxLife.Store(l); rxSlowWin.Store(w) }(rxLife.Load(), rxSlowWin.Load())
	rxLife.Store(int64(time.Second))
	rxSlowWin.Store(int64(time.Second))
	url := local(t)
	r := recvHost(t, url)
	for _, c := range []struct {
		chunk int
		alive bool
	}{{100, false}, {40000, true}} { // 500 Б/с и 200 КБ/с при потолке 64 КБ/с
		alive := false
		recvTestPC = func(pc *webrtc.PeerConnection) error {
			f, err := accFile(pc, "big.bin", 10<<20)
			if err != nil {
				return err
			}
			if s := f.wait(3 * time.Second); s != "resume:" {
				return nil
			}
			for range 20 {
				f.dc.Send(make([]byte, c.chunk))
				time.Sleep(200 * time.Millisecond)
			}
			r.a.mu.Lock()
			alive = len(r.a.recvs) == 1
			r.a.mu.Unlock()
			return nil
		}
		sendT(t, r.own(url, nil, ""))
		recvTestPC = nil
		if alive != c.alive {
			t.Fatalf("кусок %d байт / 200 мс после срока: сессия жива %v, ждали %v", c.chunk, alive, c.alive)
		}
	}
}
