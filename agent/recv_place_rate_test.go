package agent

import (
	"errors"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// TestRecvPlaceThenRate — Б1 приёмки Ч10.5 (регрессия): пока часть первого файла копируется на место (placing),
// окно скорости rxWatch начинается заново — иначе после срока первая проверка делила байты следующего файла на время
// вместе с копией и закрывала сессию «медленнее порога». Темп второго файла задаёт сам тест (4 КБ каждые 50 мс ≈
// 80 КБ/с), порог — 8 КБ/с (в 10 раз ниже), срок 1,5 с и окно 400 мс; копия первого файла — 3 с (подмена rootLink),
// второй файл начинается только после «done» первого (как отправитель: файлы подряд). Без сброса окна первая проверка
// после копии видит ≤ 1 тика байтов за ≥ 3 с — ниже порога; со сбросом — честный темп.
func TestRecvPlaceThenRate(t *testing.T) {
	defer func(a, b, c, d int64) { rxIdle.Store(a); rxLife.Store(b); rxSlowWin.Store(c); rxMinRate.Store(d) }(rxIdle.Load(), rxLife.Load(), rxSlowWin.Load(), rxMinRate.Load())
	rxIdle.Store(int64(10 * time.Second))
	rxLife.Store(int64(1500 * time.Millisecond))
	rxSlowWin.Store(int64(400 * time.Millisecond))
	rxMinRate.Store(8 << 10)
	var slow atomic.Int32
	linkSet(t, func(r *os.Root, o, n string) error {
		if slow.Add(1) == 1 { // первый файл: ФС без жёстких ссылок и долгая копия
			time.Sleep(3 * time.Second)
			return syscall.EPERM
		}
		return r.Link(o, n)
	})
	url := local(t)
	r := recvHost(t, url)
	const chunk, n = 4 << 10, 30 // второй файл: 30 кусков по 4 КБ раз в 50 мс (1,5 с)
	var got string
	recvTestPC = func(pc *webrtc.PeerConnection) error {
		c1, err := accFile(pc, "a.bin", 10)
		if err != nil {
			return err
		}
		if s := c1.wait(5 * time.Second); s != "resume:" {
			return errors.New("первый файл: " + s)
		}
		c1.dc.Send(make([]byte, 10))
		sendJSON(c1.dc, fileMsg{T: "end"})
		if s := c1.wait(10 * time.Second); s != "done:" {
			return errors.New("первый файл после копии: " + s)
		}
		c2, err := accFile(pc, "b.bin", chunk*n)
		if err != nil {
			return err
		}
		if s := c2.wait(5 * time.Second); s != "resume:" {
			return errors.New("второй файл: " + s)
		}
		tk := time.NewTicker(50 * time.Millisecond)
		defer tk.Stop()
		for range n {
			if err := c2.dc.Send(make([]byte, chunk)); err != nil {
				return err
			}
			<-tk.C
		}
		sendJSON(c2.dc, fileMsg{T: "end"})
		got = c2.wait(10 * time.Second)
		return nil
	}
	defer func() { recvTestPC = nil }()
	err := sendT(t, r.own(url, nil, ""))
	if err != nil || got != "done:" {
		t.Fatalf("после копии 3 с первого файла второй (≈ 80 КБ/с при пороге 8 КБ/с) не принят: %v, итог %q", err, got)
	}
}
