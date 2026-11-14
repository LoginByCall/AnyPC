// Общее для значка в трее Linux (tray_linux.go), строке меню Мака (window_darwin.go) и области уведомлений
// Windows (tray_windows.go): первая строка меню, номера пунктов, дроссель открытия окна, рисунок значка.
package main

import (
	"os"
	"strings"
	"sync"
	"time"
)

// Номера пунктов меню; 3 — разделитель. Одинаковы на всех ОС.
const (
	trayOpen = 1 // «имя ПК · ID» — главное окно
	trayHelp = 2 // «Помочь кому-то…»
	trayQuit = 4 // «Выйти»: единственный, кто не открывает окно
)

// trayTitle — первая строка меню: имя этого ПК и его ID группами по 3 цифры, как в окне.
func trayTitle(id string) string {
	h, _ := os.Hostname()
	var b strings.Builder
	for i, r := range id {
		if i > 0 && i%3 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	if h == "" {
		return b.String()
	}
	return h + " · " + b.String()
}

// trayPick — что делать по пункту id: «Выйти» — всегда, окно — не чаще gate; прочее (0 — меню закрыто мимо) — nil.
// TODO(ui): «Помочь кому-то…» — главное окно, пока в ui/index.html нет адреса экрана подключения.
func trayPick(id int, gate func() bool, open, quit func()) func() {
	switch {
	case id == trayQuit:
		return quit
	case (id == trayOpen || id == trayHelp) && gate():
		return open
	}
	return nil
}

// trayOpenGap — окно открывается не чаще; лишние щелчки (или поток вызовов от любого клиента шины) — мимо.
var trayOpenGap = time.Second

// trayGate — true не чаще раза в gap.
func trayGate(gap time.Duration) func() bool {
	var mu sync.Mutex
	var last time.Time
	return func() bool {
		mu.Lock()
		defer mu.Unlock()
		if now := time.Now(); last.IsZero() || now.Sub(last) >= gap {
			last = now
			return true
		}
		return false
	}
}

type trayPixmap struct {
	W, H int32
	Data []byte
}

// trayIcon — значок программы (favicon ui/index.html: контур ПК и красный ПК поверх, viewBox 26×26) n×n точек
// выборкой по центрам пикселей; цвета тёмной темы — панель Ubuntu тёмная. ARGB32, байты A,R,G,B (как требует SNI).
// Скруглённые углы (rx=2) не рисуются — на 22 точках их не видно.
func trayIcon(n int) trayPixmap { return trayIconIn(n, false) }

// trayIconIn — то же; light — цвета светлой темы favicon (светлая панель задач Windows 11).
func trayIconIn(n int, light bool) trayPixmap {
	red, line := [4]byte{0xff, 0xef, 0x6a, 0x52}, [4]byte{0xff, 0xec, 0xea, 0xe4}
	if light {
		red, line = [4]byte{0xff, 0xd2, 0x45, 0x2d}, [4]byte{0xff, 0x17, 0x18, 0x1c}
	}
	in := func(x, y, x0, y0, x1, y1 float64) bool { return x >= x0 && x < x1 && y >= y0 && y < y1 }
	b := make([]byte, 0, n*n*4)
	s := 26 / float64(n)
	for py := 0; py < n; py++ {
		for px := 0; px < n; px++ {
			x, y := (float64(px)+.5)*s, (float64(py)+.5)*s
			switch {
			case in(x, y, 10, 12, 25, 23): // <rect class='b' x='10' y='12' width='15' height='11'/>
				b = append(b, red[:]...)
			case in(x, y, 0.2, 1.7, 17.8, 15.3) && !in(x, y, 2.8, 4.3, 15.2, 12.7): // контур x=1.5 y=3 15×11, штрих 2.6
				b = append(b, line[:]...)
			default:
				b = append(b, 0, 0, 0, 0)
			}
		}
	}
	return trayPixmap{int32(n), int32(n), b}
}

// trayBGRA — те же точки в порядке байт 32-битного DIB Windows (B,G,R,A; альфа не домножена — так берёт CreateIconIndirect).
func trayBGRA(p trayPixmap) []byte {
	b := make([]byte, len(p.Data))
	for i := 0; i+3 < len(p.Data); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = p.Data[i+3], p.Data[i+2], p.Data[i+1], p.Data[i]
	}
	return b
}
