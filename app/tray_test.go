package main

import (
	"os"
	"testing"
	"time"
)

func TestTrayTitleIcon(t *testing.T) {
	h, _ := os.Hostname()
	if got := trayTitle("123456789"); got != h+" · 123 456 789" {
		t.Errorf("trayTitle: %q", got)
	}
	for _, n := range []int{16, 22, 44} {
		p := trayIcon(n)
		if p.W != int32(n) || p.H != int32(n) || len(p.Data) != n*n*4 {
			t.Fatalf("значок %d: %dx%d, %d байт", n, p.W, p.H, len(p.Data))
		}
		c := n * 3 / 4 // центр красного ПК — непрозрачный красный
		if o := (c*n + c) * 4; p.Data[o] != 0xff || p.Data[o+1] != 0xef {
			t.Errorf("значок %d: точка %d,%d = % x", n, c, c, p.Data[o:o+4])
		}
	}
}

// TestTrayBGRA: ARGB → B,G,R,A для DIB Windows; прозрачные точки остаются нулями.
func TestTrayBGRA(t *testing.T) {
	p := trayIcon(16)
	b := trayBGRA(p)
	if len(b) != len(p.Data) {
		t.Fatalf("длина %d, ждали %d", len(b), len(p.Data))
	}
	o := (12*16 + 12) * 4 // красный ПК
	if got := b[o : o+4]; got[0] != 0x52 || got[1] != 0x6a || got[2] != 0xef || got[3] != 0xff {
		t.Errorf("красная точка: % x", got)
	}
	if got := b[0:4]; got[0]|got[1]|got[2]|got[3] != 0 { // угол — прозрачный
		t.Errorf("угол: % x", got)
	}
	l := trayBGRA(trayIconIn(16, true)) // светлая панель: красный #d2452d, контур #17181c
	if got := l[o : o+4]; got[0] != 0x2d || got[2] != 0xd2 || got[3] != 0xff {
		t.Errorf("светлая, красная точка: % x", got)
	}
	if o := (2*16 + 1) * 4; l[o] != 0x1c || l[o+2] != 0x17 || l[o+3] != 0xff { // точка контура (1,2)
		t.Errorf("светлая, контур: % x", l[o:o+4])
	}
	if len(trayBGRA(trayPixmap{Data: []byte{1, 2, 3}})) != 3 { // неполная точка — без паники
		t.Error("неполная точка")
	}
}

// TestTrayPick: «Выйти» — всегда и без дросселя; окно (обе строки) — только когда дроссель пускает; прочее — ничего.
func TestTrayPick(t *testing.T) {
	var opened, quitted, gated int
	open, quit := func() { opened++ }, func() { quitted++ }
	yes := func() bool { gated++; return true }
	no := func() bool { gated++; return false }
	for _, c := range []struct {
		id         int
		gate       func() bool
		open, quit int
	}{
		{trayOpen, yes, 1, 0}, {trayHelp, yes, 1, 0}, {trayOpen, no, 0, 0}, {trayHelp, no, 0, 0},
		{trayQuit, no, 0, 1}, {trayQuit, yes, 0, 1}, {3, yes, 0, 0}, {0, yes, 0, 0}, {99, yes, 0, 0},
	} {
		opened, quitted, gated = 0, 0, 0
		if f := trayPick(c.id, c.gate, open, quit); f != nil {
			f()
		}
		if opened != c.open || quitted != c.quit {
			t.Errorf("пункт %d: окно %d, выход %d; ждали %d, %d", c.id, opened, quitted, c.open, c.quit)
		}
		if c.id == trayQuit && gated != 0 {
			t.Errorf("«Выйти» тратит дроссель")
		}
	}
}

// TestTrayGate: раз в gap; нулевой gap пускает всех. Дроссель общий для щелчка по значку и пунктов меню.
func TestTrayGate(t *testing.T) {
	g := trayGate(time.Hour)
	if !g() || g() || g() {
		t.Error("час: ждали true, false, false")
	}
	g = trayGate(30 * time.Millisecond)
	g()
	time.Sleep(40 * time.Millisecond)
	if !g() {
		t.Error("после gap не пустил")
	}
	z := trayGate(0)
	if !z() || !z() {
		t.Error("gap 0 должен пускать всех")
	}
	open, n := func() {}, 0
	gate := trayGate(time.Hour)
	for range 10 { // поток щелчков (Enter на значке Windows приходит и дважды) — одно окно
		if trayPick(trayOpen, gate, open, nil) != nil {
			n++
		}
	}
	if n != 1 {
		t.Errorf("10 щелчков за час открыли окно %d раз", n)
	}
}
