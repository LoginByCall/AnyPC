//go:build windows && (amd64 || arm64)

package main

import (
	"testing"
	"unsafe"
)

// Раскладка NOTIFYICONDATAW на 64 битах: 976 байт. Источник — shellapi.h (Windows SDK; описание полей:
// learn.microsoft.com/windows/win32/api/shellapi/ns-shellapi-notifyicondataw); числа сверены 2026-11-14 по
// mingw-w64 13 /usr/x86_64-w64-mingw32/include/shellapi.h: x86_64-w64-mingw32-gcc -S, sizeof и offsetof всех полей
// (на 386 было бы 956 — потому сборка только amd64/arm64). Проверка двойная: при компиляции (go vet / go test -c
// падают на неверном размере) и смещения полей — при запуске.
const nidSize = 976

var (
	_ [nidSize - unsafe.Sizeof(notifyIconData{})]byte
	_ [unsafe.Sizeof(notifyIconData{}) - nidSize]byte
)

func TestNotifyIconDataLayout(t *testing.T) {
	var n notifyIconData
	for _, c := range []struct {
		name     string
		got, exp uintptr
	}{
		{"sizeof", unsafe.Sizeof(n), nidSize},
		{"hWnd", unsafe.Offsetof(n.Wnd), 8},
		{"uID", unsafe.Offsetof(n.ID), 16},
		{"uFlags", unsafe.Offsetof(n.Flags), 20},
		{"uCallbackMessage", unsafe.Offsetof(n.CallbackMessage), 24},
		{"hIcon", unsafe.Offsetof(n.Icon), 32},
		{"szTip", unsafe.Offsetof(n.Tip), 40},
		{"dwState", unsafe.Offsetof(n.State), 296},
		{"dwStateMask", unsafe.Offsetof(n.StateMask), 300},
		{"szInfo", unsafe.Offsetof(n.Info), 304},
		{"uVersion", unsafe.Offsetof(n.Version), 816},
		{"szInfoTitle", unsafe.Offsetof(n.InfoTitle), 820},
		{"dwInfoFlags", unsafe.Offsetof(n.InfoFlags), 948},
		{"guidItem", unsafe.Offsetof(n.GUIDItem), 952},
		{"hBalloonIcon", unsafe.Offsetof(n.BalloonIcon), 968},
		{"ICONINFO", unsafe.Sizeof(iconInfo{}), 32}, // те же сверки mingw-w64
		{"WNDCLASSEXW", unsafe.Sizeof(wndClassEx{}), 80},
	} {
		if c.got != c.exp {
			t.Errorf("%s: %d, ждали %d", c.name, c.got, c.exp)
		}
	}
}

// TestTrayXY: точка меню из wParam со знаком — монитор левее основного даёт отрицательный x.
func TestTrayXY(t *testing.T) {
	neg := int16(-5)
	if x, y := trayXY(uintptr(uint16(neg)) | 300<<16); x != -5 || y != 300 {
		t.Errorf("trayXY: %d, %d", x, y)
	}
}

// TestTrayDraw: нарисованный значок становится HICON (GDI есть и без панели задач — на CI тоже).
func TestTrayDraw(t *testing.T) {
	for _, n := range []int{16, 20, 32} {
		for _, light := range []bool{false, true} {
			h := trayDraw(n, light)
			if h == 0 {
				t.Fatalf("trayDraw(%d, %v) = 0", n, light)
			}
			pDestroyIcon.Call(h)
		}
	}
}
