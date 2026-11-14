// Значок в области уведомлений Windows без cgo: Shell_NotifyIconW + TrackPopupMenu на скрытом окне со своим циклом
// сообщений на закреплённом потоке (образец — agent/plaque_windows.go). Меню и поведение — как в трее Linux (tray_linux.go).
// Окно открывается при запуске как раньше; значок — дополнительный вход, его отсутствие ничего не ломает.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	shell32        = syscall.NewLazyDLL("shell32.dll")
	gdi32          = syscall.NewLazyDLL("gdi32.dll")
	pNotifyIcon    = shell32.NewProc("Shell_NotifyIconW")
	pExtractIcon   = shell32.NewProc("ExtractIconExW")
	pRegClass      = user32.NewProc("RegisterClassExW")
	pCreateWindow  = user32.NewProc("CreateWindowExW")
	pDefWndProc    = user32.NewProc("DefWindowProcW")
	pRegMsg        = user32.NewProc("RegisterWindowMessageW")
	pMsgFilter     = user32.NewProc("ChangeWindowMessageFilterEx")
	pGetMessage    = user32.NewProc("GetMessageW")
	pTranslateMsg  = user32.NewProc("TranslateMessage")
	pDispatchMsg   = user32.NewProc("DispatchMessageW")
	pPostMsg       = user32.NewProc("PostMessageW")
	pPostQuit      = user32.NewProc("PostQuitMessage")
	pPopupMenu     = user32.NewProc("CreatePopupMenu")
	pAppendMenu    = user32.NewProc("AppendMenuW")
	pDefaultItem   = user32.NewProc("SetMenuDefaultItem")
	pTrackMenu     = user32.NewProc("TrackPopupMenu")
	pDestroyMenu   = user32.NewProc("DestroyMenu")
	pSetForeground = user32.NewProc("SetForegroundWindow")
	pShowWindow    = user32.NewProc("ShowWindow")
	pIsIconic      = user32.NewProc("IsIconic")
	pSysMetrics    = user32.NewProc("GetSystemMetrics")
	pIconIndirect  = user32.NewProc("CreateIconIndirect")
	pDestroyIcon   = user32.NewProc("DestroyIcon")
	pCreateDIB     = gdi32.NewProc("CreateDIBSection")
	pCreateBitmap  = gdi32.NewProc("CreateBitmap")
	pDeleteObject  = gdi32.NewProc("DeleteObject")
	pModuleHandle  = syscall.NewLazyDLL("kernel32.dll").NewProc("GetModuleHandleW")
)

// notifyIconData — NOTIFYICONDATAW целиком (shellapi.h, с hBalloonIcon — Vista+). amd64/arm64: 976 байт, смещения —
// в tray_windows_test.go (сверено с mingw-w64 13 shellapi.h: sizeof и offsetof, собрано x86_64-w64-mingw32-gcc).
type notifyIconData struct {
	Size             uint32
	Wnd              uintptr
	ID, Flags        uint32
	CallbackMessage  uint32
	Icon             uintptr
	Tip              [128]uint16
	State, StateMask uint32
	Info             [256]uint16
	Version          uint32 // объединение uTimeout / uVersion
	InfoTitle        [64]uint16
	InfoFlags        uint32
	GUIDItem         [4]uint32 // GUID: выравнивание 4
	BalloonIcon      uintptr
}

type wndClassEx struct {
	size, style                        uint32
	wndProc                            uintptr
	clsExtra, wndExtra                 int32
	instance, icon, cursor, background uintptr
	menuName, className                *uint16
	iconSm                             uintptr
}

type iconInfo struct {
	fIcon       int32
	xHot, yHot  uint32
	mask, color uintptr
}

const (
	nimAdd, nimModify, nimDelete, nimSetVersion = 0, 1, 2, 4
	nifMessage, nifIcon, nifTip, nifShowTip     = 0x1, 0x2, 0x4, 0x80
	notifyIconV4                                = 4      // NOTIFYICON_VERSION_4: событие в LOWORD(lParam), точка в wParam
	trayCallback                                = 0x8001 // WM_APP+1
	ninSelect, ninKeySelect, wmContextMenu      = 0x400, 0x401, 0x7b
	wmNull, wmDestroy, wmClose, wmSettingChange = 0x0, 0x2, 0x10, 0x1a
	tpmFlags                                    = 0x2 | 0x80 | 0x100 // TPM_RIGHTBUTTON | TPM_NONOTIFY | TPM_RETURNCMD
)

// winTray — состояние значка; трогается только из потока окна (оконная процедура и runTray).
type winTray struct {
	nid        notifyIconData
	title      string
	created    uintptr // номер сообщения TaskbarCreated
	gate       func() bool
	open, quit func()
	light      bool // значок нарисован для светлой панели
}

var (
	trayWin       *winTray // один значок на процесс
	trayClass, _  = syscall.UTF16PtrFromString("AnyPCTray")
	trayClassOnce sync.Once
	trayClassErr  error
)

// runTray — значок, пока жив ctx; возвращается, когда значок снят (NIM_DELETE). Не вышло — в журнал, окно — как обычно.
func runTray(ctx context.Context, id string, open, quit func()) {
	runtime.LockOSThread() // окно принадлежит потоку: создание и цикл сообщений — на одном (поток умрёт с горутиной)
	h, err := createTray(&winTray{title: trayTitle(id), gate: trayGate(trayOpenGap), open: open, quit: quit})
	if err != nil {
		log.Printf("трей: %v — значка не будет, окно — как обычно", err)
		return
	}
	defer context.AfterFunc(ctx, func() { pPostMsg.Call(h, wmClose, 0, 0) })()
	var m [6]uint64 // MSG, 48 байт
	for {
		if r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0); int32(r) <= 0 {
			return
		}
		pTranslateMsg.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMsg.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func createTray(t *winTray) (uintptr, error) {
	inst, _, _ := pModuleHandle.Call(0)
	trayClassOnce.Do(func() { // у NewCallback конечный запас — один раз
		wc := wndClassEx{wndProc: syscall.NewCallback(trayProc), instance: inst, className: trayClass}
		wc.size = uint32(unsafe.Sizeof(wc))
		if r, _, e := pRegClass.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
			trayClassErr = fmt.Errorf("RegisterClassEx: %v", e)
		}
	})
	if trayClassErr != nil {
		return 0, trayClassErr
	}
	tb, _ := syscall.UTF16PtrFromString("TaskbarCreated")
	t.created, _, _ = pRegMsg.Call(uintptr(unsafe.Pointer(tb)))
	// скрытое окно верхнего уровня, не HWND_MESSAGE: TaskbarCreated рассылается только им
	h, _, e := pCreateWindow.Call(0, uintptr(unsafe.Pointer(trayClass)), uintptr(unsafe.Pointer(trayClass)), 0, 0, 0, 0, 0, 0, 0, inst, 0)
	if h == 0 {
		return 0, fmt.Errorf("CreateWindowEx: %v", e)
	}
	pMsgFilter.Call(h, t.created, 1, 0) // MSGFLT_ALLOW: иначе запущенной от администратора программе не дойдёт
	t.nid = notifyIconData{Wnd: h, ID: 1, Flags: nifMessage | nifIcon | nifTip | nifShowTip, CallbackMessage: trayCallback,
		Version: notifyIconV4}
	t.nid.Icon, t.light = trayHIcon()
	t.nid.Size = uint32(unsafe.Sizeof(t.nid))
	tip, _ := syscall.UTF16FromString(t.title)
	copy(t.nid.Tip[:len(t.nid.Tip)-1], tip[:len(tip)-1])
	trayWin = t
	t.add()
	return h, nil
}

// add — значок на панель: при запуске и по TaskbarCreated (Проводник перезапущен). Уже есть — NIM_MODIFY.
// Панели ещё нет (автозапуск раньше Проводника) — ждём TaskbarCreated.
func (t *winTray) add() {
	nid := uintptr(unsafe.Pointer(&t.nid))
	if r, _, _ := pNotifyIcon.Call(nimAdd, nid); r == 0 {
		if r, _, _ := pNotifyIcon.Call(nimModify, nid); r == 0 {
			log.Print("трей: значок не добавлен (нет панели задач?) — ждём TaskbarCreated")
			return
		}
	}
	pNotifyIcon.Call(nimSetVersion, nid)
	log.Print("трей: значок добавлен")
}

func trayProc(h, msg, wp, lp uintptr) uintptr {
	t := trayWin
	switch {
	case t == nil:
	case msg == trayCallback:
		switch lp & 0xffff {
		case ninSelect, ninKeySelect: // левый щелчок, Enter/пробел — главное окно
			t.run(trayOpen)
		case wmContextMenu: // правый щелчок, Shift+F10, клавиша меню
			x, y := trayXY(wp)
			t.menu(h, x, y)
		}
		return 0
	case msg == t.created && t.created != 0:
		t.add()
		return 0
	case msg == wmSettingChange && t.light != trayLight(): // светлая/тёмная тема сменилась — перерисовать
		old := t.nid.Icon
		t.nid.Icon, t.light = trayHIcon()
		pNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&t.nid)))
		pDestroyIcon.Call(old)
		return 0
	case msg == wmDestroy:
		pNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&t.nid)))
		pDestroyIcon.Call(t.nid.Icon)
		trayWin = nil
		pPostQuit.Call(0)
		return 0
	}
	r, _, _ := pDefWndProc.Call(h, msg, wp, lp)
	return r
}

// trayXY — точка меню из wParam (NOTIFYICON_VERSION_4): x в младшем слове, y в старшем, со знаком (мониторы левее/выше).
func trayXY(wp uintptr) (x, y int32) { return int32(int16(wp)), int32(int16(wp >> 16)) }

func (t *winTray) run(id int) {
	if f := trayPick(id, t.gate, t.open, t.quit); f != nil {
		go f() // не держать поток значка
	}
}

// menu — то же меню, что на Linux и Маке. SetForegroundWindow до и WM_NULL после — иначе меню не закрывается щелчком мимо
// (KB135788).
func (t *winTray) menu(h uintptr, x, y int32) {
	m, _, _ := pPopupMenu.Call()
	if m == 0 {
		return
	}
	defer pDestroyMenu.Call(m)
	for _, it := range []struct {
		id    int
		label string
	}{{trayOpen, t.title}, {trayHelp, "Помочь кому-то…"}, {3, ""}, {trayQuit, "Выйти"}} {
		if it.label == "" {
			pAppendMenu.Call(m, 0x800, 0, 0) // MF_SEPARATOR
			continue
		}
		s, _ := syscall.UTF16PtrFromString(strings.ReplaceAll(it.label, "&", "&&")) // «&» — мнемоника
		pAppendMenu.Call(m, 0, uintptr(it.id), uintptr(unsafe.Pointer(s)))          // MF_STRING
	}
	pDefaultItem.Call(m, trayOpen, 0) // жирным — то, что делает левый щелчок
	pSetForeground.Call(h)
	cmd, _, _ := pTrackMenu.Call(m, tpmFlags, uintptr(x), uintptr(y), 0, h, 0)
	pPostMsg.Call(h, wmNull, 0, 0)
	t.run(int(cmd))
}

// trayHIcon — значок из ресурсов exe (сейчас их нет: build.sh не кладёт .syso), иначе нарисованный, как на Linux,
// в цветах текущей темы панели задач; light — какой темы (для exe — как сейчас, чтобы не перерисовывать зря).
func trayHIcon() (h uintptr, light bool) {
	light = trayLight()
	if exe, err := os.Executable(); err == nil {
		p, _ := syscall.UTF16PtrFromString(exe)
		var small uintptr
		pExtractIcon.Call(uintptr(unsafe.Pointer(p)), 0, 0, uintptr(unsafe.Pointer(&small)), 1)
		if small != 0 {
			return small, light
		}
	}
	n, _, _ := pSysMetrics.Call(49) // SM_CXSMICON: 16 при 100 %
	if n == 0 {
		n = 16
	}
	return trayDraw(int(n), light), light
}

// trayLight — панель задач светлая (HKCU\…\Themes\Personalize SystemUsesLightTheme = 1; нет значения — тёмная, как в Windows 10).
func trayLight() bool {
	var k syscall.Handle
	p, _ := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`)
	if syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, p, 0, syscall.KEY_READ, &k) != nil {
		return false
	}
	defer syscall.RegCloseKey(k)
	var v uint32
	n := uint32(unsafe.Sizeof(v))
	name, _ := syscall.UTF16PtrFromString("SystemUsesLightTheme")
	return syscall.RegQueryValueEx(k, name, nil, nil, (*byte)(unsafe.Pointer(&v)), &n) == nil && v != 0
}

// trayDraw — HICON n×n из trayIcon: 32-битный DIB с альфой сверху вниз + пустая маска (CreateIconIndirect).
func trayDraw(n int, light bool) uintptr {
	hdr := struct {
		size        uint32
		w, h        int32
		planes, bpp uint16
		_           [7]uint32 // остальные поля BITMAPINFOHEADER (до 40 байт) и bmiColors[1]
	}{size: 40, w: int32(n), h: -int32(n), planes: 1, bpp: 32}
	var bits unsafe.Pointer
	color, _, _ := pCreateDIB.Call(0, uintptr(unsafe.Pointer(&hdr)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0) // DIB_RGB_COLORS
	if color == 0 || bits == nil {
		return 0
	}
	defer pDeleteObject.Call(color)
	copy(unsafe.Slice((*byte)(bits), n*n*4), trayBGRA(trayIconIn(n, light)))
	mask := make([]byte, (n+15)/16*2*n) // строки монохромного битмапа выровнены на 16 бит
	mb, _, _ := pCreateBitmap.Call(uintptr(n), uintptr(n), 1, 1, uintptr(unsafe.Pointer(&mask[0])))
	if mb == 0 {
		return 0
	}
	defer pDeleteObject.Call(mb)
	ii := iconInfo{fIcon: 1, mask: mb, color: color}
	h, _, _ := pIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	return h
}

// showMain — главное окно наверх: свёрнутое — развернуть (SW_RESTORE), иначе SW_SHOW (не снимает «развёрнуто»).
func showMain(h uintptr) {
	if r, _, _ := pIsIconic.Call(h); r != 0 {
		pShowWindow.Call(h, 9)
	} else {
		pShowWindow.Call(h, 5)
	}
	pSetForeground.Call(h)
}
