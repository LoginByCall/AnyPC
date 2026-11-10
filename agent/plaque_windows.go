package agent

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// Плашка сессии REQ-F-15: узкая панель в правом нижнем углу рабочей области, поверх всех окон.
// Без заголовка — нечего свернуть или утащить; фокус не забирает (NOACTIVATE), поэтому не мешает оператору печатать.
// Любой путь, которым панель исчезает не по нашей команде (кнопка, Alt+F4, WM_CLOSE), рвёт сессию.
var (
	gdi32          = syscall.NewLazyDLL("gdi32.dll")
	pCreateFont    = gdi32.NewProc("CreateFontW")
	pDeleteObject  = gdi32.NewProc("DeleteObject")
	pRegClass      = user32.NewProc("RegisterClassExW")
	pCreateWindow  = user32.NewProc("CreateWindowExW")
	pDefWndProc    = user32.NewProc("DefWindowProcW")
	pDestroyWindow = user32.NewProc("DestroyWindow")
	pPostQuit      = user32.NewProc("PostQuitMessage")
	pGetMessage    = user32.NewProc("GetMessageW")
	pTranslateMsg  = user32.NewProc("TranslateMessage")
	pDispatchMsg   = user32.NewProc("DispatchMessageW")
	pSendMsg       = user32.NewProc("SendMessageW")
	pPostMsg       = user32.NewProc("PostMessageW")
	pSetWindowPos  = user32.NewProc("SetWindowPos")
	pShowWindow    = user32.NewProc("ShowWindow")
	pSetTimer      = user32.NewProc("SetTimer")
	pSysParamInfo  = user32.NewProc("SystemParametersInfoW")
	pDpiForSystem  = user32.NewProc("GetDpiForSystem") // Windows 10 1607+
	pModuleHandle  = syscall.NewLazyDLL("kernel32.dll").NewProc("GetModuleHandleW")
	plaqueClass, _ = syscall.UTF16PtrFromString("AnyPCPlaque")
	plaqueOnce     sync.Once
	plaqueErr      error
)

type wndClassEx struct {
	size, style                        uint32
	wndProc                            uintptr
	clsExtra, wndExtra                 int32
	instance, icon, cursor, background uintptr
	menuName, className                *uint16
	iconSm                             uintptr
}

type winMsg struct {
	hwnd     uintptr
	message  uint32
	wParam   uintptr
	lParam   uintptr
	time     uint32
	pt       [2]int32
	lPrivate uint32
}

const (
	wmDestroy = 0x0002
	wmClose   = 0x0010
	wmSetFont = 0x0030
	wmCommand = 0x0111
	wmTimer   = 0x0113
	idBtn     = 1
)

// plaqueProc — одна оконная процедура на все плашки (у NewCallback конечный запас — создаём один раз).
func plaqueProc(h, msg, wp, lp uintptr) uintptr {
	switch msg {
	case wmCommand:
		if wp&0xffff == idBtn {
			pDestroyWindow.Call(h)
		}
		return 0
	case wmTimer: // другое окно «поверх всех» или смена разрешения — вернуть панель на место и наверх
		placePlaque(h)
		return 0
	case wmDestroy:
		pPostQuit.Call(0) // цикл сообщений у каждой плашки свой, на своём потоке
		return 0
	}
	r, _, _ := pDefWndProc.Call(h, msg, wp, lp)
	return r
}

func dpi() uintptr {
	if pDpiForSystem.Find() == nil {
		if d, _, _ := pDpiForSystem.Call(); d != 0 {
			return d
		}
	}
	return 96
}

// plaqueSize — размеры панели в логических пикселях (96 dpi): ширина, высота, отступ от края.
const plaqueW, plaqueH, plaqueGap = 400, 40, 8

func placePlaque(h uintptr) {
	var r rect
	pSysParamInfo.Call(0x0030, 0, uintptr(unsafe.Pointer(&r)), 0) // SPI_GETWORKAREA: основной монитор без панели задач
	s := dpi()
	w, ht, g := int32(plaqueW*s/96), int32(plaqueH*s/96), int32(plaqueGap*s/96)
	pSetWindowPos.Call(h, ^uintptr(0), uintptr(r.R-w-g), uintptr(r.B-ht-g), uintptr(w), uintptr(ht), 0x0010) // HWND_TOPMOST, SWP_NOACTIVATE
}

type rect struct{ L, T, R, B int32 }

func createPlaque(label, btn string) (h, font uintptr, err error) {
	inst, _, _ := pModuleHandle.Call(0)
	plaqueOnce.Do(func() {
		wc := wndClassEx{wndProc: syscall.NewCallback(plaqueProc), instance: inst, background: 15 + 1, className: plaqueClass} // COLOR_BTNFACE
		wc.size = uint32(unsafe.Sizeof(wc))
		if r, _, e := pRegClass.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
			plaqueErr = fmt.Errorf("RegisterClassEx: %v", e)
		}
	})
	if plaqueErr != nil {
		return 0, 0, plaqueErr
	}
	l, _ := syscall.UTF16PtrFromString(label)
	b, _ := syscall.UTF16PtrFromString(btn)
	stc, _ := syscall.UTF16PtrFromString("STATIC")
	bc, _ := syscall.UTF16PtrFromString("BUTTON")
	const exStyle = 0x8 | 0x80 | 0x08000000 // WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE
	const style = 0x80000000 | 0x00800000   // WS_POPUP | WS_BORDER: без заголовка — ни «свернуть», ни «развернуть»
	const child = 0x40000000 | 0x10000000   // WS_CHILD | WS_VISIBLE
	h, _, e := pCreateWindow.Call(exStyle, uintptr(unsafe.Pointer(plaqueClass)), uintptr(unsafe.Pointer(l)), style, 0, 0, 0, 0, 0, 0, inst, 0)
	if h == 0 {
		return 0, 0, fmt.Errorf("CreateWindowEx: %v", e)
	}
	s := dpi()
	px := func(v uintptr) uintptr { return v * s / 96 }
	t, _, _ := pCreateWindow.Call(0, uintptr(unsafe.Pointer(stc)), uintptr(unsafe.Pointer(l)), child|0x0200, // SS_CENTERIMAGE: по центру по высоте
		px(10), 0, px(280), px(plaqueH), h, 0, inst, 0)
	k, _, _ := pCreateWindow.Call(0, uintptr(unsafe.Pointer(bc)), uintptr(unsafe.Pointer(b)), child,
		px(295), px(6), px(95), px(28), h, idBtn, inst, 0)
	if t == 0 || k == 0 { // без кнопки «Разорвать» плашка неполна — REQ-S-08
		pDestroyWindow.Call(h)
		return 0, 0, fmt.Errorf("плашка: элементы окна не созданы")
	}
	face, _ := syscall.UTF16PtrFromString("Segoe UI")
	font, _, _ = pCreateFont.Call(^(9*s/72)+1, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(face))) // −9 pt, CLEARTYPE_QUALITY
	pSendMsg.Call(t, wmSetFont, font, 1)
	pSendMsg.Call(k, wmSetFont, font, 1)
	placePlaque(h)
	pShowWindow.Call(h, 4) // SW_SHOWNOACTIVATE
	pSetTimer.Call(h, 1, 2000, 0)
	return h, font, nil
}

// showIndicator — плашка REQ-F-15. Не создалась → ошибка, и сессия не стартует (REQ-S-08).
func showIndicator(cid string, mode plaqueMode, onUserClose func()) (closeFn func(), err error) {
	label, btn := plaqueBar(uiLang(), cid, mode)
	var byUs atomic.Bool
	ready := make(chan error, 1)
	var hwnd uintptr
	go func() {
		runtime.LockOSThread() // окно принадлежит потоку: создание и цикл сообщений — на одном
		h, font, err := createPlaque(label, btn)
		if err != nil {
			ready <- err
			return
		}
		hwnd = h
		ready <- nil
		var m winMsg
		for {
			if r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0); int32(r) <= 0 {
				break
			}
			pTranslateMsg.Call(uintptr(unsafe.Pointer(&m)))
			pDispatchMsg.Call(uintptr(unsafe.Pointer(&m)))
		}
		pDeleteObject.Call(font)
		if !byUs.Load() {
			onUserClose()
		}
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return func() {
		byUs.Store(true)
		pPostMsg.Call(hwnd, wmClose, 0, 0)
	}, nil
}
