package agent

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var (
	user32         = syscall.NewLazyDLL("user32.dll")
	procSendInput  = user32.NewProc("SendInput")
	procMessageBox = user32.NewProc("MessageBoxW")
	procFindWindow = user32.NewProc("FindWindowW")
	procPostMsg    = user32.NewProc("PostMessageW")
)

// INPUT для x64: 40 байт, union выровнен на 8.
type mouseInput struct {
	typ    uint32
	_      uint32
	dx, dy int32
	data   int32
	flags  uint32
	time   uint32
	_      uint32
	extra  uintptr
}

type keyInput struct {
	typ   uint32
	_     uint32
	vk    uint16
	scan  uint16
	flags uint32
	time  uint32
	_     uint32
	extra uintptr
	_     [8]byte
}

func sendInput(e event, mon *Monitor) error {
	if !e.key && e.flags&mAbs != 0 && mon != nil { // выбранный монитор → координаты виртуального экрана
		e.x, e.y = virtualDesk(monPoint(mon, e.x, e.y))
		e.flags |= 0x4000 // MOUSEEVENTF_VIRTUALDESK
	}
	var p unsafe.Pointer
	if e.key {
		k := keyInput{typ: 1, scan: e.scan, flags: e.flags}
		p = unsafe.Pointer(&k)
	} else {
		m := mouseInput{typ: 0, dx: e.x, dy: e.y, data: e.data, flags: e.flags}
		p = unsafe.Pointer(&m)
	}
	n, _, err := procSendInput.Call(1, uintptr(p), 40)
	if n != 1 {
		return fmt.Errorf("SendInput: %v", err) // UIPI: окно с правами администратора — Э3
	}
	return nil
}

// uiLang — язык плашки по основному языку интерфейса Windows.
func uiLang() string {
	id, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetUserDefaultUILanguage").Call()
	return map[uintptr]string{0x09: "en", 0x19: "ru", 0x04: "zh", 0x0a: "es", 0x07: "de", 0x0c: "fr", 0x10: "it"}[id&0x3ff]
}

// showIndicator — плашка REQ-F-15 поверх всех окон. «ОК» на ней = разорвать сессию.
// ponytail: MessageBox по центру экрана, видна и оператору; маленькая панель в углу — когда начнёт мешать.
func showIndicator(cid string, onUserClose func()) (closeFn func(), err error) {
	title, text := plaqueText(uiLang(), cid)
	var byUs atomic.Bool
	go func() {
		runtime.LockOSThread()
		t, _ := syscall.UTF16PtrFromString(title)
		m, _ := syscall.UTF16PtrFromString(text)
		const flags = 0x30 | 0x1000 | 0x10000 | 0x40000 // ICONWARNING | SYSTEMMODAL | SETFOREGROUND | TOPMOST
		procMessageBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), flags)
		if !byUs.Load() {
			onUserClose()
		}
	}()
	return func() {
		byUs.Store(true)
		t, _ := syscall.UTF16PtrFromString(title)
		for i := 0; i < 20; i++ { // окно могло ещё не появиться
			if w, _, _ := procFindWindow.Call(0, uintptr(unsafe.Pointer(t))); w != 0 {
				procPostMsg.Call(w, 0x0010, 0, 0) // WM_CLOSE
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		log.Printf("плашка сессии %s не найдена для закрытия", cid)
	}, nil
}

// hideWindow: ffmpeg без консольного окна (CREATE_NO_WINDOW).
func hideWindow(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}

// AskAccept — окно «Разрешить / Отклонить» (REQ-F-03) поверх всех окон; без ответа AskTimeout → отказ.
// MessageBoxTimeoutW — недокументированная, но стабильная с Windows XP функция user32; нет её — отказ.
func AskAccept(cid, peer string) bool {
	p := user32.NewProc("MessageBoxTimeoutW")
	if p.Find() != nil {
		log.Printf("нет MessageBoxTimeoutW — подключение %s отклонено", cid)
		return false
	}
	title, text, _, _ := askText(uiLang(), cid, peer)
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(text)
	const flags = 0x4 | 0x20 | 0x1000 | 0x10000 | 0x40000 // YESNO | ICONQUESTION | SYSTEMMODAL | SETFOREGROUND | TOPMOST
	r, _, _ := p.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), flags, 0, uintptr(AskTimeout/time.Millisecond))
	return r == 6 // IDYES; 32000 — истекло время
}
