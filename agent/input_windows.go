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

func sendInput(e event) error {
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

// plaque: заголовок, текст, подсказка — по основному языку интерфейса Windows.
var plaque = map[uint16][3]string{
	0x09: {"remote session", "A remote session is in progress.", "Click “OK” to disconnect."},
	0x19: {"удалённая сессия", "Идёт удалённая сессия.", "Нажмите «ОК», чтобы разорвать."},
	0x04: {"远程会话", "正在进行远程会话。", "点击“确定”断开连接。"},
	0x0a: {"sesión remota", "Hay una sesión remota en curso.", "Pulse «Aceptar» para desconectar."},
	0x07: {"Fernsitzung", "Eine Fernsitzung ist aktiv.", "Klicken Sie auf „OK“, um zu trennen."},
	0x0c: {"session à distance", "Une session à distance est en cours.", "Cliquez sur « OK » pour déconnecter."},
	0x10: {"sessione remota", "È in corso una sessione remota.", "Fai clic su «OK» per disconnettere."},
}

func uiLang() uint16 {
	id, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetUserDefaultUILanguage").Call()
	if _, ok := plaque[uint16(id)&0x3ff]; ok {
		return uint16(id) & 0x3ff
	}
	return 0x09
}

// showIndicator — плашка REQ-F-15 поверх всех окон. «ОК» на ней = разорвать сессию.
// ponytail: MessageBox по центру экрана, видна и оператору; маленькая панель в углу — когда начнёт мешать.
func showIndicator(cid string, onUserClose func()) (closeFn func()) {
	pl := plaque[uiLang()]
	title := "AnyPC — " + pl[0] + " " + cid
	text := pl[1] + "\n" + cid + "\n\n" + pl[2]
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
	}
}

// hideWindow: ffmpeg без консольного окна (CREATE_NO_WINDOW).
func hideWindow(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}
