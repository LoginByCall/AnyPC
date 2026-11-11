package agent

import (
	"fmt"
	"log"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

var (
	user32         = syscall.NewLazyDLL("user32.dll")
	procSendInput  = user32.NewProc("SendInput")
	procCursorInfo = user32.NewProc("GetCursorInfo")
	procLoadCursor = user32.NewProc("LoadCursorW")
	winCursors     = map[uintptr]string{} // дескриптор системного курсора → имя CSS (общие для всех процессов)
)

func init() {
	for id, name := range map[uintptr]string{32512: "default", 32513: "text", 32514: "wait", 32515: "crosshair", 32642: "nwse-resize",
		32643: "nesw-resize", 32644: "ew-resize", 32645: "ns-resize", 32646: "move", 32648: "not-allowed", 32649: "pointer", 32650: "progress", 32651: "help"} {
		if h, _, _ := procLoadCursor.Call(0, id); h != 0 { // IDC_ARROW … IDC_HELP
			winCursors[h] = name
		}
	}
	cursorInfo = winCursor
}

// winCursor — GetCursorInfo: позиция в физических пикселях (процесс Per-Monitor DPI aware v2 — как DXGI) и форма;
// курсор приложения (не системный) — default.
func winCursor() (x, y int, shape string, ok bool) {
	var ci struct {
		size, flags uint32
		cursor      uintptr
		x, y        int32
	}
	ci.size = uint32(unsafe.Sizeof(ci))
	if r, _, _ := procCursorInfo.Call(uintptr(unsafe.Pointer(&ci))); r == 0 || ci.flags&1 == 0 { // CURSOR_SHOWING
		return 0, 0, "", false
	}
	if shape = winCursors[ci.cursor]; shape == "" {
		shape = "default"
	}
	return int(ci.x), int(ci.y), shape, true
}

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

// hideWindow: ffmpeg без консольного окна (CREATE_NO_WINDOW).
func hideWindow(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}

// AskAccept — окно «Разрешить / Отклонить» (REQ-F-03) поверх всех окон; без ответа AskTimeout → отказ.
// MessageBoxTimeoutW — недокументированная, но стабильная с Windows XP функция user32; нет её — отказ.
// ponytail: подписи кнопок MessageBox системные (Да/Нет/Отмена), их смысл объяснён строкой в тексте (winAskHint);
// свои подписи — TaskDialog (нужен манифест comctl32 v6), если строка окажется непонятной.
func AskAccept(cid, peer string) Answer {
	title, text, yes, no, view := askText(uiLang(), cid, peer, false)
	a, err := askTaskDialog(title, text, yes, no, view, AskTimeout, AskDelay, 0) // кнопки согласия выключены первые AskDelay
	if err == nil {
		return a
	}
	log.Printf("окно «Разрешить»: %v — запасное окно MessageBox", err)
	return askMessageBox(cid, peer)
}

// askMessageBox — запасное окно: Да / Нет / Отмена с поясняющей строкой.
func askMessageBox(cid, peer string) Answer {
	p := user32.NewProc("MessageBoxTimeoutW")
	if p.Find() != nil {
		log.Printf("нет MessageBoxTimeoutW — подключение %s отклонено", cid)
		return Deny
	}
	lang := uiLang()
	title, text, _, _, _ := askText(lang, cid, peer, true)
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(text + "\n\n" + winAskHint(lang))
	const flags = 0x3 | 0x20 | 0x200 | 0x1000 | 0x10000 | 0x40000 // YESNOCANCEL | ICONQUESTION | DEFBUTTON3 (Enter = «Отмена» = отказ) | SYSTEMMODAL | SETFOREGROUND | TOPMOST
	return askLoop(func(left time.Duration) Answer {              // у MessageBox кнопку не выключить: согласие раньше AskDelay — окно снова
		r, _, _ := p.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), flags, 0, uintptr(left/time.Millisecond))
		switch r {
		case 6: // IDYES
			return Allow
		case 7: // IDNO
			return ViewOnly
		}
		return Deny // IDCANCEL, крестик; 32000 — истекло время
	})
}
