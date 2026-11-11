package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Окно «Разрешить» через TaskDialog: три кнопки со своими подписями (Разрешить / Только просмотр / Отклонить)
// вместо Да/Нет/Отмена у MessageBox. TaskDialog есть только в Common Controls v6, а у AnyPC.exe нет манифеста —
// версия 6 включается контекстом активации из маленького манифеста во временной папке. Любая ошибка → MessageBox.

const (
	tdAllow, tdView, tdDeny = 100, 101, 102
	tdmClickButton          = 0x0400 + 102 // TDM_CLICK_BUTTON
	tdmEnableButton         = 0x0400 + 111 // TDM_ENABLE_BUTTON: wParam — ID кнопки, lParam — 0 выключить / 1 включить
	tdnCreated, tdnTimer    = 0, 4
	tdnButtonClicked        = 2 // вернуть S_FALSE (1) — окно не закрывать
	idCancel                = 2 // IDCANCEL: Esc и крестик
)

const comctl6Manifest = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<dependency><dependentAssembly><assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/></dependentAssembly></dependency>
</assembly>`

// actCtx — ACTCTXW, x64: 56 байт; выравнивание Go совпадает с C.
type actCtx struct {
	size    uint32
	flags   uint32
	source  *uint16
	arch    uint16
	lang    uint16
	asmDir  *uint16
	resName *uint16
	appName *uint16
	hModule uintptr
}

// tdRun — одно окно. Буферы, на которые смотрит comctl32, — здесь, в куче: стек горутины Go при росте переезжает,
// и адреса pButtons/pnButton со стека стали бы чужими (ответ «Разрешить» потерялся бы или испортил память).
type tdRun struct {
	timeout time.Duration
	delay   time.Duration // кнопки согласия выключены столько после появления окна
	enabled bool          // уже включены (только из tdCallbackFn — поток окна)
	click   int           // тест: нажать эту кнопку сразу после появления окна
	cfg     [160]byte     // TASKDIALOGCONFIG (pshpack1), x64
	btns    [36]byte      // 3 × TASKDIALOG_BUTTON (pshpack1): int + PCWSTR = 12 байт
	pressed int32
}

var (
	kernel32w          = syscall.NewLazyDLL("kernel32.dll")
	procCreateActCtx   = kernel32w.NewProc("CreateActCtxW")
	procActivateActCtx = kernel32w.NewProc("ActivateActCtx")
	procDeactivateCtx  = kernel32w.NewProc("DeactivateActCtx")
	procSetWindowPos   = user32.NewProc("SetWindowPos")
	procSetForeground  = user32.NewProc("SetForegroundWindow")
	procPostMessage    = user32.NewProc("PostMessageW")

	tdOnce     sync.Once
	tdCtx      uintptr // контекст активации Common Controls v6
	tdProc     uintptr // TaskDialogIndirect из comctl32 v6
	tdCallback uintptr
	tdInitErr  error

	tdMu   sync.Mutex
	tdRuns = map[uintptr]*tdRun{}
	tdSeq  uintptr
)

func tdInit() {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		tdInitErr = errors.New("TaskDialog: раскладка структур только для x64")
		return
	}
	dir, err := os.MkdirTemp("", "anypc-comctl6-") // своя папка со случайным именем: файл не подменить заранее
	if err != nil {
		tdInitErr = err
		return
	}
	path := filepath.Join(dir, "comctl6.manifest")
	if err := os.WriteFile(path, []byte(comctl6Manifest), 0o600); err != nil {
		tdInitErr = err
		return
	}
	src, _ := syscall.UTF16PtrFromString(path)
	ac := actCtx{source: src}
	ac.size = uint32(unsafe.Sizeof(ac))
	h, _, err := procCreateActCtx.Call(uintptr(unsafe.Pointer(&ac)))
	if h == ^uintptr(0) {
		tdInitErr = fmt.Errorf("CreateActCtx: %v", err)
		return
	}
	tdCtx = h
	err = withComctl6(func() error { // comctl32 v6 загружается рядом с v5 (side-by-side), только внутри контекста
		lib, err := syscall.LoadLibrary("comctl32.dll")
		if err != nil {
			return err
		}
		tdProc, err = syscall.GetProcAddress(lib, "TaskDialogIndirect")
		return err
	})
	if err != nil {
		tdInitErr = fmt.Errorf("comctl32 v6: %w", err)
		return
	}
	tdCallback = syscall.NewCallback(tdCallbackFn)
}

// withComctl6 — f внутри контекста активации; контекст привязан к потоку ОС.
func withComctl6(f func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var cookie uintptr
	if ok, _, err := procActivateActCtx.Call(tdCtx, uintptr(unsafe.Pointer(&cookie))); uint32(ok) == 0 { // BOOL — 32 бита
		return fmt.Errorf("ActivateActCtx: %v", err)
	}
	defer procDeactivateCtx.Call(0, cookie)
	return f()
}

func tdCallbackFn(hwnd uintptr, msg uint32, wparam, lparam, ref uintptr) uintptr { // msg — UINT
	tdMu.Lock()
	r := tdRuns[ref]
	tdMu.Unlock()
	if r == nil {
		return 0
	}
	switch msg {
	case tdnCreated: // поверх всех окон и на передний план, как MB_TOPMOST|MB_SETFOREGROUND
		procSetWindowPos.Call(hwnd, ^uintptr(0), 0, 0, 0, 0, 0x3) // HWND_TOPMOST, SWP_NOSIZE|SWP_NOMOVE
		procSetForeground.Call(hwnd)
		if r.delay > 0 { // «Разрешить» и «Только просмотр» — не раньше delay (включит tdnTimer)
			procPostMessage.Call(hwnd, tdmEnableButton, tdAllow, 0)
			procPostMessage.Call(hwnd, tdmEnableButton, tdView, 0)
		}
		if r.click != 0 {
			procPostMessage.Call(hwnd, tdmClickButton, uintptr(r.click), 0)
		}
	case tdnButtonClicked: // и если кнопка всё же нажата раньше delay (включилась раньше, клавиатура) — не засчитать
		if r.delay > 0 && !r.enabled && (wparam == tdAllow || wparam == tdView) {
			return 1
		}
	case tdnTimer: // wparam — мс с появления окна (таймер — раз в ~200 мс)
		if el := time.Duration(wparam) * time.Millisecond; r.delay > 0 && !r.enabled && el >= r.delay {
			r.enabled = true
			procPostMessage.Call(hwnd, tdmEnableButton, tdAllow, 1)
			procPostMessage.Call(hwnd, tdmEnableButton, tdView, 1)
		}
		if time.Duration(wparam)*time.Millisecond >= r.timeout {
			procPostMessage.Call(hwnd, tdmClickButton, tdDeny, 0) // своя кнопка точно есть; IDCANCEL без кнопки «Отмена» не гарантирован
		}
	}
	return 0
}

// askTaskDialog — окно с кнопками yes / view / no; Esc, крестик и истёкшее время → Deny. Кнопка по умолчанию — «Отклонить».
// delay > 0 — yes и view выключены первые delay (TDM_ENABLE_BUTTON по таймеру окна).
func askTaskDialog(title, text, yes, no, view string, timeout, delay time.Duration, click int) (Answer, error) {
	tdOnce.Do(tdInit)
	if tdInitErr != nil {
		return Deny, tdInitErr
	}
	u := func(s string) *uint16 { p, _ := syscall.UTF16PtrFromString(s); return p }
	t, c := u(title), u(text)
	labels := []*uint16{u(yes), u(view), u(no)}
	r := &tdRun{timeout: timeout, delay: delay, click: click}
	for i, id := range []int32{tdAllow, tdView, tdDeny} {
		binary.LittleEndian.PutUint32(r.btns[i*12:], uint32(id))
		binary.LittleEndian.PutUint64(r.btns[i*12+4:], uint64(uintptr(unsafe.Pointer(labels[i]))))
	}
	tdMu.Lock()
	tdSeq++
	ref := tdSeq
	tdRuns[ref] = r // map держит r в куче на всё время окна
	tdMu.Unlock()
	defer func() { tdMu.Lock(); delete(tdRuns, ref); tdMu.Unlock() }()

	p32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(r.cfg[off:], v) }
	p64 := func(off int, v uintptr) { binary.LittleEndian.PutUint64(r.cfg[off:], uint64(v)) }
	p32(0, 160)
	p32(20, 0x0008|0x0800)              // TDF_ALLOW_DIALOG_CANCELLATION | TDF_CALLBACK_TIMER
	p64(28, uintptr(unsafe.Pointer(t))) // pszWindowTitle
	p64(36, 0xFFFF)                     // TD_WARNING_ICON
	p64(52, uintptr(unsafe.Pointer(c))) // pszContent
	p32(60, 3)                          // cButtons
	p64(64, uintptr(unsafe.Pointer(&r.btns[0])))
	p32(72, tdDeny)      // nDefaultButton: Enter — отказ
	p64(140, tdCallback) // pfCallback
	p64(148, ref)        // lpCallbackData
	var hr uintptr
	err := withComctl6(func() error {
		hr, _, _ = syscall.SyscallN(tdProc, uintptr(unsafe.Pointer(&r.cfg[0])), uintptr(unsafe.Pointer(&r.pressed)), 0, 0)
		return nil
	})
	runtime.KeepAlive(labels)
	runtime.KeepAlive(t)
	runtime.KeepAlive(c)
	runtime.KeepAlive(r)
	if err != nil {
		return Deny, err
	}
	if int32(hr) != 0 { // HRESULT — 32 бита, старшая половина RAX не определена
		return Deny, fmt.Errorf("TaskDialogIndirect: HRESULT %#x", uint32(hr))
	}
	switch r.pressed {
	case tdAllow:
		return Allow, nil
	case tdView:
		return ViewOnly, nil
	}
	return Deny, nil
}
