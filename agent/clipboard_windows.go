package agent

import (
	"errors"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32     = syscall.NewLazyDLL("kernel32.dll")
	pOpenClip    = user32.NewProc("OpenClipboard")
	pCloseClip   = user32.NewProc("CloseClipboard")
	pEmptyClip   = user32.NewProc("EmptyClipboard")
	pGetClipData = user32.NewProc("GetClipboardData")
	pSetClipData = user32.NewProc("SetClipboardData")
	pClipSeq     = user32.NewProc("GetClipboardSequenceNumber")
	pGAlloc      = kernel32.NewProc("GlobalAlloc")
	pGLock       = kernel32.NewProc("GlobalLock")
	pGUnlock     = kernel32.NewProc("GlobalUnlock")
	pGFree       = kernel32.NewProc("GlobalFree")
	pGSize       = kernel32.NewProc("GlobalSize")
)

const cfUnicodeText = 13

func ptr(p uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&p)) }

func openClip() error {
	for i := 0; i < 10; i++ { // буфер может держать другое приложение
		if r, _, _ := pOpenClip.Call(0); r != 0 {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errors.New("буфер обмена занят")
}

// ClipSeq меняется при каждом изменении буфера обмена — дешёвая проверка без чтения.
func ClipSeq() uint32 { r, _, _ := pClipSeq.Call(); return uint32(r) }

// ClipText — текст из буфера обмена ("" — текста нет).
func ClipText() (string, error) { return clipTextN(ClipMax + 1) }

// errClipLong — буфер длиннее предела «Отправить» (1 МБ): не обрезать молча.
var errClipLong = errors.New("буфер обмена больше 1 МБ")

// clipReadFull — буфер целиком для «Отправить» (send.go): до 1 Мi знаков UTF-16, больше — errClipLong.
func clipReadFull() (string, error) {
	const lim = 1 << 20
	s, err := clipTextN(lim + 1)
	if err == nil && len(syscall.StringToUTF16(s))-1 > lim {
		return "", errClipLong
	}
	return s, err
}

// clipTextN — текст буфера, не больше lim знаков UTF-16.
func clipTextN(lim int) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := openClip(); err != nil {
		return "", err
	}
	defer pCloseClip.Call()
	h, _, _ := pGetClipData.Call(cfUnicodeText)
	if h == 0 {
		return "", nil
	}
	p, _, _ := pGLock.Call(h)
	if p == 0 {
		return "", errors.New("GlobalLock")
	}
	defer pGUnlock.Call(h)
	size, _, _ := pGSize.Call(h) // текст без NUL (его кладёт любое приложение) — не читать за блоком
	n, lim := 0, min(lim, int(size/2))
	for n < lim && *(*uint16)(unsafe.Add(ptr(p), n*2)) != 0 {
		n++
	}
	return syscall.UTF16ToString(unsafe.Slice((*uint16)(ptr(p)), n)), nil
}

func SetClipText(s string) error {
	u, err := syscall.UTF16FromString(s)
	if err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	h, _, _ := pGAlloc.Call(0x0002, uintptr(len(u)*2)) // GMEM_MOVEABLE
	if h == 0 {
		return errors.New("GlobalAlloc")
	}
	p, _, _ := pGLock.Call(h)
	if p == 0 {
		pGFree.Call(h)
		return errors.New("GlobalLock")
	}
	copy(unsafe.Slice((*uint16)(ptr(p)), len(u)), u)
	pGUnlock.Call(h)
	if err := openClip(); err != nil {
		pGFree.Call(h)
		return err
	}
	defer pCloseClip.Call()
	pEmptyClip.Call()
	if r, _, _ := pSetClipData.Call(cfUnicodeText, h); r == 0 {
		pGFree.Call(h)
		return errors.New("SetClipboardData")
	}
	return nil // память теперь принадлежит системе
}
