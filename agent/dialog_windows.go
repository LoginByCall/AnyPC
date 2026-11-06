package agent

import (
	"runtime"
	"syscall"
	"unsafe"
)

var pGetOpenFileName = syscall.NewLazyDLL("comdlg32.dll").NewProc("GetOpenFileNameW")

// OPENFILENAMEW, x64: 152 байта; выравнивание Go совпадает с C.
type openFileName struct {
	structSize    uint32
	owner         uintptr
	instance      uintptr
	filter        *uint16
	customFilter  *uint16
	maxCustFilter uint32
	filterIndex   uint32
	file          *uint16
	maxFile       uint32
	fileTitle     *uint16
	maxFileTitle  uint32
	initialDir    *uint16
	title         *uint16
	flags         uint32
	fileOffset    uint16
	fileExtension uint16
	defExt        *uint16
	custData      uintptr
	hook          uintptr
	templateName  *uint16
	reserved      uintptr
	reserved2     uint32
	flagsEx       uint32
}

// pickFile открывает на хосте окно выбора файла: оператор выбирает файл удалённой мышью.
// ponytail: окно фонового процесса может открыться за другими окнами (мигает на панели задач).
func pickFile() (string, bool) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	buf := make([]uint16, 32768)
	title, _ := syscall.UTF16PtrFromString("AnyPC")
	ofn := openFileName{file: &buf[0], maxFile: uint32(len(buf)), title: title,
		flags: 0x1000 | 0x800 | 0x80000 | 0x8} // FILEMUSTEXIST | PATHMUSTEXIST | EXPLORER | NOCHANGEDIR
	ofn.structSize = uint32(unsafe.Sizeof(ofn))
	if r, _, _ := pGetOpenFileName.Call(uintptr(unsafe.Pointer(&ofn))); r == 0 {
		return "", false // отмена или ошибка
	}
	return syscall.UTF16ToString(buf), true
}
