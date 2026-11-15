package agent

import (
	"context"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	pGetOpenFileName  = syscall.NewLazyDLL("comdlg32.dll").NewProc("GetOpenFileNameW")
	pSHBrowseForFold  = shell32.NewProc("SHBrowseForFolderW")
	pSHGetPathFromIDL = shell32.NewProc("SHGetPathFromIDListW")
	ole32             = syscall.NewLazyDLL("ole32.dll")
	pCoInitializeEx   = ole32.NewProc("CoInitializeEx")
	pCoUninitialize   = ole32.NewProc("CoUninitialize")
)

// BROWSEINFOW.
type browseInfo struct {
	owner       uintptr
	root        uintptr
	displayName *uint16
	title       *uint16
	flags       uint32
	fn          uintptr
	lparam      uintptr
	image       int32
}

// pickDir — окно выбора папки (SHBrowseForFolder; путь до MAX_PATH). Не проверено на Windows — V2.
func pickDir(context.Context) (string, bool) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if r, _, _ := pCoInitializeEx.Call(0, 2); r == 0 || r == 1 { // COINIT_APARTMENTTHREADED; S_OK, S_FALSE — снять
		defer pCoUninitialize.Call()
	}
	name := make([]uint16, 260)
	title, _ := syscall.UTF16PtrFromString("AnyPC")
	bi := browseInfo{displayName: &name[0], title: title, flags: 0x1 | 0x40} // BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE
	pidl, _, _ := pSHBrowseForFold.Call(uintptr(unsafe.Pointer(&bi)))
	if pidl == 0 {
		return "", false
	}
	defer pCoTaskMemFree.Call(pidl)
	buf := make([]uint16, 260)
	if r, _, _ := pSHGetPathFromIDL.Call(pidl, uintptr(unsafe.Pointer(&buf[0]))); r == 0 {
		return "", false
	}
	return syscall.UTF16ToString(buf), true
}

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
// ponytail: ctx не закрывает окно GetOpenFileName — выбор после перехода в просмотр отбрасывает вызывающий; закрывать
// через EndDialog по hwnd из хука, если понадобится.
func pickFile(context.Context) (string, bool) {
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
