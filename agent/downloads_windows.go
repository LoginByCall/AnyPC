package agent

import (
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	shell32           = syscall.NewLazyDLL("shell32.dll")
	pKnownFolderPath  = shell32.NewProc("SHGetKnownFolderPath")
	pCoTaskMemFree    = syscall.NewLazyDLL("ole32.dll").NewProc("CoTaskMemFree")
	folderIDDownloads = struct {
		d1     uint32
		d2, d3 uint16
		d4     [8]byte
	}{0x374DE290, 0x123F, 0x4565, [8]byte{0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B}} // FOLDERID_Downloads
)

// DownloadsDir — папка «Загрузки» по данным Windows: учитывает перенос («Свойства → Расположение», D:\Downloads,
// OneDrive). Нет ответа — %USERPROFILE%\Downloads.
func DownloadsDir() string {
	var p *uint16
	if r, _, _ := pKnownFolderPath.Call(uintptr(unsafe.Pointer(&folderIDDownloads)), 0, 0, uintptr(unsafe.Pointer(&p))); r == 0 && p != nil {
		defer pCoTaskMemFree.Call(uintptr(unsafe.Pointer(p)))
		if d := syscall.UTF16ToString(unsafe.Slice(p, 32768)); d != "" {
			return d
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Downloads")
}
