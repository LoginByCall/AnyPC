package agent

import (
	"syscall"
	"unsafe"
)

var pGetDiskFree = kernel32.NewProc("GetDiskFreeSpaceExW")

// diskFree — сколько байт в dir доступно пользователю (с учётом дисковых квот).
func diskFree(dir string) (uint64, error) {
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var free uint64
	if r, _, err := pGetDiskFree.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&free)), 0, 0); r == 0 {
		return 0, err
	}
	return free, nil
}
