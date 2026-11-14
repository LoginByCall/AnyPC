package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	pLockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")
	pFindWindow = user32.NewProc("FindWindowW")
)

// lockInstance — LockFileEx (исключительная, без ожидания) на первый байт dir/anypc.lock. Блокировка — на дескрипторе:
// вторая попытка и в том же процессе получает отказ. Дескриптор не наследуется (os.OpenFile).
func lockInstance(dir string) (unlock func(), err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "anypc.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	var ol syscall.Overlapped
	const flags = 0x2 | 0x1 // LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY
	if r, _, e := pLockFileEx.Call(f.Fd(), flags, 0, 1, 0, uintptr(unsafe.Pointer(&ol))); r == 0 {
		f.Close()
		if errors.Is(e, syscall.Errno(33)) { // ERROR_LOCK_VIOLATION
			return nil, errRunning
		}
		return nil, fmt.Errorf("LockFileEx %s: %w", f.Name(), e)
	}
	return func() { f.Close() }, nil
}

// showRunning — окно запущенной копии наверх. WebView2 — окно внутри её процесса, API у него нет: ищется по заголовку
// («AnyPC — ID …», main_windows.go), дальше — как левый щелчок по значку у часов (showMain).
func showRunning(title string) error {
	t, _ := syscall.UTF16PtrFromString(title)
	h, _, _ := pFindWindow.Call(0, uintptr(unsafe.Pointer(t)))
	if h == 0 {
		return errors.New("окно «" + title + "» не найдено")
	}
	showMain(h)
	return nil
}
