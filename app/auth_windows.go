package main

import (
	"syscall"
	"unsafe"
)

// systemAuthorize — CredUIPromptForWindowsCredentialsW: пароль/PIN проверяет сама Windows.
// Возвращённые ею учётные данные сразу затираются и освобождаются через CredFree.
var (
	credui         = syscall.NewLazyDLL("credui.dll")
	promptForCreds = credui.NewProc("CredUIPromptForWindowsCredentialsW")
	credFree       = credui.NewProc("CredFree")
	secureZero     = syscall.NewLazyDLL("kernel32.dll").NewProc("RtlSecureZeroMemory")
)

type credUIInfo struct {
	cbSize         uint32
	hwndParent     uintptr
	pszMessageText *uint16
	pszCaptionText *uint16
	hbmBanner      uintptr
}

func systemAuthorize() error {
	caption, _ := syscall.UTF16PtrFromString("AnyPC — подтверждение настроек")
	message, _ := syscall.UTF16PtrFromString("Подтвердите изменение настроек системной учётной записью.")
	info := credUIInfo{hwndParent: 0, pszMessageText: message, pszCaptionText: caption}
	info.cbSize = uint32(unsafe.Sizeof(info))
	const flags = 0x00000001 | 0x00000010 | 0x00001000 // GENERIC | AUTHPACKAGE_DEFAULT | DO_NOT_PERSIST
	var pkg uint32
	var out uintptr
	var outSize uint32
	rc, _, _ := promptForCreds.Call(
		uintptr(unsafe.Pointer(&info)), 0, uintptr(unsafe.Pointer(&pkg)),
		0, 0,
		uintptr(unsafe.Pointer(&out)), uintptr(unsafe.Pointer(&outSize)),
		0, flags,
	)
	if out != 0 {
		secureZero.Call(out, uintptr(outSize))
		credFree.Call(out)
	}
	if rc != 0 {
		return errSystemAuth
	}
	return nil
}
