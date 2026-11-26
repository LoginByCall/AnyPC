package main

/*
#cgo LDFLAGS: -framework LocalAuthentication
int anypcAuthorize(void);
*/
import "C"

// systemAuthorize — LocalAuthentication: Touch ID или системный пароль macOS.
func systemAuthorize() error {
	if C.anypcAuthorize() != 0 {
		return errSystemAuth
	}
	return nil
}
