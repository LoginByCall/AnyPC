//go:build linux

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/godbus/dbus/v5"
)

// systemAuthorize — стандартный запрос polkit: системный пароль пользователя графического сеанса.
// Секрет через AnyPC не проходит: его видит только агент аутентификации polkit.
func systemAuthorize() error {
	bus, err := dbus.SessionBus()
	if err != nil {
		log.Printf("polkit: %v — пробую sudo", err)
		return sudoAuthorize()
	}
	names := bus.Names()
	if len(names) == 0 {
		return errSystemAuth
	}
	subject := struct {
		Kind string
		ID   map[string]string
	}{"system-bus-name", map[string]string{"name": names[0]}}
	result := struct {
		Authorized  bool
		IsChallenge bool
		Details     map[string]string
	}{}
	err = bus.Object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority").Call(
		"org.freedesktop.PolicyKit1.Authority.CheckAuthorization", 0,
		"org.anypc.manage-settings", map[string]string{}, subject, uint32(1), "").Store(&result)
	if err != nil {
		log.Printf("polkit: %v — пробую sudo", err)
		return sudoAuthorize()
	}
	if !result.Authorized {
		return errSystemAuth
	}
	return nil
}

// sudoAuthorize — запасной путь для систем без polkit: sudo проверяет системный пароль,
// а zenity лишь показывает его стандартное окно ввода.
func sudoAuthorize() error {
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return errSystemAuth
	}
	zenity, err := exec.LookPath("zenity")
	if err != nil {
		return errSystemAuth
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return errSystemAuth
	}
	dir := filepath.Join(cache, "AnyPC")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errSystemAuth
	}
	askpass := filepath.Join(dir, "askpass.sh")
	if err := os.WriteFile(askpass, []byte(fmt.Sprintf("#!/bin/sh\nexec %q --password\n", zenity)), 0o700); err != nil {
		return errSystemAuth
	}
	cmd := exec.Command("sudo", "-A", "-v")
	cmd.Env = append(os.Environ(), "SUDO_ASKPASS="+askpass)
	if err := cmd.Run(); err != nil {
		return errSystemAuth
	}
	return nil
}
