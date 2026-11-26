//go:build linux

package main

import "github.com/godbus/dbus/v5"

// systemAuthorize — стандартный запрос polkit: системный пароль пользователя графического сеанса.
// Секрет через AnyPC не проходит: его видит только агент аутентификации polkit.
func systemAuthorize() error {
	bus, err := dbus.SessionBus()
	if err != nil {
		return errSystemAuth
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
	if err != nil || !result.Authorized {
		return errSystemAuth
	}
	return nil
}
