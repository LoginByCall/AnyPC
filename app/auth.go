package main

import "errors"

var errSystemAuth = errors.New("системная авторизация не пройдена")

// systemAuth вызывается только из изменяющих настройки API, а не из опросов состояния.
var systemAuth = systemAuthorize

func authDo(f func() error) error {
	if err := systemAuth(); err != nil {
		return err
	}
	return f()
}

func authResult[T any](f func() (T, error)) (T, error) {
	if err := systemAuth(); err != nil {
		var zero T
		return zero, err
	}
	return f()
}
