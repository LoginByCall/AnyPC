package main

import (
	"errors"
	"testing"

	"anypc/totp"
)

func TestAuthDo(t *testing.T) {
	old := systemAuth
	defer func() { systemAuth = old }()
	called := false
	systemAuth = func() error { return errSystemAuth }
	if err := authDo(func() error { called = true; return nil }); !errors.Is(err, errSystemAuth) || called {
		t.Fatalf("действие без авторизации: err=%v called=%v", err, called)
	}
	systemAuth = func() error { return nil }
	if err := authDo(func() error { called = true; return nil }); err != nil || !called {
		t.Fatalf("действие после авторизации: err=%v called=%v", err, called)
	}
}

func TestSpaceCallAuth(t *testing.T) {
	old := systemAuth
	defer func() { systemAuth = old }()
	systemAuth = func() error { return errSystemAuth }
	c := spaceCfg(t, spacePass, totp.NewSecret())
	if _, err := spaceCall(c, "spaceCreate", nil); !errors.Is(err, errSystemAuth) {
		t.Fatalf("spaceCreate без авторизации: %v", err)
	}
}

func TestAuthResult(t *testing.T) {
	old := systemAuth
	defer func() { systemAuth = old }()
	systemAuth = func() error { return errSystemAuth }
	v, err := authResult(func() (string, error) { return "secret", nil })
	if !errors.Is(err, errSystemAuth) || v != "" {
		t.Fatalf("результат без авторизации: %q %v", v, err)
	}
	systemAuth = func() error { return nil }
	v, err = authResult(func() (string, error) { return "ok", nil })
	if err != nil || v != "ok" {
		t.Fatalf("результат после авторизации: %q %v", v, err)
	}
}
