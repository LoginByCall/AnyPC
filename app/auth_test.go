package main

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"anypc/totp"
)

// TestAuthDo: без гранта действие не выполняется и окно ОС само не открывается; enter открыл — действия идут
// без prompt; leave закрыл — снова нужен enter.
func TestAuthDo(t *testing.T) {
	old := systemAuth
	defer func() { systemAuth = old; settingsReset() }()
	prompts := 0
	systemAuth = func() error { prompts++; return nil }
	settingsReset()
	called := false
	if err := authDo(func() error { called = true; return nil }); !errors.Is(err, errSystemAuth) || called || prompts != 0 {
		t.Fatalf("действие без гранта: err=%v called=%v окон=%d", err, called, prompts)
	}
	if err := settingsAuthorize(); err != nil {
		t.Fatalf("enter: %v", err)
	}
	if err := authDo(func() error { called = true; return nil }); err != nil || !called {
		t.Fatalf("действие после enter: err=%v called=%v", err, called)
	}
	if prompts != 1 {
		t.Fatalf("повторные действия спросили пароль: %d", prompts)
	}
	settingsReset()
	called = false
	if err := authDo(func() error { called = true; return nil }); !errors.Is(err, errSystemAuth) || called {
		t.Fatalf("действие после leave: err=%v called=%v", err, called)
	}
}

// TestAuthResult: то же для вызовов с результатом.
func TestAuthResult(t *testing.T) {
	old := systemAuth
	defer func() { systemAuth = old; settingsReset() }()
	prompts := 0
	systemAuth = func() error { prompts++; return nil }
	settingsReset()
	v, err := authResult(func() (string, error) { return "secret", nil })
	if !errors.Is(err, errSystemAuth) || v != "" || prompts != 0 {
		t.Fatalf("результат без гранта: %q %v окон=%d", v, err, prompts)
	}
	if err := settingsAuthorize(); err != nil {
		t.Fatalf("enter: %v", err)
	}
	if v, err = authResult(func() (string, error) { return "ok", nil }); err != nil || v != "ok" {
		t.Fatalf("результат после enter: %q %v", v, err)
	}
	if prompts != 1 {
		t.Fatalf("повторный результат спросил пароль: %d", prompts)
	}
}

// TestSettingsAuthorize: отказ грант не создаёт; параллельные enter — один prompt с общим результатом;
// успех кэшируется; leave требует новый enter.
func TestSettingsAuthorize(t *testing.T) {
	old := systemAuth
	defer func() { systemAuth = old; settingsReset() }()
	settingsReset()
	systemAuth = func() error { return errSystemAuth }
	if err := settingsAuthorize(); !errors.Is(err, errSystemAuth) {
		t.Fatalf("отказ: %v", err)
	}
	if err := authCheck(); !errors.Is(err, errSystemAuth) {
		t.Fatalf("отказ открыл грант: %v", err)
	}
	release := make(chan struct{})
	started := make(chan struct{}, 8)
	var prompts atomic.Int64
	systemAuth = func() error {
		prompts.Add(1)
		<-release // лидер держит окно, пока все параллельные enter не вошли
		return nil
	}
	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			started <- struct{}{}
			errs[i] = settingsAuthorize()
		}()
	}
	for range n {
		<-started
	}
	close(release) // все вошли: полёт один, ждущие делят его результат (опоздавшие — кэш гранта)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("параллельный enter %d: %v", i, err)
		}
	}
	if prompts.Load() != 1 {
		t.Fatalf("параллельные enter: окон %d, ждали 1", prompts.Load())
	}
	if err := settingsAuthorize(); err != nil || prompts.Load() != 1 { // успех кэшируется
		t.Fatalf("повторный enter: %v, окон %d", err, prompts.Load())
	}
	settingsReset()
	prompts.Store(0)
	if err := settingsAuthorize(); err != nil || prompts.Load() != 1 { // leave требует новый enter
		t.Fatalf("enter после leave: %v, окон %d", err, prompts.Load())
	}
}

func TestSettingsAuthorizeResetFlight(t *testing.T) {
	old := systemAuth
	defer func() { systemAuth = old; settingsReset() }()
	settingsReset()
	started := make(chan struct{})
	release := make(chan struct{})
	systemAuth = func() error { close(started); <-release; return nil }
	done := make(chan error, 1)
	go func() { done <- settingsAuthorize() }()
	<-started
	settingsReset()
	close(release)
	if err := <-done; !errors.Is(err, errSystemAuth) {
		t.Fatalf("поздний ответ после выхода: %v", err)
	}
	if err := authCheck(); !errors.Is(err, errSystemAuth) {
		t.Fatalf("выход из настроек во время окна оставил грант: %v", err)
	}
}

func TestSpaceCallAuth(t *testing.T) {
	old := systemAuth
	defer func() { systemAuth = old; settingsReset() }()
	systemAuth = func() error { return errSystemAuth } // окна нет и гранта нет: spaceCreate в обеих моделях отказан
	settingsReset()
	c := spaceCfg(t, spacePass, totp.NewSecret())
	if _, err := spaceCall(c, "spaceCreate", nil); !errors.Is(err, errSystemAuth) {
		t.Fatalf("spaceCreate без авторизации: %v", err)
	}
	for range 3 {
		if _, err := spaceCall(c, "spaceOp", nil); err != nil {
			t.Fatalf("spaceOp — опрос состояния, авторизация не нужна: %v", err)
		}
	}
}
