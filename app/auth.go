package main

import (
	"errors"
	"sync"
)

var errSystemAuth = errors.New("системная авторизация не пройдена")

// systemAuth — прямой запрос пароля ОС (polkit, Touch ID, CredUI): его зовут только settingsAuthorize, для тестов он
// заменяется заглушкой. API-вызовы пароль сами не спрашивают — только проверяют грант (authCheck).
var systemAuth = systemAuthorize

// Грант настроек: пароль ОС вводится один раз при входе в «Настройки» или «Доступ к этому ПК» (settingsEnter →
// settingsAuthorize) и живёт до выхода из них (settingsLeave) или закрытия приложения. Изменяющие настройки вызовы
// (authDo, authResult, spaceAuthNames) грант только проверяют.
var (
	authMu  sync.Mutex // охраняет authOK и authGen
	authOK  bool       // грант открыт
	authGen uint64     // поколение гранта: settingsReset аннулирует идущий enter
)

// authCheck — грант настроек открыт.
func authCheck() error {
	authMu.Lock()
	defer authMu.Unlock()
	if !authOK {
		return errSystemAuth
	}
	return nil
}

// settingsAuthorize — enter в настройки: параллельные вызовы делят один запрос ОС и его результат (singleflight),
// успех кэшируется до settingsReset, отказ грант не создаёт.
type authFlight struct {
	done chan struct{}
	err  error
}

var (
	authFlightMu  sync.Mutex  // охраняет authFlightCur
	authFlightCur *authFlight // идущий запрос пароля; nil — его нет
)

func settingsAuthorize() error {
	authFlightMu.Lock()
	f := authFlightCur
	if f == nil {
		f = &authFlight{done: make(chan struct{})}
		authFlightCur = f
		go func() {
			authMu.Lock()
			gen := authGen
			authMu.Unlock()
			var err error
			if authCheck() != nil { // параллельный enter уже ввёл пароль — без окна
				err = systemAuth()
			}
			authMu.Lock()
			if err == nil && authGen != gen {
				err = errSystemAuth // во время окна вышли из настроек: поздний ответ грант не открывает
			}
			if err == nil {
				authOK = true
			}
			authMu.Unlock()
			authFlightMu.Lock()
			f.err = err
			if authFlightCur == f {
				authFlightCur = nil
			}
			authFlightMu.Unlock()
			close(f.done)
		}()
	}
	authFlightMu.Unlock()
	<-f.done
	return f.err
}

// settingsReset — уход с «Настроек»/«Доступа»: грант сброшен, следующий enter спросит пароль снова.
func settingsReset() {
	authMu.Lock()
	authOK = false
	authGen++
	authMu.Unlock()
	authFlightMu.Lock()
	authFlightCur = nil // следующий enter — новый запрос; поздний ответ прежнего аннулирован authGen
	authFlightMu.Unlock()
}

func authDo(f func() error) error {
	if err := authCheck(); err != nil {
		return err
	}
	return f()
}

func authResult[T any](f func() (T, error)) (T, error) {
	if err := authCheck(); err != nil {
		var zero T
		return zero, err
	}
	return f()
}
