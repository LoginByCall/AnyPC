package main

import (
	"errors"
	"log"
)

// Одна копия AnyPC на пользователя ОС (просьба владельца 2026-11-14): блокировка файла anypc.lock в каталоге настроек
// (рядом с config.json). Её снимает ОС при любом выходе процесса, и при падении тоже, — PID-файлов «жив ли» нет.
// Блокировку берёт lockInstance: single_unix.go (flock) и single_windows.go (LockFileEx).

// errRunning — блокировку держит другая копия.
var errRunning = errors.New("AnyPC уже запущен")

// singleInstance — взять блокировку в dir. running — уже запущена другая копия: сообщить в журнал и показать её окно
// (show; nil — не показывать), этой — выйти с кодом 0. Иначе unlock держать до выхода.
func singleInstance(dir string, show func() error) (unlock func(), running bool) {
	unlock, err := lockInstance(dir)
	switch {
	case err == nil:
		return unlock, false
	case errors.Is(err, errRunning):
		log.Print("AnyPC уже запущен — эта копия выходит")
		if show != nil {
			if err := show(); err != nil {
				log.Printf("окно запущенной копии не открыто: %v", err)
			}
		}
		return nil, true
	}
	// ponytail: блокировку не взять (каталог не создаётся, нет прав, ФС без блокировок) — запускаемся с записью
	// в журнал: лучше возможная вторая копия, чем ни одной (удалённый доступ к ПК — то, ради чего программа живёт).
	log.Printf("проверка второй копии не удалась (%v) — запускаюсь без неё", err)
	return func() {}, false
}
