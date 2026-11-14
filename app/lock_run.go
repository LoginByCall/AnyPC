package main

// Общее детекторов блокировки экрана (lock_linux.go, lock_windows.go, lock_darwin.go): пауза повтора, «один детектор
// на процесс» и порядок «подписка → alive(true)» — без ограничения сборки, тест идёт на Linux (lock_run_test.go).

import (
	"context"
	"log"
	"sync/atomic"
	"time"
)

// lockRetry, lockRetryMax — пауза переподключения к источнику (растёт вдвое).
var lockRetry, lockRetryMax = 2 * time.Second, 5 * time.Minute

// lockGuard — детектор с общим состоянием (окно Windows, наблюдатель Мака) — один на процесс: второй startLock при
// живом первом получает отказ, иначе конец одного снял бы подписку другого, а тот остался бы «жив».
type lockGuard struct{ busy atomic.Bool }

func (g *lockGuard) take() bool { return g.busy.CompareAndSwap(false, true) }
func (g *lockGuard) drop()      { g.busy.Store(false) }

// lockRun — ход детектора без повторов (Мак): занят другим или ready() = false — alive(false); иначе sub() (вернулась —
// подписка стоит), затем alive(true); конец ctx — unsub() (вернулась — подписки нет), затем alive(false).
func lockRun(ctx context.Context, src string, g *lockGuard, ready func() bool, sub, unsub func(), alive func(string, bool)) {
	if !g.take() {
		log.Printf("блокировка экрана (%s): детектор уже запущен — второй не нужен", src)
		alive(src, false)
		return
	}
	defer g.drop()
	if !ready() {
		log.Printf("блокировка экрана (%s): нет графического сеанса — не отслеживается", src)
		alive(src, false)
		return
	}
	sub()
	alive(src, true)
	log.Printf("блокировка экрана: отслеживается (%s)", src)
	<-ctx.Done()
	unsub()
	alive(src, false)
}
