package main

// Этап «окна пространства», Ч2: фоновая операция пространства для окна (UI-REDESIGN.md, «API»). Привязки WebView2 на
// Windows зовутся синхронно в потоке окна, а вступление, «Работаю тут» и правки фразой идут до 60–90 с — они
// выполняются здесь в фоне, окно опрашивает spaceOp. В памяти одна операция; итог хранится spaceOpKeep; на диск
// ничего не пишется. Пароль, код и фраза живут только в замыкании операции до её конца.

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	errSpaceBusy = errors.New("пространство: уже идёт другая операция — дождитесь её конца")
	errSpaceNoOp = errors.New("пространство: подтверждать нечего")
)

// spaceOpKeep — сколько хранится итог операции; spaceOpNow — часы (тест).
var (
	spaceOpKeep = 5 * time.Minute
	spaceOpNow  = time.Now
)

// spaceOpFn — тело операции: preview — показать состав и ждать ответа из ok (только вступление).
type spaceOpFn func(ctx context.Context, preview func(spacePreview), ok <-chan bool) (any, error)

type spaceOpState struct {
	kind    string
	state   string // run | confirm | done | err
	preview *spacePreview
	result  any
	err     error
	end     time.Time // конец; нулевое — идёт
	ok      chan bool
}

type spaceOpRun struct {
	mu  sync.Mutex
	cur *spaceOpState
	wg  sync.WaitGroup // тест: дождаться конца
}

var spaceOps spaceOpRun

// liveLocked — текущая операция: идёт или кончилась не раньше spaceOpKeep назад (под r.mu).
func (r *spaceOpRun) liveLocked() *spaceOpState {
	if o := r.cur; o != nil && (o.end.IsZero() || spaceOpNow().Sub(o.end) < spaceOpKeep) {
		return o
	}
	r.cur = nil
	return nil
}

// busy — операция идёт.
func (r *spaceOpRun) busy() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	o := r.liveLocked()
	return o != nil && o.end.IsZero()
}

// start — запустить операцию kind в фоне; идёт другая — errSpaceBusy. Кончившаяся заменяется.
func (r *spaceOpRun) start(kind string, f spaceOpFn) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if o := r.liveLocked(); o != nil && o.end.IsZero() {
		return errSpaceBusy
	}
	o := &spaceOpState{kind: kind, state: "run", ok: make(chan bool, 1)}
	r.cur = o
	preview := func(p spacePreview) {
		r.mu.Lock()
		o.preview, o.state = &p, "confirm"
		r.mu.Unlock()
	}
	r.wg.Go(func() {
		res, err := f(context.Background(), preview, o.ok)
		r.mu.Lock()
		defer r.mu.Unlock()
		o.result, o.err, o.preview, o.end, o.state = res, err, nil, spaceOpNow(), "done"
		if err != nil {
			o.result, o.state = nil, "err"
		}
	})
	return nil
}

// confirm — ответ окна на «Это все ваши ПК?»; операции, ждущей ответа, нет — errSpaceNoOp.
func (r *spaceOpRun) confirm(yes bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	o := r.liveLocked()
	if o == nil || o.state != "confirm" {
		return errSpaceNoOp
	}
	o.ok <- yes // буфер 1, ответ на превью — один: preview зовётся один раз
	o.state = "run"
	return nil
}

// snap — состояние для окна: nil — операции нет; full — с превью и итогом (spaceOp), иначе только вид и состояние
// (hostInfo: итог правки фразой несёт QR нового кода).
func (r *spaceOpRun) snap(full bool) map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	o := r.liveLocked()
	if o == nil {
		return nil
	}
	m := map[string]any{"kind": o.kind, "state": o.state}
	if o.err != nil {
		m["err"] = spaceErrCode(o.err)
	}
	if full {
		if o.preview != nil {
			m["preview"] = previewJSON(*o.preview)
		}
		m["result"] = o.result
	}
	return m
}
