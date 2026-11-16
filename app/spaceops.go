package main

// Этап «окна пространства», Ч2: фоновая операция пространства для окна (UI-REDESIGN.md, «API»). Привязки WebView2 на
// Windows зовутся синхронно в потоке окна, а вступление, «Работаю тут» и правки фразой идут до 60–90 с — они
// выполняются здесь в фоне, окно опрашивает spaceOp. В памяти одна операция; итог хранится spaceOpKeep; на диск
// ничего не пишется. Пароль, код и фраза живут только в замыкании операции до её конца.

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"anypc/agent"
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
	state   string    // run | confirm | done | err
	stage   string    // Ч12: шаг идущей операции для окна (вступление: link | auth | admit | list | save), "" — нет
	stageAt time.Time // Ч12б: когда начался stage (admit — отсчёт окна «Пустить?» на том ПК)
	cancel  context.CancelFunc
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

// busyLocked — операция идёт (под r.mu).
func (r *spaceOpRun) busyLocked() bool {
	o := r.liveLocked()
	return o != nil && o.end.IsZero()
}

// hold — синхронный вызов окна (создание, выход) как операция kind: пока f идёт, остальные — errSpaceBusy; после —
// прежний итог на месте, своего следа нет.
func (r *spaceOpRun) hold(kind string, f func() error) error {
	r.mu.Lock()
	if r.busyLocked() {
		r.mu.Unlock()
		return errSpaceBusy
	}
	prev, o := r.cur, &spaceOpState{kind: kind, state: "run"}
	r.cur = o
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		if r.cur == o {
			r.cur = prev
		}
		r.mu.Unlock()
	}()
	return f()
}

// clear — стереть итог (окно: «Готово» после QR); идёт операция — errSpaceBusy.
func (r *spaceOpRun) clear() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.busyLocked() {
		return errSpaceBusy
	}
	r.cur = nil
	return nil
}

// start — запустить операцию kind в фоне; идёт другая — errSpaceBusy. Кончившаяся заменяется.
func (r *spaceOpRun) start(kind string, f spaceOpFn) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.busyLocked() {
		return errSpaceBusy
	}
	ctx, cancel := context.WithCancel(context.Background())
	o := &spaceOpState{kind: kind, state: "run", ok: make(chan bool, 1), cancel: cancel}
	r.cur = o
	ctx = context.WithValue(ctx, spaceStageKey{}, func(st string) {
		r.mu.Lock()
		if o.end.IsZero() && o.stage != st {
			o.stage, o.stageAt = st, spaceOpNow()
		}
		r.mu.Unlock()
	})
	preview := func(p spacePreview) {
		r.mu.Lock()
		if o.end.IsZero() { // превью после конца (обмен оборвался, пока Sign шёл к нему) — не воскрешать операцию
			o.preview, o.state = &p, "confirm"
		}
		r.mu.Unlock()
	}
	r.wg.Go(func() {
		res, err := f(ctx, preview, o.ok)
		cancel()
		r.mu.Lock()
		defer r.mu.Unlock()
		o.result, o.err, o.preview, o.end, o.state, o.stage = res, err, nil, spaceOpNow(), "done", ""
		if err != nil {
			o.result, o.state = nil, "err"
			if spaceErrCode(err) == "other" { // окну — код, текст — в журнал (ошибки ядра секретов не содержат)
				log.Printf("пространство: %s: %v", kind, err)
			}
		}
	})
	return nil
}

// confirm — ответ окна на «Это все ваши ПК?»; операции, ждущей ответа, нет — errSpaceNoOp.
func (r *spaceOpRun) confirm(yes bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	o := r.liveLocked()
	if o == nil || o.state != "confirm" || !o.end.IsZero() {
		return errSpaceNoOp
	}
	o.ok <- yes // буфер 1, ответ на превью — один: preview зовётся один раз
	o.state = "run"
	if yes {
		o.stage = "save"
	}
	return nil
}

// stop — «Отмена» окна (Ч12): прервать идущее вступление (соединение, проверка, превью). Итог — err "cancel". До
// отправки нового M тот ПК ничего не сохранил; после — как обрыв: повтор безопасен (SpaceJoin). Других операций
// и кончившихся — errSpaceNoOp.
func (r *spaceOpRun) stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	o := r.liveLocked()
	if o == nil || o.kind != "enter" || !o.end.IsZero() {
		return errSpaceNoOp
	}
	o.cancel()
	return nil
}

type spaceStageKey struct{}

// spaceStageOf — сообщить окну шаг операции (контекст spaceOps.start); вне операции — ничего.
func spaceStageOf(ctx context.Context) func(string) {
	if f, ok := ctx.Value(spaceStageKey{}).(func(string)); ok {
		return f
	}
	return func(string) {}
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
	if o.stage != "" {
		m["stage"] = o.stage
	}
	if o.stage == "admit" { // Ч12б: сколько ещё ждёт окно «Пустить?» на том ПК, с (вверх)
		left := agent.AdmitTimeout - spaceOpNow().Sub(o.stageAt)
		m["left"] = max(0, int((left+time.Second-1)/time.Second))
	}
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
