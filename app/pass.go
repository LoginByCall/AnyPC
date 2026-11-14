package main

// «Моё пространство», этап Э3 на мастере (UI-REDESIGN.md, решения владельца 2 и 5): «Работаю тут» без окна —
// пароль владельца и один код TOTP открывают все цели пространства в сети (каждая выдаёт пропуск на 12 ч, протокол —
// agent/pass.go); блокировка экрана мастера и выход снимают выданные пропуска. ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (CLAUDE.md
// A13: вход без второго фактора на 12 ч).
//
// Пароль и код мастер не хранит: держит в памяти не дольше passHoldFor (90 с) и затирает (байты — clear; строки Go
// неизменяемы, копии в вызовах pake живут до сборщика — по возможности, как ключ владельца в space.go). В журнал —
// только ID целей и итог.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"anypc/agent"
	"anypc/totp"
)

// passHoldFor — сколько мастер держит введённые пароль и код (≤ 90 с): за это время все цели открываются или нет.
var passHoldFor = 90 * time.Second

// Сеть (agent/pass.go); переменные — для теста.
var passOpenFn, passOffFn = agent.PassOpen, agent.PassOff

// startLock — до конца ctx звать on() при блокировке экрана этого ПК, alive(источник, жив) — о подписке на шину
// (lock_linux.go). На Маке и Windows nil — «Работаю тут» там отказывает (errNoLockDetector, решение приёмки Э3):
// TODO(Э3, macOS): com.apple.screenIsLocked из NSDistributedNotificationCenter (нужен cgo или отдельный помощник).
// TODO(Э3, Windows): WTSRegisterSessionNotification + WM_WTSSESSION_CHANGE / WTS_SESSION_LOCK окна программы.
var startLock func(ctx context.Context, on func(), alive func(src string, ok bool))

// passOffRetry, passOffRetryMax — пауза повтора «снять», не дошедшего до цели (растёт вдвое до предела).
var passOffRetry, passOffRetryMax = time.Second, 5 * time.Minute

var (
	errPassCode       = errors.New("пространство: неверный код")
	errNoLockDetector = errors.New("пространство: блокировка экрана этого ПК не отслеживается — пропуск не выдаётся (вход паролем и кодом — как обычно)")
)

// passHold — пароль и код на время «Работаю тут». wipe — по сроку (таймер) или по окончании, что раньше.
type passHold struct {
	mu       sync.Mutex
	pw, code []byte
}

func newPassHold(pw, code string, d time.Duration) *passHold {
	h := &passHold{pw: []byte(pw), code: []byte(code)}
	time.AfterFunc(d, h.wipe)
	return h
}

func (h *passHold) get() (pw, code string, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return string(h.pw), string(h.code), h.pw != nil
}

func (h *passHold) wipe() {
	h.mu.Lock()
	defer h.mu.Unlock()
	clear(h.pw)
	clear(h.code)
	h.pw, h.code = nil, nil
}

// passResult — итог «Работаю тут» по одной цели: State — "ok" | "offline" (не в сети) | "refused" (отказ, Err).
type passResult struct {
	ID    string
	State string
	Err   error
}

// passMaster — этот ПК как мастер: куда слать «снять».
type passMaster struct {
	cfg    *config
	mu     sync.Mutex
	hold   *passHold             // последний «Работаю тут» (тест: затирание)
	issued map[string]passIssued // ID цели → где пропуск выдан или мог быть выдан (ответ не дошёл)
	locks  int                   // сколько раз снимали всё (offAll): блокировка во время workHere видна по нему
	alive  map[string]bool       // источники детектора блокировки, подписанные сейчас
	bg     sync.WaitGroup        // повторы «снять»
}

// lockAlive — alive для startLock.
func (p *passMaster) lockAlive(src string, ok bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.alive == nil {
		p.alive = map[string]bool{}
	}
	p.alive[src] = ok
}

// detector — хоть один источник блокировки жив.
func (p *passMaster) detector() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ok := range p.alive {
		if ok {
			return true
		}
	}
	return false
}

type passIssued struct {
	pub ed25519.PublicKey // ключ хоста цели из M
	at  time.Time         // когда выдан (с монотонным показанием)
}

// live — пропуск на цели ещё может жить: меньше PassTTL и по монотонным, и по настенным часам.
func (t passIssued) live() bool {
	return time.Since(t.at) < agent.PassTTL && time.Now().Round(0).Sub(t.at.Round(0)) < agent.PassTTL
}

// passes — мастер этого процесса (main).
var passes passMaster

// workHere — «Работаю тут» (Э3): человек ввёл пароль владельца и код TOTP пространства. Пароль и код сверяются
// здесь (неверные не уходят в сеть и не тратят попытки целей), затем все остальные члены M открываются параллельно.
// Ошибка — до сети (детектор блокировки не жив, не в пространстве, неверный пароль или код). Блокировка экрана,
// пришедшая во время входов, снимает в конце всё, что успели выдать.
func (p *passMaster) workHere(ctx context.Context, password, code string) ([]passResult, error) {
	if !p.detector() { // без детектора пропуск не снять блокировкой — не выдавать (решение приёмки Э3)
		return nil, errNoLockDetector
	}
	c := p.cfg
	c.mu.Lock()
	c.reload()
	m := c.spaceLocked() // разобранный состав не меняется: правка даёт новый
	key, server := bytes.Clone(c.Key), c.Server
	c.mu.Unlock()
	self := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	if m == nil || !m.member(self) {
		return nil, errSpaceNotIn
	}
	if spaceOwnerCheck(m, password) != nil { // свой состав: «другой владелец» здесь — тоже неверный пароль
		return nil, errSpacePassword
	}
	if _, ok := totp.Check(m.TOTP, code, time.Now(), 0); !ok {
		return nil, errPassCode
	}
	h := newPassHold(password, code, passHoldFor)
	defer h.wipe()
	p.mu.Lock()
	p.hold = h
	locks := p.locks
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, passHoldFor)
	defer cancel()
	var targets []spaceMember
	for _, x := range m.Members {
		if !bytes.Equal(x.Pub, self) {
			targets = append(targets, x)
		}
	}
	out := make([]passResult, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Go(func() {
			r := passResult{ID: t.ID, State: "refused"}
			defer func() { out[i] = r }()
			pw, cd, ok := h.get()
			if !ok {
				r.Err = fmt.Errorf("пространство: прошло %v", passHoldFor)
				return
			}
			r.Err = passOpenFn(ctx, agent.PassDial{Server: server, ID: t.ID, HostPub: t.Pub, Key: key, Password: pw, Code: cd})
			switch {
			case r.Err == nil:
				r.State = "ok"
			case errors.Is(r.Err, agent.ErrSpaceOffline):
				r.State = "offline"
				return
			case errors.Is(r.Err, agent.ErrSpaceOld), errors.Is(r.Err, agent.ErrSpaceAsk), errors.Is(r.Err, agent.ErrSpaceAuth),
				errors.Is(r.Err, agent.ErrSpaceHostKey), errors.Is(r.Err, agent.ErrPassNone):
				return // пропуска там точно нет
			}
			p.mu.Lock()
			if p.issued == nil {
				p.issued = map[string]passIssued{}
			}
			p.issued[t.ID] = passIssued{t.Pub, time.Now()}
			p.mu.Unlock()
		})
	}
	wg.Wait()
	h.wipe()
	p.mu.Lock()
	locked := p.locks != locks
	p.mu.Unlock()
	log.Printf("Работаю тут: %s; детектор блокировки жив: %v", passSummary(out), p.detector())
	if locked { // экран заблокировали, пока открывали: выданное после — снять сразу
		log.Print("Работаю тут: экран заблокирован во время входа — пропуска снимаются")
		p.offAll(context.WithoutCancel(ctx)) // повторы переживут конец workHere
	}
	return out, nil
}

func passSummary(rs []passResult) string {
	var b strings.Builder
	for i, r := range rs {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(r.ID + " " + r.State)
	}
	return b.String()
}

// offAll — снять пропуска на всех целях, где они выданы (блокировка экрана, выход, сон). Не дошедшее «снять»
// повторяется в фоне с нарастающей паузой, пока не дойдёт, пропуск на цели не истечёт, новый «Работаю тут» его не
// заменит или не кончится ctx.
func (p *passMaster) offAll(ctx context.Context) {
	p.mu.Lock()
	p.locks++
	list := p.issued
	p.issued = nil
	p.mu.Unlock()
	if len(list) == 0 {
		return
	}
	key, server := p.cfg.key(), p.cfg.server()
	off := func(id string, t passIssued) bool {
		err := passOffFn(ctx, agent.PassDial{Server: server, ID: id, HostPub: t.pub, Key: key})
		if err != nil {
			log.Printf("пропуск на %s не снят: %v — повтор", id, err)
			return false
		}
		log.Printf("пропуск на %s снят", id)
		return true
	}
	var wg sync.WaitGroup
	for id, t := range list {
		if !t.live() {
			continue
		}
		wg.Go(func() {
			if !off(id, t) {
				p.bg.Go(func() { p.offRetry(ctx, id, t, off) })
			}
		})
	}
	wg.Wait()
}

func (p *passMaster) offRetry(ctx context.Context, id string, t passIssued, off func(string, passIssued) bool) {
	for wait := passOffRetry; ; wait = min(2*wait, passOffRetryMax) {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		p.mu.Lock()
		_, again := p.issued[id] // новый «Работаю тут» выдал свежий пропуск тому же ключу — старого на цели нет
		p.mu.Unlock()
		if again || !t.live() || off(id, t) {
			return
		}
	}
}
