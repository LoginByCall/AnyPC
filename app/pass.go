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

// startLock — до конца ctx звать on() при блокировке экрана этого ПК (lock_linux.go). На Маке и Windows nil:
// TODO(Э3, macOS): com.apple.screenIsLocked из NSDistributedNotificationCenter (нужен cgo или отдельный помощник).
// TODO(Э3, Windows): WTSRegisterSessionNotification + WM_WTSSESSION_CHANGE / WTS_SESSION_LOCK окна программы.
// Без детектора пропуска на целях живут до 12 ч, выхода мастера или перезапуска цели.
var startLock func(ctx context.Context, on func())

var errPassCode = errors.New("пространство: неверный код")

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
}

type passIssued struct {
	pub ed25519.PublicKey // ключ хоста цели из M
	at  time.Time
}

// passes — мастер этого процесса (main).
var passes passMaster

// workHere — «Работаю тут» (Э3): человек ввёл пароль владельца и код TOTP пространства. Пароль и код сверяются
// здесь (неверные не уходят в сеть и не тратят попытки целей), затем все остальные члены M открываются параллельно.
// Ошибка — до сети (не в пространстве, неверный пароль или код).
func (p *passMaster) workHere(ctx context.Context, password, code string) ([]passResult, error) {
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
	log.Printf("Работаю тут: %s", passSummary(out))
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

// offAll — снять пропуска на всех целях, где они выданы (блокировка экрана, выход). Не снятые (цель не в сети) —
// остаются в списке до следующего раза; на цели пропуск истечёт сам.
func (p *passMaster) offAll(ctx context.Context) {
	p.mu.Lock()
	list := p.issued
	p.issued = nil
	p.mu.Unlock()
	if len(list) == 0 {
		return
	}
	key, server := p.cfg.key(), p.cfg.server()
	var wg sync.WaitGroup
	for id, t := range list {
		if time.Since(t.at) >= agent.PassTTL {
			continue
		}
		wg.Go(func() {
			err := passOffFn(ctx, agent.PassDial{Server: server, ID: id, HostPub: t.pub, Key: key})
			if err == nil {
				log.Printf("пропуск на %s снят", id)
				return
			}
			log.Printf("пропуск на %s не снят: %v — снимется следующей блокировкой, выходом или сам за ≤%v", id, err, agent.PassTTL)
			p.mu.Lock()
			if p.issued == nil {
				p.issued = map[string]passIssued{}
			}
			if _, again := p.issued[id]; !again { // новый «Работаю тут» уже записал свежий
				p.issued[id] = t
			}
			p.mu.Unlock()
		})
	}
	wg.Wait()
}
