//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"anypc/agent"
	"anypc/totp"
)

// Ч12: ход вступления для окна — шаги из SpaceDial.Stage в spaceOp ("stage"), итог без шага; соединения нет —
// код nolink, тот ПК закрыл — closed (окно показывает понятный текст и что делать, а не «Выполняется…» 3 мин).
func TestSpaceEnterStages(t *testing.T) {
	opsReset(t)
	p := spaceCfg(t, spacePass, totp.NewSecret())
	ph, err := p.spaceDraft(spacePass)
	if err != nil {
		t.Fatal(err)
	}
	n := spaceCfg(t, spacePass, totp.NewSecret())
	step, end := make(chan string), make(chan error)
	withSpaceNet(t, func(ctx context.Context, d agent.SpaceDial) ([]byte, error) {
		for _, s := range []string{"link", "auth", "list"} {
			d.Stage(s)
			step <- s
			<-step
		}
		return nil, <-end
	})
	for _, c := range []struct {
		err  error
		code string
	}{{agent.ErrSpaceNoLink, "nolink"}, {agent.ErrSpaceClosed, "closed"}} {
		args := []json.RawMessage{json.RawMessage(`"` + p.ID + `"`), json.RawMessage(`"` + spacePass + `"`), json.RawMessage(`"123456"`), json.RawMessage(`"` + ph + `"`)}
		if _, err := spaceCall(n, "spaceEnter", args); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"link", "auth", "list"} {
			if s := <-step; s != want {
				t.Fatalf("шаг %q, ждали %q", s, want)
			}
			if op := spaceOps.snap(false); op["stage"] != want || op["state"] != "run" {
				t.Errorf("hostInfo.space.op на шаге %s: %v", want, op)
			}
			if op := spaceOps.snap(true); op["stage"] != want {
				t.Errorf("spaceOp на шаге %s: %v", want, op)
			}
			step <- ""
		}
		end <- c.err
		spaceOps.wg.Wait()
		if op := spaceOps.snap(true); op["state"] != "err" || op["err"] != c.code || op["stage"] != nil {
			t.Errorf("итог %v: %v", c.err, op)
		}
	}
}

// Ч12: «Отмена» в окне прерывает вступление на любом шаге (соединение, превью): итог cancel, кнопки окна
// возвращаются; отменять кончившееся и чужие операции нельзя.
func TestSpaceEnterStop(t *testing.T) {
	opsReset(t)
	p := spaceCfg(t, spacePass, totp.NewSecret())
	ph, _ := p.spaceDraft(spacePass)
	n := spaceCfg(t, spacePass, totp.NewSecret())
	in := make(chan struct{})
	withSpaceNet(t, func(ctx context.Context, d agent.SpaceDial) ([]byte, error) {
		d.Stage("link")
		close(in)
		<-ctx.Done() // ICE не сходится — ждём, пока не отменят
		return nil, ctx.Err()
	})
	if _, err := spaceCall(n, "spaceCancel", nil); err == nil || err.Error() != "space:noop" {
		t.Errorf("отмена без операции: %v", err)
	}
	args := []json.RawMessage{json.RawMessage(`"` + p.ID + `"`), json.RawMessage(`"` + spacePass + `"`), json.RawMessage(`"123456"`), json.RawMessage(`"` + ph + `"`)}
	if _, err := spaceCall(n, "spaceEnter", args); err != nil {
		t.Fatal(err)
	}
	<-in
	t0 := time.Now()
	if _, err := spaceCall(n, "spaceCancel", nil); err != nil {
		t.Fatal(err)
	}
	spaceOps.wg.Wait()
	if op := spaceOps.snap(true); op["state"] != "err" || op["err"] != "cancel" || time.Since(t0) > time.Second {
		t.Errorf("после отмены: %v (%v)", op, time.Since(t0))
	}
	if _, err := spaceCall(n, "spaceCancel", nil); err == nil || err.Error() != "space:noop" {
		t.Errorf("отмена кончившейся: %v", err)
	}
	opsReset(t)
	spaceOps.start("sync", func(ctx context.Context, _ func(spacePreview), _ <-chan bool) (any, error) {
		<-ctx.Done()
		return nil, nil
	})
	if err := spaceOps.stop(); err == nil {
		t.Error("отменили сверку")
	}
	spaceOps.mu.Lock()
	spaceOps.cur.cancel()
	spaceOps.mu.Unlock()
}

// Ч12, приёмка M3: составные ошибки — код самой точной причины (порядок spaceCodes): noudp раньше nolink, причины
// отказа хоста раньше auth и refused.
func TestSpaceCodesOrder(t *testing.T) {
	for _, c := range []struct {
		err  error
		code string
	}{
		{fmt.Errorf("%w (%w)", agent.ErrSpaceNoUDP, agent.ErrSpaceNoLink), "noudp"},
		{agent.ErrSpaceNoLink, "nolink"},
		{fmt.Errorf("%w (%w)", agent.ErrSpaceBusyThere, agent.ErrSpaceRefused), "busythere"},
		{fmt.Errorf("%w (%w)", agent.ErrSpaceLockedThere, agent.ErrSpaceAuth), "lockedthere"},
		{fmt.Errorf("%w (%w)", agent.ErrSpaceNoPassThere, agent.ErrSpaceRefused), "nopassthere"},
		{fmt.Errorf("%w: разрыв (%w)", agent.ErrSpaceRefused, agent.ErrSpaceClosed), "closed"},
	} {
		if got := spaceErrCode(c.err); got != c.code {
			t.Errorf("%v → %s, ждали %s", c.err, got, c.code)
		}
	}
}

// Ч12: «Подтвердить» в превью — сразу шаг save (окно не мигает прежним шагом до Sign); «Отказаться» — шага save нет.
func TestSpaceConfirmSave(t *testing.T) {
	for _, yes := range []bool{true, false} {
		opsReset(t)
		shown, done := make(chan struct{}), make(chan struct{})
		spaceOps.start("enter", func(ctx context.Context, preview func(spacePreview), ok <-chan bool) (any, error) {
			spaceStageOf(ctx)("list")
			preview(spacePreview{})
			close(shown)
			<-ok
			<-done
			return nil, nil
		})
		<-shown
		if err := spaceOps.confirm(yes); err != nil {
			t.Fatal(err)
		}
		op := spaceOps.snap(false)
		if want := map[bool]any{true: "save", false: "list"}[yes]; op["state"] != "run" || op["stage"] != want {
			t.Errorf("ответ %v: %v", yes, op)
		}
		close(done)
		spaceOps.wg.Wait()
	}
}
