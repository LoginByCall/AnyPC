package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"anypc/agent"
	"anypc/pake"
	"anypc/totp"
)

// sendIdle — дождаться конца фоновых отправок.
func sendIdle(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() { sendOps.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("отправка не кончилась")
	}
}

func callSend(c *config, name string, args ...any) (any, error) {
	var raw []json.RawMessage
	for _, a := range args {
		b, _ := json.Marshal(a)
		raw = append(raw, b)
	}
	return sendCall(c, name, raw)
}

// TestSendAPI — Ч10.3: кому и как доказывать (свой ПК из M — ключ из M без кода; чужой с кодом — ключ после
// отправки запомнен в known; чужой без кода — только с known), ошибки окну — коды send:<код>, ход и итог — в sendState
// и подписчику (трей), отмена, одна отправка за раз; в журнале — без путей и текста.
func TestSendAPI(t *testing.T) {
	var logs syncLog
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	withSpaceNet(t, spaceNet(p, nil))
	if _, err := n.spaceEnter(context.Background(), p.id(), spacePass, spaceCode(p, sec), ph); err != nil {
		t.Fatal(err)
	}
	_, other, _ := ed25519.GenerateKey(nil)
	var mu sync.Mutex
	var got []agent.SendDial
	block := make(chan struct{})
	sendRun = func(ctx context.Context, d agent.SendDial) (agent.SendResult, error) {
		mu.Lock()
		got = append(got, d)
		mu.Unlock()
		if d.Progress != nil {
			d.Progress(agent.SendProgress{Item: 1, Items: 2, Done: 5, Total: 10})
		}
		if d.Text == "ждать" {
			select {
			case <-ctx.Done():
				return agent.SendResult{}, ctx.Err()
			case <-block:
			}
		}
		res := agent.SendResult{HostPub: other.Public().(ed25519.PublicKey), Files: 1, Bytes: 10, Skipped: []string{"P/link"}}
		if d.HostPub != nil {
			res.HostPub = d.HostPub
		}
		return res, nil
	}
	defer func() { sendRun = agent.SendTo; sendOps.clear() }()
	var events []map[string]any
	sendOps.watch(func(m map[string]any) { mu.Lock(); events = append(events, m); mu.Unlock() })
	last := func() agent.SendDial { mu.Lock(); defer mu.Unlock(); return got[len(got)-1] }

	// свой ПК: ключ из M, без кода и known
	if _, err := callSend(n, "sendStart", map[string]any{"id": p.id(), "files": []string{"/секрет/путь.txt"}, "code": "лишний"}); err != nil {
		t.Fatal(err)
	}
	sendIdle(t)
	if d := last(); !bytes.Equal(d.HostPub, cfgPub(p)) || d.Code != "" || d.Known != "" || d.From != n.id() || !bytes.Equal(d.Key, n.key()) {
		t.Fatalf("свой ПК: %+v", d)
	}
	st, _ := callSend(n, "sendState")
	m := st.(map[string]any)
	if m["state"] != "done" || m["kind"] != "own" || m["files"] != 1 || m["done"] != int64(5) || m["skippedN"] != 1 {
		t.Fatalf("итог: %v", m)
	}
	mu.Lock()
	if len(events) < 2 || events[0]["state"] != "run" || events[len(events)-1]["state"] != "done" {
		t.Fatalf("события: %v", events)
	}
	mu.Unlock()

	// чужой с кодом: после отправки ключ того ПК — в known; затем без кода — по known
	const fid = "555666777"
	if _, err := callSend(n, "sendStart", map[string]any{"id": fid, "code": "123456", "text": "т"}); err != nil {
		t.Fatal(err)
	}
	sendIdle(t)
	fp := pake.KeyFingerprint(other.Public().(ed25519.PublicKey))
	if d := last(); d.Code != "123456" || d.HostPub != nil || d.Known != "" || n.knownGet(fid) != fp {
		t.Fatalf("по коду: %+v, known %q", d, n.knownGet(fid))
	}
	if _, err := callSend(n, "sendStart", map[string]any{"id": fid, "clip": true}); err != nil {
		t.Fatal(err)
	}
	sendIdle(t)
	if d := last(); d.Code != "" || d.Known != fp || !d.Clip {
		t.Fatalf("по known: %+v", d)
	}

	// отказы до отправки
	for _, c := range []struct {
		req  map[string]any
		code string
	}{
		{map[string]any{"id": "111222333", "files": []string{"a"}}, "send:known"},
		{map[string]any{"id": n.id(), "files": []string{"a"}}, "send:self"},
		{map[string]any{"id": "12", "files": []string{"a"}}, "send:id"},
		{map[string]any{"id": fid}, "send:empty"},
		{map[string]any{"id": fid, "text": "a", "clip": true}, "send:both"},
	} {
		if _, err := callSend(n, "sendStart", c.req); err == nil || err.Error() != c.code {
			t.Errorf("%v: %v, ждали %s", c.req, err, c.code)
		}
	}
	if _, err := sendCall(n, "sendStart", []json.RawMessage{json.RawMessage(`"x"`)}); err == nil || err.Error() != "send:args" {
		t.Errorf("неверный запрос: %v", err)
	}

	// одна за раз, отмена
	if _, err := callSend(n, "sendStart", map[string]any{"id": p.id(), "text": "ждать"}); err != nil {
		t.Fatal(err)
	}
	if _, err := callSend(n, "sendStart", map[string]any{"id": p.id(), "text": "x"}); err == nil || err.Error() != "send:running" {
		t.Fatalf("вторая: %v", err)
	}
	if _, err := callSend(n, "sendClear"); err == nil || err.Error() != "send:running" {
		t.Fatalf("стереть идущую: %v", err)
	}
	if _, err := callSend(n, "sendCancel"); err != nil {
		t.Fatal(err)
	}
	sendIdle(t)
	if st, _ := callSend(n, "sendState"); st.(map[string]any)["state"] != "err" || st.(map[string]any)["err"] != "cancel" {
		t.Fatalf("отменённая: %v", st)
	}
	if _, err := callSend(n, "sendCancel"); err == nil || err.Error() != "send:noop" {
		t.Fatalf("отменить нечего: %v", err)
	}
	if _, err := callSend(n, "sendClear"); err != nil {
		t.Fatal(err)
	}
	if st, _ := callSend(n, "sendState"); st != nil && st.(map[string]any) != nil {
		t.Fatalf("после clear: %v", st)
	}
	tg, _ := callSend(n, "sendTargets")
	j, _ := json.Marshal(tg)
	if !strings.Contains(string(j), `"own":[{"fp":"`+pake.KeyFingerprint(cfgPub(p))+`","id":"`+p.id()+`"}]`) || !strings.Contains(string(j), fid) {
		t.Fatalf("кому: %s", j)
	}
	if s := logs.String(); strings.Contains(s, "секрет") || strings.Contains(s, "путь.txt") || !strings.Contains(s, "отправка на "+p.id()+": файлов 1, 10 байт") {
		t.Fatalf("журнал:\n%s", s)
	}
	close(block)
}

// TestSendErrCode — ошибки ядра → коды окна.
func TestSendErrCode(t *testing.T) {
	for err, want := range map[error]string{
		agent.ErrRecvOldDirs:                        "olddirs",
		fmt.Errorf("%w: файл", agent.ErrRecvLimit):  "limit",
		&agent.RecvError{Code: "size"}:              "limit",
		&agent.RecvError{Code: "path"}:              "path",
		&agent.RecvError{Code: "disk"}:              "rx_disk",
		&agent.RecvError{Code: "denied"}:            "denied",
		fmt.Errorf("x: %w", os.ErrNotExist):         "nofile",
		agent.ErrRecvKnown:                          "known",
		context.Canceled:                            "cancel",
		errors.New("open /home/секрет: что-то ещё"): "other",
	} {
		if got := sendErrCode(err); got != want {
			t.Errorf("%v: %s, ждали %s", err, got, want)
		}
	}
}
