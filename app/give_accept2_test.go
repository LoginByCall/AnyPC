package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anypc/agent"
)

// приёмка: последовательность ответов на 7 неверных входов (вход и приём вперемешку) при выкл и при вкл — одна и та же
func TestAccGiveLockSeq(t *testing.T) {
	seq := func(give bool) string {
		url := syncHub(t)
		c, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
		c.mu.Lock()
		c.Server = url
		c.save()
		c.mu.Unlock()
		ctx, cancel := context.WithCancel(context.Background())
		a := &agent.Agent{Server: url, ID: c.id(), Secret: c.secret, OneTimeSecret: c.oneTimeSecret, Key: c.key(), OTP: c.otp, CodeUsed: c.codeUsed,
			Unattended: func() bool { return !c.confirm() }, SpaceGet: c.spaceGet, LoginShut: c.loginShut,
			CodeMode: c.oneTimeMode, RecvPinned: c.recvPinned, RecvPin: c.recvPin, RecvAsk: func(agent.RecvReq) bool { return true },
			Confirm: func(string, string) agent.Answer { return agent.Deny }, FileDir: t.TempDir(),
			Capture: func(context.Context, agent.Cap) (*exec.Cmd, error) {
				return nil, errors.New("тест: без захвата")
			}}
		on := make(chan bool, 8)
		a.OnState = func(o bool, _ string) {
			if o {
				select {
				case on <- o:
				default:
				}
			}
		}
		done := make(chan struct{})
		go func() { a.Run(ctx); close(done) }()
		defer func() { cancel(); <-done }()
		select {
		case <-on:
		case <-time.After(10 * time.Second):
			t.Fatal("ПК не зарегистрировался")
		}
		var codes []string
		if give {
			cd, err := setGive(c, a, true)
			if err != nil {
				t.Fatal(err)
			}
			codes = append(codes, cd)
		}
		wrong := func() string { // неверный для текущего кода
			c.mu.Lock()
			cur := c.Code
			c.mu.Unlock()
			if cur == "000000" {
				return "000001"
			}
			return "000000"
		}
		var out []string
		for i := 0; i < 7; i++ {
			_, key, _ := ed25519.GenerateKey(nil)
			var err error
			if i%2 == 0 {
				_, err = agent.SpaceJoin(context.Background(), agent.SpaceDial{Server: url, ID: c.id(), Key: key, Password: wrong(),
					Sign: func(b []byte, _ ed25519.PublicKey, _ ...[]byte) ([]byte, error) { return b, nil }})
			} else {
				cx, cc := context.WithTimeout(context.Background(), 40*time.Second)
				_, err = agent.SendTo(cx, agent.SendDial{Server: url, ID: c.id(), Key: key, Code: wrong(), From: "555666777", Name: "Чужой", Text: "x"})
				cc()
			}
			out = append(out, fmt.Sprint(err))
			time.Sleep(150 * time.Millisecond)
		}
		c.mu.Lock()
		codes = append(codes, c.Code)
		c.mu.Unlock()
		t.Logf("give=%v: коды до/после %v, giving=%v", give, codes, c.giving())
		return strings.Join(out, "\n")
	}
	off, on := seq(false), seq(true)
	t.Logf("выкл:\n%s", off)
	if off != on {
		t.Errorf("ответы при выкл и вкл различаются:\nвыкл:\n%s\nвкл:\n%s", off, on)
	}
	if !strings.Contains(off, "locked") && !strings.Contains(off, "слишком много") {
		t.Errorf("блокировка при выкл не наступила")
	}
}
