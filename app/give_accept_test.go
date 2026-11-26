package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"anypc/agent"
	"anypc/totp"
)

// приёмка (M1): переключатель не переживает уход в режим пароля и возврат в «Спрашивать».
func TestAccGiveModeChange(t *testing.T) {
	c, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	c.setPassword("пароль-123")
	if _, err := c.setGive(true); err != nil {
		t.Fatal(err)
	}
	sec := totp.NewSecret()
	now, _ := totp.Code(sec, time.Now())
	if err := c.otpEnable(sec, now, ""); err != nil {
		t.Fatal(err)
	}
	t.Logf("режим пароля: codeMode=%v giving=%v code=%q", c.codeMode(), c.giving(), c.code())
	if err := c.setConfirm(true); err != nil {
		t.Fatal(err)
	}
	t.Logf("снова «Спрашивать»: codeMode=%v giving=%v code=%q", c.codeMode(), c.giving(), c.code())
	if !c.giving() || c.code() == "" {
		t.Errorf("настройки permanent-профиля отключили одноразовый доступ: give=%v code=%q", c.giving(), c.code())
	}
}

// приёмка: приём файлов/текста по коду (Ч10.1) при выкл — тот же отказ, что неверный код; блокировка — тот же счёт
func TestAccGiveRecv(t *testing.T) {
	url := syncHub(t)
	c, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	c.mu.Lock()
	c.Server = url
	c.save()
	stored := c.Code
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
	t.Cleanup(func() { cancel(); <-done })
	select {
	case <-on:
	case <-time.After(10 * time.Second):
		t.Fatal("ПК не зарегистрировался")
	}
	_, key, _ := ed25519.GenerateKey(nil)
	send := func(code string) error {
		cx, cc := context.WithTimeout(context.Background(), 40*time.Second)
		defer cc()
		_, err := agent.SendTo(cx, agent.SendDial{Server: url, ID: c.id(), Key: key, Code: code, From: "555666777", Name: "Чужой", Text: "привет"})
		return err
	}
	wrong := "000000"
	if wrong == stored {
		wrong = "000001"
	}
	eW := send(wrong)
	eOff := send(stored)
	t.Logf("неверный код: %v; выкл + код из файла: %v", eW, eOff)
	if !errors.Is(eW, agent.ErrRecvCode) || eOff == nil || eOff.Error() != eW.Error() {
		t.Errorf("приём при выкл отличим от неверного кода или принят: %v / %v", eW, eOff)
	}
	code, err := setGive(c, a, true)
	if err != nil {
		t.Fatal(err)
	}
	if e := send(stored); !errors.Is(e, agent.ErrRecvCode) {
		t.Errorf("вкл: код прошлого запуска: %v", e)
	}
	eOn := send(code)
	t.Logf("вкл + верный код: %v", eOn)
	if eOn != nil {
		t.Errorf("вкл: приём верным кодом: %v", eOn)
	}
	// закреплённый ключ при выкл: окно «Принять?» (RecvAsk) — без кода
	setGive(c, a, false)
	cx, cc := context.WithTimeout(context.Background(), 40*time.Second)
	defer cc()
	_, ePin := agent.SendTo(cx, agent.SendDial{Server: url, ID: c.id(), Key: key, From: "555666777", Name: "Чужой", Text: "ещё"})
	t.Logf("выкл + закреплённый ключ без кода: %v", ePin)
	// счёт неудач при выкл: верный код выше сбросил счёт записи (REQ-S-22) — пять неудач подряд, шестая попытка заперта
	var errs []error
	for range 6 {
		errs = append(errs, send(wrong))
	}
	t.Logf("выкл, неверные коды подряд: %v", errs)
	for i, e := range errs[:5] {
		if !errors.Is(e, agent.ErrRecvCode) {
			t.Errorf("выкл: %d-я неудача — %v", i+1, e)
		}
	}
	if !errors.Is(errs[5], agent.ErrRecvLocked) {
		t.Errorf("выкл: блокировка перебора не сработала: %v", errs[5])
	}
}
