package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anypc/agent"
	"anypc/pake"
	"anypc/totp"
)

// «Разрешить управление» (требование владельца 2026-11-15): переключатель управляет только входом по одноразовому
// коду. После запуска — выкл (в файле не хранится); выкл — кода нет и он не действует; вкл — новый код.

// TestGiveSwitch — состояние переключателя в настройках: по умолчанию выкл, вкл — новый код (повторное вкл — снова
// новый), выкл — код не виден и не входит, соль та же (идущую сессию не рвёт), конец сессии нового кода не выдаёт.
func TestGiveSwitch(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	c, _ := loadConfig(p)
	c.mu.Lock()
	stored, salt0 := c.Code, bytes.Clone(c.CodeSalt)
	c.mu.Unlock()
	// после запуска — выкл: кода нет, код из файла не входит, но запись есть (не «nopass»: выключено не выдать)
	s, h, _ := c.secret("")
	if c.giving() || c.code() != "" || len(stored) != 6 || !c.codeMode() {
		t.Fatalf("после запуска: вкл %v, код %q", c.giving(), c.code())
	}
	if len(h) == 0 || !bytes.Equal(s, salt0) || bytes.Equal(h, pake.KDF(stored, s)) {
		t.Fatal("выкл: код из файла действует или запись по умолчанию пуста")
	}
	if _, err := c.newCode(); !errors.Is(err, errGiveOff) || c.code() != "" { // ↻ при выкл кода не выдаёт
		t.Fatalf("↻ при выкл: %v, код %q", err, c.code())
	}
	c.codeUsed() // конец сессии / блокировка при выкл — нового кода нет
	if c.code() != "" {
		t.Fatal("codeUsed при выкл выдал код")
	}
	// вкл — новый код, он и входит; соль та же
	code1, err := c.setGive(true)
	if s, h, _ := c.secret(""); err != nil || len(code1) != 6 || code1 != c.code() || code1 == stored || !bytes.Equal(s, salt0) || !bytes.Equal(h, pake.KDF(code1, s)) {
		t.Fatalf("вкл: %v, код %q (был %q)", err, code1, stored)
	}
	// повторное вкл (выкл → вкл) — новый код, старый не входит
	c.setGive(false)
	code2, _ := c.setGive(true)
	if s, h, _ := c.secret(""); code2 == code1 || bytes.Equal(h, pake.KDF(code1, s)) || !bytes.Equal(h, pake.KDF(code2, s)) {
		t.Fatalf("повторное вкл: %q → %q", code1, code2)
	}
	// конец сессии при вкл — новый код (как раньше)
	c.codeUsed()
	if code3 := c.code(); code3 == code2 || len(code3) != 6 {
		t.Fatalf("codeUsed при вкл: %q → %q", code2, code3)
	}
	// выкл во время сессии: соль та же и секрет не пуст (agent.revoked не рвёт), код не входит и не виден
	cur := c.code()
	c.setGive(false)
	s, h, _ = c.secret("")
	if c.code() != "" || !bytes.Equal(s, salt0) || len(h) == 0 || bytes.Equal(h, pake.KDF(cur, s)) {
		t.Fatal("выкл: код виден или действует, либо сменилась соль")
	}
	c.setGive(true)
	_, h1, _ := c.secret("")
	c.setGive(false)
	_, hOff1, _ := c.secret("")
	c.setGive(true)
	c.setGive(false)
	_, hOff2, _ := c.secret("")
	if bytes.Equal(hOff1, hOff2) || bytes.Equal(hOff1, h1) {
		t.Fatal("секрет выкл не меняется между выключениями")
	}
	// не хранится между запусками: включили, перечитали — выкл
	c.setGive(true)
	if c2, _ := loadConfig(p); c2.giving() || c2.code() != "" {
		t.Fatal("переключатель пережил перезапуск")
	}
}

// TestGiveOtherLogins — вход паролем (+ TOTP), записями по имени и ключом не зависит от переключателя; включить
// переключатель в режиме пароля нельзя (кода нет).
func TestGiveOtherLogins(t *testing.T) {
	c, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	c.setPassword("пароль-123")
	c.setUser("ivan", "пароль-ивана", "full")
	sec := totp.NewSecret()
	now, _ := totp.Code(sec, time.Now())
	if err := c.otpEnable(sec, now, ""); err != nil { // режим пароля: без вопросов, пароль + TOTP
		t.Fatal(err)
	}
	_, k, _ := ed25519.GenerateKey(nil)
	pub := k.Public().(ed25519.PublicKey)
	c.mu.Lock()
	s0 := c.Users[0].Salt
	c.mu.Unlock()
	c.keyTrust(pub, "", s0) // вход без пароля этим ключом (REQ-S-24)
	check := func(what string) {
		t.Helper()
		if s, h, _ := c.secret(""); !bytes.Equal(h, pake.KDF("пароль-123", s)) {
			t.Fatalf("%s: пароль по умолчанию не действует", what)
		}
		if s, h, _ := c.secret("ivan"); !bytes.Equal(h, pake.KDF("пароль-ивана", s)) {
			t.Fatalf("%s: запись по имени не действует", what)
		}
		if in, on := c.keyLogin(pub, ""); !in || !on {
			t.Fatalf("%s: вход ключом %v %v", what, in, on)
		}
		if c.code() != "" {
			t.Fatalf("%s: в режиме пароля виден код", what)
		}
	}
	check("выкл")
	if _, err := c.setGive(true); !errors.Is(err, errGiveOff) || c.giving() {
		t.Fatalf("вкл в режиме пароля: %v", err)
	}
	check("попытка вкл")
	c.setGive(false)
	check("выкл ещё раз")
}

// TestGiveLogin — по сети (хаб в памяти, настоящий agent с secret из настроек): выкл — вход кодом из файла получает тот
// же отказ, что неверный код ("fail", не «nopass»); вкл — верный код доходит до окна «Разрешить»; выкл снова — тот же
// код отказ.
func TestGiveLogin(t *testing.T) {
	url := syncHub(t)
	c, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	c.mu.Lock()
	c.Server = url
	c.save()
	stored := c.Code
	c.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	asked := make(chan bool, 4)
	a := &agent.Agent{Server: url, ID: c.id(), Secret: c.secret, Key: c.key(), OTP: c.otp, CodeUsed: c.codeUsed,
		Unattended: func() bool { return !c.confirm() }, SpaceGet: c.spaceGet, LoginShut: c.loginShut,
		Confirm: func(string, string) agent.Answer { asked <- true; return agent.Deny },
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
	login := func(code string) error {
		_, key, _ := ed25519.GenerateKey(nil)
		_, err := agent.SpaceJoin(context.Background(), agent.SpaceDial{Server: url, ID: c.id(), Key: key, Password: code,
			Sign: func(b []byte, _ ed25519.PublicKey, _ ...[]byte) ([]byte, error) { return b, nil }})
		return err
	}
	wrong := "000000"
	if wrong == stored {
		wrong = "000001"
	}
	errWrong := login(wrong) // эталон: неверный код
	if !errors.Is(errWrong, agent.ErrSpaceAuth) || !strings.HasSuffix(errWrong.Error(), ": fail") {
		t.Fatalf("неверный код: %v", errWrong)
	}
	if err := login(stored); err == nil || err.Error() != errWrong.Error() { // выкл: код из файла — тот же отказ
		t.Fatalf("выкл: вход кодом %v (неверный код: %v)", err, errWrong)
	}
	code, err := setGive(c, a, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := login(code); !errors.Is(err, agent.ErrSpaceAsk) { // вкл: верный код — до «Разрешить»
		t.Fatalf("вкл: вход кодом %v", err)
	}
	select {
	case <-asked:
	case <-time.After(10 * time.Second):
		t.Fatal("окно «Разрешить» не спросили")
	}
	time.Sleep(300 * time.Millisecond) // отказ в окне: сессия кончилась (CodeUsed — новый код)
	code = c.code()
	if _, err := setGive(c, a, false); err != nil {
		t.Fatal(err)
	}
	if err := login(code); err == nil || err.Error() != errWrong.Error() { // выкл: последний код — отказ как неверному
		t.Fatalf("выкл снова: вход кодом %v", err)
	}
}
