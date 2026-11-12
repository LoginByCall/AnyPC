package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anypc/agent"
	"anypc/hub"
	"anypc/pake"
	"anypc/totp"
)

func TestConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "AnyPC", "config.json")
	c, err := loadConfig(p)
	if err != nil || !hub.IsHostID(c.ID) {
		t.Fatalf("первый запуск: %v %+v", err, c)
	}
	// новая установка — режим «Спрашивать» (REQ-S-23): вход — только одноразовым кодом, постоянного пароля нет
	if s, h, _ := c.secret(""); len(c.code()) != 6 || !bytes.Equal(h, pake.KDF(c.code(), s)) || c.hasPass() {
		t.Fatalf("первый запуск: код %q", c.code())
	}
	if c.setPassword("short") == nil {
		t.Fatal("короткий пароль принят")
	}
	if err := c.setPassword("пароль-123"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if strings.Contains(string(b), "пароль-123") {
		t.Fatal("пароль в открытом виде в конфиге")
	}
	c2, err := loadConfig(p)                                                                    // ID и пароль переживают перезапуск
	if !bytes.Equal(c2.Key, c.Key) || len(c.Key) != 64 || c2.fingerprint() != c.fingerprint() { // ключ хоста постоянный
		t.Fatal("ключ хоста не сохранился")
	}
	if c2.knownSet("123456789", "abcd") != nil || c2.knownGet("123456789") != "abcd" || c2.knownSet("../x", "a") == nil {
		t.Fatal("известные хосты")
	}
	salt, h := c2.Users[0].Salt, c2.Users[0].Hash
	if err != nil || c2.ID != c.ID || !bytes.Equal(h, pake.KDF("пароль-123", salt)) || bytes.Equal(h, pake.KDF("пароль-124", salt)) {
		t.Fatalf("перезагрузка: %v %+v", err, c2)
	}
	if s, h, _ := c2.secret(""); bytes.Equal(h, pake.KDF("пароль-123", s)) || c2.code() != c.code() { // пароль хранится, но не действует
		t.Fatal("в режиме «Спрашивать» действует постоянный пароль или код не пережил перезапуск")
	}
}

// TestConfirmSetting — REQ-F-03: новая установка спрашивает; старая с паролем (без поля) — нет, чтобы не запереть
// ПК без человека рядом после обновления; выбор сохраняется.
func TestConfirmSetting(t *testing.T) {
	dir := t.TempDir()
	c, _ := loadConfig(filepath.Join(dir, "new.json"))
	if !c.confirm() {
		t.Fatal("новая установка должна спрашивать")
	}
	old := filepath.Join(dir, "old.json")
	os.WriteFile(old, []byte(`{"id":"123456789","salt":"AAAA","hash":"AAAA"}`), 0o600)
	if c, _ = loadConfig(old); c.confirm() {
		t.Fatal("старая установка с паролем стала спрашивать — удалённый ПК без человека будет недоступен")
	}
	if err := c.setConfirm(true); err != nil {
		t.Fatal(err)
	}
	if c, _ = loadConfig(old); !c.confirm() {
		t.Fatal("выбор не сохранился")
	}
}

// TestServerRename — старый адрес any. переводится на новый; свой адрес пользователя не трогается.
func TestServerRename(t *testing.T) {
	for in, want := range map[string]string{oldServers[0]: DefaultServer, oldServers[1]: DefaultServer, oldServers[2]: DefaultServer, "wss://my.example/ws": "wss://my.example/ws"} {
		p := filepath.Join(t.TempDir(), "config.json")
		os.WriteFile(p, []byte(`{"server":"`+in+`"}`), 0o600)
		c, err := loadConfig(p)
		if err != nil || c.Server != want {
			t.Fatalf("%s → %s, ждали %s (%v)", in, c.Server, want, err)
		}
		if c2, _ := loadConfig(p); c2.Server != want {
			t.Fatal("не сохранилось")
		}
	}
}

// TestTrusted — ключи клиентов: не больше maxTrusted (уходят давние), повтор не дублирует, смена пароля сбрасывает.
func TestTrusted(t *testing.T) {
	c, err := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	key := func(i int) []byte { return bytes.Repeat([]byte{byte(i)}, 32) }
	passwordMode(t, c) // в режиме кода закреплений нет (TestCodeTrust)
	for i := range maxTrusted + 2 {
		c.trust(key(i), "")
	}
	c.trust(key(5), "")
	if len(c.Users[0].Trusted) != maxTrusted || c.trusted(key(0), "") || c.trusted(key(1), "") || !c.trusted(key(2), "") || !c.trusted(key(5), "") {
		t.Fatalf("доверенных %d", len(c.Users[0].Trusted))
	}
	c2, _ := loadConfig(c.path)
	if !c2.trusted(key(5), "") {
		t.Fatal("не сохранилось")
	}
	c.setPassword("новый-пароль")
	if c.trusted(key(5), "") {
		t.Fatal("смена пароля не сбросила доверие")
	}
}

// TestOTPConfig — TOTP (PLAN.md): секрет сохраняется только с верным кодом и переживает перезапуск; выключить
// подтверждение без TOTP нельзя; включить подтверждение — отключить TOTP; повтор принятого кода — отказ.
func TestOTPConfig(t *testing.T) {
	c, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	if c.setConfirm(false) == nil || !c.confirm() {
		t.Fatal("подтверждение выключено без TOTP")
	}
	r, err := c.otpNew("")
	if err != nil || !strings.HasPrefix(r["svg"], "<svg") || r["uri"] != totp.URI(c.ID, r["secret"]) {
		t.Fatalf("otpNew: %v %v", err, r["uri"])
	}
	sec := r["secret"]
	if c.otpEnable(sec, "000000", "") == nil && c.otpEnable(sec, "111111", "") == nil {
		t.Fatal("неверный код принят")
	}
	if c.otpSet() || !c.confirm() {
		t.Fatal("TOTP сохранён без верного кода")
	}
	code, _ := totp.Code(sec, time.Now())
	if err := c.otpEnable(sec, code, ""); err != nil || c.confirm() || !c.otpSet() {
		t.Fatalf("верный код: %v", err)
	}
	b, _ := os.ReadFile(c.path)
	if !strings.Contains(string(b), sec) {
		t.Fatal("секрет не в настройках")
	}
	c2, _ := loadConfig(c.path)
	if set, ok := c2.otp("", code); !set || ok { // код настройки уже принят — повтор
		t.Fatalf("после перезапуска: задан %v, повтор принят %v", set, ok)
	}
	if set, ok := c2.otp("", ""); !set || ok {
		t.Fatal("пустой код")
	}
	if err := c2.setConfirm(true); err != nil || c2.otpSet() {
		t.Fatal("включение подтверждения не отключило TOTP")
	}
	if set, _ := c2.otp("", code); set {
		t.Fatal("TOTP остался")
	}
}

// TestSaved — запомненные пароли: сохраняются, "" — забыть, чужой ID — отказ.
func TestSaved(t *testing.T) {
	c, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	if c.savedSet("123456789", "пароль-1") != nil || c.savedSet("../x", "a") == nil {
		t.Fatal("savedSet")
	}
	if c2, _ := loadConfig(c.path); c2.savedGet("123456789") != "пароль-1" {
		t.Fatal("не сохранился")
	}
	if c.savedSet("123456789", "") != nil || c.savedGet("123456789") != "" {
		t.Fatal("не забылся")
	}
}

// TestViewOnlySetting — «Только показ экрана» сохраняется.
func TestViewOnlySetting(t *testing.T) {
	c, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	if c.viewOnly() || c.setViewOnly(true) != nil {
		t.Fatal("по умолчанию включено или не сохранилось")
	}
	if c2, _ := loadConfig(c.path); !c2.viewOnly() {
		t.Fatal("не пережило перезапуск")
	}
}

// TestConfigExternal — регрессия (приёмка Д3): ключ CLI при запущенной программе. Запущенный экземпляр держит
// настройки в памяти и при входе по коду пишет файл — правка CLI («только показ», «подтверждать вход») не откатывается,
// а отключённый CLI TOTP сразу не принимает коды.
func TestConfigExternal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	run, _ := loadConfig(p)
	sec := totp.NewSecret()
	code, _ := totp.Code(sec, time.Now().Add(-30*time.Second))
	if err := run.otpEnable(sec, code, ""); err != nil {
		t.Fatal(err)
	}
	cli, _ := loadConfig(p) // anypc --view-only on
	cli.setViewOnly(true)
	now, _ := totp.Code(sec, time.Now())
	if _, ok := run.otp("", now); !ok {
		t.Fatal("код не принят")
	}
	run.knownSet("123456789", "ab") // любая запись запущенного экземпляра
	if c, _ := loadConfig(p); !c.viewOnly() || c.confirm() || !c.otpSet() || c.knownGet("123456789") != "ab" {
		t.Fatalf("после записи запущенного: только показ=%v, подтверждать=%v, TOTP=%v", c.viewOnly(), c.confirm(), c.otpSet())
	}
	cli.setConfirm(true) // anypc --confirm on — TOTP отключён
	next, _ := totp.Code(sec, time.Now().Add(30*time.Second))
	if set, ok := run.otp("", next); set || ok {
		t.Fatal("TOTP, отключённый ключом CLI, ещё принимает коды")
	}
	if c, _ := loadConfig(p); !c.confirm() || c.otpSet() || !c.viewOnly() {
		t.Fatal("правка CLI откатилась")
	}
}

// TestOTPReplay — боевая защита от повтора (config.otp, приёмка Д6): из 50 параллельных входов одним кодом принят
// один; после перезапуска тот же код и код более раннего шага — отказ.
func TestOTPReplay(t *testing.T) {
	c, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	sec := totp.NewSecret()
	setup, _ := totp.Code(sec, time.Now().Add(-30*time.Second))
	if err := c.otpEnable(sec, setup, ""); err != nil {
		t.Fatal(err)
	}
	code, _ := totp.Code(sec, time.Now())
	res := make(chan bool, 50)
	for range 50 {
		go func() { _, ok := c.otp("", code); res <- ok }()
	}
	n := 0
	for range 50 {
		if <-res {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("один код принят %d раз из 50", n)
	}
	c2, _ := loadConfig(c.path)
	if _, ok := c2.otp("", code); ok {
		t.Fatal("после перезапуска тот же код принят")
	}
	if _, ok := c2.otp("", setup); ok {
		t.Fatal("код более раннего шага принят")
	}
}

// TestConfigMinimal — регрессия (Н2): в файле нет server/enc/bitrate — после записи они остаются умолчаниями.
func TestConfigMinimal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	_, k, _ := ed25519.GenerateKey(nil)
	b, _ := json.Marshal(map[string]any{"id": "123456789", "key": k, "confirm": true})
	os.WriteFile(p, b, 0o600)
	c, err := loadConfig(p)
	if err != nil || c.setViewOnly(true) != nil {
		t.Fatal(err)
	}
	c2, _ := loadConfig(p)
	for _, x := range []*config{c, c2} {
		if x.Server != DefaultServer || x.Enc != "libx264" || x.Bitrate != "4M" {
			t.Fatalf("умолчания пропали: %q %q %q", x.Server, x.Enc, x.Bitrate)
		}
	}
}

// TestConfigTwoWriters — регрессия (Н3): два процесса (CLI и программа) пишут настройки одновременно — ни ошибок,
// ни битого файла, ни брошенных временных файлов; правку CLI видит запущенная программа (viewNow).
func TestConfigTwoWriters(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	a, _ := loadConfig(p)
	b, _ := loadConfig(p)
	var wg sync.WaitGroup
	var errs atomic.Int32
	for _, c := range []*config{a, b} {
		wg.Go(func() {
			for i := range 200 {
				if c.knownSet("123456789", fmt.Sprint(i)) != nil {
					errs.Add(1)
				}
			}
		})
	}
	wg.Wait()
	if c, err := loadConfig(p); errs.Load() != 0 || err != nil || c.knownGet("123456789") != "199" {
		t.Fatalf("ошибок записи %d, чтение %v", errs.Load(), err)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(m) != 0 {
		t.Fatalf("брошены временные файлы: %v", m)
	}
	cli, _ := loadConfig(p)
	cli.setViewOnly(true) // anypc --view-only on
	if a.viewOnly() || !a.viewNow() || !a.viewOnly() {
		t.Fatal("запущенная программа не видит --view-only")
	}
}

// TestConfigBadFile — регрессия (Н5): файл испортили руками (нет ключа) при запущенной программе — reload оставляет
// прежние настройки, отпечаток не паникует.
func TestConfigBadFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	c, _ := loadConfig(p)
	fp := c.fingerprint()
	os.WriteFile(p, []byte(`{"id":"123456789","confirm":true,"view_only":true}`), 0o600)
	if c.viewNow() || c.fingerprint() != fp {
		t.Fatal("негодный файл подхвачен")
	}
}

// TestConfigReadDuringReload — регрессия (Н4, под -race): окно (hostInfo) читает ID, хаб и отпечаток, пока опрос
// перечитывает файл.
func TestConfigReadDuringReload(t *testing.T) {
	c, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 200 {
			c.viewNow()
		}
	}()
	for range 200 {
		if c.id() == "" || c.server() == "" || c.fingerprint() == "" {
			t.Fatal("пусто")
		}
	}
	<-done
}

// TestUsersConfig — REQ-S-20: старый файл (одна запись: salt/hash, trusted, account с TOTP) переезжает в запись по
// умолчанию без потери пароля, ключей и TOTP; записи по имени (без регистра) — свой пароль, права, ключи и TOTP;
// запись по умолчанию не удалить; неверные имена и короткие пароли — отказ.
func TestUsersConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	salt := []byte("0123456789abcdef")
	sec := totp.NewSecret()
	old, _ := json.Marshal(map[string]any{"id": "123456789", "salt": salt, "hash": pake.KDF("старый-пароль", salt), "confirm": false,
		"trusted": [][]byte{bytes.Repeat([]byte{1}, 32)}, "account": map[string]any{"totp": sec, "totp_step": 5}})
	os.WriteFile(p, old, 0o600)
	c, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	var raw map[string]json.RawMessage
	json.Unmarshal(b, &raw)
	if raw["salt"] != nil || raw["hash"] != nil || raw["trusted"] != nil || raw["account"] != nil || raw["users"] == nil {
		t.Fatalf("старые поля в файле после переезда: %s", b)
	}
	s, h, v := c.secret("")
	if !bytes.Equal(h, pake.KDF("старый-пароль", s)) || v || !c.trusted(bytes.Repeat([]byte{1}, 32), "") || !c.otpSet() || c.confirm() || c.Users[0].TOTPStep != 5 {
		t.Fatalf("переезд потерял пароль, ключ или TOTP: %+v", c.Users)
	}
	code, _ := totp.Code(sec, time.Now())
	if set, ok := c.otp("", code); !set || !ok {
		t.Fatal("TOTP после переезда не работает")
	}

	for _, n := range []string{"a\nb", "имя\u202e", strings.Repeat("x", 33), "a*", "<b>"} {
		if c.setUser(n, "пароль-ивана", "full") == nil {
			t.Errorf("имя %q принято", n)
		}
	}
	if c.setUser("Ivan", "short", "full") == nil || c.setUser("Ivan", "пароль-ивана", "admin") == nil {
		t.Fatal("короткий пароль или неверные права приняты")
	}
	for _, n := range []string{"", "  "} { // приёмка Д5: пустое имя — отказ, а не смена пароля по умолчанию
		if c.setUser(n, "пароль-ивана", "full") == nil {
			t.Fatalf("пустое имя %q принято", n)
		}
	}
	if err := c.setUser(" Ivan ", "пароль-ивана", ""); err != nil { // новая без явных прав — «просмотр»
		t.Fatal(err)
	}
	if s, h, v := c.secret("ivan"); !v || !bytes.Equal(h, pake.KDF("пароль-ивана", s)) {
		t.Fatal("запись ivan")
	}
	if s, h, _ := c.secret(""); !bytes.Equal(h, pake.KDF("старый-пароль", s)) {
		t.Fatal("запись по умолчанию сменила пароль")
	}
	if _, h, _ := c.secret("nobody"); h != nil {
		t.Fatal("несуществующая запись")
	}
	k := bytes.Repeat([]byte{2}, 32)
	c.trust(k, "ivan")
	if c.trusted(k, "") || !c.trusted(k, "ivan") || !c.trusted(k, agent.AnyUser) {
		t.Fatal("ключ закреплён не за своей записью")
	}
	isec := totp.NewSecret()
	icode, _ := totp.Code(isec, time.Now())
	if err := c.otpEnable(isec, icode, "IVAN"); err != nil || c.Users[0].TOTP != sec {
		t.Fatalf("TOTP ivan: %v", err)
	}
	if set, ok := c.otp("ivan", icode); !set || ok { // код настройки — повтор
		t.Fatal("TOTP ivan: повтор принят")
	}
	if u := c.users(); len(u) != 1 || u[0]["name"] != "ivan" || u[0]["view"] != true || u[0]["otp"] != true {
		t.Fatalf("список: %v", u)
	}
	c.setUser("ivan", "новый-пароль", "") // смена пароля без прав (приёмка Д3): права, TOTP и место остаются, доверие — заново
	if c.trusted(k, "ivan") || c.users()[0]["otp"] != true || c.users()[0]["view"] != true {
		t.Fatal("смена пароля ivan")
	}
	if c.setUser("ivan", "новый-пароль", "full"); c.users()[0]["view"] != false {
		t.Fatal("права full не записаны")
	}
	if c.otpOff("") == nil || c.otpOff("ivan") != nil || c.users()[0]["otp"] != false {
		t.Fatal("отключение TOTP")
	}
	c2, _ := loadConfig(p)
	if _, h, _ := c2.secret("ivan"); h == nil {
		t.Fatal("запись не сохранилась")
	}
	if c.delUser("") == nil || c.delUser("nobody") == nil || c.delUser("Ivan") != nil || len(c.users()) != 0 || !c.hasPass() {
		t.Fatal("удаление")
	}
	fresh, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	if fresh.setUser("ivan", "пароль-ивана", "full") == nil {
		t.Fatal("запись по имени без пароля по умолчанию")
	}
}

// TestCodeConfig — REQ-S-23: в режиме «Спрашивать» запись по умолчанию входит одноразовым кодом (6 цифр), постоянный
// пароль и записи по имени не действуют; код меняется по ↻ и после сессии/блокировки (codeUsed), старый не годится,
// соль та же; включение «Спрашивать» — новый код; без вопросов (TOTP) — пароль и записи, как раньше, код не меняется.
func TestCodeConfig(t *testing.T) {
	c, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	c.setPassword("пароль-123")
	c.setUser("ivan", "пароль-ивана", "full")
	code := c.code()
	s0, h0, _ := c.secret("")
	if len(code) != 6 || strings.Trim(code, "0123456789") != "" || !bytes.Equal(h0, pake.KDF(code, s0)) {
		t.Fatalf("код %q", code)
	}
	if _, h, _ := c.secret("ivan"); h != nil {
		t.Fatal("запись по имени действует в режиме «Спрашивать»")
	}
	// ↻ и codeUsed (конец сессии, блокировка): новый код, старый не годится, соль та же (совпадение — 1e-6)
	for _, rotate := range []func(){func() { c.newCode() }, c.codeUsed} {
		old, _, oldH := code, s0, h0
		rotate()
		code = c.code()
		s, h, _ := c.secret("")
		if c2, _ := loadConfig(c.path); code == old || c2.code() != code || !bytes.Equal(s, s0) || !bytes.Equal(h, pake.KDF(code, s)) || bytes.Equal(h, oldH) {
			t.Fatalf("смена кода: %q → %q", old, code)
		}
		h0 = h
	}
	before := code
	sec := totp.NewSecret()
	now, _ := totp.Code(sec, time.Now())
	if err := c.otpEnable(sec, now, ""); err != nil { // без вопросов: пароль + TOTP
		t.Fatal(err)
	}
	if s, h, _ := c.secret(""); c.code() != "" || !bytes.Equal(h, pake.KDF("пароль-123", s)) {
		t.Fatal("без вопросов: не постоянный пароль")
	}
	if _, h, _ := c.secret("ivan"); h == nil {
		t.Fatal("без вопросов записи по имени не действуют")
	}
	stored := c.Code
	c.codeUsed()
	if c.Code != stored {
		t.Fatal("без вопросов код меняется")
	}
	c.setConfirm(true)
	if c.code() == "" || c.code() == stored || c.code() == before {
		t.Fatalf("«Спрашивать» включили — код %q", c.code())
	}
}

// passwordMode — режим без вопросов: TOTP записи по умолчанию (вход паролем, записи, закреплённые ключи).
func passwordMode(t *testing.T, c *config) {
	sec := totp.NewSecret()
	code, _ := totp.Code(sec, time.Now())
	if err := c.otpEnable(sec, code, ""); err != nil {
		t.Fatal(err)
	}
}

// TestCodeTrust — приёмка otc Д1: в режиме кода ключи не закрепляются и закреплённые не действуют (иначе впущенный
// однажды клиент перебирал бы следующие коды мимо блокировки); в режиме пароля — хранятся и действуют снова.
func TestCodeTrust(t *testing.T) {
	c, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	k, k2 := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{8}, 32)
	c.trust(k, "") // вход кодом + «Разрешить»
	if c.trusted(k, "") || c.trusted(k, agent.AnyUser) || len(c.Users[0].Trusted) != 0 {
		t.Fatal("в режиме кода ключ закреплён")
	}
	passwordMode(t, c)
	c.trust(k2, "")
	if !c.trusted(k2, "") {
		t.Fatal("в режиме пароля ключ не закреплён")
	}
	c.setConfirm(true)
	if c.trusted(k2, "") || c.trusted(k2, agent.AnyUser) {
		t.Fatal("в режиме кода действует ключ из режима пароля")
	}
}

// TestCodeMode — выжившие мутации приёмки otc: хост после обновления с выключенным подтверждением без TOTP — режим
// кода (он и так спрашивает «Разрешить»); код — 6 цифр из 10^6 (2000 кодов: почти все разные, все первые цифры).
func TestCodeMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(p, []byte(`{"id":"123456789","salt":"AAAA","hash":"AAAA","confirm":false}`), 0o600)
	c, _ := loadConfig(p)
	if c.confirm() || !c.codeMode() || len(c.code()) != 6 {
		t.Fatalf("без TOTP с выключенным подтверждением: режим кода %v, код %q", c.codeMode(), c.code())
	}
	seen, first := map[string]bool{}, map[byte]bool{}
	for range 2000 {
		s := randCode()
		if len(s) != 6 || strings.Trim(s, "0123456789") != "" {
			t.Fatalf("код %q", s)
		}
		seen[s], first[s[0]] = true, true
	}
	if len(seen) < 1980 || len(first) != 10 { // из 10^6 ожидаемо ≈2 совпадения; из 10^3 — сотни
		t.Fatalf("разных кодов %d из 2000, первых цифр %d", len(seen), len(first))
	}
}

// TestListenUI — регрессия ToDo 2026-11-12 (Ubuntu): порт окна случайный — localStorage страницы новый каждый запуск
// (недавние ID, имена записей, тур). Порт запоминается и переживает перезапуск; занят — другой, и запоминается он.
func TestListenUI(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	c, _ := loadConfig(p)
	l, err := c.listenUI()
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().String()
	l.Close()
	c2, _ := loadConfig(p) // перезапуск программы
	l, err = c2.listenUI()
	if err != nil || l.Addr().String() != port {
		t.Fatalf("после перезапуска порт %v, был %s (%v)", l.Addr(), port, err)
	}
	c3, _ := loadConfig(p) // вторая копия, пока первая держит порт
	l2, err := c3.listenUI()
	if err != nil || l2.Addr().String() == port {
		t.Fatalf("занятый порт: %v %v", l2.Addr(), err)
	}
	l.Close()
	l2.Close()
	if c4, _ := loadConfig(p); c4.UIPort != l2.Addr().(*net.TCPAddr).Port {
		t.Fatalf("запомнен %d, ждали новый %s", c4.UIPort, l2.Addr())
	}
}
