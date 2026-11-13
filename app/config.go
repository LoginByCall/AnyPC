package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"anypc/agent"
	"anypc/hub"
	"anypc/pake"
	"anypc/totp"
)

// account — учётная запись входа (REQ-S-20). Name "" — запись по умолчанию: пароль из окна, ею входит клиент без имени.
type account struct {
	Name     string   `json:"name,omitempty"`      // agent.UserKey: строчными, без пробелов по краям
	Salt     []byte   `json:"salt,omitempty"`      //
	Hash     []byte   `json:"hash,omitempty"`      // Argon2id (REQ-S-03); сам пароль не хранится
	View     bool     `json:"view,omitempty"`      // права «просмотр» (REQ-F-20); иначе полный доступ
	TOTP     string   `json:"totp,omitempty"`      // секрет TOTP, base32 без '=' (файл настроек — 0600, как хэш пароля)
	TOTPStep int64    `json:"totp_step,omitempty"` // шаг последнего принятого кода: тот же и более ранний — повтор, отказ
	Trusted  [][]byte `json:"trusted,omitempty"`   // У3: ключи клиентов, входивших этой записью (старые — в начале); сброс при смене пароля
	// REQ-S-24: ключи входа без пароля (с TOTP); давно не входившие — в начале; сброс при смене пароля
	KeyLogin []loginKey `json:"key_login,omitempty"`
}

// loginKey — ключ клиента во входе без пароля (REQ-S-24): когда добавлен и когда им входили последний раз.
type loginKey struct {
	Pub   []byte    `json:"pub"`
	Added time.Time `json:"added"`
	Last  time.Time `json:"last"`
}

// config — %APPDATA%\AnyPC\config.json. Enc/Bitrate/Server правятся вручную при необходимости.
type config struct {
	settings
	mu    sync.Mutex
	path  string
	kmu   sync.Mutex // кэш KDF одноразового кода: Argon2 — раз на код, не на каждый вход
	kkey  string
	mine  string // последний код, заданный этим процессом (setCode, под mu; reload его не трогает)
	khash []byte
}

// settings — то, что лежит в файле.
type settings struct {
	ID      string            `json:"id"`
	Server  string            `json:"server"`
	Enc     string            `json:"enc"`                 // кодер H.264 в ffmpeg: libx264 | h264_nvenc | h264_qsv | h264_amf | h264_mf (VP9 выбирает клиент — «Турбо»)
	Bitrate string            `json:"bitrate"`             // ffmpeg: 4M, 1500k…
	Users   []account         `json:"users,omitempty"`     // учётные записи (REQ-S-20); [0] — по умолчанию (Name "")
	Key     []byte            `json:"key"`                 // Ed25519 ключ хоста (REQ-F-01); не покидает ПК
	Known   map[string]string `json:"known,omitempty"`     // ID удалённого ПК → отпечаток его ключа (TOFU, REQ-S-05)
	Confirm *bool             `json:"confirm"`             // REQ-F-03: окно «Разрешить / Отклонить» на каждое подключение
	Saved   map[string]string `json:"saved,omitempty"`     // ID удалённого ПК → запомненный пароль («Запомнить пароль» на управляющем ПК)
	CKeys   map[string]string `json:"ckeys,omitempty"`     // ID удалённого ПК → ключ этого ПК для него (У3, REQ-S-24): JSON {seed,pub,login,lu}
	View    bool              `json:"view_only,omitempty"` // «Только показ экрана»: каждая входящая сессия — только просмотр (REQ-F-20)
	UIPort  int               `json:"ui_port,omitempty"`   // порт окна на 127.0.0.1 (listenUI)
	// Одноразовый код (REQ-S-23): в режиме «Спрашивать» — пароль записи по умолчанию; меняется после каждой сессии,
	// блокировки и по ↻. В файле (0600, как запомненные пароли): окно, ключи CLI и запущенная программа видят один код.
	Code     string `json:"code,omitempty"`
	CodeSalt []byte `json:"code_salt,omitempty"`
	// До учётных записей (v0.1.19 и раньше) запись была одна: Salt/Hash, Trusted и account. Читаются и переезжают
	// в Users[0] (migrate), в файл больше не пишутся.
	Salt    []byte   `json:"salt,omitempty"`
	Hash    []byte   `json:"hash,omitempty"`
	Trusted [][]byte `json:"trusted,omitempty"`
	Account account  `json:"account,omitzero"`
}

// migrate — старый файл (одна запись в Salt/Hash, trusted, account) → Users[0] без потери пароля, ключей и TOTP;
// новый — Users[0] по умолчанию есть всегда. true — настройки изменились.
func (s *settings) migrate() bool {
	if len(s.Users) > 0 && s.Users[0].Name == "" && len(s.Hash) == 0 && s.Trusted == nil && s.Account.TOTP == "" {
		return false
	}
	def := account{Salt: s.Salt, Hash: s.Hash, TOTP: s.Account.TOTP, TOTPStep: s.Account.TOTPStep, Trusted: s.Trusted}
	s.Users = slices.DeleteFunc(s.Users, func(u account) bool { return u.Name == "" }) // правленный руками файл: одна по умолчанию
	s.Users = append([]account{def}, s.Users...)
	s.Salt, s.Hash, s.Trusted, s.Account = nil, nil, nil, account{}
	return true
}

const (
	// Хабы сигнализации через запятую: хост в сети на всех, клиент идёт через первый ответивший.
	DefaultServer = "wss://hk.anypc.org/ws,wss://ru.anypc.org/ws"
)

// version — из git-тега при сборке (build.sh: -ldflags -X main.version=…).
var version = "dev"

// oldServers — прежние адреса по умолчанию: переводятся на DefaultServer (свой адрес пользователя не трогается).
var oldServers = []string{"wss://any.turboseller.xyz/ws", "wss://any-hk.turboseller.xyz/ws", "wss://any-hk.turboseller.xyz/ws,wss://any-ru.turboseller.xyz/ws"}

func loadConfig(path string) (*config, error) {
	c := &config{path: path, settings: defaults()}
	b, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(b, c)
	} else if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	changed := false
	if slices.Contains(oldServers, c.Server) { // any. переименован, добавлен резервный хаб, переезд на anypc.org (2026-11-06/07)
		c.Server, changed = DefaultServer, true
	}
	if !hub.IsHostID(c.ID) {
		c.ID, changed = hub.RandDigits(9), true
	}
	if len(c.Key) != ed25519.PrivateKeySize {
		_, k, _ := ed25519.GenerateKey(nil)
		c.Key, changed = k, true
	}
	if c.Confirm == nil { // старые установки с паролем работали без окна — не запереть ПК, у которого никого нет
		v := len(c.Hash) == 0 && (len(c.Users) == 0 || len(c.Users[0].Hash) == 0)
		c.Confirm, changed = &v, true
	}
	if c.migrate() {
		changed = true
	}
	if c.codeModeLocked() && c.Code == "" { // режим «Спрашивать» без кода (новая установка, обновление) — завести
		c.setCode(randCode())
		changed = true
	}
	if changed {
		return c, c.save()
	}
	return c, nil
}

// reload — под c.mu перед правкой: файл с диска (его мог изменить ключ CLI при запущенной программе), иначе
// запись целиком откатила бы чужую правку. Файл не читается — остаётся то, что в памяти.
func (c *config) reload() {
	f := defaults() // поля, которых нет в файле, — как при запуске (loadConfig), а не пустые
	// файл негодный (правлен руками: нет ID или ключа) — остаются прежние настройки
	if b, err := os.ReadFile(c.path); err == nil && json.Unmarshal(b, &f) == nil && hub.IsHostID(f.ID) && len(f.Key) == ed25519.PrivateKeySize {
		f.migrate() // старая версия могла записать файл по-своему (откат и снова обновление)
		c.settings = f
	}
}

// defaults — настройки до чтения файла.
func defaults() settings { return settings{Server: DefaultServer, Enc: "libx264", Bitrate: "4M"} }

// save — через временный файл со своим именем (CreateTemp, 0600) и rename: CLI и запущенная программа могут писать
// одновременно, общий .tmp давал ошибки и битый файл.
func (c *config) save() error {
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(c.path), filepath.Base(c.path)+".*.tmp")
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), c.path)
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

// listenUI — окно программы на постоянном порту 127.0.0.1. localStorage у браузера и WebView2 — свой на каждый порт:
// со случайным портом каждый запуск начинался с пустого (недавние ID, имена записей, ключи клиента, тур — ToDo
// 2026-11-12, Ubuntu). Порт занят (вторая копия, чужая программа) — новый случайный, запоминается он.
func (c *config) listenUI() (net.Listener, error) {
	c.mu.Lock()
	p := c.UIPort
	c.mu.Unlock()
	if p != 0 {
		if l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p))); err == nil {
			return l, nil
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	c.UIPort = l.Addr().(*net.TCPAddr).Port
	if err := c.save(); err != nil {
		log.Printf("порт окна не запомнен: %v", err)
	}
	return l, nil
}

// viewNow — «Только показ экрана» по файлу (его мог включить ключ CLI при запущенной программе).
func (c *config) viewNow() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	return c.View
}

// setPassword — пароль записи по умолчанию (окно хоста, --password-stdin).
func (c *config) setPassword(p string) error { return c.setAccount("", p, "full") }

// maxUsers — учётных записей на хосте, кроме записи по умолчанию.
const maxUsers = 32

// validName — имя записи: 1–32 буквы, цифры, пробел и « . _ - @ » (в плашку, окно «Разрешить» и журнал — как есть).
func validName(n string) bool {
	r := []rune(n)
	return len(r) >= 1 && len(r) <= 32 && !slices.ContainsFunc(r, func(c rune) bool {
		return !unicode.IsLetter(c) && !unicode.IsDigit(c) && !strings.ContainsRune(" ._-@", c)
	})
}

// user — запись по имени (agent.UserKey) под c.mu; nil — нет.
func (c *config) user(name string) *account {
	for i := range c.Users {
		if c.Users[i].Name == name {
			return &c.Users[i]
		}
	}
	return nil
}

// setUser — добавить запись по имени или сменить её пароль и права (REQ-S-20); пустое имя — отказ (пароль по
// умолчанию — setPassword). rights: "full" | "view" | "" — у существующей оставить, новой — «просмотр» (безопаснее).
func (c *config) setUser(name, p, rights string) error {
	if agent.UserKey(name) == "" {
		return errors.New("имя не задано")
	}
	return c.setAccount(agent.UserKey(name), p, rights)
}

// setAccount — пароль и права записи name (UserKey; "" — по умолчанию, права у неё всегда полные). Новый пароль —
// доверие ключам заново; TOTP записи остаётся.
func (c *config) setAccount(name, p, rights string) error {
	if name != "" && !validName(name) {
		return errors.New("имя: 1–32 буквы, цифры, пробел и . _ - @")
	}
	if rights != "" && rights != "full" && rights != "view" {
		return errors.New("права: full или view")
	}
	if len([]rune(p)) < 8 {
		return errors.New("пароль короче 8 символов")
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	hash := pake.KDF(p, salt)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	u := c.user(name)
	switch {
	case u != nil:
	case len(c.Users[0].Hash) == 0:
		return errors.New("сначала задайте пароль этого компьютера (запись по умолчанию)")
	case len(c.Users) > maxUsers:
		return fmt.Errorf("не больше %d учётных записей", maxUsers)
	default:
		c.Users = append(c.Users, account{Name: name, View: true}) // новая без явных прав — «просмотр»
		u = &c.Users[len(c.Users)-1]
	}
	u.Salt, u.Hash, u.Trusted, u.KeyLogin = salt, hash, nil, nil
	if rights != "" {
		u.View = rights == "view" && name != ""
	}
	return c.save()
}

// delUser — удалить запись по имени; запись по умолчанию не удаляется.
func (c *config) delUser(name string) error {
	name = agent.UserKey(name)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	if name == "" || c.user(name) == nil {
		return errors.New("нет такой учётной записи")
	}
	c.Users = slices.DeleteFunc(c.Users, func(u account) bool { return u.Name == name })
	return c.save()
}

// users — записи, кроме по умолчанию, для окна хоста и --status: имя, права, TOTP.
func (c *config) users() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	l := []map[string]any{}
	for _, u := range c.Users[1:] {
		l = append(l, map[string]any{"name": u.Name, "view": u.View, "otp": u.TOTP != ""})
	}
	return l
}

func (c *config) confirm() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Confirm == nil || *c.Confirm
}

// setConfirm: включить окно «Разрешить» — это и отключить TOTP; выключить — только с настроенным TOTP (otpEnable).
func (c *config) setConfirm(on bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	if !on && c.Users[0].TOTP == "" {
		return errors.New("вход без подтверждения — только со вторым фактором (TOTP)")
	}
	c.Confirm = &on
	if on { // TOTP записи по умолчанию; у остальных записей свой — остаётся (действует, когда подтверждение снова выключат)
		c.Users[0].TOTP, c.Users[0].TOTPStep = "", 0
		c.setCode(randCode()) // режим «Спрашивать» — новый одноразовый код
	}
	return c.save()
}

// codeModeLocked — режим «Спрашивать перед каждым подключением» (REQ-S-23, под c.mu): вход записи по умолчанию —
// одноразовым кодом и «Разрешить», постоянный пароль и записи по имени не действуют (хранятся). Это и галочка, и
// хост после обновления с выключенным подтверждением без TOTP (он и так спрашивает «Разрешить»).
func (c *config) codeModeLocked() bool {
	return c.Confirm == nil || *c.Confirm || len(c.Users) == 0 || c.Users[0].TOTP == ""
}

func (c *config) codeMode() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.codeModeLocked()
}

// randCode — одноразовый код: 6 цифр crypto/rand (равномерно).
func randCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1e6))
	if err != nil {
		panic(err) // crypto/rand не отказывает
	}
	return fmt.Sprintf("%06d", n)
}

// setCode — новый код под c.mu. Соль KDF кода — одна на хост: смена кода не меняет соль, и DropRevoked не рвёт идущую
// сессию по ↻ (сессию кончает «Разорвать»); смена режима (пароль ↔ код) — меняет.
func (c *config) setCode(code string) {
	if len(c.CodeSalt) == 0 {
		c.CodeSalt = make([]byte, 16)
		rand.Read(c.CodeSalt)
	}
	c.Code, c.mine = code, code
}

// ownCode — код задал этот процесс (↻, смена после сессии): его незавершённые входы уже закрыты, а начатые новым
// кодом опрос закрывать не должен; чужой (ключ CLI в другом процессе) — закрыть.
func (c *config) ownCode(code string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return code == c.mine
}

// code — одноразовый код для окна и --status; "" — не режим «Спрашивать».
func (c *config) code() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.codeModeLocked() {
		return ""
	}
	return c.Code
}

// newCode — сменить одноразовый код (↻, конец сессии, блокировка перебора); KDF — сразу, первый вход не ждёт Argon2.
func (c *config) newCode() (string, error) {
	code := randCode()
	c.mu.Lock()
	c.reload()
	c.setCode(code)
	salt := c.CodeSalt
	err := c.save()
	c.mu.Unlock()
	go c.codeKDF(code, salt)
	return code, err
}

// codeUsed — agent.Agent.CodeUsed: код израсходован — в режиме «Спрашивать» новый.
func (c *config) codeUsed() {
	if c.codeMode() {
		if _, err := c.newCode(); err != nil {
			log.Printf("одноразовый код: %v", err)
		}
	}
}

// codeKDF — KDF(код, соль), с кэшем на последний код (без c.mu: Argon2 64 МБ не держит настройки).
func (c *config) codeKDF(code string, salt []byte) []byte {
	k := code + "\x00" + string(salt)
	c.kmu.Lock()
	defer c.kmu.Unlock()
	if c.kkey != k {
		c.kkey, c.khash = k, pake.KDF(code, salt)
	}
	return c.khash
}

// errBadCode — неверный код при настройке TOTP (окно показывает свой текст по этой метке).
var errBadCode = errors.New("bad_code")

// otpEnable — настройка TOTP записи user: секрет сохраняется только с верным кодом из приложения; у записи по
// умолчанию вместе с ним включается и вход без подтверждения.
func (c *config) otpEnable(secret, code, user string) error {
	if !totp.Valid(secret) {
		return errors.New("неверный секрет TOTP")
	}
	step, ok := totp.Check(secret, code, time.Now(), 0)
	if !ok {
		return errBadCode
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	u := c.user(agent.UserKey(user))
	if u == nil {
		return errors.New("нет такой учётной записи")
	}
	u.TOTP, u.TOTPStep = secret, step // этот код уже не войдёт (повтор)
	if u.Name == "" {
		off := false
		c.Confirm = &off
	}
	return c.save()
}

// otpOff — отключить TOTP записи (не по умолчанию: та отключается вместе с подтверждением, setConfirm(true)).
func (c *config) otpOff(user string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	u := c.user(agent.UserKey(user))
	if u == nil || u.Name == "" {
		return errors.New("нет такой учётной записи")
	}
	u.TOTP, u.TOTPStep = "", 0
	return c.save()
}

// otp — второй фактор для agent.Agent.OTP: set — у записи задан секрет; ok — код верный и новее последнего принятого.
func (c *config) otp(user, code string) (set, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	u := c.user(user)
	if u == nil || u.TOTP == "" {
		return false, false
	}
	step, ok := totp.Check(u.TOTP, code, time.Now(), u.TOTPStep)
	if ok {
		u.TOTPStep = step
		c.save()
	}
	return true, ok
}

// otpNew — новый секрет для окна настройки TOTP записи user: ключ, otpauth-URI и QR (SVG). Сохраняется только
// otpEnable. В приложении запись подписана ID и именем — у каждой записи своя.
func (c *config) otpNew(user string) (map[string]string, error) {
	sec, label := totp.NewSecret(), c.id()
	if n := agent.UserKey(user); n != "" {
		label += " " + n
	}
	u := totp.URI(url.PathEscape(label), sec)
	svg, err := totp.SVG(u)
	return map[string]string{"secret": sec, "uri": u, "svg": svg}, err
}

// otpSet — TOTP записи по умолчанию (вход без подтверждения).
func (c *config) otpSet() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Users[0].TOTP != ""
}

func (c *config) viewOnly() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.View
}

func (c *config) setViewOnly(on bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	c.View = on
	return c.save()
}

func (c *config) hasPass() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.Users[0].Hash) > 0
}

// key, id, server — под c.mu: reload (опрос раз в 2 с) меняет настройки на ходу.
func (c *config) key() ed25519.PrivateKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ed25519.PrivateKey(c.Key)
}

func (c *config) id() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ID
}

func (c *config) server() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Server
}

func (c *config) fingerprint() string {
	return pake.KeyFingerprint(c.key().Public().(ed25519.PublicKey))
}

func (c *config) knownGet(id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Known[id]
}

func (c *config) knownSet(id, fp string) error {
	if !hub.IsHostID(id) || len(fp) > 64 {
		return errors.New("неверный ID или отпечаток")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	if c.Known == nil {
		c.Known = map[string]string{}
	}
	c.Known[id] = fp
	return c.save()
}

// ckeyGet — ключ клиента для удалённого ПК (JSON окна; "" — нет): seed — секрет, поэтому в файле 0600, а не в localStorage.
func (c *config) ckeyGet(id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.CKeys[id]
}

// ckeySet — запомнить ключ клиента для удалённого ПК; "" — забыть.
func (c *config) ckeySet(id, k string) error {
	if !hub.IsHostID(id) || len(k) > 512 || k != "" && !validCKey(k) {
		return errors.New("неверный ID или ключ")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	if k == "" {
		delete(c.CKeys, id)
	} else {
		if c.CKeys == nil {
			c.CKeys = map[string]string{}
		}
		c.CKeys[id] = k
	}
	return c.save()
}

// validCKey — ключ клиента от окна: объект {seed, pub, login?, lu?}, seed — 32 байта base64, pub выводится из него.
func validCKey(k string) bool {
	var v struct {
		Seed, Pub string
		Login     bool
		Lu        string
	}
	d := json.NewDecoder(strings.NewReader(k))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.More() {
		return false
	}
	seed, err := base64.StdEncoding.DecodeString(v.Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return false
	}
	return base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)) == v.Pub
}

// savedGet — запомненный пароль удалённого ПК ("" — нет).
func (c *config) savedGet(id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Saved[id]
}

// savedSet — запомнить пароль удалённого ПК; "" — забыть.
func (c *config) savedSet(id, pw string) error {
	if !hub.IsHostID(id) || len(pw) > 1024 {
		return errors.New("неверный ID или пароль")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	if pw == "" {
		delete(c.Saved, id)
	} else {
		if c.Saved == nil {
			c.Saved = map[string]string{}
		}
		c.Saved[id] = pw
	}
	return c.save()
}

// maxTrusted — доверенных ключей клиентов; лишние — самые давние.
const maxTrusted = 20

// trusted — ключ клиента закреплён за записью user (agent.AnyUser — за любой).
// В режиме кода (REQ-S-23) закреплённых нет: код — для любого клиента одинаковая преграда, и ключ, однажды
// впущенный «Разрешить», не перебирает следующие коды мимо блокировки (закрепления хранятся для режима пароля).
func (c *config) trusted(pub []byte, user string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.codeModeLocked() {
		return false
	}
	return slices.ContainsFunc(c.Users, func(u account) bool {
		return (user == agent.AnyUser || u.Name == user) && slices.ContainsFunc(u.Trusted, func(k []byte) bool { return bytes.Equal(k, pub) })
	})
}

// trust — agent.Agent.Trust: закрепить ключ за записью user, если её соль та же, что при входе (пароль не сменили
// за время входа — иначе ключ остался бы закреплённым за новым паролем).
func (c *config) trust(pub []byte, user string, salt []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	if c.codeModeLocked() { // вход кодом ключ не закрепляет
		return
	}
	u := c.user(user)
	if u == nil || !bytes.Equal(u.Salt, salt) { // запись удалили или сменили ей пароль, пока шёл вход
		return
	}
	u.Trusted = slices.DeleteFunc(u.Trusted, func(k []byte) bool { return bytes.Equal(k, pub) })
	u.Trusted = append(u.Trusted, bytes.Clone(pub))
	if n := len(u.Trusted) - maxTrusted; n > 0 {
		u.Trusted = u.Trusted[n:]
	}
	c.save()
}

// keyLogin — agent.Agent.KeyLogin (REQ-S-24): in — ключ во входе без пароля записи user (agent.AnyUser — любой);
// on — и вход им разрешён: в режиме «Спрашивать» входа по ключу нет (ключи хранятся), как и закреплённых (trusted).
func (c *config) keyLogin(pub []byte, user string) (in, on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	in = slices.ContainsFunc(c.Users, func(u account) bool {
		return (user == agent.AnyUser || u.Name == user) && slices.ContainsFunc(u.KeyLogin, func(k loginKey) bool { return bytes.Equal(k.Pub, pub) })
	})
	return in, in && !c.codeModeLocked()
}

// keyTrust — agent.Agent.KeyTrust: salt == nil — отметка входа ключом (только если он ещё в списке записи user), иначе
// добавить его, если соль записи та же, что при входе (пароль не сменили); лишние — давно не входившие. Под c.mu:
// отзыв и смена пароля во время входа не откатываются.
func (c *config) keyTrust(pub []byte, user string, salt []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	u := c.user(user)
	if c.codeModeLocked() || u == nil || salt != nil && !bytes.Equal(u.Salt, salt) { // запись удалили или сменили ей пароль
		return
	}
	now := time.Now()
	k := loginKey{Pub: bytes.Clone(pub), Added: now, Last: now}
	i := slices.IndexFunc(u.KeyLogin, func(k loginKey) bool { return bytes.Equal(k.Pub, pub) })
	if i < 0 && salt == nil { // отозвали, пока шёл вход
		return
	}
	if i >= 0 {
		k.Added = u.KeyLogin[i].Added
		u.KeyLogin = slices.Delete(u.KeyLogin, i, i+1)
	} else {
		log.Printf("ключ %s добавлен для входа без пароля (запись %q)", pake.KeyFingerprint(pub)[:9], user)
	}
	u.KeyLogin = append(u.KeyLogin, k)
	if n := len(u.KeyLogin) - maxTrusted; n > 0 {
		u.KeyLogin = u.KeyLogin[n:]
	}
	c.save()
}

// keyDel — отозвать ключ входа без пароля записи user (fp — pake.KeyFingerprint, как в окне хоста); и из
// закреплённых У3 всех записей: отозванный ключ не обходит блокировки перебора.
func (c *config) keyDel(user, fp string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	u := c.user(agent.UserKey(user))
	if u == nil {
		return errors.New("нет такой учётной записи")
	}
	i := slices.IndexFunc(u.KeyLogin, func(k loginKey) bool { return pake.KeyFingerprint(k.Pub) == fp })
	if i < 0 {
		return errors.New("нет такого ключа")
	}
	pub := u.KeyLogin[i].Pub
	u.KeyLogin = slices.Delete(u.KeyLogin, i, i+1)
	for j := range c.Users { // из закреплённых У3 всех записей: ключ один на клиента, отозван — не доверенный нигде
		c.Users[j].Trusted = slices.DeleteFunc(c.Users[j].Trusted, func(k []byte) bool { return bytes.Equal(k, pub) })
	}
	log.Printf("ключ %s отозван (запись %q)", fp[:min(len(fp), 9)], u.Name)
	return c.save()
}

// keyList — ключи входа без пароля всех записей для окна хоста: запись, отпечаток, когда добавлен, последний вход.
func (c *config) keyList() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	l := []map[string]any{}
	for _, u := range c.Users {
		for _, k := range u.KeyLogin {
			l = append(l, map[string]any{"user": u.Name, "fp": pake.KeyFingerprint(k.Pub), "added": k.Added, "last": k.Last})
		}
	}
	return l
}

// secret — запись user для CPace (agent.Agent.Secret): соль, KDF(пароль, соль), права «просмотр»; нет — пустой hash.
// В режиме «Спрашивать» (REQ-S-23) запись по умолчанию — одноразовый код, записи по имени не действуют.
func (c *config) secret(user string) (salt, hash []byte, view bool) {
	c.mu.Lock()
	if c.codeModeLocked() {
		code, salt := c.Code, c.CodeSalt
		c.mu.Unlock()
		if user != "" || code == "" {
			return nil, nil, false
		}
		return salt, c.codeKDF(code, salt), false
	}
	defer c.mu.Unlock()
	if u := c.user(user); u != nil {
		return u.Salt, u.Hash, u.View
	}
	return nil, nil, false
}
