package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"anypc/hub"
	"anypc/pake"
	"anypc/totp"
)

// account — учётная запись входа. Пока одна (по умолчанию): второй фактор входа без подтверждения (PLAN.md «TOTP»).
type account struct {
	TOTP     string `json:"totp,omitempty"`      // секрет TOTP, base32 без '=' (файл настроек — 0600, как хэш пароля)
	TOTPStep int64  `json:"totp_step,omitempty"` // шаг последнего принятого кода: тот же и более ранний — повтор, отказ
}

// config — %APPDATA%\AnyPC\config.json. Enc/Bitrate/Server правятся вручную при необходимости.
type config struct {
	settings
	mu   sync.Mutex
	path string
}

// settings — то, что лежит в файле.
type settings struct {
	ID      string            `json:"id"`
	Server  string            `json:"server"`
	Enc     string            `json:"enc"`     // кодер H.264 в ffmpeg: libx264 | h264_nvenc | h264_qsv | h264_amf | h264_mf (VP9 выбирает клиент — «Турбо»)
	Bitrate string            `json:"bitrate"` // ffmpeg: 4M, 1500k…
	Salt    []byte            `json:"salt,omitempty"`
	Hash    []byte            `json:"hash,omitempty"`      // Argon2id (REQ-S-03); сам пароль не хранится
	Key     []byte            `json:"key"`                 // Ed25519 ключ хоста (REQ-F-01); не покидает ПК
	Known   map[string]string `json:"known,omitempty"`     // ID удалённого ПК → отпечаток его ключа (TOFU, REQ-S-05)
	Confirm *bool             `json:"confirm"`             // REQ-F-03: окно «Разрешить / Отклонить» на каждое подключение
	Trusted [][]byte          `json:"trusted,omitempty"`   // У3: ключи клиентов, входивших по паролю (старые — в начале); сброс при смене пароля
	Account account           `json:"account,omitzero"`    // учётная запись по умолчанию (PLAN.md: с учётными записями сюда переедут Salt/Hash)
	Saved   map[string]string `json:"saved,omitempty"`     // ID удалённого ПК → запомненный пароль («Запомнить пароль» на управляющем ПК)
	View    bool              `json:"view_only,omitempty"` // «Только показ экрана»: каждая входящая сессия — только просмотр (REQ-F-20)
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
		v := len(c.Hash) == 0
		c.Confirm, changed = &v, true
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
	if b, err := os.ReadFile(c.path); err == nil && json.Unmarshal(b, &f) == nil && hub.IsHostID(f.ID) {
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

// viewNow — «Только показ экрана» по файлу (его мог включить ключ CLI при запущенной программе).
func (c *config) viewNow() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	return c.View
}

func (c *config) setPassword(p string) error {
	if len([]rune(p)) < 8 {
		return errors.New("пароль короче 8 символов")
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	c.Salt, c.Hash = salt, pake.KDF(p, salt)
	c.Trusted = nil // новый пароль — доверие заново
	return c.save()
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
	if !on && c.Account.TOTP == "" {
		return errors.New("вход без подтверждения — только со вторым фактором (TOTP)")
	}
	c.Confirm = &on
	if on {
		c.Account = account{}
	}
	return c.save()
}

// errBadCode — неверный код при настройке TOTP (окно показывает свой текст по этой метке).
var errBadCode = errors.New("bad_code")

// otpEnable — настройка TOTP: секрет сохраняется только с верным кодом из приложения, и вход без подтверждения
// включается вместе с ним.
func (c *config) otpEnable(secret, code string) error {
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
	off := false
	c.Account, c.Confirm = account{TOTP: secret, TOTPStep: step}, &off // этот код уже не войдёт (повтор)
	return c.save()
}

// otp — второй фактор для agent.Agent.OTP: set — секрет задан; ok — код верный и новее последнего принятого.
func (c *config) otp(code string) (set, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	if c.Account.TOTP == "" {
		return false, false
	}
	step, ok := totp.Check(c.Account.TOTP, code, time.Now(), c.Account.TOTPStep)
	if ok {
		c.Account.TOTPStep = step
		c.save()
	}
	return true, ok
}

// otpNew — новый секрет для окна настройки TOTP: ключ, otpauth-URI и QR (SVG). Сохраняется только otpEnable.
func (c *config) otpNew() (map[string]string, error) {
	sec := totp.NewSecret()
	u := totp.URI(c.ID, sec)
	svg, err := totp.SVG(u)
	return map[string]string{"secret": sec, "uri": u, "svg": svg}, err
}

func (c *config) otpSet() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Account.TOTP != ""
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
	return len(c.Hash) > 0
}

func (c *config) key() ed25519.PrivateKey { return ed25519.PrivateKey(c.Key) }

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

func (c *config) trusted(pub []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.ContainsFunc(c.Trusted, func(k []byte) bool { return bytes.Equal(k, pub) })
}

func (c *config) trust(pub []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	c.Trusted = slices.DeleteFunc(c.Trusted, func(k []byte) bool { return bytes.Equal(k, pub) })
	c.Trusted = append(c.Trusted, bytes.Clone(pub))
	if n := len(c.Trusted) - maxTrusted; n > 0 {
		c.Trusted = c.Trusted[n:]
	}
	c.save()
}

// secret — соль и KDF(пароль, соль) для CPace (agent.Agent.Secret).
func (c *config) secret() (salt, hash []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Salt, c.Hash
}
