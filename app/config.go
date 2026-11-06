package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"anypc/hub"
	"anypc/pake"
)

// config — %APPDATA%\AnyPC\config.json. Enc/Bitrate/Server правятся вручную при необходимости.
type config struct {
	ID      string            `json:"id"`
	Server  string            `json:"server"`
	Enc     string            `json:"enc"`     // libx264 | h264_nvenc | h264_qsv | h264_amf | h264_mf
	Bitrate string            `json:"bitrate"` // ffmpeg: 4M, 1500k…
	Salt    []byte            `json:"salt,omitempty"`
	Hash    []byte            `json:"hash,omitempty"`  // Argon2id (REQ-S-03); сам пароль не хранится
	Key     []byte            `json:"key"`             // Ed25519 ключ хоста (REQ-F-01); не покидает ПК
	Known   map[string]string `json:"known,omitempty"` // ID удалённого ПК → отпечаток его ключа (TOFU, REQ-S-05)
	Confirm *bool             `json:"confirm"`         // REQ-F-03: окно «Разрешить / Отклонить» на каждое подключение

	mu   sync.Mutex
	path string
}

const (
	// Хабы сигнализации через запятую: хост в сети на всех, клиент идёт через первый ответивший.
	DefaultServer = "wss://any-hk.turboseller.xyz/ws,wss://any-ru.turboseller.xyz/ws"
)

// oldServers — прежние адреса по умолчанию: переводятся на DefaultServer (свой адрес пользователя не трогается).
var oldServers = []string{"wss://any.turboseller.xyz/ws", "wss://any-hk.turboseller.xyz/ws"}

func loadConfig(path string) (*config, error) {
	c := &config{path: path, Server: DefaultServer, Enc: "libx264", Bitrate: "4M"}
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
	if slices.Contains(oldServers, c.Server) { // any. переименован, затем добавлен резервный хаб (2026-11-06)
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

func (c *config) save() error {
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

func (c *config) setPassword(p string) error {
	if len([]rune(p)) < 8 {
		return errors.New("пароль короче 8 символов")
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Salt, c.Hash = salt, pake.KDF(p, salt)
	return c.save()
}

func (c *config) confirm() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Confirm == nil || *c.Confirm
}

func (c *config) setConfirm(on bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Confirm = &on
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
	if c.Known == nil {
		c.Known = map[string]string{}
	}
	c.Known[id] = fp
	return c.save()
}

// secret — соль и KDF(пароль, соль) для CPace (agent.Agent.Secret).
func (c *config) secret() (salt, hash []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Salt, c.Hash
}
