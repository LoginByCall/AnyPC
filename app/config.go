package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"anypc/hub"
	"anypc/pake"
)

// config — %APPDATA%\AnyPC\config.json. Enc/Bitrate/Server правятся вручную при необходимости.
type config struct {
	ID      string `json:"id"`
	Server  string `json:"server"`
	Enc     string `json:"enc"`     // libx264 | h264_nvenc | h264_qsv | h264_amf | h264_mf
	Bitrate string `json:"bitrate"` // ffmpeg: 4M, 1500k…
	Salt    []byte `json:"salt,omitempty"`
	Hash    []byte `json:"hash,omitempty"` // Argon2id (REQ-S-03); сам пароль не хранится

	mu   sync.Mutex
	path string
}

func loadConfig(path string) (*config, error) {
	c := &config{path: path, Server: "wss://any.turboseller.xyz/ws", Enc: "libx264", Bitrate: "4M"}
	b, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(b, c)
	} else if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	if !hub.IsHostID(c.ID) {
		c.ID = hub.RandDigits(9)
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

func (c *config) hasPass() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.Hash) > 0
}

// secret — соль и KDF(пароль, соль) для CPace (agent.Agent.Secret).
func (c *config) secret() (salt, hash []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Salt, c.Hash
}
