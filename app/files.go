package main

import (
	"encoding/base64"
	"errors"
	"path/filepath"
	"sync"

	"anypc/agent"
)

// files — приём файлов с удалённого ПК сразу на диск (с докачкой) для окна программы:
// страница получает куски по каналу WebRTC и передаёт их сюда блоками ~1 МБ.
type files struct {
	mu   sync.Mutex
	dir  string
	next int
	open map[int]*agent.Receiver
}

func newFiles(dir string) *files { return &files{dir: dir, open: map[int]*agent.Receiver{}} }

func (f *files) get(h int) (*agent.Receiver, error) {
	r, ok := f.open[h]
	if !ok {
		return nil, errors.New("нет такого приёма")
	}
	return r, nil
}

func (f *files) Open(name string, size float64, id string) (map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := agent.NewReceiver(f.dir)
	off, err := r.Open(name, int64(size), id)
	if err != nil {
		return nil, err
	}
	f.next++
	f.open[f.next] = r
	return map[string]any{"handle": f.next, "offset": off}, nil
}

func (f *files) Write(h int, b64 string) error {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.get(h)
	if err != nil {
		return err
	}
	return r.Write(data)
}

func (f *files) Finish(h int) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := f.get(h)
	if err != nil {
		return nil, err
	}
	delete(f.open, h)
	dst, sum, err := r.Finish()
	if err != nil {
		return nil, err
	}
	return map[string]string{"name": filepath.Base(dst), "sha256": sum}, nil
}

// Abort: keep — обрыв (оставить часть для докачки), иначе отмена.
func (f *files) Abort(h int, keep bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, err := f.get(h); err == nil {
		r.Abort(keep)
		delete(f.open, h)
	}
}
