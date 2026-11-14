package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
)

// fakeSync — SpaceSyncer без формата: M — непрозрачные байты; gate — пускать ли; got — что пришло в SyncApply.
type fakeSync struct {
	mu   sync.Mutex
	m    []byte
	gate bool
	recs [][]byte
	got  [][]byte
}

func (f *fakeSync) SyncGate(ed25519.PublicKey, []byte) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.gate {
		return nil
	}
	return bytes.Clone(f.m)
}
func (f *fakeSync) SyncRecs([]byte) [][]byte { f.mu.Lock(); defer f.mu.Unlock(); return f.recs }
func (f *fakeSync) SyncApply(p []byte, recs [][]byte) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(append(f.got, recs...), p)
	if len(recs) > 0 { // «принял» записи и M другой стороны
		f.m = bytes.Clone(p)
	}
	return bytes.Clone(f.m)
}

// TestSpaceSyncWire — Э4, обмен сверки по сети: отставший хост получает записи цепочки по порядку и M клиента;
// составы сходятся (same). Вход не выполняется: неудач нет, места сессии сверка не занимает. Отказы: ключ клиента
// не член — refused; под ID другой ключ — ErrSpaceIDKey (С4); хост без сверки — ErrSpaceOld.
func TestSpaceSyncWire(t *testing.T) {
	url := local(t)
	host := &fakeSync{m: []byte("M1"), gate: true}
	r := spaceHost(t, url, "123456789", func(r *spaceRig) { r.a.SpaceSync = host })
	_, ckey, _ := ed25519.GenerateKey(nil)
	cli := &fakeSync{m: []byte("M3"), gate: true, recs: [][]byte{[]byte("R2")}}
	hpub := r.a.Key.Public().(ed25519.PublicKey)
	d := SyncDial{Server: url, ID: "123456789", HostPub: hpub, Key: ckey, S: cli}
	same, err := SpaceSync(context.Background(), d)
	if err != nil || !same {
		t.Fatalf("сверка: %v %v", same, err)
	}
	host.mu.Lock()
	got := host.got
	host.mu.Unlock()
	if len(got) != 2 || string(got[0]) != "R2" || string(got[1]) != "M3" {
		t.Errorf("хост получил %q", got)
	}
	if f, _ := lock(r.a); f != 0 {
		t.Errorf("неудач у хоста %d", f)
	}
	r.a.mu.Lock()
	busy := r.a.sess != nil
	r.a.mu.Unlock()
	if busy {
		t.Error("сверка заняла место сессии")
	}

	host.mu.Lock()
	host.gate = false
	host.mu.Unlock()
	if _, err := SpaceSync(context.Background(), d); !errors.Is(err, ErrSpaceRefused) {
		t.Errorf("не член: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	d.HostPub = other
	if _, err := SpaceSync(context.Background(), d); !errors.Is(err, ErrSpaceIDKey) {
		t.Errorf("чужой ключ под ID: %v", err)
	}
	old := spaceHost(t, url, "223456789") // SpaceSync == nil — как старая версия
	d.ID, d.HostPub = "223456789", old.a.Key.Public().(ed25519.PublicKey)
	if _, err := SpaceSync(context.Background(), d); !errors.Is(err, ErrSpaceOld) {
		t.Errorf("старый хост: %v", err)
	}
	if f, _ := lock(old.a); f != 0 {
		t.Errorf("неудач у старого хоста %d", f)
	}
}
