package agent

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// Регрессионные тесты приёмки Ч10.1, круг 2 (N1, N2, N3, N4).

// круг 2: опрос настроек (DropRevoked раз в 2 с) попал между rxStart и RecvPin — приём верным кодом не должен рваться
func TestAccR2PinRace(t *testing.T) {
	url := local(t)
	r := recvHost(t, url, func(r *recvRig) {
		pin := r.a.RecvPin
		r.a.RecvPin = func(pub []byte, id, name string) {
			r.a.DropRevoked() // опрос pollConfig в этот миг
			pin(pub, id, name)
		}
	})
	_, fkey, _ := ed25519.GenerateKey(nil)
	err := sendT(t, foreign(url, fkey, "secret123", []string{srcFile(t, "a.txt", []byte("x"))}, ""))
	t.Logf("err=%v файлы=%v код израсходован=%d закреплён=%v", err, r.files(t), r.used.Load(), r.pinned(fkey.Public().(ed25519.PublicKey)))
	if err != nil || len(r.files(t)) != 1 {
		t.Fatal("верный код: сессию закрыл опрос настроек до закрепления")
	}
}

// круг 2: срок жизни рвёт файл, который идёт (байты текут)
func TestAccR2LifeCuts(t *testing.T) {
	defer rxLife.Store(rxLife.Load())
	rxLife.Store(int64(1200 * time.Millisecond))
	url := local(t)
	r := recvHost(t, url)
	var got atomic.Value
	got.Store("")
	recvTestPC = func(pc *webrtc.PeerConnection) error {
		c, err := accFile(pc, "big.bin", 100000)
		if err != nil {
			return err
		}
		if s := c.wait(3 * time.Second); s != "resume:" {
			got.Store(s)
			return nil
		}
		for range 15 {
			c.dc.Send(make([]byte, 1000))
			time.Sleep(200 * time.Millisecond)
		}
		r.a.mu.Lock()
		if len(r.a.recvs) == 0 {
			got.Store("сессия закрыта при идущем файле")
		}
		r.a.mu.Unlock()
		return nil
	}
	defer func() { recvTestPC = nil }()
	sendT(t, r.own(url, nil, ""))
	if s := got.Load().(string); s != "" {
		t.Fatal(s)
	}
}

// круг 2: текст в буфер — ZWJ/ZWNJ (эмодзи, персидский) должны уцелеть
func TestAccR2ClipZW(t *testing.T) {
	for _, s := range []string{"\U0001F468‍\U0001F469‍\U0001F467", "می‌خواهم", "co­op"} {
		if got := rxClipText(s); got != s {
			t.Errorf("%q → %q", s, got)
		}
	}
}

// круг 2: чужой с тем же id докачки видит и удаляет чужую часть
func TestAccR2ForeignPart(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	fkey := accPinned(t, r)
	part := filepath.Join(r.dir, ".anypc-aaaaaaaaaaaaaaaa.part")
	os.WriteFile(part, []byte("hello"), 0o644) // часть своего ПК, прерванная
	var leak atomic.Bool
	recvTestPC = func(pc *webrtc.PeerConnection) error {
		dc, err := pc.CreateDataChannel("file", nil)
		if err != nil {
			return err
		}
		c := &accCh{dc: dc, res: make(chan fileMsg, 8)}
		open := make(chan struct{})
		dc.OnOpen(func() { close(open) })
		dc.OnMessage(func(m webrtc.DataChannelMessage) {
			var fm fileMsg
			if json.Unmarshal(m.Data, &fm) == nil {
				if fm.T == "resume" && fm.Offset > 0 {
					leak.Store(true) // смещение чужой части отдано
				}
				c.res <- fm
			}
		})
		<-open
		sendJSON(dc, fileMsg{T: "meta", Name: "x.txt", Size: 10, ID: "aaaaaaaaaaaaaaaa"})
		c.wait(3 * time.Second)
		dc.Close()
		time.Sleep(time.Second)
		return nil
	}
	defer func() { recvTestPC = nil }()
	d := foreign(url, fkey, "", nil, "")
	d.Known = recvHostFP.Load().(string)
	sendT(t, d)
	_, err := os.Stat(part)
	if leak.Load() || err != nil {
		t.Fatal("чужой отправитель добрался до части другого отправителя")
	}
}
