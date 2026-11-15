package agent

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// Регрессионные тесты приёмки Ч10.1 (Fable high, круг 1): B1–B4, M1–M3, M5.

func accPinned(t *testing.T, r *recvRig) ed25519.PrivateKey {
	_, fkey, _ := ed25519.GenerateKey(nil)
	pub := fkey.Public().(ed25519.PublicKey)
	r.mu.Lock()
	r.pins[string(pub)], r.pinID[string(pub)] = "Друг", "555666777"
	r.mu.Unlock()
	return fkey
}

// «Только показ экрана»: ни файлы, ни буфер не должны доходить (REQ-F-25)
func TestAccViewOnly(t *testing.T) {
	defer rxRateFor.Store(rxRateFor.Load())
	rxRateFor.Store(100)
	url := local(t)
	r := recvHost(t, url, func(r *recvRig) { r.a.ViewOnly = func() bool { return true } })
	f := srcFile(t, "a.txt", []byte("x"))
	err := sendT(t, r.own(url, []string{f}, "clip"))
	t.Logf("свой ПК → «Только показ экрана»: err=%v файлы=%v буфер=%q", err, r.files(t), r.clip())
	fkey := accPinned(t, r)
	err2 := sendT(t, foreign(url, fkey, "", []string{f}, "clip2"))
	t.Logf("чужой закреплённый → «Только показ экрана»: err=%v файлы=%v буфер=%q окон=%d", err2, r.files(t), r.clip(), r.askN())
	if len(r.files(t)) != 0 || len(r.clip()) != 0 || r.askN() != 0 {
		t.Fatal("приём прошёл на хосте «Только показ экрана»")
	}
	if err := sendT(t, r.own(url, nil, "")); !errors.Is(err, ErrRecvViewOnly) { // отказ в "rx", а не на первом файле
		t.Fatalf("свой ПК без файлов: %v", err)
	}
	_, nkey, _ := ed25519.GenerateKey(nil)
	err3 := sendT(t, foreign(url, nkey, "secret123", []string{f}, "")) // разовым кодом: отказ до кода — код не израсходован
	if !errors.Is(err, ErrRecvViewOnly) || !errors.Is(err2, ErrRecvViewOnly) || !errors.Is(err3, ErrRecvViewOnly) || r.used.Load() != 0 || r.pinned(nkey.Public().(ed25519.PublicKey)) {
		t.Fatalf("отказ не «Только показ экрана» в начале: %v / %v / %v, код %d", err, err2, err3, r.used.Load())
	}
}

// окно «Принять?» закреплённого: ID — закреплённый, а не заявленный в этом соединении
func TestAccPinnedID(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	fkey := accPinned(t, r)
	d := foreign(url, fkey, "", []string{srcFile(t, "a.txt", []byte("x"))}, "")
	d.From, d.Name = "111222333", "Мама"
	if err := sendT(t, d); err != nil {
		t.Fatal(err)
	}
	if q := r.ask(0); strings.Contains(q.From, "111222333") || strings.Contains(q.From, "Мама") || !strings.Contains(q.From, "Друг (ID 555666777") {
		t.Fatalf("в окне не закреплённые ID/имя: %q", q.From)
	}
}

type accCh struct {
	dc  *webrtc.DataChannel
	res chan fileMsg
}

func accFile(pc *webrtc.PeerConnection, name string, size int64) (*accCh, error) {
	dc, err := pc.CreateDataChannel("file", nil)
	if err != nil {
		return nil, err
	}
	c := &accCh{dc: dc, res: make(chan fileMsg, 8)}
	open := make(chan struct{})
	dc.OnOpen(func() { close(open) })
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		var fm fileMsg
		if json.Unmarshal(m.Data, &fm) == nil {
			c.res <- fm
		}
	})
	select {
	case <-open:
	case <-time.After(10 * time.Second):
		return nil, errors.New("канал не открылся")
	}
	sendJSON(dc, fileMsg{T: "meta", Name: name, Size: size})
	return c, nil
}

func (c *accCh) wait(d time.Duration) string {
	select {
	case fm := <-c.res:
		return fm.T + ":" + fm.Code
	case <-time.After(d):
		return ""
	}
}

// исключён из M во время приёма: файл, ждавший очереди, после исключения открываться не должен
func TestAccGoneQueued(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	n := &r.flip
	var late []string
	recvTestPC = func(pc *webrtc.PeerConnection) error {
		var chs []*accCh
		for i := range 6 {
			c, err := accFile(pc, fmt.Sprintf("f%d.txt", i), 2)
			if err != nil {
				return err
			}
			chs = append(chs, c)
		}
		var open, wait []*accCh
		for _, c := range chs {
			if got := c.wait(1500 * time.Millisecond); got == "resume:" {
				open = append(open, c)
			} else if got == "" {
				wait = append(wait, c)
			} else {
				return errors.New("meta: " + got)
			}
		}
		if len(open) != 4 || len(wait) != 2 {
			return fmt.Errorf("открыто %d, ждёт %d", len(open), len(wait))
		}
		n.Store(0) // исключён
		for _, c := range open {
			c.dc.Send([]byte("ok"))
			sendJSON(c.dc, fileMsg{T: "end"})
			c.wait(3 * time.Second)
		}
		for _, c := range wait {
			got := c.wait(3 * time.Second)
			late = append(late, got)
			if got == "resume:" {
				c.dc.Send([]byte("ok"))
				sendJSON(c.dc, fileMsg{T: "end"})
				late = append(late, c.wait(3*time.Second))
			}
		}
		return nil
	}
	defer func() { recvTestPC = nil }()
	if err := sendT(t, r.own(url, nil, "")); err != nil {
		t.Fatal(err)
	}
	t.Logf("ждавшие очереди после исключения: %v; в загрузках %v", late, r.files(t))
	for _, l := range late {
		if l == "resume:" || l == "done:" {
			t.Fatalf("файл открыт/принят после исключения ключа: %v", late)
		}
	}
}

// «Отклонить» — одно окно на сессию, второе (ждавший файл) не выскакивает
func TestAccDeclineOnce(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	fkey := accPinned(t, r)
	r.mu.Lock()
	r.answer = func(RecvReq) bool { time.Sleep(100 * time.Millisecond); return false }
	r.mu.Unlock()
	recvTestPC = func(pc *webrtc.PeerConnection) error {
		for i := range 3 {
			if _, err := accFile(pc, fmt.Sprintf("f%d.txt", i), 2); err != nil {
				return err
			}
		}
		time.Sleep(3 * time.Second)
		return nil
	}
	defer func() { recvTestPC = nil }()
	sendT(t, foreign(url, fkey, "", nil, ""))
	if n := r.askN(); n != 1 {
		t.Fatalf("окон «Принять?» после «Отклонить»: %d", n)
	}
}

// до сверки (решение 12 A, LoginShut) приём от «члена» из несверенного M
func TestAccLoginShut(t *testing.T) {
	url := local(t)
	r := recvHost(t, url, func(r *recvRig) { r.a.LoginShut = func(string) bool { return true } })
	err := sendT(t, r.own(url, []string{srcFile(t, "a.txt", []byte("x"))}, ""))
	t.Logf("err=%v файлы=%v", err, r.files(t))
	if len(r.files(t)) != 0 {
		t.Fatal("приём от члена несверенного состава (SpaceWait)")
	}
}

// текст ошибки хоста чужому отправителю — без путей хоста
func TestAccErrLeak(t *testing.T) {
	url := local(t)
	bad := filepath.Join(srcFile(t, "notdir", []byte("x")), "sub")
	r := recvHost(t, url, func(r *recvRig) { r.a.FileDir = bad })
	fkey := accPinned(t, r)
	err := sendT(t, foreign(url, fkey, "", []string{srcFile(t, "a.txt", []byte("x"))}, ""))
	t.Logf("err=%v", err)
	var re *RecvError
	if !errors.As(err, &re) || re.Code != "io" || strings.Contains(err.Error(), filepath.Dir(bad)) {
		t.Fatal("путь хоста ушёл чужому отправителю")
	}
}

// сессия без единого завершённого приёма не должна жить дольше rxIdle по капле (место из rxMaxSess, без окна)
func TestAccTrickle(t *testing.T) {
	defer rxIdle.Store(rxIdle.Load())
	rxIdle.Store(int64(800 * time.Millisecond))
	url := local(t)
	r := recvHost(t, url)
	fkey := accPinned(t, r)
	var alive atomic.Bool
	recvTestPC = func(pc *webrtc.PeerConnection) error {
		dc, err := pc.CreateDataChannel("text", nil)
		if err != nil {
			return err
		}
		open := make(chan struct{})
		dc.OnOpen(func() { close(open) })
		<-open
		sendJSON(dc, fileMsg{T: "text", Size: 100000})
		for range 20 {
			dc.Send([]byte("x"))
			time.Sleep(200 * time.Millisecond)
		}
		r.a.mu.Lock()
		alive.Store(len(r.a.recvs) == 1)
		r.a.mu.Unlock()
		return nil
	}
	defer func() { recvTestPC = nil }()
	sendT(t, foreign(url, fkey, "", nil, ""))
	if alive.Load() {
		t.Fatal("сессия приёма держится по капле без окна и без предела времени")
	}
}

// исключение рвёт идущую сессию приёма (DropRevoked — опрос настроек)
func TestAccGonePrune(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	n := &r.flip
	got := ""
	recvTestPC = func(pc *webrtc.PeerConnection) error {
		c, err := accFile(pc, "big.bin", 1000)
		if err != nil {
			return err
		}
		if s := c.wait(3 * time.Second); s != "resume:" {
			return errors.New(s)
		}
		c.dc.Send([]byte("часть"))
		n.Store(0)
		r.a.DropRevoked()
		time.Sleep(time.Second)
		r.a.mu.Lock()
		got = fmt.Sprint(len(r.a.recvs))
		r.a.mu.Unlock()
		return nil
	}
	defer func() { recvTestPC = nil }()
	sendT(t, r.own(url, nil, ""))
	if got != "0" {
		t.Fatalf("сессия приёма исключённого ключа жива после DropRevoked: %s", got)
	}
}

// память: 1000 каналов "text" по заявленному 1 МБ — без единого окна
func TestAccTextMem(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	fkey := accPinned(t, r)
	var before, after runtime.MemStats
	recvTestPC = func(pc *webrtc.PeerConnection) error {
		runtime.GC()
		runtime.ReadMemStats(&before)
		for i := range 300 {
			dc, err := pc.CreateDataChannel("text", nil)
			if err != nil {
				return err
			}
			open := make(chan struct{})
			dc.OnOpen(func() { close(open) })
			select {
			case <-open:
			case <-time.After(10 * time.Second):
				return fmt.Errorf("канал %d не открылся", i)
			}
			sendJSON(dc, fileMsg{T: "text", Size: 1 << 20})
			dc.Send([]byte("x"))
		}
		time.Sleep(2 * time.Second)
		runtime.GC()
		runtime.ReadMemStats(&after)
		return nil
	}
	defer func() { recvTestPC = nil }()
	sendT(t, foreign(url, fkey, "", nil, ""))
	mb := (int64(after.HeapAlloc) - int64(before.HeapAlloc)) >> 20
	t.Logf("300 текстов по 1 байту: куча +%d МБ, окон %d", mb, r.askN())
	if mb > 100 {
		t.Fatalf("память под заявленный размер без данных: +%d МБ", mb)
	}
}
