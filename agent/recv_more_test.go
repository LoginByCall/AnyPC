package agent

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// Ч10.1, круг 2 приёмки (M10): места, простой, срок жизни, частота чужого, текст, «Отклонить», имя в окне, части.

// addMember — ещё один ключ члена M получателя.
func (r *recvRig) addMember() ed25519.PrivateKey {
	_, k, _ := ed25519.GenerateKey(nil)
	r.sync.mu.Lock()
	r.sync.members = append(r.sync.members, k.Public().(ed25519.PublicKey))
	r.sync.mu.Unlock()
	return k
}

// recvCount — сессий приёма на хосте.
func (r *recvRig) recvCount() int { r.a.mu.Lock(); defer r.a.mu.Unlock(); return len(r.a.recvs) }

// hold — recvTestPC держит n сессий, пока не закроют release; лишняя сессия (мутант: места не считаются) — ошибка
// errExtra сразу, без паники и без ожидания.
var errExtra = errors.New("лишняя сессия приёма")

func hold(t *testing.T, n int) (started *sync.WaitGroup, release chan struct{}) {
	started, release = &sync.WaitGroup{}, make(chan struct{})
	started.Add(n)
	var c atomic.Int32
	recvTestPC = func(*webrtc.PeerConnection) error {
		if c.Add(1) > int32(n) {
			return errExtra
		}
		started.Done()
		<-release
		return nil
	}
	t.Cleanup(func() { recvTestPC = nil })
	return started, release
}

// TestRecvSlots — не больше rxMaxSess сессий приёма сразу (пятая — "busy"); чужой ключ — не больше одной сессии
// сразу; чужой — не больше 3 сессий в минуту.
func TestRecvSlots(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	started, release := hold(t, rxMaxSess)
	errs := make(chan error, rxMaxSess)
	for range rxMaxSess {
		d := r.own(url, nil, "")
		d.Key = r.addMember() // у каждого члена своё место сверки до "b"
		go func() { errs <- sendT(t, d) }()
	}
	started.Wait()
	d := r.own(url, nil, "")
	d.Key = r.addMember()
	if err := sendT(t, d); !errors.Is(err, ErrRecvBusy) {
		t.Fatalf("пятая сессия: %v", err)
	}
	close(release)
	for range rxMaxSess {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	// чужой: одна сессия сразу
	fkey := accPinned(t, r)
	started, release = hold(t, 1)
	first := make(chan error, 1)
	go func() { first <- sendT(t, foreign(url, fkey, "", nil, "")) }()
	started.Wait()
	if err := sendT(t, foreign(url, fkey, "", nil, "")); !errors.Is(err, ErrRecvBusy) {
		t.Fatalf("вторая сессия чужого ключа: %v", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	recvTestPC = nil
	for i := range 2 { // ещё две — всего три за минуту
		if err := sendT(t, foreign(url, fkey, "", nil, "")); err != nil {
			t.Fatalf("сессия %d: %v", i+2, err)
		}
	}
	if err := sendT(t, foreign(url, fkey, "", nil, "")); !errors.Is(err, ErrRecvRate) {
		t.Fatalf("четвёртая за минуту: %v", err)
	}
	_, ckey, _ := ed25519.GenerateKey(nil) // и разовым кодом (в тесте код не меняется)
	for i := range 3 {
		if err := sendT(t, foreign(url, ckey, "secret123", nil, "")); err != nil {
			t.Fatalf("с кодом %d: %v", i+1, err)
		}
	}
	if err := sendT(t, foreign(url, ckey, "secret123", nil, "")); !errors.Is(err, ErrRecvRate) {
		t.Fatalf("с кодом, четвёртая за минуту: %v", err)
	}
}

// TestRecvIdleLife — без сообщений rxIdle — сессия закрыта; байты по капле (медленнее rxMinRate за окно) — закрыта;
// дольше rxLife без продвижения байт (сообщения есть, байтов нет) — закрыта.
func TestRecvIdleLife(t *testing.T) {
	defer func(i, l, w int64) { rxIdle.Store(i); rxLife.Store(l); rxSlowWin.Store(w) }(rxIdle.Load(), rxLife.Load(), rxSlowWin.Load())
	rxIdle.Store(int64(600 * time.Millisecond))
	url := local(t)
	r := recvHost(t, url)
	var idle, life atomic.Int32
	recvTestPC = func(*webrtc.PeerConnection) error {
		time.Sleep(1500 * time.Millisecond)
		idle.Store(int32(r.recvCount()))
		return nil
	}
	defer func() { recvTestPC = nil }()
	sendT(t, r.own(url, nil, ""))
	if idle.Load() != 0 {
		t.Fatal("сессия без сообщений жива дольше rxIdle")
	}
	rxIdle.Store(int64(time.Minute))
	rxSlowWin.Store(int64(time.Second))
	recvTestPC = func(pc *webrtc.PeerConnection) error {
		c, err := accFile(pc, "big.bin", 1<<20)
		if err != nil {
			return err
		}
		if s := c.wait(3 * time.Second); s != "resume:" {
			return errors.New(s)
		}
		for range 15 { // капля каждые 200 мс — простоя нет
			c.dc.Send([]byte("x"))
			time.Sleep(200 * time.Millisecond)
		}
		life.Store(int32(r.recvCount()))
		return nil
	}
	sendT(t, r.own(url, nil, ""))
	if life.Load() != 0 {
		t.Fatal("сессия по капле байт жива")
	}
	rxSlowWin.Store(int64(time.Hour))
	rxLife.Store(int64(time.Second))
	life.Store(-1)
	recvTestPC = func(pc *webrtc.PeerConnection) error {
		for range 12 { // сообщения без байт: отказы по размеру — простоя нет, продвижения нет
			c, err := accFile(pc, "x", -1)
			if err != nil {
				break
			}
			c.wait(time.Second)
			time.Sleep(150 * time.Millisecond)
		}
		life.Store(int32(r.recvCount()))
		return nil
	}
	sendT(t, r.own(url, nil, ""))
	if life.Load() != 0 {
		t.Fatal("сессия без продвижения байт жива дольше rxLife")
	}
}

// rawText — канал "text": заявлено size, отправлено body; ответ хоста ("done:" или "err:код").
func rawText(pc *webrtc.PeerConnection, size int64, body []byte, end bool) (string, error) {
	dc, err := pc.CreateDataChannel("text", nil)
	if err != nil {
		return "", err
	}
	c := &accCh{dc: dc, res: make(chan fileMsg, 8)}
	open := make(chan struct{})
	dc.OnOpen(func() { close(open) })
	dc.OnMessage(func(m webrtc.DataChannelMessage) { c.res <- parseFM(m.Data) })
	select {
	case <-open:
	case <-time.After(10 * time.Second):
		return "", errors.New("канал не открылся")
	}
	sendJSON(dc, fileMsg{T: "text", Size: size})
	dc.Send(body)
	if end {
		sendJSON(dc, fileMsg{T: "end"})
	}
	return c.wait(3 * time.Second), nil
}

// TestRecvTextBad — текст больше заявленного и не UTF-8 — "text"; управляющие и форматные символы в буфер не идут.
func TestRecvTextBad(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	var got []string
	recvTestPC = func(pc *webrtc.PeerConnection) error {
		for _, c := range []struct {
			size int64
			body string
		}{{3, "12345"}, {2, "\xff\xfe"}, {int64(len("ls\x1b[2J\u202Erm\r\n\t")), "ls\x1b[2J\u202Erm\r\n\t"}} {
			s, err := rawText(pc, c.size, []byte(c.body), true)
			if err != nil {
				return err
			}
			got = append(got, s)
		}
		// больше заявленного — отказ сразу, не дожидаясь "end" (память — не больше заявленного)
		s, err := rawText(pc, 3, []byte("12345"), false)
		if err != nil {
			return err
		}
		got = append(got, s)
		// один текст за раз: второй канал, пока первый не кончен, — "count"
		c1, err := pc.CreateDataChannel("text", nil)
		if err != nil {
			return err
		}
		open := make(chan struct{})
		c1.OnOpen(func() { close(open) })
		<-open
		sendJSON(c1, fileMsg{T: "text", Size: 5})
		c1.Send([]byte("12"))
		time.Sleep(300 * time.Millisecond)
		s, err = rawText(pc, 2, []byte("ab"), true)
		got = append(got, s)
		return err
	}
	defer func() { recvTestPC = nil }()
	if err := sendT(t, r.own(url, nil, "")); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != "err:text err:text done: err:text err:count" {
		t.Fatalf("ответы: %v", got)
	}
	if c := r.clip(); len(c) != 1 || c[0] != "ls[2Jrm\r\n\t" {
		t.Fatalf("буфер: %q", c)
	}
}

// TestRecvDeclineCloses — «Отклонить» закрывает сессию; имя в окне — после safeName; size < 0 — "size".
func TestRecvDeclineCloses(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	fkey := accPinned(t, r)
	var after atomic.Int32
	var neg, deny string
	recvTestPC = func(pc *webrtc.PeerConnection) error {
		c, err := accFile(pc, "x", -1)
		if err != nil {
			return err
		}
		neg = c.wait(3 * time.Second)
		r.mu.Lock()
		r.answer = func(RecvReq) bool { return false }
		r.mu.Unlock()
		if c, err = accFile(pc, "../../evil\u202Etxt.exe", 2); err != nil {
			return err
		}
		deny = c.wait(3 * time.Second)
		time.Sleep(1500 * time.Millisecond)
		after.Store(int32(r.recvCount()))
		return nil
	}
	defer func() { recvTestPC = nil }()
	sendT(t, foreign(url, fkey, "", nil, ""))
	if neg != "err:size" || deny != "err:denied" || after.Load() != 0 {
		t.Fatalf("size<0: %q, отказ: %q, сессий после «Отклонить»: %d", neg, deny, after.Load())
	}
	if q := r.ask(0); q.Name != "evil_txt.exe" {
		t.Fatalf("имя в окне: %q", q.Name)
	}
}

// TestRecvUnpinDrops — откреплённый ключ: идущая сессия рвётся (DropRevoked), часть от чужого не остаётся.
func TestRecvUnpinDrops(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	fkey := accPinned(t, r)
	var alive atomic.Int32
	recvTestPC = func(pc *webrtc.PeerConnection) error {
		c, err := accFile(pc, "big.bin", 1000)
		if err != nil {
			return err
		}
		if s := c.wait(3 * time.Second); s != "resume:" {
			return errors.New(s)
		}
		c.dc.Send([]byte("часть"))
		time.Sleep(300 * time.Millisecond)
		r.unpin(fkey.Public().(ed25519.PublicKey))
		r.a.DropRevoked()
		time.Sleep(time.Second)
		alive.Store(int32(r.recvCount()))
		return nil
	}
	defer func() { recvTestPC = nil }()
	sendT(t, foreign(url, fkey, "", nil, ""))
	if alive.Load() != 0 {
		t.Fatal("сессия откреплённого ключа жива")
	}
	l, _ := os.ReadDir(r.dir)
	if len(l) != 0 {
		t.Fatalf("в загрузках осталось: %v", l)
	}
}

// TestRecvParts — общий потолок открытых частей приёма ("disk"); чужому без кода нужен ключ получателя (M7).
func TestRecvParts(t *testing.T) {
	defer rxPartMax.Store(rxPartMax.Load())
	rxPartMax.Store(10)
	url := local(t)
	r := recvHost(t, url)
	err := sendT(t, r.own(url, []string{srcFile(t, "a.bin", make([]byte, 11))}, ""))
	var re *RecvError
	if !errors.As(err, &re) || re.Code != "disk" {
		t.Fatalf("потолок частей: %v", err)
	}
	_, fkey, _ := ed25519.GenerateKey(nil)
	d := foreign(url, fkey, "", nil, "x")
	d.Known = ""
	if err := sendT(t, d); !errors.Is(err, ErrRecvKnown) {
		t.Fatalf("без Known: %v", err)
	}
}

func parseFM(b []byte) fileMsg { var fm fileMsg; json.Unmarshal(b, &fm); return fm }

// TestRecvViewOnlyMid — «Только показ экрана» включили посреди сессии приёма: следующий файл — отказ, а
// ViewOnlyChanged (галочка в окне, Windows без опроса настроек) рвёт сессию сразу.
func TestRecvViewOnlyMid(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	var next string
	var alive atomic.Int32
	recvTestPC = func(pc *webrtc.PeerConnection) error {
		if err := rawFile(pc, "a.txt", []byte("ok")); err != nil {
			return err
		}
		r.view.Store(true)
		c, err := accFile(pc, "b.txt", 2)
		if err != nil {
			return err
		}
		next = c.wait(3 * time.Second)
		r.a.ViewOnlyChanged(true)
		time.Sleep(time.Second)
		alive.Store(int32(r.recvCount()))
		return nil
	}
	defer func() { recvTestPC = nil }()
	sendT(t, r.own(url, nil, ""))
	if next != "err:viewonly" || alive.Load() != 0 || len(r.files(t)) != 1 {
		t.Fatalf("после «Только показ экрана»: %q, сессий %d, файлов %v", next, alive.Load(), r.files(t))
	}
}

// TestRecvPartsFree — место частей возвращается после файла: два файла подряд в потолке на один проходят.
func TestRecvPartsFree(t *testing.T) {
	defer rxPartMax.Store(rxPartMax.Load())
	rxPartMax.Store(15)
	url := local(t)
	r := recvHost(t, url)
	f1, f2 := srcFile(t, "a.bin", make([]byte, 10)), srcFile(t, "b.bin", make([]byte, 10))
	if err := sendT(t, r.own(url, []string{f1, f2}, "")); err != nil {
		t.Fatal(err)
	}
	r.a.mu.Lock()
	defer r.a.mu.Unlock()
	if r.a.rxParts != 0 || len(r.files(t)) != 2 {
		t.Fatalf("занято частей %d, файлов %v", r.a.rxParts, r.files(t))
	}
}
