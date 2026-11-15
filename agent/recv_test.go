package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anypc/pake"

	"github.com/pion/webrtc/v4"
)

// recvRig — получатель Ч10.1: P из spaceRig (запись по умолчанию secret123 — в тестах это «разовый код»), каталог
// загрузок, закреплённые ключи, окно «Принять?» и буфер обмена — подмены.
type recvRig struct {
	*spaceRig
	dir    string
	member ed25519.PrivateKey // ключ члена M
	sync   *fakeSync
	mu     sync.Mutex
	pins   map[string]string // ключ → имя
	pinID  map[string]string // ключ → ID
	asks   []RecvReq
	answer func(RecvReq) bool
	clips  []string
	used   atomic.Int32 // CodeUsed
	flip   atomic.Int32 // SyncKey годен ещё столько раз (keyFlip)
	codeOn atomic.Bool  // CodeMode
	view   atomic.Bool  // ViewOnly («Только показ экрана»)
}

// recvHostFP — отпечаток ключа последнего получателя recvHost: SendDial.Known чужого без кода (M7).
var recvHostFP atomic.Value

// ask — i-е окно «Принять?».
func (r *recvRig) ask(i int) RecvReq {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i >= len(r.asks) { // окна не было — пустой запрос (тест упадёт на сравнении, а не паникой)
		return RecvReq{}
	}
	return r.asks[i]
}

func (r *recvRig) askN() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.asks) }
func (r *recvRig) clip() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.clips...)
}
func (r *recvRig) pinned(pub ed25519.PublicKey) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.pins[string(pub)]
	return ok
}
func (r *recvRig) unpin(pub ed25519.PublicKey) {
	r.mu.Lock()
	delete(r.pins, string(pub))
	r.mu.Unlock()
}

// files — имена в каталоге загрузок (без частей докачки).
func (r *recvRig) files(t *testing.T) []string {
	t.Helper()
	l, _ := os.ReadDir(r.dir)
	var out []string
	for _, e := range l {
		if !strings.HasPrefix(e.Name(), ".anypc-") {
			out = append(out, e.Name())
		}
	}
	return out
}

func recvHost(t *testing.T, url string, opt ...func(*recvRig)) *recvRig {
	_, member, _ := ed25519.GenerateKey(nil)
	r := &recvRig{dir: t.TempDir(), member: member, pins: map[string]string{}, pinID: map[string]string{},
		answer: func(RecvReq) bool { return true }}
	r.sync = &fakeSync{m: []byte("M1"), gate: true, members: []ed25519.PublicKey{member.Public().(ed25519.PublicKey)}}
	r.flip.Store(1 << 30)
	r.codeOn.Store(true)
	setClip = func(s string) error { r.mu.Lock(); r.clips = append(r.clips, s); r.mu.Unlock(); return nil }
	t.Cleanup(func() { setClip = SetClipText })
	r.spaceRig = spaceHost(t, url, "123456789", func(p *spaceRig) {
		a := p.a
		a.FileDir = r.dir
		a.SpaceSync = &keyFlip{fakeSync: r.sync, left: &r.flip}
		a.CodeMode = r.codeOn.Load
		a.ViewOnly = r.view.Load
		a.CodeUsed = func() { r.used.Add(1) }
		a.RecvPinned = func(pub []byte) (string, string, bool) {
			r.mu.Lock()
			defer r.mu.Unlock()
			n, ok := r.pins[string(pub)]
			return r.pinID[string(pub)], n, ok
		}
		a.RecvPin = func(pub []byte, id, name string) {
			r.mu.Lock()
			r.pins[string(pub)], r.pinID[string(pub)] = name, id
			r.mu.Unlock()
		}
		a.RecvAsk = func(q RecvReq) bool {
			r.mu.Lock()
			r.asks = append(r.asks, q)
			f := r.answer
			r.mu.Unlock()
			return f(q)
		}
		r.spaceRig = p
		for _, f := range opt {
			f(r)
		}
	})
	recvHostFP.Store(pake.KeyFingerprint(r.a.Key.Public().(ed25519.PublicKey)))
	return r
}

// own / foreign — SendDial своего ПК (ключ члена) и чужого (key; code — разовый код).
func (r *recvRig) own(url string, files []string, text string) SendDial {
	return SendDial{Server: url, ID: "123456789", HostPub: r.a.Key.Public().(ed25519.PublicKey), Key: r.member,
		From: "987654321", Name: "Ноутбук", Files: files, Text: text}
}

func foreign(url string, key ed25519.PrivateKey, code string, files []string, text string) SendDial {
	d := SendDial{Server: url, ID: "123456789", Key: key, Code: code, From: "555666777", Name: "Чужой ПК",
		Files: files, Text: text}
	if code == "" {
		d.Known, _ = recvHostFP.Load().(string)
	}
	return d
}

func sendT(t *testing.T, d SendDial) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := SendTo(ctx, d)
	return err
}

// srcFile — файл отправителя name с содержимым body.
func srcFile(t *testing.T, name string, body []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// waitLog — ждать строку want в журнале.
func waitLog(t *testing.T, logs *syncBuf, want string) string {
	t.Helper()
	for range 50 {
		if s := logs.String(); strings.Contains(s, want) {
			return s
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("в журнале нет %q:\n%s", want, logs.String())
	return ""
}

// TestRecvOwn — свой ПК (ключ члена M): файлы и текст приняты сразу, без кода и без окна; в журнале одна строка
// без имён файлов и текста; вход не выполнен, места сессии нет, неудач нет.
func TestRecvOwn(t *testing.T) {
	var logs syncBuf
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	url := local(t)
	r := recvHost(t, url)
	f1 := srcFile(t, "отчёт-секрет.txt", []byte("содержимое-1"))
	f2 := srcFile(t, "b.bin", bytes.Repeat([]byte{7}, 100_000))
	if err := sendT(t, r.own(url, []string{f1, f2}, "текст-секрет")); err != nil {
		t.Fatal(err)
	}
	if got := r.files(t); len(got) != 2 {
		t.Fatalf("в загрузках %v", got)
	}
	if b, _ := os.ReadFile(filepath.Join(r.dir, "отчёт-секрет.txt")); string(b) != "содержимое-1" {
		t.Fatalf("файл: %q", b)
	}
	if c := r.clip(); len(c) != 1 || c[0] != "текст-секрет" {
		t.Fatalf("буфер: %q", c)
	}
	if r.askN() != 0 || r.used.Load() != 0 {
		t.Fatalf("окно «Принять?» %d, код израсходован %d", r.askN(), r.used.Load())
	}
	me := "приём от " + rxLabel("987654321", "Ноутбук", r.member.Public().(ed25519.PublicKey)) // строки прошлых тестов — мимо
	s := waitLog(t, &logs, me)
	if strings.Count(s, me) != 1 || !strings.Contains(s, me+" (свой ПК): файлов 2, 100022 байт, текстов 1") {
		t.Fatalf("журнал:\n%s", s)
	}
	if strings.Contains(s, "секрет") {
		t.Fatalf("содержимое в журнале:\n%s", s)
	}
	r.a.mu.Lock()
	defer r.a.mu.Unlock()
	if r.a.sess != nil || r.a.fails != 0 || len(r.a.recvs) != 0 {
		t.Fatalf("sess %v, неудач %d, приёмов %d", r.a.sess, r.a.fails, len(r.a.recvs))
	}
}

// TestRecvOwnRefused — ключ не из M (исключённый ПК) — отказ до "b"; ключ исключили во время приёма — следующий
// файл отклонён ("gone"); в "b" доказан не тот ключ, что в sx, или подпись не над этим соединением — "denied".
func TestRecvOwnRefused(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	f := srcFile(t, "a.txt", []byte("x"))
	d := r.own(url, []string{f}, "")
	_, other, _ := ed25519.GenerateKey(nil)
	d.Key = other // не член M цели: sx не открылся — "who" — цель не считает этот ПК членом
	if err := sendT(t, d); !errors.Is(err, ErrSpaceRefused) {
		t.Fatalf("ключ не из M: %v", err)
	}
	for _, tamper := range []string{"cpub", "client"} {
		syncTamper.Store(tamper)
		err := sendT(t, r.own(url, []string{f}, ""))
		syncTamper.Store("")
		if !errors.Is(err, ErrRecvDenied) {
			t.Fatalf("%s: %v", tamper, err)
		}
	}
	if len(r.files(t)) != 0 {
		t.Fatalf("принято: %v", r.files(t))
	}
	// исключение во время приёма: SyncKey годен для "b" и первого файла, дальше — нет
	r.flip.Store(3) // "b", окно файла, очередь файла
	f2 := srcFile(t, "b.txt", []byte("y"))
	if err := sendT(t, r.own(url, []string{f, f2}, "")); !errors.Is(err, ErrRecvGone) {
		t.Fatalf("исключён во время приёма: %v", err)
	}
	if got := r.files(t); len(got) != 1 || got[0] != "a.txt" {
		t.Fatalf("принято: %v", got)
	}
}

// keyFlip — SyncKey годен ещё left раз, потом ключ «исключён».
type keyFlip struct {
	*fakeSync
	left *atomic.Int32
}

func (k *keyFlip) SyncKey(pub ed25519.PublicKey) bool {
	return k.left.Add(-1) >= 0 && k.fakeSync.SyncKey(pub)
}

// TestRecvForeignCode — чужой ПК: без кода и без закрепления — отказ (без неудачи); неверный код — отказ, после 5 —
// блокировка (и верный код не проходит); верный — файл и текст приняты (текст — через «Принять?»), код израсходован,
// ключ закреплён с ID и именем.
func TestRecvForeignCode(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	_, fkey, _ := ed25519.GenerateKey(nil)
	f := srcFile(t, "a.txt", []byte("x"))
	if err := sendT(t, foreign(url, fkey, "", []string{f}, "")); !errors.Is(err, ErrRecvNoKey) {
		t.Fatalf("без кода: %v", err)
	}
	r.a.mu.Lock()
	fails := r.a.fails
	r.a.mu.Unlock()
	if fails != 0 || r.askN() != 0 {
		t.Fatalf("незнакомый ключ: неудач %d, окон %d", fails, r.askN())
	}
	r.codeOn.Store(false) // вход паролем: разового кода нет, пароль чужим не годится
	if err := sendT(t, foreign(url, fkey, "secret123", []string{f}, "")); !errors.Is(err, ErrRecvNoCode) {
		t.Fatalf("без режима кода: %v", err)
	}
	r.codeOn.Store(true)
	for i := range 5 {
		if err := sendT(t, foreign(url, fkey, "wrong-code", []string{f}, "")); !errors.Is(err, ErrRecvCode) {
			t.Fatalf("неверный код %d: %v", i+1, err)
		}
	}
	if err := sendT(t, foreign(url, fkey, "secret123", []string{f}, "")); !errors.Is(err, ErrRecvLocked) {
		t.Fatalf("после 5 неверных: %v", err)
	}
	if len(r.files(t)) != 0 || r.pinned(fkey.Public().(ed25519.PublicKey)) {
		t.Fatal("принято или закреплено под блокировкой")
	}
	r.a.mu.Lock()
	delete(r.a.names, "") // блокировка прошла
	r.a.mu.Unlock()
	used := r.used.Load()
	if err := sendT(t, foreign(url, fkey, "secret123", []string{f}, "привет")); err != nil {
		t.Fatal(err)
	}
	if got := r.files(t); len(got) != 1 {
		t.Fatalf("принято: %v", got)
	}
	if c := r.clip(); len(c) != 1 || c[0] != "привет" {
		t.Fatalf("буфер: %q", c)
	}
	if q := r.ask(0); r.askN() != 1 || !q.IsText || q.Text != "привет" || !strings.Contains(q.From, "Чужой ПК") {
		t.Fatalf("окна: %+v", q)
	}
	pub := fkey.Public().(ed25519.PublicKey)
	r.mu.Lock()
	name, id := r.pins[string(pub)], r.pinID[string(pub)]
	r.mu.Unlock()
	if name != "Чужой ПК" || id != "555666777" {
		t.Fatalf("закреплён %q %q", name, id)
	}
	if r.used.Load() <= used {
		t.Fatal("код не израсходован")
	}
}

// TestRecvForeignPinned — закреплённый ключ без кода: «Принять?» один раз на файлы сессии; «Отклонить» и нет
// ответа — отказ, файл не принят; текст «Отклонить» — в буфер не попал; откреплённый — снова нужен код.
func TestRecvForeignPinned(t *testing.T) {
	defer rxRateFor.Store(rxRateFor.Load())
	rxRateFor.Store(100)
	url := local(t)
	r := recvHost(t, url)
	_, fkey, _ := ed25519.GenerateKey(nil)
	pub := fkey.Public().(ed25519.PublicKey)
	r.mu.Lock()
	r.pins[string(pub)], r.pinID[string(pub)] = "Друг", "555666777"
	r.mu.Unlock()
	f1, f2 := srcFile(t, "a.txt", []byte("x")), srcFile(t, "b.txt", []byte("y"))
	if err := sendT(t, foreign(url, fkey, "", []string{f1, f2}, "")); err != nil {
		t.Fatal(err)
	}
	if q := r.ask(0); len(r.files(t)) != 2 || r.askN() != 1 || q.Name != "a.txt" || !strings.Contains(q.From, "Друг (ID 555666777") {
		t.Fatalf("файлы %v, окно %+v", r.files(t), q)
	}
	syncTamper.Store("client") // подпись не над этим соединением: ключ не доказан — закрепление не действует
	err := sendT(t, foreign(url, fkey, "", []string{srcFile(t, "t.txt", []byte("t"))}, ""))
	syncTamper.Store("")
	if !errors.Is(err, ErrRecvDenied) || r.askN() != 1 {
		t.Fatalf("ключ не доказан: %v, окон %d", err, r.askN())
	}
	for _, c := range []struct {
		name string
		ans  func(RecvReq) bool
	}{
		{"отклонить", func(RecvReq) bool { return false }},
		{"нет ответа", func(RecvReq) bool { time.Sleep(time.Second); return false }}, // AskRecv по AskTimeout отвечает «нет»
	} {
		r.mu.Lock()
		r.answer = c.ans
		r.mu.Unlock()
		f := srcFile(t, "c-"+strings.ReplaceAll(c.name, " ", "")+".txt", []byte("z"))
		if err := sendT(t, foreign(url, fkey, "", []string{f}, "")); !errors.Is(err, ErrRecvDenied) {
			t.Fatalf("%s: %v", c.name, err)
		}
		if err := sendT(t, foreign(url, fkey, "", nil, "текст")); !errors.Is(err, ErrRecvDenied) {
			t.Fatalf("%s, текст: %v", c.name, err)
		}
	}
	if len(r.files(t)) != 2 || len(r.clip()) != 0 {
		t.Fatalf("после отказов: файлы %v, буфер %q", r.files(t), r.clip())
	}
	r.unpin(pub)
	if err := sendT(t, foreign(url, fkey, "", []string{f1}, "")); !errors.Is(err, ErrRecvNoKey) {
		t.Fatalf("откреплён: %v", err)
	}
}

// TestRecvLimits — потолки: размер файла, объём и число за сессию, размер текста, частота сессий с одного ключа.
func TestRecvLimits(t *testing.T) {
	defer func(l *rxLimits, n int32) { rxLimP.Store(l); rxRateOwn.Store(n) }(rxLimP.Load(), rxRateOwn.Load())
	rxLimP.Store(&rxLimits{File: 1000, Total: 1500, Items: 2, Text: 10})
	rxRateOwn.Store(100)
	url := local(t)
	r := recvHost(t, url)
	small := srcFile(t, "s.txt", bytes.Repeat([]byte{1}, 800))
	small2 := srcFile(t, "s2.txt", bytes.Repeat([]byte{2}, 800))
	big := srcFile(t, "big.txt", bytes.Repeat([]byte{3}, 1001))
	cases := []struct {
		name  string
		files []string
		text  string
		code  string
	}{
		{"размер файла", []string{big}, "", "size"},
		{"объём за сессию", []string{small, small2}, "", "total"},
		{"число", []string{small}, "", ""},
		{"текст", nil, "больше десяти байт", "text"},
	}
	for _, c := range cases[:2] {
		err := sendT(t, r.own(url, c.files, c.text))
		var re *RecvError
		if !errors.As(err, &re) || re.Code != c.code || !errors.Is(err, ErrRecvLimit) {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
	rxLimP.Store(&rxLimits{File: 1000, Total: 1 << 20, Items: 2, Text: 10})
	err := sendT(t, r.own(url, []string{small, small2, srcFile(t, "s3.txt", []byte("3"))}, ""))
	var re *RecvError
	if !errors.As(err, &re) || re.Code != "count" {
		t.Fatalf("число: %v", err)
	}
	err = sendT(t, r.own(url, nil, cases[3].text))
	if !errors.As(err, &re) || re.Code != "text" {
		t.Fatalf("текст: %v", err)
	}
	if len(r.clip()) != 0 {
		t.Fatalf("буфер: %q", r.clip())
	}
	rxRateOwn.Store(2) // за минуту уже 4 сессии
	if err := sendT(t, r.own(url, []string{small}, "")); !errors.Is(err, ErrRecvRate) {
		t.Fatalf("частота: %v", err)
	}
}

// TestRecvOnlyReceive — в соединении приёма нет ничего, кроме приёма: каналы клиента "input", "video", "clip",
// "ctl" закрываются; буфер и выбор файла по "ctl" хоста не действуют; видео не идёт; сессия не входит. Имена с
// путями, абсолютные и зарезервированные Windows — через safeName, всё — внутри каталога загрузок.
func TestRecvOnlyReceive(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	var ctl atomic.Pointer[webrtc.DataChannel]
	recvTestDC = func(dc *webrtc.DataChannel) {
		if dc.Label() == "ctl" {
			dc.OnOpen(func() { ctl.Store(dc) })
		}
	}
	names := map[string]string{"../../evil.txt": "evil.txt", "/etc/passwd": "passwd", `C:\Windows\x.dll`: "x.dll",
		"CON.txt": "_CON.txt", "a\u202Etxt.exe": "a_txt.exe"}
	var tracks atomic.Int32
	recvTestPC = func(pc *webrtc.PeerConnection) error {
		pc.OnTrack(func(*webrtc.TrackRemote, *webrtc.RTPReceiver) { tracks.Add(1) })
		for _, l := range []string{"input", "video", "clip", "ctl"} {
			dc, err := pc.CreateDataChannel(l, nil)
			if err != nil {
				return err
			}
			closed := make(chan struct{})
			dc.OnClose(func() { close(closed) })
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				return errors.New("канал " + l + " не закрыт хостом")
			}
		}
		if c := ctl.Load(); c != nil {
			c.SendText(`{"t":"clip","text":"evil"}`)
			c.SendText(`{"t":"pick"}`)
		} else {
			return errors.New("ctl хоста не открылся")
		}
		for n := range names {
			if err := rawFile(pc, n, []byte("ok")); err != nil {
				return err
			}
		}
		time.Sleep(time.Second)
		r.a.mu.Lock()
		defer r.a.mu.Unlock()
		for s := range r.a.recvs {
			if s.authed.Load() || s.control() {
				return errors.New("сессия приёма вошла")
			}
		}
		if len(r.a.recvs) != 1 || r.a.sess != nil {
			return errors.New("не та сессия")
		}
		return nil
	}
	defer func() { recvTestDC, recvTestPC = nil, nil }()
	if err := sendT(t, r.own(url, nil, "")); err != nil {
		t.Fatal(err)
	}
	if len(r.clip()) != 0 || tracks.Load() != 0 {
		t.Fatalf("буфер %q, видео %d", r.clip(), tracks.Load())
	}
	got := strings.Join(r.files(t), "|")
	for n, want := range names {
		if b, err := os.ReadFile(filepath.Join(r.dir, want)); err != nil || string(b) != "ok" {
			t.Fatalf("%q → %q: %v (в загрузках %s)", n, want, err, got)
		}
	}
	if len(r.files(t)) != len(names) {
		t.Fatalf("в загрузках %s", got)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(r.dir), "evil.txt")); err == nil {
		t.Fatal("файл вне загрузок")
	}
}

// rawFile — файл по протоколу file.go с именем name как есть.
func rawFile(pc *webrtc.PeerConnection, name string, body []byte) error {
	dc, err := pc.CreateDataChannel("file", nil)
	if err != nil {
		return err
	}
	defer dc.Close()
	res := make(chan fileMsg, 4)
	open := make(chan struct{})
	dc.OnOpen(func() { close(open) })
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		var fm fileMsg
		if json.Unmarshal(m.Data, &fm) == nil {
			res <- fm
		}
	})
	wait := func() (fileMsg, error) {
		select {
		case fm := <-res:
			return fm, nil
		case <-time.After(10 * time.Second):
			return fileMsg{}, errors.New("нет ответа")
		}
	}
	<-open
	sendJSON(dc, fileMsg{T: "meta", Name: name, Size: int64(len(body))})
	if fm, err := wait(); err != nil || fm.T != "resume" {
		return errors.New("meta " + name + ": " + fm.T + " " + fm.Msg)
	}
	dc.Send(body)
	sendJSON(dc, fileMsg{T: "end"})
	if fm, err := wait(); err != nil || fm.T != "done" {
		return errors.New("end " + name + ": " + fm.T + " " + fm.Msg)
	}
	return nil
}

// TestRecvOld — хост старой версии (приём не объявлен): отправитель кончает до "b" понятной ошибкой; на хосте ни
// неудач, ни файлов (старый хост принял бы "b" с кодом за вход).
func TestRecvOld(t *testing.T) {
	url := local(t)
	r := recvHost(t, url, func(r *recvRig) { r.a.noRecv = true })
	f := srcFile(t, "a.txt", []byte("x"))
	_, fkey, _ := ed25519.GenerateKey(nil)
	for _, d := range []SendDial{r.own(url, []string{f}, ""), foreign(url, fkey, "secret123", []string{f}, "")} {
		if err := sendT(t, d); !errors.Is(err, ErrRecvOld) || err.Error() != "На том ПК старая версия AnyPC" {
			t.Fatalf("старый хост: %v", err)
		}
	}
	r.a.mu.Lock()
	defer r.a.mu.Unlock()
	if r.a.fails != 0 || len(r.files(t)) != 0 || r.used.Load() != 0 {
		t.Fatalf("неудач %d, файлов %v, код %d", r.a.fails, r.files(t), r.used.Load())
	}
}

// TestRecvPreview — окно «Принять?»: текст обрезан, управляющие и форматные символы заменены.
func TestRecvPreview(t *testing.T) {
	p, _ := recvPreview("a\u202Eb\x1b[31mc\n" + strings.Repeat("x\n", 20))
	if strings.ContainsAny(p, "\u202E\x1b") || !strings.HasSuffix(p, "…") || strings.Count(p, "\n") != 12 {
		t.Fatalf("%q", p)
	}
	_, text, yes, _, _ := recvAskText("ru", RecvReq{From: "Друг (ID 1)", Name: "a.txt", Size: 3 << 20}, true)
	if yes != "Принять" || !strings.Contains(text, "Принять от Друг (ID 1)?") || !strings.Contains(text, "3.0 МБ") {
		t.Fatalf("%q", text)
	}
	if rxClean("Имя<script>\u202E/../ПК", 32) != "Имяscript..ПК" {
		t.Fatalf("%q", rxClean("Имя<script>\u202E/../ПК", 32))
	}
}
