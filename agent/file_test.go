package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

func TestSafeName(t *testing.T) {
	for in, want := range map[string]string{
		"отчёт.pdf":           "отчёт.pdf",
		`..\..\Windows\x.dll`: "x.dll",
		"../evil:name?.bin":   "evil_name_.bin",
		"con.txt":             "_con.txt",
		"name. . ":            "name",
		"":                    "_",
		"a\x01b":              "a_b",
		"COM9.log":            "_COM9.log",
		"lpt¹":                "_lpt¹",
		"CONOUT$":             "_CONOUT$",
		"con .txt":            "_con .txt",
		"COM10.txt":           "COM10.txt",
		"фото\u202egpj.exe":   "фото_gpj.exe",
	} {
		if got := safeName(in); got != want {
			t.Errorf("safeName(%q) = %q, ждали %q", in, got, want)
		}
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), nil, 0o644)
	os.WriteFile(filepath.Join(dir, "a (1).txt"), nil, 0o644)
	if got := filepath.Base(freePath(dir, "a.txt")); got != "a (2).txt" {
		t.Errorf("freePath: %s", got)
	}
}

// pair — два соединённых WebRTC-узла в одном процессе (без сигнализации).
func pair(t *testing.T) (client, host *webrtc.PeerConnection) {
	t.Helper()
	// ponytail: только loopback — на Маке ICE-пинг через en0 мог навсегда зависнуть в UDP WriteTo (pion ice v4.4.8)
	var se webrtc.SettingEngine
	se.SetIncludeLoopbackCandidate(true)
	se.SetInterfaceFilter(func(n string) bool { return strings.HasPrefix(n, "lo") })
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	api := webrtc.NewAPI(webrtc.WithSettingEngine(se))
	client, _ = api.NewPeerConnection(webrtc.Configuration{})
	host, _ = api.NewPeerConnection(webrtc.Configuration{})
	t.Cleanup(func() { client.Close(); host.Close() })
	client.CreateDataChannel("init", nil)
	offer, _ := client.CreateOffer(nil)
	g := webrtc.GatheringCompletePromise(client)
	client.SetLocalDescription(offer)
	<-g
	host.SetRemoteDescription(*client.LocalDescription())
	ans, _ := host.CreateAnswer(nil)
	g = webrtc.GatheringCompletePromise(host)
	host.SetLocalDescription(ans)
	<-g
	client.SetRemoteDescription(*host.LocalDescription())
	return client, host
}

func randFile(t *testing.T, n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// upload — клиент шлёт файл как ui/index.html: meta → ждать resume → куски с offset → end.
// stopAt > 0 — оборвать канал после стольких байт; cancel — перед этим явно отменить.
func upload(t *testing.T, pc *webrtc.PeerConnection, name, id string, data []byte, stopAt int, cancel bool) (fileMsg, int64) {
	t.Helper()
	dc, _ := pc.CreateDataChannel("file", nil)
	res := make(chan fileMsg, 4)
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		var fm fileMsg
		json.Unmarshal(m.Data, &fm)
		res <- fm
	})
	dc.OnOpen(func() { sendJSON(dc, fileMsg{T: "meta", Name: name, Size: int64(len(data)), ID: id}) })
	var r fileMsg
	select {
	case r = <-res:
	case <-time.After(10 * time.Second):
		t.Fatal("нет resume")
	}
	if r.T != "resume" {
		t.Fatalf("ждали resume: %+v", r)
	}
	for off := int(r.Offset); off < len(data); off += fileChunk {
		if stopAt > 0 && off >= stopAt {
			if cancel {
				sendJSON(dc, fileMsg{T: "cancel"})
			}
			for i := 0; i < 100 && dc.BufferedAmount() > 0; i++ { // обрыв после доставки отправленного,
				time.Sleep(10 * time.Millisecond) // иначе хост может не получить ни байта
			}
			time.Sleep(100 * time.Millisecond)
			dc.Close()
			return fileMsg{}, r.Offset
		}
		for dc.BufferedAmount() > fileHigh {
			time.Sleep(time.Millisecond)
		}
		dc.Send(data[off:min(off+fileChunk, len(data))])
	}
	sendJSON(dc, fileMsg{T: "end"})
	select {
	case d := <-res:
		return d, r.Offset
	case <-time.After(20 * time.Second):
		t.Fatal("нет ответа хоста")
	}
	return fileMsg{}, 0
}

func hostWith(t *testing.T) (*webrtc.PeerConnection, string) {
	client, host := pair(t)
	dir := t.TempDir()
	a := &Agent{FileDir: dir}
	recv := new(atomic.Int32) // как в agent.go: один счётчик на сессию
	s := &session{}
	s.authed.Store(true)
	s.view.Store(hostView)
	host.OnDataChannel(func(dc *webrtc.DataChannel) { a.clientChannel(s, dc, recv) })
	return client, dir
}

var hostView bool // hostWith: сессия «только просмотр»

// TestUploadViewOnly — REQ-F-20: в «только просмотр» хост отвечает отказом с причиной (а не молча закрывает канал,
// что старый клиент показывал как обрыв «отправьте ещё раз»), файлов в папке нет.
func TestUploadViewOnly(t *testing.T) {
	hostView = true
	defer func() { hostView = false }()
	client, dir := hostWith(t)
	dc, _ := client.CreateDataChannel("file", nil)
	res := make(chan fileMsg, 1)
	dc.OnMessage(func(m webrtc.DataChannelMessage) { var fm fileMsg; json.Unmarshal(m.Data, &fm); res <- fm })
	dc.OnOpen(func() { sendJSON(dc, fileMsg{T: "meta", Name: "x.bin", Size: 1}) })
	select {
	case r := <-res:
		if r.T != "err" || !strings.Contains(r.Msg, "только просмотр") {
			t.Fatalf("ответ: %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("нет ответа хоста")
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("в папке: %v", left)
	}
}

func waitParts(t *testing.T, dir string, want int) {
	t.Helper()
	for i := 0; i < 50; i++ {
		if p, _ := filepath.Glob(filepath.Join(dir, ".anypc-*.part")); len(p) == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	p, _ := filepath.Glob(filepath.Join(dir, ".anypc-*.part"))
	t.Fatalf("частей %d, ждали %d", len(p), want)
}

func TestFileUpload(t *testing.T) {
	client, dir := hostWith(t)
	data := randFile(t, 3<<20)
	r, _ := upload(t, client, "../evil:name.bin", "", data, 0, false)
	got, err := os.ReadFile(filepath.Join(dir, "evil_name.bin")) // имя очищено, из папки не вышли
	if r.T != "done" || err != nil || !bytes.Equal(got, data) || r.SHA256 != sha(data) {
		t.Fatalf("приём: %+v %v", r, err)
	}
	// явная отмена: часть удаляется
	upload(t, client, "big.bin", "00112233445566778899aabbccddeeff", randFile(t, 2<<20), 256<<10, true)
	waitParts(t, dir, 0)
}

// TestUploadResume — обрыв на середине; повторная отправка того же файла продолжает с места обрыва.
func TestUploadResume(t *testing.T) {
	client, dir := hostWith(t)
	data := randFile(t, 3<<20)
	id := "0123456789abcdef0123456789abcdef"
	upload(t, client, "отчёт.bin", id, data, 1<<20, false)
	waitParts(t, dir, 1) // часть сохранена
	r, off := upload(t, client, "отчёт.bin", id, data, 0, false)
	got, _ := os.ReadFile(filepath.Join(dir, "отчёт.bin"))
	if off <= 0 || r.T != "done" || !bytes.Equal(got, data) || r.SHA256 != sha(data) {
		t.Fatalf("докачка: offset=%d %+v", off, r)
	}
	waitParts(t, dir, 0)
}

// download — клиент принимает файл с хоста, как программа (Receiver на диск); stopAt — оборвать.
func download(client *webrtc.PeerConnection, dir string, stopAt int64) chan string {
	done := make(chan string, 1)
	client.OnDataChannel(func(dc *webrtc.DataChannel) {
		r := NewReceiver(dir)
		var mu sync.Mutex
		dc.OnMessage(func(m webrtc.DataChannelMessage) {
			mu.Lock()
			defer mu.Unlock()
			if !m.IsString {
				if r.Write(m.Data) == nil && stopAt > 0 && r.got >= stopAt {
					r.Abort(true)
					dc.Close()
				}
				return
			}
			var fm fileMsg
			json.Unmarshal(m.Data, &fm)
			switch fm.T {
			case "meta":
				off, _ := r.Open(fm.Name, fm.Size, fm.ID)
				sendJSON(dc, fileMsg{T: "resume", Offset: off})
			case "end":
				dst, sum, err := r.Finish()
				if err != nil {
					sendJSON(dc, fileMsg{T: "err", Msg: err.Error()})
					return
				}
				sendJSON(dc, fileMsg{T: "done", SHA256: sum})
				done <- dst
			}
		})
	})
	return done
}

func TestFileDownloadResume(t *testing.T) {
	data := randFile(t, 3<<20)
	src := filepath.Join(t.TempDir(), "с хоста.bin")
	os.WriteFile(src, data, 0o644)
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, host := pair(t) // первая попытка обрывается на ~1 МБ
	download(client, dir, 1<<20)
	if err := sendFile(ctx, host, src); err == nil {
		t.Fatal("обрыв не замечен отправителем")
	}
	waitParts(t, dir, 1)

	client2, host2 := pair(t) // новое соединение, тот же файл — докачка
	done := download(client2, dir, 0)
	if err := sendFile(ctx, host2, src); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(<-done)
	if !bytes.Equal(got, data) || filepath.Base(src) != "с хоста.bin" {
		t.Fatal("файл после докачки искажён")
	}
	waitParts(t, dir, 0)
}

func TestReceiver(t *testing.T) {
	dir := t.TempDir()
	id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	r := NewReceiver(dir)
	if off, err := r.Open("a.txt", 6, id); off != 0 || err != nil {
		t.Fatal(off, err)
	}
	r.Write([]byte("abc"))
	r.Abort(true)
	r = NewReceiver(dir)
	if off, _ := r.Open("a.txt", 6, id); off != 3 {
		t.Fatalf("докачка с %d, ждали 3", off)
	}
	if r.Write([]byte("defg")) == nil {
		t.Fatal("лишние данные приняты")
	}
	r.Write([]byte("def"))
	dst, sum, err := r.Finish()
	if b, _ := os.ReadFile(dst); err != nil || string(b) != "abcdef" || sum != sha([]byte("abcdef")) {
		t.Fatalf("%q %v", b, err)
	}
	r = NewReceiver(dir) // плохой id → без докачки, но приём работает, из папки не выходит
	if off, err := r.Open("b.txt", 1, "../../etc"); off != 0 || err != nil {
		t.Fatal(off, err)
	}
	r.Abort(false)
	if p, _ := filepath.Glob(filepath.Join(dir, ".anypc-*")); len(p) != 0 {
		t.Fatalf("отмена оставила %v", p)
	}
}

// TestFinishNoOverwrite — приёмы с одним именем завершаются одновременно: между проверкой
// свободного имени и переносом другой приём занимает его, но ни один файл не перезаписан.
func TestFinishNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	const n = 30
	rs := make([]*Receiver, n)
	for i := range rs {
		rs[i] = NewReceiver(dir)
		if _, err := rs[i].Open("same.txt", 2, ""); err != nil {
			t.Fatal(err)
		}
		rs[i].Write([]byte{'a' + byte(i/26), 'a' + byte(i%26)})
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, r := range rs {
		wg.Go(func() {
			<-start
			if _, _, err := r.Finish(); err != nil {
				t.Error(err)
			}
		})
	}
	close(start)
	wg.Wait()
	got := map[string]bool{}
	files, _ := filepath.Glob(filepath.Join(dir, "same*.txt"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		got[string(b)] = true
	}
	if len(got) != n {
		t.Fatalf("целых файлов %d из %d (%d имён)", len(got), n, len(files))
	}
}

// TestDiskRoom — файл, после которого на диске останется меньше 1 ГБ, не принимается.
func TestDiskRoom(t *testing.T) {
	dir := t.TempDir()
	free, err := diskFree(dir)
	if err != nil || free == 0 {
		t.Fatal(free, err)
	}
	r := NewReceiver(dir)
	if _, err := r.Open("big.bin", int64(free), ""); err == nil || !strings.Contains(err.Error(), "мало места") {
		t.Fatalf("файл размером со всё свободное место принят: %v", err)
	}
	if p, _ := filepath.Glob(filepath.Join(dir, ".anypc-*")); len(p) != 0 {
		t.Fatalf("отказ оставил %v", p)
	}
	if free > 2<<30 {
		if _, err := r.Open("small.bin", 1, ""); err != nil {
			t.Fatal(err)
		}
		r.Abort(false)
	}
}

// TestRecvLimit — пятый одновременный приём в сессии отклоняется; когда один закончился — снова можно.
func TestRecvLimit(t *testing.T) {
	client, _ := hostWith(t)
	start := func(name string) (*webrtc.DataChannel, fileMsg, chan fileMsg) {
		dc, _ := client.CreateDataChannel("file", nil)
		res := make(chan fileMsg, 4)
		dc.OnMessage(func(m webrtc.DataChannelMessage) {
			var fm fileMsg
			json.Unmarshal(m.Data, &fm)
			res <- fm
		})
		dc.OnOpen(func() { sendJSON(dc, fileMsg{T: "meta", Name: name, Size: 1}) })
		select {
		case r := <-res:
			return dc, r, res
		case <-time.After(10 * time.Second):
			t.Fatal("нет ответа хоста")
		}
		return nil, fileMsg{}, nil
	}
	var first *webrtc.DataChannel
	var firstRes chan fileMsg
	for i := range maxRecv {
		dc, r, res := start(string(rune('a'+i)) + ".bin")
		if r.T != "resume" {
			t.Fatalf("приём %d: %+v", i+1, r)
		}
		if i == 0 {
			first, firstRes = dc, res
		}
	}
	// пятый ждёт очереди (раньше — отказ, а клиент шлёт все выбранные файлы разом)
	fifth, _ := client.CreateDataChannel("file", nil)
	res5 := make(chan fileMsg, 4)
	fifth.OnMessage(func(m webrtc.DataChannelMessage) { var fm fileMsg; json.Unmarshal(m.Data, &fm); res5 <- fm })
	fifth.OnOpen(func() { sendJSON(fifth, fileMsg{T: "meta", Name: "e.bin", Size: 1}) })
	select {
	case r := <-res5:
		t.Fatalf("пятый приём не ждёт: %+v", r)
	case <-time.After(700 * time.Millisecond):
	}
	first.Send([]byte{1})
	sendJSON(first, fileMsg{T: "end"})
	select {
	case r := <-firstRes:
		if r.T != "done" {
			t.Fatalf("первый приём: %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("первый приём не закончился")
	}
	select {
	case r := <-res5:
		if r.T != "resume" {
			t.Fatalf("пятый после окончания первого: %+v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("пятый не дождался очереди")
	}
}
