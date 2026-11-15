package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// Ч10.2–Ч10.3: папки на приёме (safeRel, mkRoot, placeIn) и отправитель (makePlan, SendTo).

// TestSafeRelTable — каждый вид опасного пути отклонён; годные — составляющие, запрещённые в Windows знаки — «_».
func TestSafeRelTable(t *testing.T) {
	deep := strings.Repeat("d/", relMaxDepth-1) + "f"
	bad := map[string]string{
		"пусто": "", "одна составляющая": "a.txt", "..": "P/../x", ". ": "P/./x", "в начале ..": "../x",
		"абсолютный": "/etc/passwd", "UNC": `\\srv\share\x`, "UNC через /": "//srv/share/x", `\\?\`: `\\?\C:\x`,
		"обратная черта": `P\..\x`, "диск": "C:/Windows/x", "поток NTFS": "P/a.txt:evil", "пустая составляющая": "P//x",
		"в конце /": "P/x/", "CON": "P/CON", "nul.txt": "P/nul.txt", "COM1 в папке": "P/COM1/x", "LPT¹": "P/LPT¹.log",
		"CON с пробелом": "P/CON .txt", "папка-устройство": "AUX/x", "NUL": "P/a\x00b", "управляющий": "P/a\x1bb",
		"DEL": "P/a\x7fb", "C1": "P/a\u0085b", "RLO": "P/фото\u202Egpj.exe", "LRE": "P/\u202Ax", "FSI": "P/a\u2068b",
		"PDI": "P/a\u2069", "только точки": "P/...", "только пробелы": "P/  ", "глубже 32": deep + "/g",
		"длиннее 1024":       "P/" + strings.Repeat("a", 200) + "/" + strings.Repeat("b", 200) + "/" + strings.Repeat("c", 200) + "/" + strings.Repeat("d", 200) + "/" + strings.Repeat("e", 230),
		"составляющая > 255": "P/" + strings.Repeat("я", 128), "не UTF-8": "P/a\xffb", "место частей": ".anypc-1.part/x", "место частей, регистр": ".ANYPC-1.part/x",
	}
	for k, p := range bad {
		if got, err := safeRel(p); err == nil {
			t.Errorf("%s (%q): принят как %q", k, p, got)
		}
	}
	good := map[string][]string{
		"Папка/a.txt":         {"Папка", "a.txt"},
		"P/sub/deep/x.bin":    {"P", "sub", "deep", "x.bin"},
		"P/what?.mp3":         {"P", "what_.mp3"},
		"P/a<b>|\"*.txt":      {"P", "a_b____.txt"},
		"P/dir./name. ":       {"P", "dir", "name"},
		".hidden/.git/x":      {".hidden", ".git", "x"},
		"P/👩\u200d💻 файл.txt": {"P", "👩_💻 файл.txt"}, // Cf → «_», как safeName (M6 приёмки)
		"P/a\u200bb\u200e\u200f\u061c\ufeff\u2028\u2029c": {"P", "a_b______c"},
		"P/CONSOLE.txt":                 {"P", "CONSOLE.txt"},
		deep:                            strings.Split(deep, "/"),
		"P/" + strings.Repeat("я", 127): {"P", strings.Repeat("я", 127)},
	}
	for p, want := range good {
		if got, err := safeRel(p); err != nil || !slices.Equal(got, want) {
			t.Errorf("%q: %q %v, ждали %q", p, got, err, want)
		}
	}
}

// tree — дерево файлов в новом каталоге: путь «a/b/c.txt» → содержимое.
func tree(t *testing.T, root string, files map[string]string) string {
	t.Helper()
	for p, body := range files {
		f := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// readTree — файлы под root: путь «/» → содержимое (части докачки — мимо).
func readTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() || strings.HasPrefix(e.Name(), ".anypc-") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if e.Type()&os.ModeSymlink != 0 {
			out[filepath.ToSlash(rel)] = "->link"
			return nil
		}
		b, _ := os.ReadFile(p)
		out[filepath.ToSlash(rel)] = string(b)
		return nil
	})
	return out
}

func sameMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// TestSendFolder — свой ПК: папка с вложенностью принята целиком в «Загрузки/Папка», вместе с файлом и текстом; вторая
// отправка той же папки — «Папка (1)»; ход дошёл до конца; символьные ссылки в отправляемой папке (на файл снаружи, на
// папку снаружи, внутрь) не идут и названы в Skipped.
func TestSendFolder(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	src := filepath.Join(t.TempDir(), "Папка")
	files := map[string]string{"a.txt": "A", "sub/b.txt": "B", "sub/deep/c/d.bin": strings.Repeat("x", 70_000),
		".hidden/e": "E", "пустой-рядом/f.txt": ""}
	tree(t, src, files)
	outside := tree(t, t.TempDir(), map[string]string{"secret.txt": "СЕКРЕТ", "dir/s.txt": "СЕКРЕТ2"})
	os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(src, "link-file"))
	os.Symlink(filepath.Join(outside, "dir"), filepath.Join(src, "sub", "link-dir"))
	os.Symlink("a.txt", filepath.Join(src, "link-in"))
	os.Mkdir(filepath.Join(src, "empty"), 0o755)
	one := srcFile(t, "один.txt", []byte("1"))
	var last SendProgress
	d := r.own(url, []string{one}, "текст")
	d.Dirs = []string{src}
	d.Progress = func(p SendProgress) { last = p }
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := SendTo(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if got := readTree(t, filepath.Join(r.dir, "Папка")); !sameMap(got, files) {
		t.Fatalf("принято %v", got)
	}
	if b, _ := os.ReadFile(filepath.Join(r.dir, "один.txt")); string(b) != "1" {
		t.Fatalf("файл: %q", b)
	}
	if c := r.clip(); len(c) != 1 || c[0] != "текст" {
		t.Fatalf("буфер %q", c)
	}
	slices.Sort(res.Skipped)
	if want := []string{"Папка/link-file", "Папка/link-in", "Папка/sub/link-dir"}; !slices.Equal(res.Skipped, want) {
		t.Fatalf("пропущено %q", res.Skipped)
	}
	var total int64 = 1 + int64(len("текст"))
	for _, b := range files {
		total += int64(len(b))
	}
	if res.Files != 6 || res.Bytes != total-int64(len("текст")) || !res.Text || last.Done != total || last.Total != total ||
		last.Items != 7 || last.Item != 7 || !bytes.Equal(res.HostPub, r.a.Key.Public().(ed25519.PublicKey)) {
		t.Fatalf("итог %+v, ход %+v (всего %d)", res, last, total)
	}
	if got := readTree(t, r.dir); strings.Contains(fmt.Sprint(got), "СЕКРЕТ") {
		t.Fatalf("ссылка ушла: %v", got)
	}
	d.Files, d.Text = nil, ""
	if _, err := SendTo(ctx, d); err != nil {
		t.Fatal(err)
	}
	if got := readTree(t, filepath.Join(r.dir, "Папка (1)")); !sameMap(got, files) {
		t.Fatalf("второй раз принято %v", got)
	}
}

// rawMeta — файл по протоколу file.go с meta как есть; итог — последний ответ получателя ("done" или "err").
func rawMeta(pc *webrtc.PeerConnection, meta fileMsg, body []byte) (fileMsg, error) {
	dc, err := pc.CreateDataChannel("file", nil)
	if err != nil {
		return fileMsg{}, err
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
	meta.T, meta.Size = "meta", int64(len(body))
	sendJSON(dc, meta)
	fm, err := wait()
	if err != nil || fm.T != "resume" {
		return fm, err
	}
	dc.Send(body)
	sendJSON(dc, fileMsg{T: "end"})
	return wait()
}

// rawSend — своё по одной сессии приёма свой ПК → r (recvTestPC).
func rawSend(t *testing.T, r *recvRig, url string, f func(pc *webrtc.PeerConnection) error) error {
	t.Helper()
	recvTestPC = f
	defer func() { recvTestPC = nil }()
	return sendT(t, r.own(url, nil, ""))
}

// TestRecvFolderPaths — путь в meta от отправителя (не SendTo): каждый опасный путь — "path", вне «Загрузок» и вне
// папки приёма ничего; годный — в папке; один и тот же путь дважды — «(1)»; папка с тем же именем уже в «Загрузках» —
// «Папка (1)», чужое в ней не тронуто.
func TestRecvFolderPaths(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	tree(t, r.dir, map[string]string{"Папка/old.txt": "старое"})
	paths := []string{"../evil.txt", "Папка/../../evil.txt", "/tmp/evil.txt", `C:\evil.txt`, "C:/evil.txt",
		`\\srv\s\evil.txt`, `\\?\C:\evil.txt`, "Папка/CON", "Папка/a\u202Etxt.exe", "Папка/a\x00.txt", "Папка//x",
		"Папка/a.txt:ads", strings.Repeat("d/", 40) + "x", "одно.txt"}
	err := rawSend(t, r, url, func(pc *webrtc.PeerConnection) error {
		for _, p := range paths {
			fm, err := rawMeta(pc, fileMsg{Name: "x.txt", Path: p}, []byte("evil"))
			if err != nil || fm.T != "err" || fm.Code != "path" {
				return fmt.Errorf("%q: %+v %v", p, fm, err)
			}
		}
		for range 2 {
			if fm, err := rawMeta(pc, fileMsg{Name: "a.txt", Path: "Папка/sub/a.txt"}, []byte("A")); err != nil || fm.T != "done" {
				return fmt.Errorf("годный: %+v %v", fm, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"Папка/old.txt": "старое", "Папка (1)/sub/a.txt": "A", "Папка (1)/sub/a (1).txt": "A"}
	if got := readTree(t, r.dir); !sameMap(got, want) {
		t.Fatalf("загрузки %v", got)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(r.dir), "evil.txt")); err == nil {
		t.Fatal("файл вне загрузок")
	}
}

// TestRecvFolderSymlink — символьная ссылка в «Загрузках» с именем папки (наружу) не пройдена: папка приёма —
// «Папка (1)»; ссылка, подложенная внутрь папки приёма посреди передачи, — отказ "path", снаружи ничего; ссылка
// на месте файла не перезаписана.
func TestRecvFolderSymlink(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	out := t.TempDir()
	os.Symlink(out, filepath.Join(r.dir, "Папка"))
	err := rawSend(t, r, url, func(pc *webrtc.PeerConnection) error {
		if fm, err := rawMeta(pc, fileMsg{Name: "a.txt", Path: "Папка/a.txt"}, []byte("A")); err != nil || fm.T != "done" {
			return fmt.Errorf("первый: %+v %v", fm, err)
		}
		os.Symlink(out, filepath.Join(r.dir, "Папка (1)", "sub"))                           // папка-ссылка внутри
		os.Symlink(filepath.Join(out, "t.txt"), filepath.Join(r.dir, "Папка (1)", "t.txt")) // файл-ссылка внутри
		if fm, err := rawMeta(pc, fileMsg{Name: "b.txt", Path: "Папка/sub/b.txt"}, []byte("B")); err != nil || fm.T != "err" || fm.Code != "path" {
			return fmt.Errorf("через ссылку: %+v %v", fm, err)
		}
		if fm, err := rawMeta(pc, fileMsg{Name: "t.txt", Path: "Папка/t.txt"}, []byte("T")); err != nil || fm.T != "done" {
			return fmt.Errorf("на месте ссылки: %+v %v", fm, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if l, _ := os.ReadDir(out); len(l) != 0 {
		t.Fatalf("снаружи: %v", l)
	}
	want := map[string]string{"Папка (1)/a.txt": "A", "Папка (1)/t (1).txt": "T", "Папка (1)/t.txt": "->link", "Папка (1)/sub": "->link", "Папка": "->link"}
	got := map[string]string{}
	for k, v := range readTree(t, r.dir) {
		got[k] = v
	}
	if st, err := os.Lstat(filepath.Join(r.dir, "Папка")); err == nil && st.Mode()&os.ModeSymlink != 0 {
		got["Папка"] = "->link"
	}
	if !sameMap(got, want) {
		t.Fatalf("загрузки %v", got)
	}
}

// TestRecvFolderLimits — потолки Ч10.1 — на сумму файлов папки: отправитель отказывает до первого байта (lim из "rx"),
// хост — сам, если отправитель их не проверил.
func TestRecvFolderLimits(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	old := rxLimP.Load()
	defer rxLimP.Store(old)
	l := *old
	l.Items, l.Total = 3, 100
	rxLimP.Store(&l)
	src := tree(t, filepath.Join(t.TempDir(), "P"), map[string]string{"a": "1", "b": "2", "c/d": "3", "c/e": "4"})
	d := r.own(url, nil, "")
	d.Dirs = []string{src}
	if err := sendT(t, d); !errors.Is(err, ErrRecvLimit) {
		t.Fatalf("4 файла при потолке 3: %v", err)
	}
	big := tree(t, filepath.Join(t.TempDir(), "B"), map[string]string{"a": strings.Repeat("x", 60), "b": strings.Repeat("y", 60)})
	d.Dirs = []string{big}
	if err := sendT(t, d); !errors.Is(err, ErrRecvLimit) {
		t.Fatalf("120 байт при потолке 100: %v", err)
	}
	if got := readTree(t, r.dir); len(got) != 0 {
		t.Fatalf("принято %v", got)
	}
	err := rawSend(t, r, url, func(pc *webrtc.PeerConnection) error {
		for i := range 4 {
			fm, err := rawMeta(pc, fileMsg{Name: "f", Path: fmt.Sprintf("P/f%d", i)}, []byte("z"))
			if want := map[bool]string{true: "done", false: "err"}[i < 3]; err != nil || fm.T != want || i == 3 && fm.Code != "count" {
				return fmt.Errorf("%d: %+v %v", i, fm, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestRecvFolderOldHost — хост Ч10.1 (папок не объявляет, путь пропускает): папку ему не шлём (ErrRecvOldDirs, ни
// байта), файлы и текст — как раньше; путь в meta он кладёт плоско, как настоящий хост Ч10.1.
func TestRecvFolderOldHost(t *testing.T) {
	url := local(t)
	r := recvHost(t, url, func(r *recvRig) { r.a.noDirs = true })
	src := tree(t, filepath.Join(t.TempDir(), "P"), map[string]string{"a.txt": "A"})
	d := r.own(url, nil, "")
	d.Dirs = []string{src}
	if err := sendT(t, d); !errors.Is(err, ErrRecvOldDirs) || err.Error() != "На том ПК версия AnyPC без приёма папок — обновите её" {
		t.Fatalf("папка старому хосту: %v", err)
	}
	if got := readTree(t, r.dir); len(got) != 0 {
		t.Fatalf("принято %v", got)
	}
	if err := sendT(t, r.own(url, []string{srcFile(t, "f.txt", []byte("F"))}, "т")); err != nil {
		t.Fatal(err)
	}
	err := rawSend(t, r, url, func(pc *webrtc.PeerConnection) error {
		if fm, err := rawMeta(pc, fileMsg{Name: "g.txt", Path: "../P/g.txt"}, []byte("G")); err != nil || fm.T != "done" {
			return fmt.Errorf("%+v %v", fm, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := readTree(t, r.dir); !sameMap(got, map[string]string{"f.txt": "F", "g.txt": "G"}) {
		t.Fatalf("загрузки %v", got)
	}
}

// TestSendKinds — отправитель: буфер обмена этого ПК своему; закреплённому чужому (Known, «Принять?» один раз на
// файлы папки); чужому по коду (код израсходован, ключ закреплён); пустой буфер — ErrSendClip.
func TestSendKinds(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	clipRead = func() (string, error) { return "из буфера", nil }
	defer func() { clipRead = ClipText }()
	d := r.own(url, nil, "")
	d.Clip = true
	if err := sendT(t, d); err != nil {
		t.Fatal(err)
	}
	if c := r.clip(); len(c) != 1 || c[0] != "из буфера" {
		t.Fatalf("буфер %q", c)
	}
	clipRead = func() (string, error) { return "", nil }
	if err := sendT(t, d); !errors.Is(err, ErrSendClip) {
		t.Fatalf("пустой буфер: %v", err)
	}
	_, fkey, _ := ed25519.GenerateKey(nil)
	src := tree(t, filepath.Join(t.TempDir(), "Чужое"), map[string]string{"a": "1", "b/c": "2"})
	fd := foreign(url, fkey, "secret123", nil, "")
	fd.Dirs = []string{src}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := SendTo(ctx, fd)
	if err != nil || !r.pinned(fkey.Public().(ed25519.PublicKey)) || r.used.Load() != 1 || r.askN() != 0 || res.Files != 2 {
		t.Fatalf("по коду: %v, закреплён %v, код %d, окон %d, %+v", err, r.pinned(fkey.Public().(ed25519.PublicKey)), r.used.Load(), r.askN(), res)
	}
	fd = foreign(url, fkey, "", nil, "")
	fd.Dirs = []string{src}
	if _, err := SendTo(ctx, fd); err != nil || r.askN() != 1 || r.ask(0).Name != "Чужое/a" && r.ask(0).Name != "Чужое/b/c" {
		t.Fatalf("закреплённому: %v, окон %d %+v", err, r.askN(), r.ask(0))
	}
	want := map[string]string{"Чужое/a": "1", "Чужое/b/c": "2", "Чужое (1)/a": "1", "Чужое (1)/b/c": "2"}
	if got := readTree(t, r.dir); !sameMap(got, want) {
		t.Fatalf("загрузки %v", got)
	}
	fd.Known = ""
	if _, err := SendTo(ctx, fd); !errors.Is(err, ErrRecvKnown) {
		t.Fatalf("чужому без кода и Known: %v", err)
	}
	// план — до соединения: папка как файл, файл как папка, нет файла (хаба нет — дошли бы до сети)
	off := SendDial{Server: "ws://127.0.0.1:1", ID: "123456789", HostPub: r.a.Key.Public().(ed25519.PublicKey), Key: r.member}
	for _, c := range []struct {
		files, dirs []string
		want        error
	}{{[]string{src}, nil, ErrSendNotFile}, {nil, []string{srcFile(t, "f", nil)}, ErrSendNotFile},
		{[]string{filepath.Join(src, "нет")}, nil, os.ErrNotExist}} {
		off.Files, off.Dirs = c.files, c.dirs
		if _, err := SendTo(ctx, off); !errors.Is(err, c.want) {
			t.Errorf("%v %v: %v", c.files, c.dirs, err)
		}
	}
}

// TestSendCancel — отмена посреди файла: SendTo — context.Canceled, у получателя ни файла, ни части (отправитель
// послал "cancel").
func TestSendCancel(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	big := srcFile(t, "big.bin", bytes.Repeat([]byte{1}, 64<<20))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	d := r.own(url, []string{big}, "")
	var once atomic.Bool
	d.Progress = func(p SendProgress) {
		if p.Done > 1<<20 && once.CompareAndSwap(false, true) {
			cancel()
		}
	}
	if _, err := SendTo(ctx, d); !errors.Is(err, context.Canceled) {
		t.Fatalf("отмена: %v", err)
	}
	for range 50 {
		l, _ := os.ReadDir(r.dir)
		if len(l) == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	l, _ := os.ReadDir(r.dir)
	t.Fatalf("у получателя осталось %v", l)
}

// TestSendResume — регрессия: докачка у отправителя приёма (quiet) не делала Seek — получатель отказывал «лишние
// данные». Часть от прошлой попытки — файл дописан с её конца, содержимое целое.
func TestSendResume(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	body := make([]byte, 300_000)
	for i := range body {
		body[i] = byte(i * 7)
	}
	f := srcFile(t, "r.bin", body)
	st, _ := os.Stat(f)
	os.WriteFile(filepath.Join(r.dir, ".anypc-"+fileID(f, st)+".part"), body[:100_000], 0o644)
	var first int64 = -1
	d := r.own(url, []string{f}, "")
	d.Progress = func(p SendProgress) {
		if first < 0 && p.Done > 0 {
			first = p.Done
		}
	}
	if err := sendT(t, d); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(r.dir, "r.bin")); !bytes.Equal(b, body) || first != 100_000 {
		t.Fatalf("докачка: %d байт, равно %v, ход с %d", len(b), bytes.Equal(b, body), first)
	}
}
