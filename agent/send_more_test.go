package agent

// Круг 2 приёмки Ч10.2–Ч10.3 (Fable high): M1 проверки получателя, M2 запись и план, M3 ключ после отказа, M4 папка
// «.» и корень, M7 ФС без жёстких ссылок. Часть — перенесённые тесты приёмщика (zz_*_test.go).

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"anypc/pake"
)

// TestSendHostProof — M1: отправитель проверяет "rx" получателя: отпечаток Known, подпись хоста, подтверждение кода,
// ключ своего ПК из M. Не доказано — ErrSpaceHostKey, ни байта, ключ не возвращён (не запомнится).
func TestSendHostProof(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	_, fkey, _ := ed25519.GenerateKey(nil)
	pub := fkey.Public().(ed25519.PublicKey)
	r.mu.Lock()
	r.pins[string(pub)], r.pinID[string(pub)] = "Друг", "555666777"
	r.mu.Unlock()
	f := srcFile(t, "a.txt", []byte("x"))
	_, other, _ := ed25519.GenerateKey(nil)
	defer rxTestRx.Store(nil)
	flip := func(b []byte) []byte { b = bytes.Clone(b); b[0] ^= 1; return b }
	cases := []struct {
		name string
		d    SendDial
		hook func(m *authMsg, fpc, fph string)
	}{
		{"чужой отпечаток Known", func() SendDial { d := foreign(url, fkey, "", []string{f}, ""); d.Known = "0000 1111"; return d }(), nil},
		{"подпись не доказана", foreign(url, fkey, "", []string{f}, ""), func(m *authMsg, _, _ string) { m.Sig = flip(m.Sig) }},
		{"код не доказан хостом", foreign(url, fkey, "secret123", []string{f}, ""), func(m *authMsg, _, _ string) { m.Conf = flip(m.Conf) }},
		{"свой ПК: другой ключ с верной подписью", r.own(url, []string{f}, ""), func(m *authMsg, fpc, fph string) {
			m.Pub, m.Sig = other.Public().(ed25519.PublicKey), pake.HostSign(other, "123456789", fpc, fph)
		}},
	}
	for _, c := range cases {
		rxTestRx.Store(&c.hook)
		res, err := SendTo(t.Context(), c.d)
		if !errors.Is(err, ErrSpaceHostKey) || len(res.HostPub) != 0 || res.Files != 0 || len(r.files(t)) != 0 {
			t.Errorf("%s: %v, ключ %x, файлов %d %v", c.name, err, res.HostPub, res.Files, r.files(t))
		}
	}
}

// TestSendBurnKeepsKey — M3: отказ отправителя после "rx" (хост без папок) — код израсходован, но ключ получателя
// возвращён (окно запомнит его в known), отправитель у получателя закреплён.
func TestSendBurnKeepsKey(t *testing.T) {
	url := local(t)
	r := recvHost(t, url, func(r *recvRig) { r.a.noDirs = true })
	_, fkey, _ := ed25519.GenerateKey(nil)
	d := foreign(url, fkey, "secret123", nil, "")
	d.Dirs = []string{tree(t, filepath.Join(t.TempDir(), "P"), map[string]string{"a.txt": "A"})}
	res, err := SendTo(t.Context(), d)
	if !errors.Is(err, ErrRecvOldDirs) || !bytes.Equal(res.HostPub, r.a.Key.Public().(ed25519.PublicKey)) ||
		r.used.Load() != 1 || !r.pinned(fkey.Public().(ed25519.PublicKey)) {
		t.Fatalf("%v, ключ %x, код %d", err, res.HostPub, r.used.Load())
	}
}

// TestPlaceRace — M2: папку пути подменяют ссылкой (наружу и внутрь «Загрузок») посреди placeIn — ни выхода за
// «Загрузки», ни перезаписи файла получателя (os.Root + Lstat, Link не перезаписывает). Новый файл в другой папке
// «Загрузок» при подмене «внутрь» возможен [вывод: подменить может только локальный процесс с правом записи в «Загрузки» —
// он и так пишет туда что угодно; отправитель ссылок не создаёт]. Тест приёмщика (zz_paths_test.go), 2 с на вид.
func TestPlaceRace(t *testing.T) {
	for _, mode := range []string{"outside", "inside"} {
		dir, out := t.TempDir(), t.TempDir()
		os.WriteFile(filepath.Join(out, "x"), []byte("orig-out"), 0o644)
		os.Mkdir(filepath.Join(dir, "Victim"), 0o755)
		os.WriteFile(filepath.Join(dir, "Victim", "x"), []byte("orig"), 0o644)
		top, err := mkRoot(dir, "T")
		if err != nil {
			t.Fatal(err)
		}
		os.Mkdir(filepath.Join(dir, top, "sub"), 0o755)
		target := out
		if mode == "inside" {
			target = "../Victim"
		}
		var stop atomic.Bool
		done := make(chan struct{})
		go func() {
			defer close(done)
			s, b := filepath.Join(dir, top, "sub"), filepath.Join(dir, top, "sub.bak")
			for !stop.Load() {
				os.Rename(s, b)
				os.Symlink(target, s)
				os.Remove(s)
				os.Rename(b, s)
			}
		}()
		for i, end := 0, time.Now().Add(2*time.Second); time.Now().Before(end); i++ {
			part := fmt.Sprintf(".anypc-%032x.part", i)
			os.WriteFile(filepath.Join(dir, part), []byte("evil"), 0o644)
			if _, err := placeIn(dir, part, []string{top, "sub", "x"}); err != nil {
				os.Remove(filepath.Join(dir, part))
			}
		}
		stop.Store(true)
		<-done
		lo, _ := os.ReadDir(out)
		bo, _ := os.ReadFile(filepath.Join(out, "x"))
		lv, _ := os.ReadDir(filepath.Join(dir, "Victim"))
		bv, _ := os.ReadFile(filepath.Join(dir, "Victim", "x"))
		if len(lo) != 1 || string(bo) != "orig-out" || string(bv) != "orig" {
			t.Errorf("%s: снаружи %v %q, в Victim %v %q", mode, lo, bo, lv, bv)
		}
	}
}

// TestPlaceLinkInside — M2: ссылка внутрь «Загрузок» на месте папки пути (Lstat, не Stat) — отказ errRelDir, чужая
// папка получателя не тронута; файл на месте папки — тоже отказ.
func TestPlaceLinkInside(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "Victim"), 0o755)
	top, _ := mkRoot(dir, "T")
	os.Symlink("../Victim", filepath.Join(dir, top, "sub"))
	os.WriteFile(filepath.Join(dir, top, "file"), []byte("F"), 0o644)
	for _, rel := range [][]string{{top, "sub", "x"}, {top, "file", "x"}} {
		os.WriteFile(filepath.Join(dir, ".anypc-1.part"), []byte("evil"), 0o644)
		if _, err := placeIn(dir, ".anypc-1.part", rel); !errors.Is(err, errRelDir) {
			t.Errorf("%q: %v", rel, err)
		}
	}
	if l, _ := os.ReadDir(filepath.Join(dir, "Victim")); len(l) != 0 {
		t.Fatalf("в Victim: %v", l)
	}
}

// TestPlaceNoHardLinks — M7: ФС без жёстких ссылок (FAT/exFAT): одноимённые файлы, переносимые одновременно, — каждый
// под своим именем, ни один не перезаписан (O_EXCL, не Rename); уже лежащий файл не тронут.
func TestPlaceNoHardLinks(t *testing.T) {
	rootLink = func(*os.Root, string, string) error { return syscall.EPERM }
	defer func() { rootLink = func(r *os.Root, o, n string) error { return r.Link(o, n) } }()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("старое"), 0o644)
	const n = 20
	var wg sync.WaitGroup
	for i := range n {
		part := fmt.Sprintf(".anypc-%032x.part", i)
		os.WriteFile(filepath.Join(dir, part), []byte(fmt.Sprint(i)), 0o644)
		wg.Go(func() {
			if _, err := place(filepath.Join(dir, part), dir, "a.txt"); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	got := readTree(t, dir)
	seen := map[string]bool{}
	for _, v := range got {
		seen[v] = true
	}
	if len(got) != n+1 || got["a.txt"] != "старое" || len(seen) != n+1 {
		t.Fatalf("%v", got)
	}
}

// TestSendPlanEdge — M4 и M2: папка «.» и «sub/..» — папка со своим именем; корень — ErrSendRoot; негодные на той
// стороне имена (файл и вся ветка) — в Skipped; файл, подменённый после плана ссылкой наружу, — не открыт (os.Root);
// больше sendMaxItems — ErrSendMany.
func TestSendPlanEdge(t *testing.T) {
	base := filepath.Join(t.TempDir(), "Дом")
	tree(t, base, map[string]string{"a.txt": "A", "sub/b.txt": "B", "a:b": "X", "x:y/f": "F", "CON": "C", "ok/d": "D"})
	t.Chdir(base)
	for _, d := range []string{".", "sub/..", base + "/"} {
		p, err := makePlan(nil, []string{d}, "")
		if err != nil {
			t.Fatal(err)
		}
		var w []string
		for _, it := range p.items {
			w = append(w, it.wire)
		}
		if strings.Join(w, ",") != "Дом/a.txt,Дом/ok/d,Дом/sub/b.txt" || strings.Join(p.skipped, ",") != "Дом/CON,Дом/a:b,Дом/x:y/" {
			t.Errorf("%q: уходит %q, пропущено %q", d, w, p.skipped)
		}
		p.close()
	}
	if _, err := makePlan(nil, []string{"/"}, ""); !errors.Is(err, ErrSendRoot) {
		t.Errorf("корень: %v", err)
	}
	p, err := makePlan(nil, []string{base}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	out := srcFile(t, "secret", []byte("S"))
	os.Remove(filepath.Join(base, "a.txt"))
	os.Symlink(out, filepath.Join(base, "a.txt"))
	if f, _, err := p.items[0].open(); err == nil {
		f.Close()
		t.Fatal("ссылка наружу открыта")
	}
	defer func(n int) { sendMaxItems = n }(sendMaxItems)
	sendMaxItems = 1
	if _, err := makePlan(nil, []string{base}, ""); !errors.Is(err, ErrSendMany) {
		t.Errorf("больше предела: %v", err)
	}
}

// TestSendGrowing — файл растёт во время отправки: уходит размер из meta (LimitReader), а не «лишние данные».
func TestSendGrowing(t *testing.T) {
	url := local(t)
	r := recvHost(t, url)
	body := bytes.Repeat([]byte("абв"), 100_000)
	f := srcFile(t, "g.bin", body)
	d := r.own(url, []string{f}, "")
	var once sync.Once
	d.Progress = func(p SendProgress) {
		if p.Done > 0 {
			once.Do(func() {
				w, _ := os.OpenFile(f, os.O_APPEND|os.O_WRONLY, 0)
				w.Write(bytes.Repeat([]byte{'z'}, 500_000))
				w.Close()
			})
		}
	}
	if err := sendT(t, d); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(r.dir, "g.bin")); !bytes.Equal(b, body) {
		t.Fatalf("принято %d байт", len(b))
	}
}

// TestFileControlPathIgnored — M2: path в meta сессии управления не действует — файл плоско в «Загрузки».
func TestFileControlPathIgnored(t *testing.T) {
	client, dir := hostWith(t)
	if fm, err := rawMeta(client, fileMsg{Name: "a.txt", Path: "P/sub/a.txt"}, []byte("A")); err != nil || fm.T != "done" {
		t.Fatalf("%+v %v", fm, err)
	}
	if got := readTree(t, dir); len(got) != 1 || got["a.txt"] != "A" {
		t.Fatalf("загрузки %v", got)
	}
}

// TestSendFileLimit — отправитель отказывает файлу больше lim.file до первого байта.
func TestSendFileLimit(t *testing.T) {
	old := rxLimP.Load()
	defer rxLimP.Store(old)
	l := *old
	l.File = 10
	rxLimP.Store(&l)
	url := local(t)
	r := recvHost(t, url)
	if err := sendT(t, r.own(url, []string{srcFile(t, "big", bytes.Repeat([]byte{1}, 11))}, "")); !errors.Is(err, ErrRecvLimit) || errors.As(err, new(*RecvError)) {
		t.Fatalf("файл больше потолка: %v", err)
	}
}
