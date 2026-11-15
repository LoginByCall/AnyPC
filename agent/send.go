package agent

// Ч10.2–Ч10.3 «Отправить» (UI-REDESIGN.md, «Ч10 «Отправить»»): что отправить — файлы, папки целиком, текст или буфер
// обмена этого ПК; кому и как доказывается — recv.go (SendTo, sendVia). Здесь — план: что именно уйдёт, в каком
// порядке и сколько байт, и его отправка по каналам "file"/"text" сессии приёма.
//
// Папка (Ч10.2): каждый её файл — "meta" с полем path «Папка/подпапка/файл» (fileMsg.Path; safeRel на обеих
// сторонах). Внутри папки ничьи символьные ссылки не идут (ни на файл, ни на папку, ни внутрь, ни наружу), как и
// устройства, сокеты, FIFO: они в Skipped. Файлы папки открываются через os.Root папки — ссылка, подложенная после
// обхода, наружу не выведет. Имя, негодное на той стороне (safeRel: «a:b», «CON», глубже 32…), — тоже в Skipped:
// отказ получателя на середине папки хуже. Пустые папки не передаются. Хост Ч10.1 папок не объявляет (lim.dirs) —
// папку ему не шлём (ErrRecvOldDirs), файлы и текст — да.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"syscall"

	"github.com/pion/webrtc/v4"
)

// PickFile, PickDir — окно выбора файла или папки ОС на этом ПК для «Отправить» (Ч10.3): путь выбирает человек, страница
// получает только метку (app/send.go). ctx кончился — окно закрывается (кроме Windows).
func PickFile(ctx context.Context) (string, bool) { return pickFile(ctx) }
func PickDir(ctx context.Context) (string, bool)  { return pickDir(ctx) }

// SendProgress — ход отправки: Item — номер текущего (с 1; текст — последний), Done и Total — байт (с текстом).
type SendProgress struct {
	Item, Items int
	Done, Total int64
}

// SendResult — итог SendTo: ключ получателя, сколько ушло, что пропущено в папках (пути внутри папок, «/»).
type SendResult struct {
	HostPub []byte
	Files   int
	Bytes   int64
	Text    bool
	Skipped []string
}

var (
	ErrSendEmpty   = errors.New("отправка: нечего отправлять") // окну (app/send.go); SendTo пустой план шлёт: проверка и закрепление
	ErrSendClip    = errors.New("отправка: буфер обмена пуст, больше 1 МБ или недоступен (Wayland: окно AnyPC должно быть в фокусе)")
	ErrSendRoot    = errors.New("отправка: корень диска целиком не отправляется — выберите папку")
	ErrSendNotFile = errors.New("отправка: не файл и не папка")
	ErrSendMany    = errors.New("отправка: больше 100000 файлов")
)

// clipRead — буфер обмена этого ПК целиком (до 1 МБ; больше — ошибка, не обрезка); подмена — в тестах: wl-paste в
// GNOME крадёт фокус.
var clipRead = clipReadFull

// sendMaxItems — файлов в плане: обход огромного дерева кончается до соединения (переменная — тест).
var sendMaxItems = 100_000

// sendItem — файл плана: отдельный (root nil, path) или файл папки (root — её os.Root, rel — путь в ней).
type sendItem struct {
	path string   // полный путь: id докачки (fileID)
	root *os.Root // файл папки: открыть через root
	rel  string   // путь в root (разделители ОС)
	wire string   // fileMsg.Path «Папка/…/файл»; "" — отдельный файл
	size int64
}

type sendPlan struct {
	items   []sendItem
	roots   []*os.Root
	text    string
	total   int64
	dirs    bool
	skipped []string

	sentFiles int
	sentBytes int64
	sentText  bool
}

func (p *sendPlan) close() {
	for _, r := range p.roots {
		r.Close()
	}
}

// makePlan — отдельные файлы (ссылка, выбранная человеком, — её цель; должна быть обычным файлом), затем папки
// (обход без ссылок, см. начало файла), затем текст.
func makePlan(files, dirs []string, text string) (_ *sendPlan, err error) {
	p := &sendPlan{text: text, total: int64(len(text))}
	defer func() { // ошибка — открытые os.Root папок закрыть (return nil, err обнулил бы именованный p)
		if err != nil {
			p.close()
		}
	}()
	for _, f := range files {
		st, err := os.Stat(f)
		if err != nil {
			return nil, err
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: %s", ErrSendNotFile, f)
		}
		p.items = append(p.items, sendItem{path: f, size: st.Size()})
		p.total += st.Size()
	}
	for _, d := range dirs {
		if d, err = filepath.Abs(d); err != nil { // «.» и «sub/..» — папка со своим именем
			return nil, err
		}
		if filepath.Dir(d) == d { // «/», «C:\», UNC-корень «\\srv\share\»: имени нет, и целиком — не то, что хотели
			return nil, ErrSendRoot
		}
		if st, err := os.Stat(d); err != nil {
			return nil, err
		} else if !st.IsDir() {
			return nil, fmt.Errorf("%w: %s", ErrSendNotFile, d)
		}
		root, err := os.OpenRoot(d)
		if err != nil {
			return nil, err
		}
		p.roots, p.dirs = append(p.roots, root), true
		name := filepath.Base(d)
		skip := func(rel string) { p.skipped = append(p.skipped, name+"/"+rel) }
		err = fs.WalkDir(root.FS(), ".", func(rel string, e fs.DirEntry, err error) error {
			if err != nil { // папку не прочитать — пропустить её, а не всю отправку
				skip(rel)
				if e != nil && e.IsDir() && rel != "." {
					return fs.SkipDir
				}
				return nil
			}
			wire := path.Join(name, rel)
			switch t := e.Type(); {
			case rel == ".":
				return nil
			case t&fs.ModeSymlink != 0: // WalkDir по ссылкам и так не ходит; не шлём и ссылку на файл
				skip(rel)
			case e.IsDir():
				if _, err := safeRel(wire + "/x"); err != nil { // имя или глубина не годны — вся ветка
					skip(rel + "/")
					return fs.SkipDir
				}
			case !t.IsRegular():
				skip(rel)
			default:
				info, err := e.Info()
				if _, bad := safeRel(wire); bad != nil || err != nil {
					skip(rel)
					return nil
				}
				if len(p.items) >= sendMaxItems {
					return ErrSendMany
				}
				p.items = append(p.items, sendItem{path: filepath.Join(d, filepath.FromSlash(rel)), root: root,
					rel: filepath.FromSlash(rel), wire: wire, size: info.Size()})
				p.total += info.Size()
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return p, nil
}

// fits — план в потолках получателя ("rx" lim) и получатель понимает папки; иначе — до первого байта.
func (p *sendPlan) fits(l *rxLimits) error {
	if p.dirs && (l == nil || !l.Dirs) {
		return ErrRecvOldDirs
	}
	if l == nil {
		return nil
	}
	n, sum := len(p.items), int64(0)
	if p.text != "" {
		n++
	}
	if n > l.Items {
		return fmt.Errorf("%w: файлов и текстов %d, тот ПК примет %d", ErrRecvLimit, n, l.Items)
	}
	if int64(len(p.text)) > l.Text {
		return fmt.Errorf("%w: текст %d байт, тот ПК примет %d", ErrRecvLimit, len(p.text), l.Text)
	}
	for _, it := range p.items {
		if it.size > l.File {
			return fmt.Errorf("%w: файл %d байт, тот ПК примет %d", ErrRecvLimit, it.size, l.File)
		}
		sum += it.size
	}
	if sum > l.Total {
		return fmt.Errorf("%w: %d байт, тот ПК примет %d", ErrRecvLimit, sum, l.Total)
	}
	return nil
}

// open — файл плана: файл папки — через её os.Root (ссылка наружу — ошибка), и только обычный файл.
func (it sendItem) open() (*os.File, os.FileInfo, error) {
	var f *os.File
	var err error
	// O_NONBLOCK: FIFO, подложенный после обхода, не вешает открытие (дальше — отказ «не обычный файл»)
	if it.root != nil {
		f, err = it.root.OpenFile(it.rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	} else {
		f, err = os.OpenFile(it.path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	}
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err == nil && !st.Mode().IsRegular() {
		err = fmt.Errorf("%w: %s", ErrSendNotFile, it.rel)
	}
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, st, nil
}

// send — файлы по очереди, затем текст; prog — ход (из этого потока).
func (p *sendPlan) send(ctx context.Context, pc *webrtc.PeerConnection, prog func(SendProgress)) error {
	items := len(p.items)
	if p.text != "" {
		items++
	}
	cur := SendProgress{Items: items, Total: p.total}
	report := func() {
		if prog != nil {
			prog(cur)
		}
	}
	for i, it := range p.items {
		cur.Item = i + 1
		report()
		f, st, err := it.open()
		if err != nil {
			return err
		}
		start := cur.Done
		meta := fileMsg{T: "meta", Name: filepath.Base(it.rel), Size: st.Size(), ID: fileID(it.path, st), Path: it.wire}
		if it.root == nil {
			meta.Name = filepath.Base(it.path)
		}
		err = sendOpen(ctx, pc, f, meta, it.path, recvWait, true, func(n int64) { cur.Done += n; report() })
		f.Close()
		if err != nil {
			return err
		}
		cur.Done = start + it.size // файл изменился после плана — ход по плану
		p.sentFiles++
		p.sentBytes += st.Size()
	}
	if p.text != "" {
		cur.Item = items
		report()
		if err := sendText(ctx, pc, p.text); err != nil {
			return err
		}
		cur.Done += int64(len(p.text))
		p.sentText = true
	}
	report()
	return nil
}
