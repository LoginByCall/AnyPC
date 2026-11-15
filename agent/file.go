package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/pion/webrtc/v4"
)

// Передача файлов (REQ-F-12): отдельный канал "file" на каждый файл, в любую сторону, с докачкой.
//
//	отправитель → {"t":"meta","name","size","id"}         id — хэш имени/размера/времени изменения
//	получатель  → {"t":"resume","offset"}                 сколько уже есть от прошлой попытки
//	отправитель → двоичные куски ≤ 16 КБ с offset, {"t":"end"}
//	получатель  → {"t":"done","sha256"} | {"t":"err","msg"}, затем закрывает канал.
//
// {"t":"cancel"} от любой стороны — отмена: часть удаляется. Закрытие канала без "done"/"cancel" —
// обрыв: часть остаётся до повторной отправки того же файла (или 7 дней).
// Целостность кусков обеспечивает DTLS; SHA-256 всего файла — для журнала и проверки человеком.
type fileMsg struct {
	T      string `json:"t"`
	Name   string `json:"name,omitempty"`
	Size   int64  `json:"size,omitempty"`
	ID     string `json:"id,omitempty"`
	Offset int64  `json:"offset,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Msg    string `json:"msg,omitempty"`
	Code   string `json:"code,omitempty"` // Ч10.1: в "err" сессии приёма — код отказа (rxWhy, recv.go)
	Path   string `json:"path,omitempty"` // Ч10.2: в "meta" сессии приёма — путь в папке «Папка/подпапка/файл» (safeRel)
}

const (
	fileChunk = 16 << 10 // совместимо со всеми браузерами
	fileHigh  = 4 << 20  // ждать, если в буфере канала больше
)

// reserved — имена устройств Windows (с любым расширением и пробелами перед ним).
var reserved = regexp.MustCompile(`^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(COM|LPT)[0-9¹²³]) *$`)

// safeName — имя файла от другой стороны без путей, управляющих и запрещённых в Windows символов.
func safeName(name string) string {
	name = name[strings.LastIndexAny(name, `/\`)+1:]
	name = strings.Map(func(r rune) rune {
		if r < 32 || strings.ContainsRune(`<>:"/\|?*`, r) || unicode.Is(unicode.Cf, r) { // Cf: U+202E подделывает расширение («фото‮gpj.exe»)
			return '_'
		}
		return r
	}, name)
	name = strings.TrimRight(name, ". ")
	if r := []rune(name); len(r) > 200 {
		name = string(r[len(r)-200:])
	}
	if base := strings.ToUpper(strings.SplitN(name, ".", 2)[0]); name == "" || reserved.MatchString(base) {
		name = "_" + name
	}
	return name
}

// Ч10.2: путь файла в папке от другой стороны (fileMsg.Path). ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (A13): проверка путей.
const (
	relMaxDepth = 32   // составляющих пути, считая папку и имя файла
	relMaxLen   = 1024 // байт во всём пути
	relMaxComp  = 255  // байт в одной составляющей
)

var errRel = errors.New("недопустимый путь в папке")

// relBidi — подмены направления письма (U+202A–202E, U+2066–2069): «фото‮gpj.exe».
func relBidi(r rune) bool { return r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069 }

// safeRel — путь файла в папке «Папка/подпапка/файл» (разделитель только "/") → составляющие, годные на любой ОС.
// Отказ (errRel): пусто, длиннее relMaxLen, не UTF-8; "\" и ":" где угодно (UNC, \\?\, «C:», потоки NTFS «a:b»);
// меньше двух или больше relMaxDepth составляющих; пустая составляющая (абсолютный путь, «//»), «.», «..», только
// точки и пробелы, длиннее relMaxComp; управляющие C0, DEL, C1; подмены направления; имена устройств Windows (CON,
// NUL.txt, COM1…); папка «.anypc-…» (место частей докачки). Запрещённые в Windows «<>"|?*» → «_», точки и пробелы в
// конце составляющей отбрасываются (Windows их срезает сам — имена совпали бы иначе молча: совпадения — «(1)»).
func safeRel(p string) ([]string, error) {
	if p == "" || len(p) > relMaxLen || !utf8.ValidString(p) || strings.ContainsAny(p, `\:`) {
		return nil, errRel
	}
	parts := strings.Split(p, "/")
	if len(parts) < 2 || len(parts) > relMaxDepth {
		return nil, errRel
	}
	for i, c := range parts {
		if c == "." || c == ".." || len(c) > relMaxComp {
			return nil, errRel
		}
		for _, r := range c {
			if r < 32 || r == 0x7f || r >= 0x80 && r <= 0x9f || relBidi(r) {
				return nil, errRel
			}
		}
		c = strings.TrimRight(strings.Map(func(r rune) rune {
			if strings.ContainsRune(`<>"|?*`, r) {
				return '_'
			}
			return r
		}, c), ". ")
		if c == "" || reserved.MatchString(strings.ToUpper(strings.SplitN(c, ".", 2)[0])) || i == 0 && strings.HasPrefix(c, ".anypc-") {
			return nil, errRel
		}
		parts[i] = c
	}
	return parts, nil
}

// errRelDir — составляющая пути в папке приёма уже есть, но не папка (файл, символьная ссылка, точка повторной
// обработки Windows): за ней не идём.
var errRelDir = errors.New("в пути папки — не папка (файл или ссылка)")

// mkRoot — новая папка приёма dir/name, а если занято — «name (1)»… (Mkdir не идёт по ссылке с этим именем: занято).
func mkRoot(dir, name string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	for i := range 1000 {
		n := name
		if i > 0 {
			n = fmt.Sprintf("%s (%d)", name, i)
		}
		err := root.Mkdir(n, 0o755)
		if err == nil {
			return n, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	return "", errors.New("нет свободного имени папки")
}

// placeIn переносит часть dir/part в dir/rel[0]/…/rel[n-1] (rel — составляющие после safeRel, rel[0] — папка приёма
// от mkRoot). Всё — через os.Root каталога dir: ни ссылка, ни «..» не выведут за него (Windows — и точки повторной
// обработки); каждая папка пути — настоящая папка (Lstat, не ссылка), иначе errRelDir. Занятое имя файла — «(1)».
func placeIn(dir, part string, rel []string) (string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	sub := ""
	for i, c := range rel[:len(rel)-1] {
		sub = filepath.Join(sub, c)
		if i > 0 {
			if err := root.Mkdir(sub, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
				return "", err
			}
		}
		if st, err := root.Lstat(sub); err != nil || st.Mode().Type() != os.ModeDir {
			return "", errRelDir
		}
	}
	name := rel[len(rel)-1]
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := range 1000 {
		n := name
		if i > 0 {
			n = fmt.Sprintf("%s (%d)%s", stem, i, ext)
		}
		dst := filepath.Join(sub, n)
		err := root.Link(part, dst)
		if err == nil {
			root.Remove(part) // не удалилась — уберёт cleanParts
			return filepath.Join(dir, dst), nil
		}
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if _, e := root.Lstat(dst); !errors.Is(e, os.ErrNotExist) { // FAT/exFAT без жёстких ссылок: Rename — только на свободное
			continue
		}
		return filepath.Join(dir, dst), root.Rename(part, dst)
	}
	return "", errors.New("нет свободного имени")
}

// freePath — dir/name, а если занято — "name (1).ext", "name (2).ext"…
func freePath(dir, name string) string {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	p := filepath.Join(dir, name)
	for i := 1; ; i++ {
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			return p
		}
		p = filepath.Join(dir, fmt.Sprintf("%s (%d)%s", stem, i, ext))
	}
}

// place переносит part в свободное имя dir/name. Link, в отличие от Rename, не перезаписывает файл,
// появившийся между проверкой freePath и переносом (другой приём, пользователь): занято → следующее имя.
func place(part, dir, name string) (string, error) {
	for range 100 {
		dst := freePath(dir, name)
		err := os.Link(part, dst)
		if err == nil {
			os.Remove(part) // не удалилась — уберёт cleanParts
			return dst, nil
		}
		if !errors.Is(err, os.ErrExist) { // FAT/exFAT, SMB без жёстких ссылок — как раньше
			return dst, os.Rename(part, dst)
		}
	}
	return "", errors.New("нет свободного имени")
}

func (a *Agent) fileDir() string {
	if a.FileDir != "" {
		return a.FileDir
	}
	return DownloadsDir()
}

func sendJSON(dc *webrtc.DataChannel, m fileMsg) {
	b, _ := json.Marshal(m)
	dc.SendText(string(b))
}

// Receiver — приём файла на диск с докачкой. Общий для хоста (канал "file") и программы
// (окно получает файл с удалённого ПК и передаёт куски сюда через привязки).
type Receiver struct {
	dir       string
	f         *os.File
	part, dst string
	name      string
	size, got int64
	checked   int64 // got на последней проверке места (Write)
	h         hash.Hash
	rel       []string // Ч10.2: путь в папке приёма (safeRel; rel[0] — папка от mkRoot); nil — файл прямо в dir
}

var idRe = regexp.MustCompile(`^[0-9a-f]{16,64}$`)

func NewReceiver(dir string) *Receiver { return &Receiver{dir: dir} }

// Open начинает приём; offset — сколько байт уже есть от прерванной попытки с тем же id.
func (r *Receiver) Open(name string, size int64, id string) (offset int64, err error) {
	if r.f != nil || size < 0 {
		return 0, errors.New("неверное начало приёма")
	}
	if err := os.MkdirAll(r.dir, 0o755); err != nil {
		return 0, err
	}
	cleanParts(r.dir)
	if !idRe.MatchString(id) { // без id — без докачки
		id = hex.EncodeToString(randBytes(16))
	}
	r.name, r.size, r.h = safeName(name), size, sha256.New()
	r.part = filepath.Join(r.dir, ".anypc-"+id+".part")
	if err := r.room(); err != nil {
		return 0, err
	}
	if r.f, err = os.OpenFile(r.part, os.O_RDWR|os.O_CREATE, 0o644); err != nil {
		return 0, err
	}
	n, err := io.Copy(r.h, r.f) // хэш уже принятого; позиция — в конце
	if err != nil || n > size {
		r.f.Truncate(0)
		r.f.Seek(0, io.SeekStart)
		r.h.Reset()
		n = 0
	}
	r.got = n
	return n, nil
}

// freeSpace — свободно на диске каталога (подмена — в тестах).
var freeSpace = diskFree

// diskReserve — сколько места оставить на диске после приёма: заполненный диск ломает ОС и программы.
// diskCheck — через сколько принятых байт проверять запас снова (Write).
const diskReserve, diskCheck = 1 << 30, 1 << 20

// room — отказ до приёма, если файл (без уже принятой части) не помещается с запасом diskReserve.
func (r *Receiver) room() error {
	free, err := freeSpace(r.dir)
	if err != nil {
		return nil // не узнали — не мешаем; Write всё равно остановится на ошибке записи
	}
	need := r.size
	if st, err := os.Stat(r.part); err == nil && st.Size() <= need {
		need -= st.Size()
	}
	if need > int64(free)-diskReserve {
		return fmt.Errorf("мало места на диске: файл %.1f ГБ, свободно %.1f ГБ (1 ГБ должен остаться)", float64(r.size)/(1<<30), float64(free)/(1<<30))
	}
	return nil
}

func (r *Receiver) Write(b []byte) error {
	if r.f == nil || r.got+int64(len(b)) > r.size {
		return errors.New("лишние данные")
	}
	if r.got-r.checked >= diskCheck { // запас места — на каждом мегабайте: диск могли занять во время приёма
		r.checked = r.got
		if free, err := freeSpace(r.dir); err == nil && int64(free) < diskReserve+int64(len(b)) {
			return fmt.Errorf("мало места на диске: свободно %.1f ГБ (1 ГБ должен остаться)", float64(free)/(1<<30))
		}
	}
	if _, err := r.f.Write(b); err != nil {
		return err // например, нет места на диске
	}
	r.h.Write(b)
	r.got += int64(len(b))
	return nil
}

// Finish проверяет размер и даёт файлу настоящее имя (свободное: «name (1).ext»…).
func (r *Receiver) Finish() (dst, sum string, err error) {
	if r.f == nil {
		return "", "", errors.New("приём не начат")
	}
	err = r.f.Close()
	r.f = nil
	if err == nil && r.got != r.size {
		err = fmt.Errorf("получено %d из %d байт", r.got, r.size)
	}
	if err == nil && r.rel != nil {
		r.dst, err = placeIn(r.dir, filepath.Base(r.part), r.rel)
	} else if err == nil {
		r.dst, err = place(r.part, r.dir, r.name)
	}
	if err != nil {
		os.Remove(r.part)
		return "", "", err
	}
	return r.dst, hex.EncodeToString(r.h.Sum(nil)), nil
}

// Abort: keep — оставить часть для докачки (обрыв), иначе удалить (отмена).
func (r *Receiver) Abort(keep bool) {
	if r.f == nil {
		return
	}
	r.f.Close()
	r.f = nil
	if !keep {
		os.Remove(r.part)
	}
}

// cleanParts удаляет брошенные части старше 7 дней.
func cleanParts(dir string) {
	old, _ := filepath.Glob(filepath.Join(dir, ".anypc-*.part"))
	for _, p := range old {
		if st, err := os.Stat(p); err == nil && time.Since(st.ModTime()) > 7*24*time.Hour {
			os.Remove(p)
		}
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// fileID — id для докачки: тот же файл (путь, размер, время изменения) → тот же id.
func fileID(path string, st os.FileInfo) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", path, st.Size(), st.ModTime().UnixNano())))
	return hex.EncodeToString(h[:16])
}

// maxRecv — сколько файлов сессия принимает одновременно: каждый держит открытый файл и место на диске.
const maxRecv = 4

// fileOK — сессия принимает файлы: управление или сессия приёма (Ч10.1, recv.go).
func (s *session) fileOK() bool { return s.control() || s.rx.Load() != nil }

// receiveFile принимает файл от клиента в папку загрузок хоста; active — идущие приёмы этой сессии. Сессия ушла
// в просмотр — приём обрывается сразу (REQ-F-26), ждавший очереди не открывается. Сессия приёма (Ч10.1) — ещё
// потолки и окно «Принять?» (rxCount, rxConfirm); в журнал — без имён файлов (одна строка на приём, rxState.end).
func (a *Agent) receiveFile(dc *webrtc.DataChannel, active *atomic.Int32, s *session) {
	r := NewReceiver(a.fileDir())
	rx := s.rx.Load()
	name := func() string { // имя для журнала
		if rx != nil {
			return "приёма от " + rx.from
		}
		return fmt.Sprintf("%q", r.name)
	}
	var mu sync.Mutex
	state := "new"  // new → wait → open → finished; в open занято место в active
	var done func() // снять обрыв при переходе в просмотр
	var held int64  // сессия приёма: место в общем потолке .part (rxReserve)
	end := func() {
		if state == "open" {
			active.Add(-1)
		}
		if held > 0 {
			a.rxFree(held)
			held = 0
		}
		state = "finished"
		if done != nil {
			done()
		}
	}
	failCode := func(code, msg string) {
		log.Printf("файл %s: %s", name(), msg)
		if rx != nil && !rx.own { // чужому — только код: ни путей, ни свободного места этого ПК (M5)
			if rxWhy[code] == "" {
				code = "io"
			}
			msg = rxWhy[code]
		}
		r.Abort(false)
		end()
		sendJSON(dc, fileMsg{T: "err", Msg: msg, Code: code})
		dc.Close()
	}
	fail := func(msg string) { failCode("", msg) }
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		mu.Lock()
		defer mu.Unlock()
		if state == "finished" {
			return
		}
		if rx != nil {
			rx.touch()
		}
		if !s.fileOK() {
			fail(viewFiles)
			return
		}
		if !m.IsString {
			if state != "open" {
				fail("данные до meta")
			} else if err := r.Write(m.Data); err != nil {
				fail(err.Error())
			} else if rx != nil {
				rx.moved.Add(int64(len(m.Data)))
			}
			return
		}
		var fm fileMsg
		json.Unmarshal(m.Data, &fm)
		switch {
		case fm.T == "meta" && state == "new":
			var rel []string // Ч10.2: файл папки — путь в ней (только сессия приёма хоста, объявившего папки)
			if rx != nil && fm.Path != "" && rx.lim.Dirs {
				var err error
				if rel, err = safeRel(fm.Path); err != nil {
					failCode("path", rxWhy["path"])
					return
				}
			}
			if rx != nil {
				if code := rx.count(fm.Size, false); code != "" {
					failCode(code, rxWhy[code])
					return
				}
			}
			// Лишние файлы ждут очереди, а не получают отказ: клиент шлёт все выбранные сразу (выбрали 10 — 6 отказов).
			// Ждать здесь нельзя: обработчик зовётся из цикла чтения SCTP — встали бы и идущие передачи.
			state = "wait"
			go func() {
				if rx != nil { // окно «Принять?» (чужой ПК) — до места в очереди
					q := RecvReq{Name: safeName(fm.Name), Size: fm.Size}
					if rel != nil {
						q.Name = strings.Join(rel, "/")
					}
					if code := a.rxConfirm(s, rx, q); code != "" {
						mu.Lock()
						if state == "wait" {
							failCode(code, rxWhy[code])
						}
						mu.Unlock()
						return
					}
				}
				// ponytail: опрос раз в 200 мс; семафор на сессию — если ожидающих станут сотни
				for active.Add(1) > maxRecv {
					active.Add(-1)
					time.Sleep(200 * time.Millisecond)
					mu.Lock()
					waiting := state == "wait"
					mu.Unlock()
					if !waiting { // отмена или обрыв, пока ждали
						return
					}
				}
				mu.Lock()
				defer mu.Unlock()
				if state != "wait" {
					active.Add(-1)
					return
				}
				if !s.fileOK() { // ушли в просмотр, пока ждали места
					active.Add(-1)
					fail(viewFiles)
					return
				}
				if rx != nil { // исключили или открепили, пока ждали места
					if code := a.rxStill(rx); code != "" {
						active.Add(-1)
						failCode(code, rxWhy[code])
						return
					}
					if !a.rxReserve(fm.Size) { // общий потолок открытых .part всех сессий приёма
						active.Add(-1)
						failCode("disk", "общий потолок частей приёма")
						return
					}
					held = fm.Size
				}
				if rx != nil && !rx.own { // часть чужого не хранится — и id частей других отправителей ему не открывать
					fm.ID = ""
				}
				var top string
				if rel != nil { // папка приёма этой папки отправителя: первая — новая «Загрузки/<папка>[ (n)]»
					var err error
					if top, err = rx.rxRoot(r.dir, rel[0]); err != nil {
						active.Add(-1)
						fail(err.Error())
						return
					}
				}
				off, err := r.Open(fm.Name, fm.Size, fm.ID)
				if err != nil {
					active.Add(-1)
					fail(err.Error())
					return
				}
				if rel != nil {
					r.rel = append([]string{top}, rel[1:]...)
				}
				state = "open"
				if off > 0 {
					log.Printf("файл %s: докачка с %d байт", name(), off)
				}
				sendJSON(dc, fileMsg{T: "resume", Offset: off})
			}()
		case fm.T == "end" && state == "open":
			dst, sum, err := r.Finish()
			if errors.Is(err, errRelDir) { // в пути папки — ссылка или файл (Ч10.2)
				failCode("path", err.Error())
				return
			}
			if err != nil {
				fail(err.Error())
				return
			}
			end()
			if rx != nil {
				if !rx.own {
					markForeign(dst) // метка происхождения: ОС спросит перед запуском (M8)
				}
				rx.mu.Lock()
				rx.nf++
				rx.nb += r.size
				rx.mu.Unlock()
			} else {
				log.Printf("файл принят: %s (%d байт, SHA-256 %s)", dst, r.size, sum)
			}
			sendJSON(dc, fileMsg{T: "done", SHA256: sum})
		case fm.T == "cancel":
			r.Abort(false)
			end()
			dc.Close()
		default:
			fail("неожиданное сообщение")
		}
	})
	if rx == nil { // сессия приёма в просмотр не уходит (управления у неё нет)
		d := s.whileControl(func() {
			mu.Lock()
			defer mu.Unlock()
			if state != "finished" {
				fail(viewFiles)
			}
		})
		mu.Lock()
		if state == "finished" {
			d()
		} else {
			done = d
		}
		mu.Unlock()
	}
	dc.OnClose(func() { // обрыв без done/cancel: часть остаётся для докачки
		mu.Lock()
		defer mu.Unlock()
		if state == "open" {
			keep := rx == nil || rx.own // часть от чужого не хранится (M4)
			r.Abort(keep)
			log.Printf("файл %s: передача прервана, принято %d из %d байт%s", name(), r.got, r.size, map[bool]string{true: " — докачается при повторной отправке"}[keep])
		}
		end()
	})
}

// sendFile отправляет файл хоста клиенту по новому каналу "file".
func sendFile(ctx context.Context, pc *webrtc.PeerConnection, path string) error {
	return sendFileWait(ctx, pc, path, 30*time.Second, false)
}

// sendFileWait — sendFile, ответ получателя на meta ждать wait (приём, Ч10.1: окно «Принять?» у получателя).
// Отказ с кодом (сессия приёма) — *RecvError. quiet — без путей в журнале (отправитель приёма, Ч10.1).
func sendFileWait(ctx context.Context, pc *webrtc.PeerConnection, path string, wait time.Duration, quiet bool) error {
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()
	st, err := src.Stat()
	if err != nil {
		return err
	}
	return sendOpen(ctx, pc, src, fileMsg{T: "meta", Name: filepath.Base(path), Size: st.Size(), ID: fileID(path, st)}, path, wait, quiet, nil)
}

// sendOpen — открытый src (meta — его "meta": имя, размер, id, путь в папке) по новому каналу "file"; prog — сколько
// байт ушло (докачка — сразу offset). Отмена ctx после meta — {"t":"cancel"}: получатель удаляет часть.
func sendOpen(ctx context.Context, pc *webrtc.PeerConnection, src *os.File, meta fileMsg, path string, wait time.Duration, quiet bool, prog func(int64)) error {
	if prog == nil {
		prog = func(int64) {}
	}
	dc, err := pc.CreateDataChannel("file", nil)
	if err != nil {
		return err
	}
	defer dc.Close()
	open, closed, low := make(chan struct{}), make(chan struct{}), make(chan struct{}, 1)
	result := make(chan fileMsg, 4)
	dc.OnOpen(func() { close(open) })
	dc.OnClose(func() { close(closed) })
	dc.SetBufferedAmountLowThreshold(fileHigh / 4)
	dc.OnBufferedAmountLow(func() {
		select {
		case low <- struct{}{}:
		default:
		}
	})
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		var fm fileMsg
		if json.Unmarshal(m.Data, &fm) == nil {
			select {
			case result <- fm:
			default:
			}
		}
	})
	select {
	case <-open:
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
		return errors.New("канал не открылся")
	}
	size := meta.Size
	sendJSON(dc, meta)
	cancel := func() error { // "cancel" — за кусками в буфере канала: ждать, пока получатель закроет канал (удалив часть)
		sendJSON(dc, fileMsg{T: "cancel"})
		select {
		case <-closed:
		case <-time.After(sendGrace - 500*time.Millisecond):
		}
		return ctx.Err()
	}
	var off int64
	select {
	case r := <-result:
		if r.T == "err" && r.Code != "" {
			return &RecvError{Code: r.Code, Msg: r.Msg}
		}
		if r.T != "resume" || r.Offset < 0 || r.Offset > size {
			return fmt.Errorf("получатель: %s %s", r.T, r.Msg)
		}
		off = r.Offset
	case <-closed:
		select { // отказ с кодом и закрытие канала приходят почти вместе
		case r := <-result:
			if r.T == "err" && r.Code != "" {
				return &RecvError{Code: r.Code, Msg: r.Msg}
			}
		default:
		}
		return errors.New("отменено получателем")
	case <-ctx.Done():
		return cancel()
	case <-time.After(wait):
		return errors.New("получатель не ответил")
	}
	if off > 0 { // quiet — только без журнала: докачка без Seek послала бы начало файла в конец части
		if !quiet {
			log.Printf("отправка %s: докачка с %d байт", path, off)
		}
		if _, err := src.Seek(off, io.SeekStart); err != nil {
			return err
		}
		prog(off)
	}
	in := io.LimitReader(src, size-off) // файл вырос после Stat — лишнего не слать (получатель отказал бы)
	buf := make([]byte, fileChunk)
	for {
		if ctx.Err() != nil {
			return cancel()
		}
		n, err := in.Read(buf)
		if n > 0 {
			for dc.BufferedAmount() > fileHigh {
				select {
				case <-low:
				case <-closed:
					return errors.New("отменено получателем")
				case <-ctx.Done():
					return cancel()
				}
			}
			if err := dc.Send(buf[:n]); err != nil {
				return err
			}
			prog(int64(n))
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	sendJSON(dc, fileMsg{T: "end"})
	select {
	case r := <-result:
		if r.T == "err" && r.Code != "" {
			return &RecvError{Code: r.Code, Msg: r.Msg}
		}
		if r.T != "done" {
			return fmt.Errorf("получатель: %s %s", r.T, r.Msg)
		}
		if !quiet {
			log.Printf("файл отправлен: %s (SHA-256 у получателя %s)", path, r.SHA256)
		}
		return nil
	case <-closed:
		select { // отказ с кодом (место на диске, путь) и закрытие приходят почти вместе
		case r := <-result:
			if r.T == "err" && r.Code != "" {
				return &RecvError{Code: r.Code, Msg: r.Msg}
			}
		default:
		}
		return errors.New("отменено получателем")
	case <-ctx.Done():
		return cancel()
	}
}
