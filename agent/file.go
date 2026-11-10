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
	h         hash.Hash
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

// diskReserve — сколько места оставить на диске после приёма: заполненный диск ломает ОС и программы.
const diskReserve = 1 << 30

// room — отказ до приёма, если файл (без уже принятой части) не помещается с запасом diskReserve.
func (r *Receiver) room() error {
	free, err := diskFree(r.dir)
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
	if err == nil {
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

// receiveFile принимает файл от клиента в папку загрузок хоста; active — идущие приёмы этой сессии.
func (a *Agent) receiveFile(dc *webrtc.DataChannel, active *atomic.Int32) {
	r := NewReceiver(a.fileDir())
	var mu sync.Mutex
	state := "new" // new → open → finished; в open занято место в active
	end := func() {
		if state == "open" {
			active.Add(-1)
		}
		state = "finished"
	}
	fail := func(msg string) {
		log.Printf("файл %q: %s", r.name, msg)
		r.Abort(false)
		end()
		sendJSON(dc, fileMsg{T: "err", Msg: msg})
		dc.Close()
	}
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		mu.Lock()
		defer mu.Unlock()
		if state == "finished" {
			return
		}
		if !m.IsString {
			if state != "open" {
				fail("данные до meta")
			} else if err := r.Write(m.Data); err != nil {
				fail(err.Error())
			}
			return
		}
		var fm fileMsg
		json.Unmarshal(m.Data, &fm)
		switch {
		case fm.T == "meta" && state == "new":
			if active.Add(1) > maxRecv {
				active.Add(-1)
				fail(fmt.Sprintf("одновременно принимается не больше %d файлов — дождитесь окончания", maxRecv))
				return
			}
			off, err := r.Open(fm.Name, fm.Size, fm.ID)
			if err != nil {
				active.Add(-1)
				fail(err.Error())
				return
			}
			state = "open"
			if off > 0 {
				log.Printf("файл %q: докачка с %d байт", r.name, off)
			}
			sendJSON(dc, fileMsg{T: "resume", Offset: off})
		case fm.T == "end" && state == "open":
			dst, sum, err := r.Finish()
			if err != nil {
				fail(err.Error())
				return
			}
			end()
			log.Printf("файл принят: %s (%d байт, SHA-256 %s)", dst, r.size, sum)
			sendJSON(dc, fileMsg{T: "done", SHA256: sum})
		case fm.T == "cancel":
			r.Abort(false)
			end()
			dc.Close()
		default:
			fail("неожиданное сообщение")
		}
	})
	dc.OnClose(func() { // обрыв без done/cancel: часть остаётся для докачки
		mu.Lock()
		defer mu.Unlock()
		if state == "open" {
			r.Abort(true)
			log.Printf("файл %q: передача прервана, принято %d из %d байт — докачается при повторной отправке", r.name, r.got, r.size)
		}
		end()
	})
}

// sendFile отправляет файл хоста клиенту по новому каналу "file".
func sendFile(ctx context.Context, pc *webrtc.PeerConnection, path string) error {
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()
	st, err := src.Stat()
	if err != nil {
		return err
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
	sendJSON(dc, fileMsg{T: "meta", Name: filepath.Base(path), Size: st.Size(), ID: fileID(path, st)})
	var off int64
	select {
	case r := <-result:
		if r.T != "resume" || r.Offset < 0 || r.Offset > st.Size() {
			return fmt.Errorf("получатель: %s %s", r.T, r.Msg)
		}
		off = r.Offset
	case <-closed:
		return errors.New("отменено получателем")
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(30 * time.Second):
		return errors.New("получатель не ответил")
	}
	if off > 0 {
		log.Printf("отправка %s: докачка с %d байт", path, off)
		if _, err := src.Seek(off, io.SeekStart); err != nil {
			return err
		}
	}
	buf := make([]byte, fileChunk)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			for dc.BufferedAmount() > fileHigh {
				select {
				case <-low:
				case <-closed:
					return errors.New("отменено получателем")
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			if err := dc.Send(buf[:n]); err != nil {
				return err
			}
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
		if r.T != "done" {
			return fmt.Errorf("получатель: %s %s", r.T, r.Msg)
		}
		log.Printf("файл отправлен: %s (SHA-256 у получателя %s)", path, r.SHA256)
		return nil
	case <-closed:
		return errors.New("отменено получателем")
	case <-ctx.Done():
		return ctx.Err()
	}
}
