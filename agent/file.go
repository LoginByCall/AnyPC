package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pion/webrtc/v4"
)

// Передача файлов (REQ-F-12): отдельный канал "file" на каждый файл, в любую сторону.
//
//	отправитель → {"t":"meta","name","size"}, двоичные куски ≤ 16 КБ, {"t":"end"}
//	получатель  → {"t":"done","sha256"} | {"t":"err","msg"}, затем закрывает канал.
//
// Закрытие канала до "done" = отмена: получатель удаляет недокачанный файл.
// Целостность кусков обеспечивает DTLS; SHA-256 всего файла — для журнала и проверки человеком.
type fileMsg struct {
	T      string `json:"t"`
	Name   string `json:"name,omitempty"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Msg    string `json:"msg,omitempty"`
}

const (
	fileChunk = 16 << 10 // совместимо со всеми браузерами
	fileHigh  = 4 << 20  // ждать, если в буфере канала больше
)

var reserved = map[string]bool{"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "LPT1": true, "LPT2": true, "LPT3": true}

// safeName — имя файла от другой стороны без путей, управляющих и запрещённых в Windows символов.
func safeName(name string) string {
	name = name[strings.LastIndexAny(name, `/\`)+1:]
	name = strings.Map(func(r rune) rune {
		if r < 32 || strings.ContainsRune(`<>:"/\|?*`, r) {
			return '_'
		}
		return r
	}, name)
	name = strings.TrimRight(name, ". ")
	if r := []rune(name); len(r) > 200 {
		name = string(r[len(r)-200:])
	}
	if base := strings.ToUpper(strings.SplitN(name, ".", 2)[0]); name == "" || reserved[base] {
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

func (a *Agent) fileDir() string {
	if a.FileDir != "" {
		return a.FileDir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Downloads")
}

func sendJSON(dc *webrtc.DataChannel, m fileMsg) {
	b, _ := json.Marshal(m)
	dc.SendText(string(b))
}

// receiveFile принимает файл от клиента в папку загрузок хоста.
func (a *Agent) receiveFile(dc *webrtc.DataChannel) {
	var (
		f         *os.File
		part, dst string
		size, got int64
		h         = sha256.New()
		done      bool
	)
	fail := func(msg string) {
		log.Printf("файл %q: %s", dst, msg)
		sendJSON(dc, fileMsg{T: "err", Msg: msg})
		done = true
		dc.Close()
	}
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		if done {
			return
		}
		if !m.IsString {
			if f == nil || got+int64(len(m.Data)) > size {
				fail("лишние данные")
				return
			}
			if _, err := f.Write(m.Data); err != nil {
				fail(err.Error()) // например, нет места на диске
				return
			}
			h.Write(m.Data)
			got += int64(len(m.Data))
			return
		}
		var fm fileMsg
		json.Unmarshal(m.Data, &fm)
		switch {
		case fm.T == "meta" && f == nil && fm.Size >= 0:
			dir := a.fileDir()
			os.MkdirAll(dir, 0o755)
			dst = freePath(dir, safeName(fm.Name))
			part, size = dst+".anypc-part", fm.Size
			var err error
			if f, err = os.Create(part); err != nil {
				fail(err.Error())
			}
		case fm.T == "end" && f != nil:
			err := f.Close()
			f = nil
			if err == nil && got != size {
				err = fmt.Errorf("получено %d из %d байт", got, size)
			}
			if err == nil {
				dst = freePath(filepath.Dir(dst), filepath.Base(dst)) // имя могли занять за время передачи
				err = os.Rename(part, dst)
			}
			if err != nil {
				os.Remove(part)
				fail(err.Error())
				return
			}
			sum := hex.EncodeToString(h.Sum(nil))
			log.Printf("файл принят: %s (%d байт, SHA-256 %s)", dst, size, sum)
			done = true
			sendJSON(dc, fileMsg{T: "done", SHA256: sum})
		default:
			fail("неожиданное сообщение")
		}
	})
	dc.OnClose(func() { // отмена или обрыв: не оставлять недокачанное
		if f != nil {
			f.Close()
			os.Remove(part)
			log.Printf("файл %q: передача прервана", dst)
		}
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
	result := make(chan fileMsg, 1)
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
	sendJSON(dc, fileMsg{T: "meta", Name: filepath.Base(path), Size: st.Size()})
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
			return errors.New(r.Msg)
		}
		log.Printf("файл отправлен: %s (SHA-256 у получателя %s)", path, r.SHA256)
		return nil
	case <-closed:
		return errors.New("отменено получателем")
	case <-ctx.Done():
		return ctx.Err()
	}
}
