package agent

import (
	"os"
	"syscall"
	"testing"
	"time"
)

// TestRecvSlowPlace — остаток Ч10.2–3: без жёстких ссылок (FAT/exFAT, SMB) часть копируется в конечный файл внутри
// обработчика "end"; копия дольше простоя rxIdle не должна закрывать сессию приёма (rxWatch): файл лёг — отправитель
// получает успех, а не обрыв. Медленная копия — подмена rootLink, ждущая 3 простоя и отвечающая «ссылок нет».
func TestRecvSlowPlace(t *testing.T) {
	defer func(i int64) { rxIdle.Store(i) }(rxIdle.Load())
	rxIdle.Store(int64(600 * time.Millisecond))
	rootLink = func(*os.Root, string, string) error { time.Sleep(1800 * time.Millisecond); return syscall.EPERM }
	defer func() { rootLink = func(r *os.Root, o, n string) error { return r.Link(o, n) } }()
	url := local(t)
	r := recvHost(t, url)
	err := sendT(t, r.own(url, []string{srcFile(t, "big.bin", []byte("payload"))}, ""))
	if err != nil {
		t.Fatalf("копия части дольше простоя оборвала приём: %v", err)
	}
	if b, _ := os.ReadFile(r.dir + "/big.bin"); string(b) != "payload" {
		t.Fatalf("файл не лёг: %q, в папке %v", b, r.files(t))
	}
}
