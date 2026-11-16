package agent

import (
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// linkHook — подмена rootLink в тестах без записи в саму переменную во время прогона: хост предыдущего теста может ещё
// переносить файл (запись rootLink из теста — гонка под -race, круг 2 приёмки Ч10.5). rootLink подменяется один раз в
// init, до любых горутин.
var linkHook atomic.Pointer[func(*os.Root, string, string) error]

func init() {
	rootLink = func(r *os.Root, o, n string) error {
		if h := linkHook.Load(); h != nil {
			return (*h)(r, o, n)
		}
		return r.Link(o, n)
	}
}

// linkSet — подмена до конца теста t.
func linkSet(t *testing.T, f func(*os.Root, string, string) error) {
	linkHook.Store(&f)
	t.Cleanup(func() { linkHook.Store(nil) })
}

// TestRecvSlowPlace — остаток Ч10.2–3: без жёстких ссылок (FAT/exFAT, SMB) часть копируется в конечный файл внутри
// обработчика "end"; копия дольше простоя rxIdle не должна закрывать сессию приёма (rxWatch): файл лёг — отправитель
// получает успех, а не обрыв. Медленная копия — подмена rootLink, ждущая 3 простоя и отвечающая «ссылок нет».
func TestRecvSlowPlace(t *testing.T) {
	defer func(i int64) { rxIdle.Store(i) }(rxIdle.Load())
	rxIdle.Store(int64(600 * time.Millisecond))
	linkSet(t, func(*os.Root, string, string) error { time.Sleep(1800 * time.Millisecond); return syscall.EPERM })
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
