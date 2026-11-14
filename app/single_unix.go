//go:build linux || darwin

package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// lockInstance — flock(LOCK_EX|LOCK_NB) на dir/anypc.lock. Блокировка — на открытом файле: вторая попытка и в том же
// процессе получает отказ; дескриптор с O_CLOEXEC (os.OpenFile) — ffmpeg и браузер его не наследуют.
func lockInstance(dir string) (unlock func(), err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "anypc.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errRunning
		}
		return nil, fmt.Errorf("flock %s: %w", f.Name(), err)
	}
	return func() { f.Close() }, nil
}

// secondShow — что делает вторая копия с окном первой: с --no-browser (автозапуск) — ничего, иначе showRunning.
func secondShow(noBrowser bool, urlFile string) func() error {
	if noBrowser {
		return nil
	}
	return func() error { return showRunning(urlFile) }
}

// alreadyNotice — окно первой не открылось: уведомление рабочего стола, если есть notify-send (Linux); иначе только журнал.
var alreadyNotice = func() {
	if p, err := exec.LookPath("notify-send"); err == nil {
		exec.Command(p, "AnyPC", "AnyPC уже запущен — откройте окно значком AnyPC").Run()
	}
}

// showRunning — окно запущенной копии: её адрес и токен — из её window.url (0600, тот же пользователь), запрос
// showWindow — в её API; окно она открывает своим способом (Chrome, браузер, WKWebView) с одноразовым кодом —
// токен в аргументы браузера не попадает.
func showRunning(urlFile string) error {
	b, err := os.ReadFile(urlFile)
	if err != nil {
		return err
	}
	u, err := url.Parse(strings.TrimSpace(string(b)))
	if err != nil || u.Hostname() != "127.0.0.1" || u.Query().Get("t") == "" {
		return fmt.Errorf("в %s не адрес окна", urlFile)
	}
	req, _ := http.NewRequest(http.MethodPost, "http://"+u.Host+"/api/showWindow", strings.NewReader("[]"))
	req.Header.Set("X-Token", u.Query().Get("t"))
	cl := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }} // X-Token — только по адресу из файла
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("запущенная копия ответила %s", resp.Status)
	}
	return nil
}
