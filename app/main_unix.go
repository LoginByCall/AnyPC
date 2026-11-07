//go:build linux || darwin

// AnyPC для Linux и macOS: хост + тот же интерфейс в браузере на 127.0.0.1 (своё для ОС — platform_*.go).
// Привязки окна Windows (hostInfo, setPassword…) здесь — локальный HTTP API с токеном.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"anypc/agent"
	"anypc/pake"
	"anypc/ui"
)

func main() {
	noBrowser := flag.Bool("no-browser", false, "не открывать браузер, только напечатать адрес")
	flag.Parse()
	cfgDir, _ := os.UserConfigDir()
	cacheDir, _ := os.UserCacheDir()
	os.MkdirAll(filepath.Join(cacheDir, "AnyPC"), 0o700)
	logw := io.Writer(os.Stderr) // и журнал, и вывод ffmpeg — в терминал и в файл (иначе причину «серого экрана» не узнать)
	if f, err := os.OpenFile(filepath.Join(cacheDir, "AnyPC", "anypc.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		logw = io.MultiWriter(os.Stderr, f)
		log.SetOutput(logw)
	}
	cfg, err := loadConfig(filepath.Join(cfgDir, "AnyPC", "config.json"))
	if err != nil {
		log.Fatal("настройки: ", err)
	}
	for _, b := range deps() {
		if _, err := exec.LookPath(b); err != nil {
			log.Printf("ВНИМАНИЕ: нет %s — %s", b, hint[b])
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a := &agent.Agent{Server: cfg.Server, ID: cfg.ID, Secret: cfg.secret, Key: cfg.key(), FPS: 30,
		Bitrate: agent.Kbps(cfg.Bitrate),
		Confirm: func(cid, peer string) bool { return !cfg.confirm() || agent.AskAccept(cid, peer) }, Capture: hostCapture(cfg.Enc), FileDir: downloads(), Stderr: logw}
	var mu sync.Mutex
	online, session, update := false, "", ""
	a.OnState = func(on bool, s string) { mu.Lock(); online, session = on, s; mu.Unlock() }
	info := func() map[string]any {
		node, pub := cfg.node()
		mu.Lock()
		defer mu.Unlock()
		return map[string]any{"id": cfg.ID, "fp": cfg.fingerprint(), "online": online, "session": session, "hasPass": cfg.hasPass(), "confirm": cfg.confirm(), "version": version, "update": update, "node": node, "nodePub": pub, "server": cfg.Server}
	}
	go watchUpdates(func(v string) { mu.Lock(); update = v; mu.Unlock() })

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	addr := l.Addr().String()
	tok := make([]byte, 16)
	rand.Read(tok)
	token := hex.EncodeToString(tok)
	page, err := shimmed(cfg.Server, token)
	if err != nil {
		log.Fatal(err)
	}
	run := &runner{a: a, ctx: ctx}
	h := handler(addr, token, page, cfg, a, run, info, newFiles(downloads()))
	go http.Serve(l, h)
	url := "http://" + addr + "/?t=" + token
	log.Printf("AnyPC запущен (%s), ID %s. Окно: %s", platformKind(), cfg.ID, url)
	if !*noBrowser {
		exec.Command(openCmd, url).Start()
	}
	run.start(cfg.Server)
	run.wait()
}

// handler — интерфейс и API. Чужие страницы не могут ни прочитать токен, ни вызвать API:
// страница отдаётся только с ?t=токен, API требует заголовок X-Token (кросс-доменный запрос с ним
// упирается в CORS), Host проверяется против DNS rebinding.
func handler(addr, token string, page []byte, cfg *config, a *agent.Agent, run *runner, info func() map[string]any, fl *files) http.Handler {
	files := http.FileServer(http.FS(ui.FS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != addr {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/"):
			if r.Method != http.MethodPost || r.Header.Get("X-Token") != token {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			api(w, r, strings.TrimPrefix(r.URL.Path, "/api/"), cfg, a, run, info, fl)
		case r.URL.Path == "/" || r.URL.Path == "/index.html":
			if r.URL.Query().Get("t") != token {
				http.Error(w, "Откройте ссылку, которую напечатал AnyPC в терминале", http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.Write(page)
		default:
			files.ServeHTTP(w, r)
		}
	})
}

// shimmed — ui/index.html с привязками через локальный API (как WebView2-привязки в Windows).
func shimmed(server, token string) ([]byte, error) {
	b, err := fs.ReadFile(ui.FS, "index.html")
	if err != nil {
		return nil, err
	}
	ws, _ := json.Marshal(server)
	t, _ := json.Marshal(token)
	shim := fmt.Sprintf(`<script>
window.ANYPC = {ws: %s};
(() => {
  const T = %s;
  const api = (n, ...a) => fetch('/api/' + n, {method: 'POST', headers: {'X-Token': T, 'Content-Type': 'application/json'}, body: JSON.stringify(a)})
    .then(async r => { const j = await r.json(); if (!r.ok) throw j.error; return j.result; });
  for (const n of ['hostInfo', 'setPassword', 'setConfirm', 'setNode', 'quit', 'hostDisconnect', 'getClip', 'setClip', 'pakeRespond', 'hostVerify', 'knownGet', 'knownSet', 'fileOpen', 'fileWrite', 'fileFinish', 'fileAbort']) window[n] = (...a) => api(n, ...a);
  window.fullscreen = on => on ? document.documentElement.requestFullscreen().then(() => navigator.keyboard?.lock()).catch(() => {})
                               : document.fullscreenElement && document.exitFullscreen();
})();
</script>
<script>`, ws, t)
	return []byte(strings.Replace(string(b), "<script>", shim, 1)), nil
}

func api(w http.ResponseWriter, r *http.Request, name string, cfg *config, a *agent.Agent, run *runner, info func() map[string]any, fl *files) {
	var args []json.RawMessage
	json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&args) // кусок файла 1 МБ в base64
	str := func(i int) string {
		var s string
		if i < len(args) {
			json.Unmarshal(args[i], &s)
		}
		return s
	}
	num := func(i int) float64 {
		var n float64
		if i < len(args) {
			json.Unmarshal(args[i], &n)
		}
		return n
	}
	var res any
	var err error
	switch name {
	case "fileOpen":
		res, err = fl.Open(str(0), num(1), str(2))
	case "fileWrite":
		err = fl.Write(int(num(0)), str(1))
	case "fileFinish":
		res, err = fl.Finish(int(num(0)))
	case "fileAbort":
		var keep bool
		if len(args) > 1 {
			json.Unmarshal(args[1], &keep)
		}
		fl.Abort(int(num(0)), keep)
	case "hostInfo":
		res = info()
	case "setPassword":
		err = cfg.setPassword(str(0))
	case "setConfirm":
		var on bool
		if len(args) > 0 {
			json.Unmarshal(args[0], &on)
		}
		err = cfg.setConfirm(on)
	case "setNode":
		var pub bool
		if len(args) > 1 {
			json.Unmarshal(args[1], &pub)
		}
		res, err = setNode(cfg, run, str(0), pub)
	case "quit": // вкладка браузера — не процесс: без кнопки программа живёт до Ctrl+C
		a.Disconnect()
		go func() { time.Sleep(300 * time.Millisecond); os.Exit(0) }()
	case "hostDisconnect":
		a.Disconnect()
	case "getClip":
		res, err = agent.ClipText()
	case "setClip":
		err = agent.SetClipText(str(0))
	case "hostVerify":
		res, err = pake.HostVerifyB64(str(0), str(1), str(2), str(3), str(4))
	case "knownGet":
		res = cfg.knownGet(str(0))
	case "knownSet":
		err = cfg.knownSet(str(0), str(1))
	case "pakeRespond":
		res, err = pake.ClientRespondB64(str(0), str(1), str(2), str(3), str(4), str(5))
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"result": res})
}

