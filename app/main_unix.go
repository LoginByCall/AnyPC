//go:build linux || darwin

// AnyPC для Linux и macOS: хост + тот же интерфейс в браузере на 127.0.0.1 (своё для ОС — platform_*.go).
// Привязки окна Windows (hostInfo, setPassword…) здесь — локальный HTTP API с токеном.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"sync/atomic"
	"syscall"
	"time"

	"anypc/agent"
	"anypc/pake"
	"anypc/ui"
)

func main() {
	noBrowser := flag.Bool("no-browser", false, "не открывать браузер; адрес окна — в терминале и в файле window.url рядом с журналом")
	showVersion := flag.Bool("version", false, "напечатать версию и выйти")
	showID := flag.Bool("id", false, "напечатать ID этого компьютера и выйти")
	pwStdin := flag.Bool("password-stdin", false, "задать пароль входа из stdin (первая строка; в терминале — скрытый ввод дважды) и выйти;\nпример: echo 'пароль' | anypc --password-stdin")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "AnyPC %s — удалённый доступ к этому компьютеру (https://www.anypc.org)\n\n"+
			"Запуск: %s [ключи]\n\nКлючи (можно и -ключ, и --ключ):\n", version, filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		cfg, _ := os.UserConfigDir()
		cache, _ := os.UserCacheDir()
		fmt.Fprintf(flag.CommandLine.Output(), "\nНастройки: %s\nЖурнал: %s\n", filepath.Join(cfg, "AnyPC", "config.json"), filepath.Join(cache, "AnyPC", "anypc.log"))
	}
	flag.Parse()
	if *showVersion {
		fmt.Println("AnyPC", version)
		return
	}
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
	if *showID {
		fmt.Println(cfg.ID)
		return
	}
	if done, err := runCLI(cfg); done {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *pwStdin {
		p, err := readPassword(os.Stdin)
		if err == nil {
			err = cfg.setPassword(p)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "пароль:", err)
			os.Exit(1)
		}
		fmt.Println("пароль задан; если AnyPC уже запущен — перезапустите его")
		return
	}
	if !cfg.confirm() && !cfg.otpSet() { // хост обновлён с выключенным подтверждением: без TOTP — снова окно «Разрешить»
		log.Printf("ВНИМАНИЕ: вход без подтверждения выключен, пока не настроен второй фактор (TOTP): каждый вход спросит «Разрешить». Настройте: %s --confirm off", filepath.Base(os.Args[0]))
	}
	for _, b := range deps() {
		if _, err := exec.LookPath(b); err != nil {
			log.Printf("ВНИМАНИЕ: нет %s — %s", b, hint[b])
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a := &agent.Agent{Audio: true, Server: cfg.Server, ID: cfg.ID, Secret: cfg.secret, Key: cfg.key(), FPS: 30, Trusted: cfg.trusted, Trust: cfg.trust,
		Bitrate: agent.Kbps(cfg.Bitrate),
		Confirm: agent.AskAccept, Unattended: func() bool { return !cfg.confirm() }, OTP: cfg.otp, ViewOnly: cfg.viewOnly, // без подтверждения — с TOTP (PLAN.md)
		Capture: hostCapture(cfg.Enc), Locked: hostLocked, FileDir: downloads(), Stderr: logw}
	var mu sync.Mutex
	online, session, update := false, "", ""
	a.OnState = func(on bool, s string) { mu.Lock(); online, session = on, s; mu.Unlock() }
	info := func() map[string]any {
		node, pub := cfg.node()
		mu.Lock()
		defer mu.Unlock()
		return map[string]any{"id": cfg.ID, "fp": cfg.fingerprint(), "online": online, "session": session, "hasPass": cfg.hasPass(), "confirm": cfg.confirm(), "otp": cfg.otpSet(), "viewOnly": cfg.viewOnly(), "version": version, "update": update, "node": node, "nodePub": pub, "server": cfg.Server, "audio": audioInfo(a)}
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
	rand.Read(tok)
	once := &onceCode{code: hex.EncodeToString(tok)}
	run := &runner{a: a, ctx: ctx}
	h := handler(addr, token, page, cfg, a, run, info, newFiles(downloads()), once)
	go http.Serve(l, h)
	// токен — ключ к окну (смена пароля): не в журнал (journald читают администраторы, anypc.log прикладывают к тикетам),
	// а в файл 0600 и, если запущено из терминала, в терминал
	url, urlFile := "http://"+addr+"/?t="+token, filepath.Join(cacheDir, "AnyPC", "window.url")
	os.WriteFile(urlFile, []byte(url+"\n"), 0o600)
	log.Printf("AnyPC запущен (%s), ID %s. Окно: http://%s/ — ссылка с ключом в %s", platformKind(), cfg.ID, addr, urlFile)
	if st, err := os.Stderr.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprintln(os.Stderr, "Окно:", url)
	}
	if !*noBrowser { // аргументы браузера видны всем пользователям ПК (/proc/*/cmdline) — в них одноразовый код, не токен
		openWindow("http://" + addr + "/?n=" + once.code)
	}
	run.start(cfg.Server)
	run.wait()
}

// onceCode — код для первого открытия окна. Токен в аргументах xdg-open/open читал бы любой пользователь ПК;
// код годен один раз, и браузер тратит его сразу. Файл со ссылкой не годится: Firefox из snap (Ubuntu) не читает ~/.config.
// ponytail: локальный пользователь, опрашивающий /proc в цикле, может успеть раньше браузера — тогда окно владельца
// покажет «ссылка уже использована» (заметно); закрыть совсем — ключ через stdin браузера, которого у xdg-open нет.
type onceCode struct {
	code string
	used atomic.Bool
}

func (o *onceCode) use(c string) bool {
	return o != nil && c != "" && subtle.ConstantTimeCompare([]byte(c), []byte(o.code)) == 1 && o.used.CompareAndSwap(false, true)
}

// handler — интерфейс и API. Чужие страницы не могут ни прочитать токен, ни вызвать API:
// страница отдаётся только с ?t=токен, API требует заголовок X-Token (кросс-доменный запрос с ним
// упирается в CORS), Host проверяется против DNS rebinding.
func handler(addr, token string, page []byte, cfg *config, a *agent.Agent, run *runner, info func() map[string]any, fl *files, once *onceCode) http.Handler {
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
		case r.URL.Path == "/" && r.URL.Query().Has("n"): // одноразовый код из аргументов браузера → страница с токеном
			if !once.use(r.URL.Query().Get("n")) {
				http.Error(w, "Ссылка уже использована — откройте адрес из журнала AnyPC", http.StatusForbidden)
				return
			}
			http.Redirect(w, r, "/?t="+token, http.StatusSeeOther)
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
	js := fmt.Sprintf(`
window.ANYPC = {ws: %s, clipPoll: %t};
(() => {
  const T = %s;
  const api = (n, ...a) => fetch('/api/' + n, {method: 'POST', headers: {'X-Token': T, 'Content-Type': 'application/json'}, body: JSON.stringify(a)})
    .then(async r => { const j = await r.json(); if (!r.ok) throw j.error; return j.result; });
  for (const n of ['hostInfo', 'setPassword', 'setConfirm', 'setNode', 'quit', 'hostDisconnect', 'getClip', 'setClip', 'pakeRespond', 'hostVerify', 'knownGet', 'knownSet', 'savedGet', 'savedSet', 'otpNew', 'otpEnable', 'setViewOnly', 'fileOpen', 'fileWrite', 'fileFinish', 'fileAbort', 'audioAnswer', 'audioMic']) window[n] = (...a) => api(n, ...a);
  window.fullscreen = on => on ? document.documentElement.requestFullscreen().then(() => navigator.keyboard?.lock()).catch(() => {})
                               : document.fullscreenElement && document.exitFullscreen();
})();
`, ws, agent.ClipCheap(), t)
	// CSP страницы пускает встроенные скрипты только по хэшу: добавить хэш этого (токен в нём свой на каждый запуск)
	sum := sha256.Sum256([]byte(js))
	page := strings.Replace(string(b), "script-src 'self'", "script-src 'self' 'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'", 1)
	return []byte(strings.Replace(page, "<script>", "<script>"+js+"</script>\n<script>", 1)), nil
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
	case "audioAnswer":
		err = a.AudioAnswer(str(0), str(1))
	case "audioMic":
		var on bool
		if len(args) > 0 {
			json.Unmarshal(args[0], &on)
		}
		a.AudioMic(on)
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
	case "savedGet":
		res = cfg.savedGet(str(0))
	case "savedSet":
		err = cfg.savedSet(str(0), str(1))
	case "setViewOnly":
		var on bool
		if len(args) > 0 {
			json.Unmarshal(args[0], &on)
		}
		err = setViewOnly(cfg, a, on)
	case "otpNew":
		res, err = cfg.otpNew()
	case "otpEnable":
		err = cfg.otpEnable(str(0), str(1))
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

// readPassword — пароль из stdin, а не из аргументов (их видно в ps любому пользователю ПК).
// Терминал: ввод без эха (stty), дважды — опечатку вслепую иначе не заметить. Канал: первая строка.
func readPassword(f *os.File) (string, error) {
	r := bufio.NewReader(f)
	line := func() (string, error) {
		s, err := r.ReadString('\n')
		if err != nil && (err != io.EOF || s == "") {
			return "", errors.New("пустой ввод")
		}
		return strings.TrimRight(s, "\r\n"), nil
	}
	if st, err := f.Stat(); err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return line()
	}
	stty := func(arg string) { c := exec.Command("stty", arg); c.Stdin = f; c.Run() }
	stty("-echo")
	defer stty("echo")
	fmt.Fprint(os.Stderr, "Новый пароль: ")
	p, err := line()
	fmt.Fprint(os.Stderr, "\nЕщё раз: ")
	if err != nil {
		return "", err
	}
	again, err := line()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if p != again {
		return "", errors.New("пароли не совпали")
	}
	return p, nil
}
