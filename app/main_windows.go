// AnyPC.exe — одна программа на оба ПК: «это рабочее место» (хост) + подключение к удалённому.
// Окно — WebView2 (есть в Windows 11), интерфейс — ui/index.html; ffmpeg скачивается при первом запуске (ffmpeg.go).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"anypc/agent"
	"anypc/pake"
	"anypc/ui"

	webview2 "github.com/jchv/go-webview2"
)

var (
	user32     = syscall.NewLazyDLL("user32.dll")
	pGetWL     = user32.NewProc("GetWindowLongPtrW")
	pSetWL     = user32.NewProc("SetWindowLongPtrW")
	pGetWR     = user32.NewProc("GetWindowRect")
	pSetWP     = user32.NewProc("SetWindowPos")
	pMonFromW  = user32.NewProc("MonitorFromWindow")
	pGetMonInf = user32.NewProc("GetMonitorInfoW")
	pMsgBox    = user32.NewProc("MessageBoxW")
)

func fatal(msg string) {
	log.Print(msg)
	t, _ := syscall.UTF16PtrFromString("AnyPC")
	m, _ := syscall.UTF16PtrFromString(msg)
	pMsgBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x10)
	os.Exit(1)
}

func main() {
	// Per-Monitor DPI aware v2: координаты DXGI (физические пиксели) и ввода совпадают при масштабе 125–200 %.
	user32.NewProc("SetProcessDpiAwarenessContext").Call(^uintptr(3)) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
	dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "AnyPC")
	os.MkdirAll(dir, 0o700)
	logf, err := os.OpenFile(filepath.Join(dir, "anypc.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err == nil {
		log.SetOutput(logf) // ponytail: без ротации; REQ-F-16 (журнал ≤ 10 МБ) — Э3
	}
	cfg, err := loadConfig(filepath.Join(os.Getenv("APPDATA"), "AnyPC", "config.json"))
	if err != nil {
		fatal("Настройки: " + err.Error())
	}
	cfg.codeUsed() // режим «Спрашивать»: новый код при запуске — программа могла кончиться посреди сессии (REQ-S-23)
	// FFmpeg — в фоне: окно и сигнализация работают сразу, захват — когда загрузится (повтор раз в 30 с без сети).
	var ffMu sync.Mutex
	ff, ffState := "", "0" // путь к ffmpeg.exe; ffState — проценты загрузки, "err" или "" (готов)
	zipName := path.Base(ffMirrors[0])
	ffLocal = []string{filepath.Join(agent.DownloadsDir(), zipName)}
	if exe, err := os.Executable(); err == nil {
		ffLocal = append(ffLocal, filepath.Join(filepath.Dir(exe), zipName))
	}
	go func() {
		for {
			p, err := ensureFFmpeg(dir, func(d, t int64) { ffMu.Lock(); ffState = strconv.Itoa(int(d * 100 / max(t, 1))); ffMu.Unlock() })
			ffMu.Lock()
			if err == nil {
				ff, ffState = p, ""
				ffMu.Unlock()
				return
			}
			ffState = "err"
			ffMu.Unlock()
			log.Printf("FFmpeg: %v — повтор через 30 с", err)
			time.Sleep(30 * time.Second)
		}
	}()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatal("Локальный порт интерфейса: " + err.Error())
	}
	go http.Serve(l, http.FileServer(http.FS(ui.FS)))

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		AutoFocus:     true,
		DataPath:      filepath.Join(dir, "webview"),
		WindowOptions: webview2.WindowOptions{Title: "AnyPC — ID " + cfg.ID, Width: 1100, Height: 720, Center: true},
	})
	if w == nil {
		fatal("Не найден Microsoft Edge WebView2 Runtime. Установите его с сайта Microsoft и запустите AnyPC снова.")
	}
	defer w.Destroy()

	ctx, cancel := context.WithCancel(context.Background())
	a := &agent.Agent{Audio: true,
		Server: cfg.Server, ID: cfg.ID, Secret: cfg.secret, Key: cfg.key(), FPS: 30, Stderr: logf, Trusted: cfg.trusted, Trust: cfg.trust,
		Bitrate: agent.Kbps(cfg.Bitrate),
		Confirm: agent.AskAccept, ConfirmControl: agent.AskControl, Unattended: func() bool { return !cfg.confirm() }, OTP: cfg.otp, ViewOnly: cfg.viewOnly, // без подтверждения — с TOTP (PLAN.md)
		CodeUsed: cfg.codeUsed, // «Спрашивать»: код сменить после сессии и блокировки (REQ-S-23)
		Capture: func(ctx context.Context, c agent.Cap) (*exec.Cmd, error) { // выход DXGI c.Mon
			ffMu.Lock()
			ff := ff
			ffMu.Unlock()
			if ff == "" {
				return nil, errors.New("FFmpeg ещё загружается")
			}
			return exec.CommandContext(ctx, ff, agent.FFArgs(fmt.Sprintf("desktop:%d", max(c.Mon, 0)), cfg.Enc, c)...), nil
		},
	}
	var mu sync.Mutex
	online, session, update := false, "", ""
	info := func() map[string]any {
		node, pub := cfg.node()
		mu.Lock()
		defer mu.Unlock()
		return map[string]any{"id": cfg.id(), "fp": cfg.fingerprint(), "online": online, "session": session, "hasPass": cfg.hasPass(), "confirm": cfg.confirm(), "otp": cfg.otpSet(), "users": cfg.users(), "code": cfg.code(), "viewOnly": cfg.viewOnly(), "version": version, "ffmpeg": ffSnap(&ffMu, &ffState), "update": update, "node": node, "nodePub": pub, "server": cfg.server(), "audio": audioInfo(a)}
	}
	go watchUpdates(func(v string) { mu.Lock(); update = v; mu.Unlock() }) // окно опрашивает hostInfo
	a.OnState = func(on bool, s string) {
		mu.Lock()
		online, session = on, s
		mu.Unlock()
		j, _ := json.Marshal(info())
		w.Dispatch(func() { w.Eval("window.onHostState && onHostState(" + string(j) + ")") })
	}
	w.Bind("hostInfo", info)
	w.Bind("audioAnswer", a.AudioAnswer)
	w.Bind("audioMic", a.AudioMic)
	w.Bind("openUpdate", func() { exec.Command("rundll32", "url.dll,FileProtocolHandler", updateSite).Start() }) // адрес фиксирован: странице не открыть произвольный
	w.Bind("openSite", func() { exec.Command("rundll32", "url.dll,FileProtocolHandler", siteHome).Start() })
	w.Bind("setPassword", func(p string) error { return dropAfter(a, cfg.setPassword(p)) })
	w.Bind("setConfirm", func(on bool) error { return dropAfter(a, cfg.setConfirm(on)) }) // смена режима рвёт сессию по паролю/записи
	w.Bind("otpNew", cfg.otpNew)
	w.Bind("setViewOnly", func(on bool) error { return setViewOnly(cfg, a, on) })
	w.Bind("otpEnable", func(s, code, user string) error { return dropAfter(a, cfg.otpEnable(s, code, user)) })
	w.Bind("otpOff", cfg.otpOff)
	w.Bind("newCode", func() (string, error) { return newCode(cfg, a) })
	w.Bind("userSet", func(name, pw, rights string) error { return dropAfter(a, cfg.setUser(name, pw, rights)) })
	w.Bind("userDel", func(name string) error { return dropAfter(a, cfg.delUser(name)) })
	run := &runner{a: a, ctx: ctx}
	w.Bind("setNode", func(node string, public bool) (string, error) { return setNode(cfg, run, node, public) })
	w.Bind("hostDisconnect", a.Disconnect)
	w.Bind("fullscreen", func(on bool) { setFullscreen(uintptr(w.Window()), on) })
	w.Bind("minimize", func() { user32.NewProc("ShowWindowAsync").Call(uintptr(w.Window()), 6) }) // SW_MINIMIZE
	w.Bind("pakeRespond", pake.ClientRespondB64)
	w.Bind("hostVerify", pake.HostVerifyB64)
	w.Bind("knownGet", cfg.knownGet)
	w.Bind("knownSet", cfg.knownSet)
	w.Bind("savedGet", cfg.savedGet)
	w.Bind("savedSet", cfg.savedSet)
	fl := newFiles(agent.DownloadsDir()) // и клиент, и хост — в настоящие «Загрузки» (могут быть перенесены)
	w.Bind("fileOpen", fl.Open)
	w.Bind("fileWrite", fl.Write)
	w.Bind("fileFinish", fl.Finish)
	w.Bind("fileAbort", fl.Abort)
	w.Bind("getClip", agent.ClipText)
	w.Bind("setClip", agent.SetClipText)
	srv, _ := json.Marshal(cfg.Server)
	w.Init("window.ANYPC = {ws: " + string(srv) + "};")
	w.Navigate("http://" + l.Addr().String() + "/")

	log.Printf("AnyPC запущен, ID %s", cfg.ID)
	run.start(cfg.Server)
	w.Run()
	cancel()
	run.wait()
}

// ffSnap — состояние загрузки FFmpeg для окна.
func ffSnap(mu *sync.Mutex, st *string) string {
	mu.Lock()
	defer mu.Unlock()
	return *st
}

type rect struct{ L, T, R, B int32 }

type monitorInfo struct {
	Size    uint32
	Monitor rect
	Work    rect
	Flags   uint32
}

var saved struct {
	style uintptr
	r     rect
}

// setFullscreen: окно без рамки на весь монитор и обратно (HTML Fullscreen в WebView2 занимает только окно).
func setFullscreen(h uintptr, on bool) {
	const gwlStyle = ^uintptr(15) // GWL_STYLE = -16
	const overlapped = 0x00CF0000 // WS_OVERLAPPEDWINDOW
	const flags = 0x0020 | 0x0200 // SWP_FRAMECHANGED | SWP_NOOWNERZORDER
	if on {
		saved.style, _, _ = pGetWL.Call(h, gwlStyle)
		pGetWR.Call(h, uintptr(unsafe.Pointer(&saved.r)))
		mi := monitorInfo{Size: uint32(unsafe.Sizeof(monitorInfo{}))}
		m, _, _ := pMonFromW.Call(h, 2) // MONITOR_DEFAULTTONEAREST
		pGetMonInf.Call(m, uintptr(unsafe.Pointer(&mi)))
		r := mi.Monitor
		pSetWL.Call(h, gwlStyle, saved.style&^overlapped)
		pSetWP.Call(h, 0, uintptr(r.L), uintptr(r.T), uintptr(r.R-r.L), uintptr(r.B-r.T), flags)
		return
	}
	if saved.style == 0 {
		return
	}
	r := saved.r
	pSetWL.Call(h, gwlStyle, saved.style)
	pSetWP.Call(h, 0, uintptr(r.L), uintptr(r.T), uintptr(r.R-r.L), uintptr(r.B-r.T), flags|0x0004) // SWP_NOZORDER
}
