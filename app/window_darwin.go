package main

// Своё окно и значок в строке меню на Маке (window_darwin.m). AppKit работает только в главном потоке: init закрепляет
// за ним main(), main() отдаёт программу горутине (hostMain) и при первом окне или значке уходит в [NSApp run].
// Без графического сеанса (ssh, служба вне Aqua) AppKit не запускается: окно — прежним `open <url>`, значка нет.

/*
#cgo LDFLAGS: -framework Cocoa -framework WebKit
#include <stdlib.h>
int anypcGUI(void);
void anypcRun(void);
int anypcOpen(const char *url, const char *title, int monitor, int main, const char *seed);
void anypcEval(int win, const char *body, int seq);
void anypcClose(int win);
char *anypcScreens(void);
void anypcTray(const char *title, const char *help, const char *quit);
void anypcTrayOff(void);
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

func init() {
	runtime.LockOSThread() // main() — на главном потоке процесса
	startTray = macTray
}

var (
	uiOnce sync.Once
	uiOK   bool
	uiGo   = make(chan struct{})
)

// uiStart — запустить AppKit (один раз); false — графического сеанса нет.
func uiStart() bool {
	uiOnce.Do(func() {
		if uiOK = C.anypcGUI() != 0; uiOK {
			close(uiGo)
		} else {
			log.Printf("нет графического сеанса: своего окна и значка в строке меню не будет")
		}
	})
	return uiOK
}

// mainLoop — f в горутине (её конец — конец программы), главный поток — AppKit, когда он понадобится.
func mainLoop(f func()) {
	go func() { f(); os.Exit(0) }()
	<-uiGo
	C.anypcRun() // не возвращается
}

func cstr(s string) *C.char {
	if s == "" {
		return nil
	}
	return C.CString(s)
}

// nativeOpen — окно WKWebView с адресом u (одноразовый код в нём — не в argv и не в журнале); 0 — не создано.
func nativeOpen(u, title string, monitor int, main bool, seed string) int {
	if !uiStart() {
		return 0
	}
	cu, ct, cs := cstr(u), cstr(title), cstr(seed)
	defer C.free(unsafe.Pointer(cu))
	defer C.free(unsafe.Pointer(ct))
	defer C.free(unsafe.Pointer(cs))
	m := C.int(0)
	if main {
		m = 1
	}
	return int(C.anypcOpen(cu, ct, C.int(monitor), m, cs))
}

// openWindow — главное окно AnyPC: по умолчанию браузер, как раньше; своё (WKWebView) — с ANYPC_MACWIN=1
// (не создалось — тоже браузер). Окна ПК и значок в строке меню — свои всегда.
// ponytail: своё главное окно по умолчанию — до переноса mine/users/stats в config.json (FINDINGS): localStorage
// браузера в WKWebView не переходит, у пользователей пропали бы «Мои ПК».
func openWindow(u string) {
	if !mainNative(os.Getenv) || nativeOpen(u, "AnyPC", -1, true, "") == 0 {
		openBrowser(u)
	}
}

// mainNative — главное окно своё: переменная окружения ANYPC_MACWIN=1.
func mainNative(getenv func(string) string) bool { return getenv("ANYPC_MACWIN") == "1" }

var openBrowser = func(u string) { exec.Command("open", u).Start() } // в тестах подменяется

func nativeClose(w int) { C.anypcClose(C.int(w)) }

type evalRes struct {
	ok int // 1 — ответ, 0 — ошибка JS, -1 — окна нет
	s  string
}

var errClosed = errors.New("окно закрыто")

var evals = struct {
	sync.Mutex
	seq int
	m   map[int]chan evalRes
}{m: map[int]chan evalRes{}}

//export goEvalDone
func goEvalDone(seq, ok C.int, res *C.char) {
	evals.Lock()
	ch := evals.m[int(seq)]
	delete(evals.m, int(seq))
	evals.Unlock()
	if ch != nil {
		ch <- evalRes{int(ok), C.GoString(res)}
	}
}

// wkEval — выражение expr (может быть Promise) в окне win; ответ — JSON его значения.
func wkEval(ctx context.Context, win int, expr string) (string, error) {
	ch := make(chan evalRes, 1)
	evals.Lock()
	evals.seq++
	seq := evals.seq
	evals.m[seq] = ch
	evals.Unlock()
	cb := C.CString("return JSON.stringify(await (" + expr + ") ?? null)")
	C.anypcEval(C.int(win), cb, C.int(seq))
	C.free(unsafe.Pointer(cb))
	select {
	case r := <-ch:
		if r.ok < 0 {
			return "", errClosed
		}
		if r.ok == 0 {
			return "", errors.New(r.s)
		}
		return r.s, nil
	case <-ctx.Done():
		evals.Lock()
		delete(evals.m, seq)
		evals.Unlock()
		return "", fmt.Errorf("не дождался %s: %w", expr, ctx.Err())
	}
}

func wkUntil(ctx context.Context, win int, expr string) error {
	for {
		if r, err := wkEval(ctx, win, "!!("+expr+")"); r == "true" {
			return nil
		} else if ctx.Err() != nil || errors.Is(err, errClosed) {
			return err
		}
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// macWins — окна ПК в своих NSWindow (UI-REDESIGN, решение 6 на Маке): тот же сценарий, что chromeWin.open.
type macWins struct {
	base  string
	issue func() string
}

func nativeWins(base string, issue func() string) pcOpener { return macWins{base, issue} }

func (m macWins) open(ctx context.Context, id string, monitor int, seed map[string]string) (err error) {
	src, err := seedScript(m.base, seed)
	if err != nil {
		return err
	}
	s, err := m.screens(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", errNoWindow, err)
	}
	if monitor >= len(s) {
		return fmt.Errorf("нет монитора %d", monitor)
	}
	w := nativeOpen(m.base+"/?n="+m.issue(), "AnyPC — "+id, monitor, false, src)
	if w == 0 {
		return errNoWindow
	}
	defer func() {
		if err != nil {
			nativeClose(w)
		}
	}()
	idj := jsStr(id)
	frame := fmt.Sprintf("[...document.querySelectorAll('#frames iframe')].find(f => f.src.includes('embed=' + %s))", idj)
	if err = wkUntil(ctx, w, "typeof myPcAdd === 'function'"); err != nil {
		return err
	}
	if _, err = wkEval(ctx, w, "myPcAdd("+idj+")"); err != nil {
		return err
	}
	if err = wkUntil(ctx, w, frame+"?.contentWindow?.embedSetActive"); err != nil {
		return err
	}
	// кнопка полного экрана фрейма → myPcFull окна → window.fullscreen (window_darwin.m) → toggleFullScreen: свой Space
	_, err = wkEval(ctx, w, frame+".contentDocument.getElementById('fsbtn').click()")
	return err
}

func (macWins) screens(context.Context) ([]screenInfo, error) {
	if !uiStart() {
		return nil, errors.New("нет графического сеанса")
	}
	p := C.anypcScreens()
	defer C.free(unsafe.Pointer(p))
	var s []screenInfo
	return s, json.Unmarshal([]byte(C.GoString(p)), &s)
}

var tray struct {
	sync.Mutex
	open, quit func()
}

// macTray — значок в строке меню до конца ctx; пункты — как в трее Linux (trayMenu).
func macTray(ctx context.Context, id string, open, quit func()) {
	if !uiStart() {
		return
	}
	tray.Lock()
	tray.open, tray.quit = open, quit
	tray.Unlock()
	t, h, q := C.CString(trayTitle(id)), C.CString("Помочь кому-то…"), C.CString("Выйти")
	C.anypcTray(t, h, q)
	C.free(unsafe.Pointer(t))
	C.free(unsafe.Pointer(h))
	C.free(unsafe.Pointer(q))
	<-ctx.Done()
	C.anypcTrayOff()
}

//export goTrayClick
func goTrayClick(tag C.int) {
	tray.Lock()
	f := tray.open
	if tag == trayQuit {
		f = tray.quit
	}
	tray.Unlock()
	if f != nil {
		go f() // из главного потока: окно создаётся через него же (dispatch_sync), ждать здесь нельзя
	}
}

//export goQuit
func goQuit() {
	tray.Lock()
	f := tray.quit
	tray.Unlock()
	if f == nil {
		f = func() { os.Exit(0) }
	}
	go f()
}

//export goOpenSite
func goOpenSite(which C.int) {
	u := updateSite
	if which == 1 {
		u = siteHome
	}
	go exec.Command("open", u).Run() // адреса фиксированы в программе: странице не открыть произвольный
}
