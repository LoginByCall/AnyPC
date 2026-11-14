//go:build linux || darwin

// «ПК как монитор» (UI-REDESIGN, решение 6, маршрут L3): удалённый ПК — в своём окне Chrome во весь экран на выбранном
// мониторе; окном AnyPC управляет по Chrome DevTools Protocol. Только канал pipe (fd 3 — команды Chrome, fd 4 — ответы,
// JSON с \0 в конце): отладочный TCP-порт дал бы любому локальному процессу окно со страницей и токеном.
// Chrome не отлаживает профиль по умолчанию — свой профиль в каталоге настроек AnyPC (0700).
// Измерено (Chrome 157, Wayland): Chrome выходит, когда AnyPC закрывает pipe; requestFullscreen({screen}) и keyboard.lock
// работают после grantPermissions(windowManagement) и activateTarget; hidden-цели по pipe запрещены, minimized не действует.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

// cdpConn — соединение CDP по паре pipe: запрос {id, method, params, sessionId} и ответ {id, result|error};
// события (без id) пропускаются.
type cdpConn struct {
	w    io.WriteCloser
	wmu  sync.Mutex // запись сообщения целиком
	mu   sync.Mutex
	next int
	wait map[int]chan cdpReply
	done chan struct{}
	err  error  // причина закрытия; задаётся до close(done)
	kill func() // убить Chrome (запись в pipe не прошла в срок); nil — нечего
	bctx string // свой контекст браузера (Target.createBrowserContext): история и кэш — в памяти, не в профиле
}

type cdpReply struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func newCDP(r io.Reader, w io.WriteCloser) *cdpConn {
	c := &cdpConn{w: w, wait: map[int]chan cdpReply{}, done: make(chan struct{})}
	go c.read(bufio.NewReaderSize(r, 64<<10))
	return c
}

func (c *cdpConn) read(r *bufio.Reader) {
	for {
		b, err := r.ReadBytes(0)
		if err != nil {
			c.close(fmt.Errorf("cdp: канал закрыт (%v)", err))
			return
		}
		var m cdpReply
		if json.Unmarshal(b[:len(b)-1], &m) != nil || m.ID == 0 {
			continue
		}
		c.mu.Lock()
		ch := c.wait[m.ID]
		delete(c.wait, m.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- m // буфер 1: читатель не ждёт ушедшего по ctx
		}
	}
}

func (c *cdpConn) close(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return
	}
	c.err = err
	close(c.done)
	c.w.Close()
}

func (c *cdpConn) alive() bool {
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

// call — команда method (session "" — браузер, иначе сессия страницы); результат — в out, если не nil.
func (c *cdpConn) call(ctx context.Context, session, method string, params, out any) error {
	if params == nil {
		params = struct{}{}
	}
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return c.err
	}
	c.next++
	id, ch := c.next, make(chan cdpReply, 1)
	c.wait[id] = ch
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.wait, id); c.mu.Unlock() }()
	msg, err := json.Marshal(struct {
		ID      int    `json:"id"`
		Method  string `json:"method"`
		Params  any    `json:"params"`
		Session string `json:"sessionId,omitempty"`
	}{id, method, params, session})
	if err != nil {
		return err
	}
	c.wmu.Lock()
	if d, ok := c.w.(interface{ SetWriteDeadline(time.Time) error }); ok { // Chrome завис и не читает — не ждать вечно
		dl, has := ctx.Deadline()
		if !has {
			dl = time.Now().Add(10 * time.Second)
		}
		d.SetWriteDeadline(dl)
	}
	_, err = c.w.Write(append(msg, 0))
	c.wmu.Unlock()
	if err != nil {
		c.close(err)
		if c.kill != nil {
			c.kill()
		}
		return err
	}
	select {
	case m := <-ch:
		if m.Error != nil {
			return fmt.Errorf("%s: %s", method, m.Error.Message)
		}
		if out != nil {
			return json.Unmarshal(m.Result, out)
		}
		return nil
	case <-c.done:
		return c.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// eval — выражение в странице (обещание дожидается); результат по значению — в out.
func (c *cdpConn) eval(ctx context.Context, session, expr string, gesture bool, out any) error {
	var r struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		Exc *struct {
			Text      string `json:"text"`
			Exception struct {
				Description string `json:"description"`
			} `json:"exception"`
		} `json:"exceptionDetails"`
	}
	if err := c.call(ctx, session, "Runtime.evaluate", map[string]any{"expression": expr, "awaitPromise": true, "returnByValue": true, "userGesture": gesture}, &r); err != nil {
		return err
	}
	if r.Exc != nil { // описание исключения — со стеком и адресами страницы (?t=токен): в ошибку — первая строка без них
		d, _, _ := strings.Cut(r.Exc.Exception.Description, "\n")
		return fmt.Errorf("страница: %s %s", scrub(r.Exc.Text), scrub(d))
	}
	if out != nil && len(r.Result.Value) > 0 {
		return json.Unmarshal(r.Result.Value, out)
	}
	return nil
}

var secretRe = regexp.MustCompile(`([?&][tn]=)[^\s&#"'\x60)]*`)

// scrub — убрать из текста для журнала токен (?t=) и код окна (?n=).
func scrub(s string) string { return secretRe.ReplaceAllString(s, "${1}…") }

// until — ждать, пока выражение не станет true (страница грузится).
func (c *cdpConn) until(ctx context.Context, session, expr string) error {
	for {
		var ok bool
		if err := c.eval(ctx, session, expr, false, &ok); err == nil && ok {
			return nil
		} else if !c.alive() {
			return c.err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("не дождался %s: %w", expr, ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// chromeWin — свой процесс Chrome для окон ПК: запускается при первом окне, после выхода Chrome — заново.
type chromeWin struct {
	base  string        // http://127.0.0.1:порт — источник страницы
	issue func() string // одноразовый код окна (?n=), уходит по pipe, не в argv
	dir   string        // профиль Chrome AnyPC
	look  func(string) (string, error)
	mu    sync.Mutex
	c     *cdpConn
	bad   map[string]bool // браузеры, не ответившие по pipe (snap за обёрткой-скриптом и т. п.): до перезапуска AnyPC — мимо
}

var cdpStartWait = 10 * time.Second // сколько ждать ответа Chrome по pipe при запуске

// pcWin — окна ПК (только Linux: main_unix.go); nil — нет.
var pcWin *chromeWin

// pcFallback — прежнее поведение (окно AnyPC в браузере), когда Chrome по pipe не открылся или pcWin нет (Мак).
var pcFallback func()

// cdpBrowsers — Chromium-браузеры с CDP по pipe. Snap (Chromium Ubuntu) — мимо: каталог ~/.config ему закрыт.
var cdpBrowsers = []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge"}

func cdpBrowser(look func(string) (string, error), real func(string) (string, error)) string {
	for _, b := range cdpBrowsers {
		p, err := look(b)
		if err != nil {
			continue
		}
		if r, err := real(p); strings.HasPrefix(p, "/snap/") || (err == nil && strings.HasPrefix(r, "/snap/")) {
			continue
		}
		return p
	}
	return ""
}

// chromeArgs — аргументы Chrome: в них нет ни кода окна, ни токена (/proc/*/cmdline читают все пользователи ПК).
func chromeArgs(dir string) []string {
	return []string{"--remote-debugging-pipe", "--user-data-dir=" + dir, "--no-first-run", "--no-default-browser-check", "--no-startup-window"}
}

func (w *chromeWin) conn(ctx context.Context) (*cdpConn, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.c != nil && w.c.alive() {
		return w.c, nil
	}
	w.c = nil
	bin := cdpBrowser(func(n string) (string, error) {
		p, err := w.look(n)
		if err == nil && w.bad[p] {
			return "", errors.New("не ответил по pipe")
		}
		return p, err
	}, filepath.EvalSymlinks)
	if bin == "" {
		return nil, errors.New("нет Chrome, Chromium или Edge (не snap), ответившего по pipe")
	}
	if err := profileDir(w.dir); err != nil {
		return nil, err
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		return nil, err
	}
	// Без systemd-run --scope (ср. launch): Chrome всё равно выходит вместе с pipe, то есть с AnyPC
	cmd := exec.Command(bin, chromeArgs(w.dir)...)
	cmd.ExtraFiles = []*os.File{inR, outW} // fd 3 и fd 4 Chrome
	err = cmd.Start()
	inR.Close()
	outW.Close()
	if err != nil {
		inW.Close()
		outR.Close()
		w.markBad(bin)
		return nil, err
	}
	c := newCDP(outR, inW)
	c.kill = func() { cmd.Process.Kill() }
	go func() { err := cmd.Wait(); c.close(fmt.Errorf("Chrome вышел (%v)", err)); outR.Close() }()
	var v struct {
		Product string `json:"product"`
	}
	vctx, cancel := context.WithTimeout(ctx, cdpStartWait)
	defer cancel()
	var b struct {
		ID string `json:"browserContextId"`
	}
	err = c.call(vctx, "", "Browser.getVersion", nil, &v)
	if err == nil { // измерено приёмщиком: в своём контексте полный экран и keyboard.lock работают, в профиле — ни адресов, ни кодов
		err = c.call(vctx, "", "Target.createBrowserContext", map[string]any{"disposeOnDetach": true}, &b)
	}
	if err != nil {
		c.close(err)
		cmd.Process.Kill()
		w.markBad(bin)
		return nil, fmt.Errorf("%s по pipe: %w", filepath.Base(bin), err)
	}
	c.bctx = b.ID
	log.Printf("окно ПК: %s по pipe, профиль %s", v.Product, w.dir)
	w.c = c
	return c, nil
}

func (w *chromeWin) markBad(bin string) {
	if w.bad == nil {
		w.bad = map[string]bool{}
	}
	w.bad[bin] = true
}

// profileDir — каталог профиля: абсолютный, свой (uid), не ссылка, 0700.
func profileDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("профиль Chrome: путь %q не абсолютный (нет каталога настроек)", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !fi.IsDir() || !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("профиль Chrome %s: не свой каталог (или ссылка)", dir)
	}
	return os.Chmod(dir, 0o700)
}

// closeTarget — закрыть окно после неудачи (повтор не плодит окна).
func closeTarget(c *cdpConn, tid string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.call(ctx, "", "Target.closeTarget", map[string]any{"targetId": tid}, nil)
}

var errNoWindow = errors.New("окно не открыто") // ошибка до появления окна: можно открыть прежнее

// page — новое окно на странице path; ждёт ready. Возвращает соединение, цель и сессию.
func (w *chromeWin) page(ctx context.Context, path, seed, ready string) (*cdpConn, string, string, error) {
	c, err := w.conn(ctx)
	if err != nil {
		return nil, "", "", fmt.Errorf("%w: %v", errNoWindow, err)
	}
	var t struct {
		TargetID string `json:"targetId"`
	}
	if err := c.call(ctx, "", "Target.createTarget", map[string]any{"url": "about:blank", "newWindow": true, "browserContextId": c.bctx}, &t); err != nil {
		return nil, "", "", fmt.Errorf("%w: %v", errNoWindow, err)
	}
	var s struct {
		SessionID string `json:"sessionId"`
	}
	err = c.call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": t.TargetID, "flatten": true}, &s)
	if err == nil && seed != "" { // без Page.enable скрипт не выполняется (измерено)
		if err = c.call(ctx, s.SessionID, "Page.enable", nil, nil); err == nil {
			err = c.call(ctx, s.SessionID, "Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": seed}, nil)
		}
	}
	if err == nil { // grantPermissions отклонил бы источнику все прочие разрешения (микрофон, буфер) — измерено приёмщиком
		err = c.call(ctx, "", "Browser.setPermission", map[string]any{"permission": map[string]any{"name": "window-management"}, "setting": "granted", "origin": w.base, "browserContextId": c.bctx}, nil)
	}
	if err == nil {
		err = c.call(ctx, s.SessionID, "Page.navigate", map[string]any{"url": w.base + path}, nil)
	}
	if err == nil {
		err = c.until(ctx, s.SessionID, ready)
	}
	if err != nil {
		closeTarget(c, t.TargetID)
		return nil, "", "", err
	}
	return c, t.TargetID, s.SessionID, nil
}

var pcIDre = regexp.MustCompile(`^\d{9}$`)

// open — ПК id во весь экран на мониторе monitor (индекс window.getScreenDetails().screens).
// Страница — окно AnyPC (вне фрейма ?embed= сам не входит, см. EMBED в ui/index.html) с одной вкладкой «Моих ПК»;
// полный экран — кнопкой панели фрейма (её путь — window.fullscreen шима с anypcScreen), то есть с keyboard.lock.
func (w *chromeWin) open(ctx context.Context, id string, monitor int, seed map[string]string) (err error) {
	src, err := seedScript(w.base, seed)
	if err != nil {
		return err
	}
	c, tid, sid, err := w.page(ctx, "/?n="+w.issue(), src, "typeof myPcAdd === 'function'")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			closeTarget(c, tid)
		}
	}()
	idj, _ := json.Marshal(id)
	frame := fmt.Sprintf("[...document.querySelectorAll('#frames iframe')].find(f => f.src.includes('embed=' + %s))", idj)
	if err = c.eval(ctx, sid, "myPcAdd("+string(idj)+")", false, nil); err != nil {
		return err
	}
	if err = c.until(ctx, sid, "!!"+frame+"?.contentWindow?.embedSetActive"); err != nil {
		return err
	}
	if err = c.call(ctx, "", "Target.activateTarget", map[string]any{"targetId": tid}, nil); err != nil {
		return err
	}
	var b *screenInfo
	err = c.eval(ctx, sid, fmt.Sprintf(`(async () => { const s = (await getScreenDetails()).screens[%d]; if (!s) return null;
  window.anypcScreen = s; %s.contentDocument.getElementById('fsbtn').click(); return {left: s.left, top: s.top, width: s.width, height: s.height}; })()`, monitor, frame), true, &b)
	if err != nil {
		return err
	}
	if b == nil {
		return fmt.Errorf("нет монитора %d", monitor)
	}
	var win struct {
		WindowID int `json:"windowId"`
		Bounds   struct {
			State string `json:"windowState"`
		} `json:"bounds"`
	}
	for i := 0; i < 15; i++ { // полный экран страницы → окно fullscreen (измерено: < 1 с)
		if err = c.call(ctx, "", "Browser.getWindowForTarget", map[string]any{"targetId": tid}, &win); err != nil {
			return err
		}
		if win.Bounds.State == "fullscreen" {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	// страница полный экран не получила: окно — на монитор (X11; на Wayland место выбирает композитор) и fullscreen без keyboard.lock
	log.Printf("окно ПК: полный экран страницы не включился — fullscreen окна")
	c.call(ctx, "", "Browser.setWindowBounds", map[string]any{"windowId": win.WindowID, "bounds": map[string]any{"windowState": "normal", "left": b.Left, "top": b.Top, "width": b.Width, "height": b.Height}}, nil)
	return c.call(ctx, "", "Browser.setWindowBounds", map[string]any{"windowId": win.WindowID, "bounds": map[string]any{"windowState": "fullscreen"}}, nil)
}

type screenInfo struct {
	Label   string  `json:"label"`
	Left    int     `json:"left"`
	Top     int     `json:"top"`
	Width   int     `json:"width"`
	Height  int     `json:"height"`
	Primary bool    `json:"primary"`
	Scale   float64 `json:"scale"`
}

// screens — мониторы этого ПК глазами Chrome (порядок = индекс для open). Нужна страница источника AnyPC:
// окно /blank на миг открывается и закрывается (скрытые цели по pipe Chrome не создаёт).
func (w *chromeWin) screens(ctx context.Context) ([]screenInfo, error) {
	c, tid, sid, err := w.page(ctx, "/blank", "", "document.readyState === 'complete' && location.origin === "+jsStr(w.base))
	if err != nil {
		return nil, err
	}
	defer closeTarget(c, tid)
	var l []screenInfo
	err = c.eval(ctx, sid, `getScreenDetails().then(d => d.screens.map(s => ({label: s.label, left: s.left, top: s.top, width: s.width, height: s.height, primary: s.isPrimary, scale: s.devicePixelRatio})))`, false, &l)
	return l, err
}

func jsStr(s string) string { b, _ := json.Marshal(s); return string(b) }

// seedKeys — что страница окна ПК берёт из localStorage окна AnyPC (другой профиль — своё хранилище): имена своих ПК,
// имя записи для входа, Турбо, выбор TURN, статистика. Секретов в localStorage программы нет (пароли и ключи — config.json).
var seedKeys = []string{"mine", "users", "turbo", "turn", "stats"}

// seedScript — скрипт до скриптов страницы: перенести seed в localStorage профиля окна; подсказки тура — показаны.
func seedScript(origin string, seed map[string]string) (string, error) {
	kv := map[string]string{"tour_home": "1", "tour_sess": "1"}
	for k, v := range seed {
		if !slices.Contains(seedKeys, k) || len(v) > 64<<10 {
			return "", fmt.Errorf("ключ %q не переносится", k)
		}
		kv[k] = v
	}
	j, _ := json.Marshal(kv)
	return fmt.Sprintf("if (location.origin === %s) try { for (const [k, v] of Object.entries(%s)) localStorage.setItem(k, v); } catch {}", jsStr(origin), j), nil
}

// openPCWindow — ПК id во весь экран на мониторе monitor. "window" — своё окно Chrome; "browser" — Chrome по pipe
// не открылся (одна строка в журнал), открыто окно AnyPC прежним способом.
func openPCWindow(id string, monitor int, seed map[string]string) (string, error) {
	if !pcIDre.MatchString(id) || monitor < 0 {
		return "", errors.New("нужны ID из 9 цифр и номер монитора")
	}
	if pcWin != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := pcWin.open(ctx, id, monitor, seed)
		if err == nil || !errors.Is(err, errNoWindow) {
			if err != nil {
				log.Printf("окно ПК %s: %s", id, scrub(err.Error()))
				return "window", errors.New(scrub(err.Error()))
			}
			return "window", nil
		}
		log.Printf("окно ПК: %s — окно AnyPC прежним способом", scrub(err.Error()))
	}
	if pcFallback != nil {
		pcFallback()
	}
	return "browser", nil
}

func pcScreens() ([]screenInfo, error) {
	if pcWin == nil {
		return nil, errors.New("окна ПК здесь не поддерживаются")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return pcWin.screens(ctx)
}
