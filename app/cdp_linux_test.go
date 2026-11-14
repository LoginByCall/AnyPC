package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"anypc/agent"
)

// fakeChrome — поддельный Chrome на паре os.Pipe: читает команды до \0, отвечает reply(method, params)
// (nil — ответа нет), перед каждым ответом шлёт событие, а ответ режет на две записи.
type fakeChrome struct {
	mu    sync.Mutex
	calls []fakeCall
}

type fakeCall struct {
	Method  string
	Session string
	Params  map[string]any
}

func (f *fakeChrome) start(t *testing.T, reply func(method string, p map[string]any) any) *cdpConn {
	inR, inW, _ := os.Pipe()   // AnyPC → Chrome (fd 3)
	outR, outW, _ := os.Pipe() // Chrome → AnyPC (fd 4)
	t.Cleanup(func() { inW.Close(); outR.Close() })
	go func() {
		defer outW.Close()
		r := bufio.NewReader(inR)
		for {
			b, err := r.ReadBytes(0)
			if err != nil {
				return
			}
			var m struct {
				ID      int            `json:"id"`
				Method  string         `json:"method"`
				Session string         `json:"sessionId"`
				Params  map[string]any `json:"params"`
			}
			if json.Unmarshal(b[:len(b)-1], &m) != nil {
				t.Errorf("не JSON: %q", b)
				return
			}
			f.mu.Lock()
			f.calls = append(f.calls, fakeCall{m.Method, m.Session, m.Params})
			f.mu.Unlock()
			res := reply(m.Method, m.Params)
			if res == nil {
				continue
			}
			outW.Write([]byte(`{"method":"Target.targetInfoChanged","params":{}}` + "\x00"))
			var out []byte
			if e, ok := res.(error); ok {
				out, _ = json.Marshal(map[string]any{"id": m.ID, "error": map[string]any{"code": -32000, "message": e.Error()}})
			} else {
				out, _ = json.Marshal(map[string]any{"id": m.ID, "result": res})
			}
			out = append(out, 0)
			outW.Write(out[:len(out)/2])
			time.Sleep(time.Millisecond)
			outW.Write(out[len(out)/2:])
		}
	}()
	return newCDP(outR, inW)
}

func (f *fakeChrome) log() []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeCall(nil), f.calls...)
}

// TestCDPPipe: сообщения с \0 собираются из кусков, события пропускаются, ошибка Chrome — ошибка вызова,
// закрытый Chrome — ошибка ждущего вызова, а не зависание.
func TestCDPPipe(t *testing.T) {
	var f fakeChrome
	c := f.start(t, func(m string, p map[string]any) any {
		switch m {
		case "Browser.getVersion":
			return map[string]any{"product": "Chrome/157"}
		case "Bad.method":
			return errors.New("'Bad.method' wasn't found")
		case "Hang":
			return nil
		}
		return map[string]any{}
	})
	ctx := context.Background()
	var v struct{ Product string }
	if err := c.call(ctx, "", "Browser.getVersion", nil, &v); err != nil || v.Product != "Chrome/157" {
		t.Fatalf("getVersion: %v %+v", err, v)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ { // параллельные вызовы: ответ — своему id
		wg.Add(1)
		go func() { defer wg.Done(); c.call(ctx, "S1", "Page.navigate", map[string]any{"url": "x"}, nil) }()
	}
	wg.Wait()
	if err := c.call(ctx, "", "Bad.method", nil, nil); err == nil || !strings.Contains(err.Error(), "wasn't found") {
		t.Errorf("ошибка Chrome: %v", err)
	}
	tctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	if err := c.call(tctx, "", "Hang", nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("нет ответа: %v", err)
	}
	cancel()
	if l := f.log(); l[1].Session != "S1" || l[1].Params["url"] != "x" {
		t.Errorf("сессия и параметры: %+v", l[1])
	}
	done := make(chan error, 1)
	go func() { done <- c.call(ctx, "", "Hang", nil, nil) }()
	time.Sleep(20 * time.Millisecond)
	c.w.Close() // Chrome увидит EOF и выйдет — его ответный канал закроется
	select {
	case err := <-done:
		if err == nil {
			t.Error("вызов к вышедшему Chrome без ошибки")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("вызов к вышедшему Chrome завис")
	}
	if c.alive() || c.call(ctx, "", "Browser.getVersion", nil, nil) == nil {
		t.Error("соединение не закрыто")
	}
}

// TestPCWindowFlow: окно ПК — код окна только в Page.navigate по pipe (не в argv), разрешение — только своему
// источнику, ПК — вкладкой окна AnyPC, полный экран — кнопкой фрейма на мониторе по индексу.
func TestPCWindowFlow(t *testing.T) {
	var f fakeChrome
	state := "normal"
	c := f.start(t, func(m string, p map[string]any) any {
		switch m {
		case "Target.createTarget":
			return map[string]any{"targetId": "T1"}
		case "Target.attachToTarget":
			return map[string]any{"sessionId": "S1"}
		case "Runtime.evaluate":
			e := p["expression"].(string)
			if strings.Contains(e, "getScreenDetails") {
				state = "fullscreen"
				return map[string]any{"result": map[string]any{"value": map[string]any{"left": 1920, "top": 0, "width": 1280, "height": 1024}}}
			}
			if strings.HasPrefix(e, "myPcAdd(") {
				return map[string]any{"result": map[string]any{"type": "undefined"}}
			}
			return map[string]any{"result": map[string]any{"value": true}}
		case "Browser.getWindowForTarget":
			return map[string]any{"windowId": 7, "bounds": map[string]any{"windowState": state}}
		}
		return map[string]any{}
	})
	c.bctx = "B1"
	w := &chromeWin{base: "http://127.0.0.1:5000", issue: func() string { return "code42" }, c: c}
	if err := w.open(context.Background(), "123456789", 1, map[string]string{"mine": `[{"id":"123456789","name":"Офис"}]`}); err != nil {
		t.Fatal(err)
	}
	var seen []string
	for _, k := range f.log() {
		seen = append(seen, k.Method)
		switch k.Method {
		case "Target.createTarget":
			if k.Params["url"] != "about:blank" || k.Params["newWindow"] != true || k.Params["browserContextId"] != "B1" {
				t.Errorf("createTarget: %+v", k.Params)
			}
		case "Page.navigate":
			if k.Params["url"] != "http://127.0.0.1:5000/?n=code42" || k.Session != "S1" {
				t.Errorf("navigate: %+v %q", k.Params, k.Session)
			}
		case "Browser.grantPermissions": // отклонил бы источнику микрофон и буфер
			t.Error("grantPermissions вместо setPermission")
		case "Browser.setPermission":
			if k.Params["origin"] != "http://127.0.0.1:5000" || k.Params["setting"] != "granted" || k.Params["browserContextId"] != "B1" ||
				k.Params["permission"].(map[string]any)["name"] != "window-management" {
				t.Errorf("разрешение: %+v", k.Params)
			}
		case "Target.closeTarget":
			t.Error("удавшееся окно закрыто")
		case "Page.addScriptToEvaluateOnNewDocument":
			if s := k.Params["source"].(string); !strings.Contains(s, `location.origin === "http://127.0.0.1:5000"`) || !strings.Contains(s, "Офис") {
				t.Errorf("перенос localStorage: %s", s)
			}
		case "Runtime.evaluate":
			if e := k.Params["expression"].(string); strings.Contains(e, "getScreenDetails") && (!strings.Contains(e, "screens[1]") || k.Params["userGesture"] != true || !strings.Contains(e, "fsbtn")) {
				t.Errorf("полный экран: %+v", k.Params)
			}
		case "Browser.setWindowBounds":
			t.Error("запасной путь при удавшемся полном экране страницы")
		}
	}
	if want := "Target.createTarget Target.attachToTarget Page.enable Page.addScriptToEvaluateOnNewDocument Browser.setPermission Page.navigate"; !strings.HasPrefix(strings.Join(seen, " "), want) {
		t.Errorf("порядок: %v", seen)
	}
	if _, err := seedScript("http://x", map[string]string{"pass": "{}"}); err == nil {
		t.Error("перенос ключа вне списка (пароли браузера)")
	}
	if _, err := seedScript("http://x", map[string]string{"mine": strings.Repeat("x", 64<<10)}); err != nil {
		t.Errorf("64 КБ: %v", err)
	}
	if _, err := seedScript("http://x", map[string]string{"mine": strings.Repeat("x", 64<<10+1)}); err == nil {
		t.Error("больше 64 КБ принято")
	}
}

// TestPCWindowErrors: любая ошибка после создания окна закрывает его (повтор не плодит окна); исключение страницы —
// в ошибке первой строкой и без ?t= и ?n=.
func TestPCWindowErrors(t *testing.T) {
	exc := func(d string) any {
		return map[string]any{"result": map[string]any{}, "exceptionDetails": map[string]any{"text": "Uncaught", "exception": map[string]any{"description": d}}}
	}
	for _, tc := range []struct {
		name, fail string
		ret        any
	}{
		{"setPermission", "Browser.setPermission", errors.New("Permission can't be granted")},
		{"navigate", "Page.navigate", errors.New("Cannot navigate")},
		{"fullscreen", "getScreenDetails", exc("TypeError: not granted at http://127.0.0.1:5000/?t=SECRETTOK&x=1\n    at f (http://127.0.0.1:5000/?n=SECRETCODE:1:2)")},
		{"monitor", "getScreenDetails", map[string]any{"result": map[string]any{"type": "object", "subtype": "null", "value": nil}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var f fakeChrome
			c := f.start(t, func(m string, p map[string]any) any {
				e, _ := p["expression"].(string)
				if m == tc.fail || m == "Runtime.evaluate" && strings.Contains(e, tc.fail) {
					return tc.ret
				}
				switch m {
				case "Target.createTarget":
					return map[string]any{"targetId": "T1"}
				case "Target.attachToTarget":
					return map[string]any{"sessionId": "S1"}
				case "Runtime.evaluate":
					return map[string]any{"result": map[string]any{"value": true}}
				}
				return map[string]any{}
			})
			w := &chromeWin{base: "http://127.0.0.1:5000", issue: func() string { return "SECRETCODE" }, c: c}
			err := w.open(context.Background(), "123456789", 3, nil)
			if err == nil {
				t.Fatal("нет ошибки")
			}
			if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "    at ") {
				t.Errorf("в ошибке токен, код или стек: %v", err)
			}
			if tc.name == "monitor" && !strings.Contains(err.Error(), "нет монитора 3") {
				t.Errorf("монитор вне списка: %v", err)
			}
			closed := false
			for _, k := range f.log() {
				closed = closed || k.Method == "Target.closeTarget" && k.Params["targetId"] == "T1"
			}
			if !closed {
				t.Errorf("окно не закрыто после ошибки: %v", err)
			}
		})
	}
	if s := scrub("at http://h/?t=abc&n=def#x and /?n=123)"); s != "at http://h/?t=…&n=…#x and /?n=…)" {
		t.Errorf("scrub: %q", s)
	}
}

// TestPCWindowAPI: /api/pcWindow — ID, монитор и перенос; кривой перенос — 400, без Chrome — прежнее окно.
func TestPCWindowAPI(t *testing.T) {
	defer func(w *chromeWin, f func()) { pcWin, pcFallback = w, f }(pcWin, pcFallback)
	opened := 0
	pcWin, pcFallback = nil, func() { opened++ } // как на Маке: своего Chrome нет
	cfg, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	h := handler("127.0.0.1:5000", "tok123", []byte("page"), cfg, &agent.Agent{}, nil, nil, newFiles(t.TempDir()), nil)
	do := func(body string) (int, string) {
		r := httptest.NewRequest("POST", "/api/pcWindow", strings.NewReader(body))
		r.Host = "127.0.0.1:5000"
		r.Header.Set("X-Token", "tok123")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code, strings.TrimSpace(w.Body.String())
	}
	if c, b := do(`["123456789", 0, {"mine": "[]"}]`); c != 200 || b != `{"result":"browser"}` || opened != 1 {
		t.Errorf("без Chrome: %d %s %d", c, b, opened)
	}
	if c, b := do(`["123456789", 0, "x"]`); c != 400 || opened != 1 {
		t.Errorf("кривой перенос: %d %s", c, b)
	}
	if c, _ := do(`["123456789", 0, {"mine": 5}]`); c != 400 {
		t.Errorf("перенос не строкой: %d", c)
	}
	if c, _ := do(`["1234", 0]`); c != 400 || opened != 1 {
		t.Errorf("неверный ID: %d", c)
	}
}

// TestCDPBadBrowser: браузер, не ответивший по pipe, до перезапуска AnyPC больше не запускается.
func TestCDPBadBrowser(t *testing.T) {
	defer func(d time.Duration) { cdpStartWait = d }(cdpStartWait)
	cdpStartWait = 300 * time.Millisecond
	dir := t.TempDir()
	bin, starts := filepath.Join(dir, "chromium-browser"), filepath.Join(dir, "starts")
	os.WriteFile(bin, []byte("#!/bin/sh\necho x >> "+starts+"\nexec sleep 5\n"), 0o755)
	w := &chromeWin{base: "http://127.0.0.1:5000", dir: filepath.Join(dir, "p"), look: func(n string) (string, error) {
		if n == "chromium-browser" {
			return bin, nil
		}
		return "", errors.New("нет")
	}}
	for i := 0; i < 2; i++ {
		if _, err := w.conn(context.Background()); err == nil {
			t.Fatal("заглушка ответила по pipe")
		}
	}
	if b, _ := os.ReadFile(starts); strings.Count(string(b), "x") != 1 {
		t.Errorf("запусков: %q", b)
	}
	if st, err := os.Stat(w.dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("профиль: %v %v", st, err)
	}
	if profileDir("AnyPC/chrome") == nil {
		t.Error("относительный путь профиля принят (нет каталога настроек)")
	}
	os.Symlink(dir, filepath.Join(dir, "link"))
	if profileDir(filepath.Join(dir, "link")) == nil {
		t.Error("профиль — ссылка, принят")
	}
}

// TestPCWindowFallback: Chrome не найден — прежнее поведение (окно AnyPC), неверный ID — отказ без окна.
func TestPCWindowFallback(t *testing.T) {
	defer func(w *chromeWin, f func()) { pcWin, pcFallback = w, f }(pcWin, pcFallback)
	opened := 0
	pcFallback = func() { opened++ }
	pcWin = &chromeWin{base: "http://127.0.0.1:5000", issue: func() string { return "c" }, dir: t.TempDir(), look: func(string) (string, error) { return "", errors.New("нет") }}
	if r, err := openPCWindow("123456789", 0, nil); r != "browser" || err != nil || opened != 1 {
		t.Errorf("без Chrome: %q %v %d", r, err, opened)
	}
	if _, err := openPCWindow("12345678x", 0, nil); err == nil || opened != 1 {
		t.Error("неверный ID принят")
	}
}

// TestCDPBrowser: порядок выбора браузера; snap — мимо (профиль в ~/.config ему закрыт).
func TestCDPBrowser(t *testing.T) {
	have := map[string]string{"chromium": "/usr/bin/chromium", "chromium-browser": "/usr/bin/chromium-browser", "microsoft-edge": "/usr/bin/microsoft-edge"}
	look := func(n string) (string, error) {
		if p, ok := have[n]; ok {
			return p, nil
		}
		return "", errors.New("нет")
	}
	real := func(p string) (string, error) {
		if p == "/usr/bin/chromium" {
			return "/snap/bin/chromium", nil
		}
		return p, nil
	}
	if b := cdpBrowser(look, real); b != "/usr/bin/chromium-browser" {
		t.Errorf("выбран %q", b)
	}
	have["google-chrome"] = "/usr/bin/google-chrome"
	if b := cdpBrowser(look, real); b != "/usr/bin/google-chrome" {
		t.Errorf("Chrome не первым: %q", b)
	}
	if b := cdpBrowser(func(string) (string, error) { return "", errors.New("нет") }, real); b != "" {
		t.Errorf("без браузеров: %q", b)
	}
}

// TestNoDebugPort: окно ПК — только pipe. Отладочного TCP-порта нет ни в аргументах Chrome, ни где-либо в исходниках
// программы; в аргументах нет кода окна и токена.
func TestNoDebugPort(t *testing.T) {
	a := strings.Join(chromeArgs("/home/u/.config/AnyPC/chrome"), " ")
	if !strings.Contains(a, "--remote-debugging-pipe") || strings.Contains(a, "remote-debugging-port") || strings.Contains(a, "remote-debugging-address") {
		t.Errorf("аргументы: %s", a)
	}
	if strings.Contains(a, "?n=") || strings.Contains(a, "?t=") || strings.Contains(a, "http") {
		t.Errorf("адрес окна в аргументах: %s", a)
	}
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		if strings.Contains(string(b), "remote-debugging-"+"port") {
			t.Errorf("%s: отладочный порт", f)
		}
	}
}

// TestCDPLive — настоящий Chrome (V1): ANYPC_CDP_LIVE=<каталог профиля, будет удалён>. Окно живёт ≤10 с.
func TestCDPLive(t *testing.T) {
	dir := os.Getenv("ANYPC_CDP_LIVE")
	if dir == "" {
		t.Skip("ANYPC_CDP_LIVE не задан")
	}
	dir, err := os.MkdirTemp(dir, "live-") // удаляется только свой подкаталог
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	cfg, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	page, _ := shimmed("ws://127.0.0.1:1/ws", "toklive") // хабов нет: фрейм не выходит в сеть
	once := &onceCode{}
	info := func() map[string]any {
		return map[string]any{"id": cfg.ID, "users": []any{}, "keys": []any{}, "version": "test"}
	}
	go http.Serve(l, handler(addr, "toklive", page, cfg, &agent.Agent{}, nil, info, newFiles(t.TempDir()), once))
	var codes []string
	w := &chromeWin{base: "http://" + addr, issue: func() string { c := once.issue(); codes = append(codes, c); return c }, dir: dir, look: exec.LookPath}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	t0 := time.Now()
	l2, err := w.screens(ctx)
	t.Logf("мониторы: %+v %v", l2, err)
	if err != nil || len(l2) == 0 {
		t.Fatal("нет мониторов")
	}
	if err := w.open(ctx, "123456789", 0, map[string]string{"mine": `[{"id":"123456789","name":"Офис"}]`}); err != nil {
		t.Fatal(err)
	}
	var st struct {
		Mine string `json:"mine"`
		Fs   bool   `json:"fs"`
		Tok  bool   `json:"tok"`
		Body string `json:"fsbody"`
		Mic  string `json:"mic"`
	}
	c := w.c
	var tg struct {
		TargetInfos []struct{ TargetID, Type, URL string }
	}
	c.call(ctx, "", "Target.getTargets", nil, &tg)
	pid := ""
	for _, x := range tg.TargetInfos {
		if x.Type == "page" {
			pid = x.TargetID
		}
	}
	var s struct{ SessionID string }
	c.call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": pid, "flatten": true}, &s)
	err = c.eval(ctx, s.SessionID, `(async () => ({mine: localStorage.getItem('mine') + JSON.stringify(Object.keys(localStorage)), fs: !!document.fullscreenElement, tok: location.search.includes('t=toklive'), fsbody: [...document.querySelectorAll('#frames iframe')].map(f => f.contentDocument.body.className).join(), mic: await navigator.permissions.query({name: 'microphone'}).then(p => p.state)}))()`, false, &st)
	t.Logf("страница: %+v %v, за %v", st, err, time.Since(t0))
	if !st.Fs || !strings.Contains(st.Mine, "Офис") || !st.Tok || st.Mic != "prompt" {
		t.Error("окно ПК не в полном экране, без переноса или с отклонённым микрофоном")
	}
	time.Sleep(time.Second)
	c.call(ctx, "", "Browser.close", nil, nil)
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Error("Chrome не вышел")
	}
	time.Sleep(500 * time.Millisecond)
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error { // свой контекст браузера: на диске ни токена, ни кодов
		if err == nil && fi.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			for _, x := range append(codes, "toklive") {
				if strings.Contains(string(b), x) {
					t.Errorf("%s в профиле: %s", x, p)
				}
			}
		}
		return nil
	})
}

// TestCDPExpiredCtx: вызов с уже истёкшим сроком не пишет в pipe и не убивает Chrome (приёмка, круг 2).
func TestCDPExpiredCtx(t *testing.T) {
	var f fakeChrome
	c := f.start(t, func(string, map[string]any) any { return map[string]any{} })
	killed := false
	c.kill = func() { killed = true }
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	if err := c.call(ctx, "", "Browser.getVersion", nil, nil); err == nil {
		t.Fatal("истёкший срок: ждали ошибку")
	}
	if killed || !c.alive() {
		t.Fatalf("истёкший срок убил Chrome: killed=%v alive=%v", killed, c.alive())
	}
	if err := c.call(context.Background(), "", "Browser.getVersion", nil, nil); err != nil {
		t.Fatalf("после истёкшего срока соединение должно жить: %v", err)
	}
}
