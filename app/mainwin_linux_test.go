package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"anypc/agent"
)

// mainFake — Chrome AnyPC с уже открытым соединением (окна ПК): главное окно — новой целью T-main.
func mainFake(t *testing.T, f *fakeChrome, extra func(m string, p map[string]any) any) (*chromeWin, chan string) {
	closed := make(chan string, 4)
	w := &chromeWin{base: "http://127.0.0.1:5000", issue: func() string { return "code1" }}
	w.onClose = func() { closed <- "closed" }
	c := f.startEv(t, func(m string, p map[string]any) any {
		if extra != nil {
			if r := extra(m, p); r != nil {
				return r
			}
		}
		switch m {
		case "Target.createTarget":
			return map[string]any{"targetId": "T-main"}
		case "Target.attachToTarget":
			return map[string]any{"sessionId": "S-main"}
		case "Runtime.evaluate":
			return map[string]any{"result": map[string]any{"value": true}}
		}
		return map[string]any{}
	}, w.event)
	w.mu.Lock()
	w.c = c
	w.mu.Unlock()
	return w, closed
}

func noClose(t *testing.T, closed chan string, what string) {
	t.Helper()
	select {
	case <-closed:
		t.Errorf("%s: принято за закрытие главного окна", what)
	case <-time.After(150 * time.Millisecond):
	}
}

func gotClose(t *testing.T, closed chan string, what string) {
	t.Helper()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s: закрытие главного окна не замечено", what)
	}
}

// TestMainWindowClose: главное окно в Chrome AnyPC — код только по pipe; повторное «Открыть» поднимает то же окно;
// закрытие окна ПК, перезагрузка и прочие события — не выход; закрытие главной цели — выход ровно один раз.
func TestMainWindowClose(t *testing.T) {
	var f fakeChrome
	w, closed := mainFake(t, &f, nil)
	ctx := context.Background()
	if err := w.openMain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.openMain(ctx); err != nil { // «Открыть» из трея при открытом окне
		t.Fatal(err)
	}
	creates, activated := 0, false
	for _, k := range f.log() {
		switch k.Method {
		case "Target.createTarget":
			creates++
			if _, ok := k.Params["browserContextId"]; ok || k.Params["newWindow"] != true || k.Params["url"] != "about:blank" {
				t.Errorf("createTarget: %+v", k.Params)
			}
		case "Page.navigate":
			if k.Params["url"] != "http://127.0.0.1:5000/?n=code1" || k.Session != "S-main" {
				t.Errorf("navigate: %+v %q", k.Params, k.Session)
			}
		case "Target.activateTarget":
			activated = k.Params["targetId"] == "T-main"
		case "Target.closeTarget":
			t.Error("удавшееся окно закрыто")
		}
	}
	if creates != 1 || !activated {
		t.Errorf("повторное «Открыть»: окон %d, поднято %v", creates, activated)
	}
	f.emit("Target.detachedFromTarget", map[string]any{"sessionId": "S-pc", "targetId": "T-pc"}) // окно ПК закрыто
	f.emit("Inspector.detached", map[string]any{"reason": "target_closed"})
	f.emit("Target.targetInfoChanged", map[string]any{"targetInfo": map[string]any{"targetId": "T-main", "url": "http://127.0.0.1:5000/?t=x"}}) // перезагрузка, переход
	f.emit("Target.detachedFromTarget", map[string]any{})
	noClose(t, closed, "окно ПК, перезагрузка")
	f.emit("Target.detachedFromTarget", map[string]any{"sessionId": "S-main", "targetId": "T-main"})
	gotClose(t, closed, "крестик")
	f.emit("Target.detachedFromTarget", map[string]any{"sessionId": "S-main", "targetId": "T-main"})
	f.emit(cdpGone, nil)
	noClose(t, closed, "повтор")
}

// TestMainWindowChromeGone: Chrome AnyPC упал при открытом главном окне — выход; без главного окна (только окна ПК) — нет.
func TestMainWindowChromeGone(t *testing.T) {
	var f fakeChrome
	w, closed := mainFake(t, &f, nil)
	if err := w.openMain(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.wmu.Lock()
	f.outW.Close() // Chrome вышел: канал закрыт
	f.wmu.Unlock()
	gotClose(t, closed, "Chrome упал")

	var g fakeChrome
	_, closed2 := mainFake(t, &g, nil) // главное окно не в нём (прежний способ), только окна ПК
	g.wmu.Lock()
	g.outW.Close()
	g.wmu.Unlock()
	noClose(t, closed2, "Chrome без главного окна")
}

// TestMainWindowShut: «Выйти» закрывает Chrome (Browser.close) — это не «пользователь закрыл окно»;
// Chrome не ответил — pipe закрыт всё равно.
func TestMainWindowShut(t *testing.T) {
	var f fakeChrome
	w, closed := mainFake(t, &f, func(m string, p map[string]any) any {
		if m == "Browser.close" {
			f.emit("Target.detachedFromTarget", map[string]any{"targetId": "T-main"}) // Chrome закрывает окна и выходит
			return fakeExit
		}
		return nil
	})
	if err := w.openMain(context.Background()); err != nil {
		t.Fatal(err)
	}
	w.shut()
	if w.c.alive() {
		t.Error("Chrome не закрыт")
	}
	noClose(t, closed, "Выйти")
	if l := f.log(); l[len(l)-1].Method != "Browser.close" {
		t.Errorf("последний вызов: %+v", l[len(l)-1])
	}
}

// TestMainWindowFail: страница не открылась (код отклонён) — своё окно закрыто без «выхода», ошибка — errNoWindow
// (вызывающий открывает окно прежним способом); нет Chrome — тоже errNoWindow, без попытки по pipe.
func TestMainWindowFail(t *testing.T) {
	var f fakeChrome
	w, closed := mainFake(t, &f, func(m string, p map[string]any) any {
		switch m {
		case "Runtime.evaluate":
			return map[string]any{"result": map[string]any{"value": false}} // «Ссылка уже использована»: привязок нет
		case "Target.closeTarget":
			f.emit("Target.detachedFromTarget", map[string]any{"targetId": "T-main"})
		}
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	if err := w.openMain(ctx); !errors.Is(err, errNoWindow) {
		t.Fatalf("ошибка: %v", err)
	}
	noClose(t, closed, "своё закрытие после ошибки")
	closedT := false
	for _, k := range f.log() {
		closedT = closedT || k.Method == "Target.closeTarget" && k.Params["targetId"] == "T-main"
	}
	if !closedT {
		t.Error("окно после ошибки не закрыто")
	}
	none := &chromeWin{base: "http://127.0.0.1:5000", issue: func() string { return "c" }, dir: t.TempDir(), look: func(string) (string, error) { return "", errors.New("нет") }}
	if err := none.openMain(context.Background()); !errors.Is(err, errNoWindow) {
		t.Errorf("без Chrome: %v", err)
	}
}

// TestMainWindowFallback: mainWindow — без Chrome AnyPC окно прежним способом; окно есть, но не поднялось — второго нет.
func TestMainWindowFallback(t *testing.T) {
	defer func(w *chromeWin) { pcWin = w }(pcWin)
	opened := 0
	pcWin = nil
	mainWindow(func() { opened++ })
	pcWin = &chromeWin{base: "http://127.0.0.1:5000", issue: func() string { return "c" }, dir: t.TempDir(), look: func(string) (string, error) { return "", errors.New("нет") }}
	mainWindow(func() { opened++ })
	if opened != 2 {
		t.Errorf("прежним способом: %d", opened)
	}
	var f fakeChrome
	w, _ := mainFake(t, &f, func(m string, p map[string]any) any {
		if m == "Target.activateTarget" {
			return errors.New("no target")
		}
		return nil
	})
	if err := w.openMain(context.Background()); err != nil {
		t.Fatal(err)
	}
	pcWin = w
	mainWindow(func() { opened++ }) // поднять не удалось
	if opened != 2 {
		t.Errorf("окно есть, а открыто ещё и прежним способом: %d", opened)
	}
}

// TestMainClosedService: закрытие главного окна — выход (exit 0: служба с Restart=on-failure не перезапускается);
// под службой (INVOCATION_ID) — не выход: Chrome AnyPC закрыт, программа и значок остаются.
func TestMainClosedService(t *testing.T) {
	defer func(e func(int), w *chromeWin) { exit, pcWin = e, w; quitOnce = sync.Once{} }(exit, pcWin)
	codes := make(chan int, 2)
	exit = func(c int) { codes <- c }
	var f fakeChrome
	w, _ := mainFake(t, &f, func(m string, p map[string]any) any {
		if m == "Browser.close" {
			return fakeExit
		}
		return nil
	})
	pcWin = w
	t.Setenv("INVOCATION_ID", "abc")
	quitOnce = sync.Once{}
	mainClosed(&agent.Agent{})
	if w.c.alive() {
		t.Error("служба: Chrome AnyPC не закрыт")
	}
	select {
	case c := <-codes:
		t.Errorf("служба: выход %d", c)
	case <-time.After(500 * time.Millisecond):
	}
	t.Setenv("INVOCATION_ID", "")
	mainClosed(&agent.Agent{})
	quitNow(&agent.Agent{}) // и «Выйти» следом — второго выхода нет
	select {
	case c := <-codes:
		if c != 0 {
			t.Errorf("выход %d: служба с Restart=on-failure перезапустилась бы", c)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("нет выхода")
	}
	select {
	case <-codes:
		t.Error("выход дважды")
	case <-time.After(500 * time.Millisecond):
	}
	if !strings.Contains(serviceUnit("/x"), "Restart=on-failure") {
		t.Error("служба перезапускается не только при сбое")
	}
}

// TestCDPMainLive — настоящий Chrome (V1): ANYPC_CDP_LIVE=<каталог профиля, будет удалён>; ANYPC_CDP_HEADLESS=1 — без окон
// (headless не открывает --app: окно приложения проверяется только с окнами). Главное окно: страница с токеном,
// перезагрузка и окно ПК — не выход, закрытие окна — выход, «Выйти» — Chrome вышел.
func TestCDPMainLive(t *testing.T) {
	dir := os.Getenv("ANYPC_CDP_LIVE")
	if dir == "" {
		t.Skip("ANYPC_CDP_LIVE не задан")
	}
	if os.Getenv("ANYPC_CDP_HEADLESS") == "1" {
		defer func(a []string) { chromeTestArgs = a }(chromeTestArgs)
		chromeTestArgs = []string{"--headless=new"}
	}
	dir, err := os.MkdirTemp(dir, "live-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	cfg, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	cfg.uiSet("mine", `[{"id":"123456789","name":"Офис"}]`)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	page, _ := shimmed("ws://127.0.0.1:1/ws", "toklive")
	once := &onceCode{}
	info := func() map[string]any {
		return map[string]any{"id": cfg.ID, "users": []any{}, "keys": []any{}, "version": "test"}
	}
	go http.Serve(l, handler(addr, "toklive", page, cfg, &agent.Agent{}, nil, info, newFiles(t.TempDir()), once))
	closed := make(chan string, 4)
	w := &chromeWin{base: "http://" + addr, issue: once.issue, dir: dir, look: exec.LookPath, onClose: func() { closed <- "closed" }}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := w.openMain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.openMain(ctx); err != nil { // поднять
		t.Fatal(err)
	}
	w.mu.Lock()
	c, tid := w.c, w.main
	w.mu.Unlock()
	var s struct{ SessionID string }
	c.call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": tid, "flatten": true}, &s)
	var st struct {
		Tok  bool   `json:"tok"`
		Mine string `json:"mine"`
		N    int    `json:"n"`
	}
	ex := `({tok: location.search.includes('t=toklive'), mine: JSON.stringify(window.ANYPC_UI || {}), n: 0})`
	if err := c.eval(ctx, s.SessionID, ex, false, &st); err != nil || !st.Tok || !strings.Contains(st.Mine, "Офис") {
		t.Errorf("страница: %+v %v", st, err)
	}
	c.call(ctx, s.SessionID, "Page.reload", nil, nil)
	time.Sleep(time.Second)
	if err := c.until(ctx, s.SessionID, "typeof hostInfo === 'function'"); err != nil {
		t.Errorf("после перезагрузки: %v", err)
	}
	if _, err := w.screens(ctx); err != nil { // окно /blank открывается и закрывается — как окно ПК
		t.Errorf("мониторы: %v", err)
	}
	noClose(t, closed, "перезагрузка, окно ПК")
	var tg struct {
		TargetInfos []struct{ TargetID, Type string }
	}
	c.call(ctx, "", "Target.getTargets", nil, &tg)
	pages := 0
	for _, x := range tg.TargetInfos {
		if x.Type == "page" {
			pages++
		}
	}
	if pages != 1 {
		t.Errorf("окон: %d (повторное «Открыть» открыло второе?)", pages)
	}
	c.call(ctx, "", "Target.closeTarget", map[string]any{"targetId": tid}, nil) // как крестик
	gotClose(t, closed, "закрытие окна")
	if err := w.openMain(ctx); err != nil { // служба: окно снова (Chrome жив — обычное окно)
		t.Fatal(err)
	}
	c = w.c
	w.shut()
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Error("Chrome не вышел")
	}
	noClose(t, closed, "Выйти")
}
