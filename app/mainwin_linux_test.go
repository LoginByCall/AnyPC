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
	"syscall"
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
		case "Target.getTargets": // открыто окно ПК
			return map[string]any{"targetInfos": []any{map[string]any{"targetId": "T-pc", "type": "page"}, map[string]any{"targetId": "W1", "type": "service_worker"}}}
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
	f.emit("Target.detachedFromTarget", map[string]any{"sessionId": "S-pc", "targetId": "T-pc"})      // окно ПК закрыто
	f.emit("Target.detachedFromTarget", map[string]any{"sessionId": "S-other", "targetId": "T-main"}) // чужая сессия к главной цели
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

// chromeEnd — Chrome вышел: конец pipe и (если code не nil) код выхода; exitFirst — код раньше конца pipe.
func chromeEnd(f *fakeChrome, c *cdpConn, code *error, exitFirst bool) {
	send := func() {
		if code != nil {
			c.exit <- *code
		}
	}
	if exitFirst {
		send()
	}
	f.wmu.Lock()
	f.outW.Close()
	f.wmu.Unlock()
	if !exitFirst {
		time.Sleep(100 * time.Millisecond) // конец pipe раньше, чем Wait вернул код
		send()
	}
}

// TestMainWindowChromeGone: конец pipe при открытом главном окне. Код 0 (Chrome 157 по SIGTERM выходит так, без
// detachedFromTarget; так может закрыться и последнее окно) — закрыто пользователем → выход, в любом порядке кода и
// конца pipe. Сигнал (OOM −9, падение −11), ненулевой код, кода нет — падение: не выход, окно — по «Открыть».
// Меню Chrome «Выход» (detach, затем pipe) — выход один раз.
func TestMainWindowChromeGone(t *testing.T) {
	defer func(d time.Duration) { cdpExitWait = d }(cdpExitWait)
	cdpExitWait = 300 * time.Millisecond
	ok := error(nil)
	killed, segv, rc1 := errors.New("signal: killed"), errors.New("signal: segmentation fault"), errors.New("exit status 1")
	for _, tc := range []struct {
		name      string
		code      *error
		exitFirst bool
		quit      bool
	}{
		{"код 0, pipe первым", &ok, false, true},
		{"код 0, код первым", &ok, true, true},
		{"OOM -9", &killed, false, false},
		{"падение -11", &segv, true, false},
		{"код 1", &rc1, false, false},
		{"кода нет", nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var f fakeChrome
			w, closed := mainFake(t, &f, nil)
			if err := w.openMain(context.Background()); err != nil {
				t.Fatal(err)
			}
			chromeEnd(&f, w.c, tc.code, tc.exitFirst)
			if tc.quit {
				gotClose(t, closed, tc.name)
				noClose(t, closed, "повтор")
			} else {
				select {
				case <-closed:
					t.Errorf("%s: принято за закрытие окна", tc.name)
				case <-time.After(cdpExitWait + 200*time.Millisecond):
				}
			}
			w.mu.Lock()
			m := w.main
			w.mu.Unlock()
			if m != "" {
				t.Errorf("цель вышедшего Chrome осталась главной: %q", m)
			}
		})
	}

	var g fakeChrome
	w2, closed2 := mainFake(t, &g, nil)
	if err := w2.openMain(context.Background()); err != nil {
		t.Fatal(err)
	}
	g.emit("Target.detachedFromTarget", map[string]any{"sessionId": "S-main", "targetId": "T-main"})
	chromeEnd(&g, w2.c, &ok, false)
	gotClose(t, closed2, "окно закрыто, Chrome вышел")
	noClose(t, closed2, "повтор после выхода Chrome")
}

// TestMainWindowStaleConn: событие прежнего (вышедшего) Chrome не закрывает окно нового.
func TestMainWindowStaleConn(t *testing.T) {
	var f, g fakeChrome
	old, _ := mainFake(t, &g, nil)
	w, closed := mainFake(t, &f, nil)
	if err := w.openMain(context.Background()); err != nil {
		t.Fatal(err)
	}
	w.event(old.c, "Target.detachedFromTarget", []byte(`{"sessionId":"S-main","targetId":"T-main"}`))
	w.event(old.c, cdpGone, nil)
	old.c.exit <- nil
	noClose(t, closed, "событие прежнего Chrome")
}

// TestMainWindowRestart: Chrome AnyPC жив без окон, главного нет — перезапуск с --app (Browser.close и новый запуск),
// а не окно с вкладками; есть окно ПК — обычное окно (TestMainWindowClose).
func TestMainWindowRestart(t *testing.T) {
	var f fakeChrome
	w, _ := mainFake(t, &f, func(m string, p map[string]any) any {
		switch m {
		case "Target.getTargets":
			return map[string]any{"targetInfos": []any{map[string]any{"targetId": "W1", "type": "service_worker"}}}
		case "Browser.close":
			return fakeExit
		}
		return nil
	})
	starts := 0
	w.dir, w.look = t.TempDir(), func(string) (string, error) { starts++; return "", errors.New("нет") }
	if err := w.openMain(context.Background()); !errors.Is(err, errNoWindow) {
		t.Fatalf("ошибка: %v", err)
	}
	var seen []string
	for _, k := range f.log() {
		seen = append(seen, k.Method)
	}
	if strings.Join(seen, " ") != "Target.getTargets Browser.close" || starts == 0 {
		t.Errorf("вызовы %v, запусков %d", seen, starts)
	}
	if a := strings.Join(chromeArgs("/p", true), " "); !strings.Contains(a, "--app=data:") || !strings.Contains(a, "--hide-crash-restore-bubble") || strings.Contains(a, "--no-startup-window") {
		t.Errorf("аргументы окна приложения: %s", a)
	}
}

// TestMainWindowShut: «Выйти» закрывает Chrome (Browser.close) — это не «пользователь закрыл окно»;
// Chrome не ответил — pipe закрыт всё равно.
func TestMainWindowShut(t *testing.T) {
	var f fakeChrome
	w, closed := mainFake(t, &f, func(m string, p map[string]any) any {
		if m == "Browser.close" {
			f.emit("Target.detachedFromTarget", map[string]any{"sessionId": "S-main", "targetId": "T-main"}) // Chrome закрывает окна и выходит
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
			f.emit("Target.detachedFromTarget", map[string]any{"sessionId": "S-main", "targetId": "T-main"})
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

// setCgroup — /proc/self/cgroup этого процесса для теста.
func setCgroup(t *testing.T, text string) {
	t.Helper()
	old := cgroupFile
	cgroupFile = filepath.Join(t.TempDir(), "cgroup")
	os.WriteFile(cgroupFile, []byte(text), 0o600)
	t.Cleanup(func() { cgroupFile = old })
}

func stubExit(t *testing.T) chan int {
	codes := make(chan int, 4)
	old := exit
	exit = func(c int) { codes <- c }
	quitOnce = sync.Once{}
	t.Cleanup(func() { exit = old; quitOnce = sync.Once{} })
	return codes
}

func wantExit(t *testing.T, codes chan int, what string) {
	t.Helper()
	select {
	case c := <-codes:
		if c != 0 {
			t.Errorf("%s: выход %d — служба с Restart=on-failure перезапустилась бы", what, c)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("%s: нет выхода", what)
	}
	select {
	case <-codes:
		t.Errorf("%s: выход дважды", what)
	case <-time.After(400 * time.Millisecond):
	}
}

// TestMainClosedService: закрытие главного окна — выход (exit 0); под службой (cgroup anypc.service) — не выход:
// Chrome AnyPC закрыт, программа и значок остаются. INVOCATION_ID без cgroup службы (запуск из Nemo: app-gnome-*.scope
// наследует его от gnome-shell, измерено у владельца) — обычный запуск, выход.
func TestMainClosedService(t *testing.T) {
	defer func(w *chromeWin) { pcWin = w }(pcWin)
	codes := stubExit(t)
	var f fakeChrome
	w, _ := mainFake(t, &f, func(m string, p map[string]any) any {
		if m == "Browser.close" {
			return fakeExit
		}
		return nil
	})
	pcWin = w
	setCgroup(t, "0::/user.slice/user-1000.slice/user@1000.service/app.slice/anypc.service\n")
	if !inService() {
		t.Fatal("cgroup службы не узнан")
	}
	for _, cg := range []string{"0::/user.slice/app.slice/myanypc.service\n", "0::/user.slice/app.slice/anypc.service/sub\n"} {
		setCgroup(t, cg)
		if inService() {
			t.Errorf("чужая служба принята за anypc.service: %q", cg)
		}
	}
	setCgroup(t, "0::/user.slice/user-1000.slice/user@1000.service/app.slice/anypc.service\n")
	mainClosed(&agent.Agent{})
	if w.c.alive() {
		t.Error("служба: Chrome AnyPC не закрыт")
	}
	select {
	case c := <-codes:
		t.Errorf("служба: выход %d", c)
	case <-time.After(500 * time.Millisecond):
	}
	t.Setenv("INVOCATION_ID", "abc")
	t.Setenv("JOURNAL_STREAM", "8:123")
	setCgroup(t, "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-nemo-tabs-4242.scope\n")
	if inService() {
		t.Fatal("запуск из Nemo принят за службу")
	}
	mainClosed(&agent.Agent{})
	quitNow(&agent.Agent{}) // и «Выйти» следом — второго выхода нет
	wantExit(t, codes, "закрытие окна")
	if !strings.Contains(serviceUnit("/x"), "Restart=on-failure") {
		t.Error("служба перезапускается не только при сбое")
	}
	cgroupFile = filepath.Join(t.TempDir(), "нет") // Мак, нет /proc
	if inService() {
		t.Error("без /proc — служба")
	}
}

// TestQuitClosesChrome: «Выйти» закрывает Chrome AnyPC (Browser.close) и выходит 0.
func TestQuitClosesChrome(t *testing.T) {
	defer func(w *chromeWin) { pcWin = w }(pcWin)
	codes := stubExit(t)
	var f fakeChrome
	w, closed := mainFake(t, &f, func(m string, p map[string]any) any {
		if m == "Browser.close" {
			return fakeExit
		}
		return nil
	})
	if err := w.openMain(context.Background()); err != nil {
		t.Fatal(err)
	}
	pcWin = w
	quitNow(&agent.Agent{})
	wantExit(t, codes, "Выйти")
	if w.c.alive() {
		t.Error("Chrome не закрыт")
	}
	if l := f.log(); l[len(l)-1].Method != "Browser.close" {
		t.Errorf("последний вызов: %+v", l[len(l)-1])
	}
	noClose(t, closed, "Выйти")
}

// TestSetupWindows: связка hostMain. Без Chrome: showWindow второй копии (raiseWindow) и «Открыть» трея — окно
// прежним способом один раз, без рекурсии; закрытие главного окна (onClose) — выход; «Выйти» трея — выход.
func TestSetupWindows(t *testing.T) {
	defer func(w *chromeWin, f, r func()) { pcWin, pcFallback, raiseWindow = w, f, r }(pcWin, pcFallback, raiseWindow)
	setCgroup(t, "0::/user.slice/app.slice/app-gnome-x.scope\n")
	codes := stubExit(t)
	opened := make(chan string, 4)
	n := 0
	issue := func() string { n++; return "code" + string(rune('0'+n)) }
	open, quit := setupWindows("http://127.0.0.1:5000", issue, t.TempDir(), func(string) (string, error) { return "", errors.New("нет") },
		func(u string) { opened <- u }, &agent.Agent{})
	if pcWin == nil || pcWin.onClose == nil || pcWin.base != "http://127.0.0.1:5000" {
		t.Fatalf("pcWin: %+v", pcWin)
	}
	done := make(chan struct{})
	go func() { raiseWindow(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("showWindow без Chrome завис (рекурсия?)")
	}
	if u := <-opened; u != "http://127.0.0.1:5000/?n=code1" {
		t.Errorf("прежний способ: %q", u)
	}
	open()
	select {
	case u := <-opened:
		if u != "http://127.0.0.1:5000/?n=code2" {
			t.Errorf("«Открыть»: %q", u)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("«Открыть» трея не открыло окно")
	}
	select {
	case u := <-opened:
		t.Errorf("лишнее окно: %q", u)
	case <-time.After(200 * time.Millisecond):
	}
	onClose := pcWin.onClose
	var f fakeChrome // окно в Chrome AnyPC открыто: showWindow второй копии поднимает его, нового не открывает
	w, _ := mainFake(t, &f, nil)
	if err := w.openMain(context.Background()); err != nil {
		t.Fatal(err)
	}
	pcWin = w
	raiseWindow()
	if l := f.log(); l[len(l)-1].Method != "Target.activateTarget" {
		t.Errorf("showWindow при открытом окне: %+v", l[len(l)-1])
	}
	select {
	case u := <-opened:
		t.Errorf("showWindow открыл окно прежним способом: %q", u)
	case <-time.After(200 * time.Millisecond):
	}
	onClose()
	wantExit(t, codes, "закрытие окна")
	quitOnce = sync.Once{}
	quit()
	wantExit(t, codes, "«Выйти» трея")
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
		chromeTestArgs = []string{"--headless=new", "--no-proxy-server", "--disable-background-networking"}
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
	if err := w.openMain(ctx); err != nil { // служба: окно снова (Chrome жив без окон — перезапуск с --app)
		t.Fatal(err)
	}
	w.mu.Lock()
	c = w.c
	w.mu.Unlock()
	syscall.Kill(c.pid, syscall.SIGTERM) // Chrome 157 по SIGTERM: код 0, без detachedFromTarget — как закрытие окна
	gotClose(t, closed, "SIGTERM Chrome")
	if err := w.openMain(ctx); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	c = w.c
	w.mu.Unlock()
	w.shut()
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Error("Chrome не вышел")
	}
	noClose(t, closed, "Выйти")
}
