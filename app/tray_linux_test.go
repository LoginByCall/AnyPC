package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"anypc/agent"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"
)

// startBus — своя сессионная шина (dbus-daemon --session --nofork), не шина владельца; "" — dbus-daemon нет.
// Процесс — наш ребёнок: убивается в Cleanup и (Pdeathsig) при гибели теста.
func startBus(t *testing.T, extra ...string) string {
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		return ""
	}
	c := exec.Command("dbus-daemon", append([]string{"--session", "--nofork", "--print-address=1"}, extra...)...)
	c.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	out, err := c.StdoutPipe()
	if err != nil || c.Start() != nil {
		return ""
	}
	t.Cleanup(func() { c.Process.Kill(); c.Wait() })
	addr, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatalf("dbus-daemon: %v", err)
	}
	return strings.TrimSpace(addr)
}

func privateBus(t *testing.T, extra ...string) string {
	addr := startBus(t, extra...)
	if addr == "" {
		t.Skip("нет dbus-daemon")
	}
	return addr
}

// fakeWatcher — org.kde.StatusNotifierWatcher с хостом: запоминает регистрации.
type fakeWatcher struct {
	conn *dbus.Conn
	reg  chan string
}

func (w *fakeWatcher) RegisterStatusNotifierItem(s string) *dbus.Error { w.reg <- s; return nil }

func newWatcher(t *testing.T, addr string) *fakeWatcher {
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	w := &fakeWatcher{conn: conn, reg: make(chan string, 4)}
	conn.Export(w, watcherPath, watcherName)
	ro := func(v any) *prop.Prop { return &prop.Prop{Value: v, Emit: prop.EmitFalse} }
	if _, err := prop.Export(conn, watcherPath, prop.Map{watcherName: {
		"IsStatusNotifierHostRegistered": ro(true),
		"RegisteredStatusNotifierItems":  ro([]string{}),
	}}); err != nil {
		t.Fatal(err)
	}
	w.own(t)
	return w
}

func (w *fakeWatcher) own(t *testing.T) {
	if r, err := w.conn.RequestName(watcherName, dbus.NameFlagDoNotQueue); err != nil || r != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("имя Watcher: %v %v", r, err)
	}
}

func (w *fakeWatcher) next(t *testing.T) string {
	select {
	case s := <-w.reg:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("значок не зарегистрировался у Watcher")
		return ""
	}
}

func (w *fakeWatcher) none(t *testing.T, why string) {
	select {
	case s := <-w.reg:
		t.Errorf("%s: лишняя регистрация %q", why, s)
	case <-time.After(500 * time.Millisecond):
	}
}

// testTrayDeps — трей вне пространства с подписями ru; первая строка — «имя ПК · 123 456 789».
func testTrayDeps(open, quit func()) trayDeps {
	return trayDeps{id: "123456789", open: open, quit: quit, tx: trayTextsFor("ru", "linux"),
		state: func() trayState { return trayState{Self: "123456789"} }}
}

// startTestTray — serveTray на шине addr; open и quit — подменённые. Возвращает канал выхода serveTray.
func startTestTray(t *testing.T, addr string, open, quit func()) <-chan error {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveTray(ctx, addr, testTrayDeps(open, quit)) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("serveTray не остановился по ctx")
		}
	})
	return done
}

// trayCounter — подменённое действие: считает вызовы и сообщает о каждом.
type trayCounter struct {
	n  atomic.Int32
	ch chan struct{}
}

func newTrayCounter() *trayCounter { return &trayCounter{ch: make(chan struct{}, 64)} }
func (c *trayCounter) f()          { c.n.Add(1); c.ch <- struct{}{} }
func (c *trayCounter) wait(t *testing.T, what string) {
	select {
	case <-c.ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: действие не вызвано", what)
	}
}

func setOpenGap(t *testing.T, d time.Duration) {
	old := trayOpenGap
	trayOpenGap = d
	t.Cleanup(func() { trayOpenGap = old })
}

// TestTray: регистрация у Watcher, меню из трёх пунктов и разделителя; Activate, первая строка и «Помочь кому-то…»
// открывают окно, «Выйти» — завершение; перерегистрация, когда Watcher пропал и вернулся (блокировка экрана).
func TestTray(t *testing.T) {
	setOpenGap(t, 0)
	addr := privateBus(t)
	w := newWatcher(t, addr)
	open, quit := newTrayCounter(), newTrayCounter()
	startTestTray(t, addr, open.f, quit.f)
	name := w.next(t)
	if !strings.HasPrefix(name, "org.kde.StatusNotifierItem-") {
		t.Fatalf("имя значка: %q", name)
	}

	item := w.conn.Object(name, sniPath)
	if v, err := item.GetProperty(sniIface + ".Menu"); err != nil || v.Value() != menuPath {
		t.Errorf("Menu: %v %v", v, err)
	}
	if v, err := item.GetProperty(sniIface + ".IconPixmap"); err != nil || !strings.Contains(v.Signature().String(), "a(iiay)") {
		t.Errorf("IconPixmap: %v %v", v.Signature(), err)
	}

	menu := w.conn.Object(name, menuPath)
	var rev uint32
	var root trayLayout
	if err := menu.Call(menuIface+".GetLayout", 0, int32(0), int32(-1), []string{}).Store(&rev, &root); err != nil {
		t.Fatal("GetLayout: ", err)
	}
	var labels []string
	seps := 0
	for _, c := range root.Children {
		f := c.Value().([]any)
		p := f[1].(map[string]dbus.Variant)
		if p["type"].Value() == "separator" {
			seps++
			continue
		}
		labels = append(labels, p["label"].Value().(string))
	}
	if want := []string{trayTitle("123456789"), "Отправить", "Помочь кому-то…", "Выйти"}; strings.Join(labels, "|") != strings.Join(want, "|") || seps != 1 {
		t.Errorf("меню: %q, разделителей %d", labels, seps)
	}

	if err := item.Call(sniIface+".Activate", 0, int32(0), int32(0)).Err; err != nil {
		t.Fatal("Activate: ", err)
	}
	open.wait(t, "Activate")
	for _, id := range []int32{1, 2} {
		if err := menu.Call(menuIface+".Event", 0, id, "clicked", dbus.MakeVariant(""), uint32(0)).Err; err != nil {
			t.Fatal("Event: ", err)
		}
		open.wait(t, "Event clicked")
	}
	menu.Call(menuIface+".Event", 0, int32(3), "clicked", dbus.MakeVariant(""), uint32(0))        // разделитель
	menu.Call(menuIface+".Event", 0, int32(1), "hovered", dbus.MakeVariant(""), uint32(0))        // не щелчок
	menu.Call(menuIface+".Event", 0, int32(trayQuit), "clicked", dbus.MakeVariant(""), uint32(0)) // «Выйти»
	quit.wait(t, "«Выйти»")
	time.Sleep(100 * time.Millisecond)
	if o, q := open.n.Load(), quit.n.Load(); o != 3 || q != 1 {
		t.Errorf("открытий %d (ждали 3), выходов %d (ждали 1)", o, q)
	}

	// Watcher пропал (блокировка экрана) и вернулся — значок регистрируется заново
	if _, err := w.conn.ReleaseName(watcherName); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	w.own(t)
	if again := w.next(t); again != name {
		t.Errorf("перерегистрация: %q, ждали %q", again, name)
	}

	// поддельный NameOwnerChanged от обычного клиента (адресный и широковещательный) — не повод регистрироваться
	other, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	other.Emit("/org/freedesktop/DBus", "org.freedesktop.DBus.NameOwnerChanged", watcherName, "", ":9.9")
	other.Send(&dbus.Message{Type: dbus.TypeSignal, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldPath: dbus.MakeVariant(dbus.ObjectPath("/x")), dbus.FieldInterface: dbus.MakeVariant("org.freedesktop.DBus"),
		dbus.FieldMember: dbus.MakeVariant("NameOwnerChanged"), dbus.FieldDestination: dbus.MakeVariant(name),
		dbus.FieldSignature: dbus.MakeVariant(dbus.SignatureOf("", "", "")),
	}, Body: []any{watcherName, "", ":9.9"}}, nil)
	w.none(t, "поддельный NameOwnerChanged")
}

// TestTrayFlood: поток Activate и EventGroup от любого клиента шины открывает окно один раз за trayOpenGap;
// «Выйти» пределом не ограничен.
func TestTrayFlood(t *testing.T) {
	setOpenGap(t, time.Hour)
	addr := privateBus(t)
	w := newWatcher(t, addr)
	open, quit := newTrayCounter(), newTrayCounter()
	startTestTray(t, addr, open.f, quit.f)
	name := w.next(t)
	for i := 0; i < 200; i++ {
		w.conn.Object(name, sniPath).Call(sniIface+".Activate", dbus.FlagNoReplyExpected, int32(0), int32(0))
	}
	evs := make([]trayEvt, 1000)
	for i := range evs {
		evs[i] = trayEvt{1, "clicked", dbus.MakeVariant(""), 0}
	}
	evs[len(evs)-1].ID = trayQuit
	if err := w.conn.Object(name, menuPath).Call(menuIface+".EventGroup", 0, evs).Err; err != nil {
		t.Fatal("EventGroup: ", err)
	}
	quit.wait(t, "«Выйти» в потоке")
	time.Sleep(300 * time.Millisecond)
	if n := open.n.Load(); n != 1 {
		t.Errorf("открытий окна %d, ждали 1", n)
	}
}

// trayLayoutLabels — подписи верхнего уровня меню (разделитель — «—»).
func trayLayoutLabels(t *testing.T, menu dbus.BusObject) (uint32, string) {
	t.Helper()
	var rev uint32
	var root trayLayout
	if err := menu.Call(menuIface+".GetLayout", 0, int32(0), int32(-1), []string{}).Store(&rev, &root); err != nil {
		t.Fatal("GetLayout: ", err)
	}
	var l []string
	for _, c := range root.Children {
		p := c.Value().([]any)[1].(map[string]dbus.Variant)
		if p["type"].Value() == "separator" {
			l = append(l, "—")
		} else {
			l = append(l, p["label"].Value().(string))
		}
	}
	return rev, strings.Join(l, "|")
}

// TestTrayLive — меню следует за состоянием: вступили в пространство и «я тут» здесь — LayoutUpdated с новой
// ревизией и пункты по макету; щелчок по ПК пространства зовёт pc с его ID; без перемен ревизия не растёт.
func TestTrayLive(t *testing.T) {
	setOpenGap(t, 0)
	old := trayPoll
	trayPoll = 20 * time.Millisecond
	t.Cleanup(func() { trayPoll = old })
	addr := privateBus(t)
	w := newWatcher(t, addr)
	var st atomic.Pointer[trayState]
	st.Store(&trayState{Self: "123456789"})
	pcs := make(chan string, 4)
	d := trayDeps{id: "123456789", open: func() {}, quit: func() {}, tx: trayTextsFor("ru", "linux"),
		state: func() trayState { return *st.Load() }, pc: func(id string) { pcs <- id }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveTray(ctx, addr, d) }()
	t.Cleanup(func() { cancel(); <-done })
	name := w.next(t)
	menu := w.conn.Object(name, menuPath)
	rev0, l0 := trayLayoutLabels(t, menu)
	if l0 != trayTitle("123456789")+"|Отправить|Помочь кому-то…|—|Выйти" {
		t.Errorf("вне пространства: %s", l0)
	}
	time.Sleep(100 * time.Millisecond) // несколько опросов без перемен
	if rev, _ := trayLayoutLabels(t, menu); rev != rev0 {
		t.Errorf("ревизия без перемен: %d → %d", rev0, rev)
	}
	sig := make(chan *dbus.Signal, 8)
	w.conn.Signal(sig)
	if err := w.conn.AddMatchSignal(dbus.WithMatchInterface(menuIface), dbus.WithMatchMember("LayoutUpdated")); err != nil {
		t.Fatal(err)
	}
	st.Store(&trayState{Self: "123456789", In: true, Here: "123456789", PCs: []trayPC{{"200000001", "Офис"}, {"200000002", ""}}})
	select {
	case s := <-sig:
		if len(s.Body) != 2 || s.Body[0].(uint32) <= rev0 || s.Body[1].(int32) != 0 {
			t.Errorf("LayoutUpdated: %v", s.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("нет LayoutUpdated")
	}
	h, _ := os.Hostname()
	if rev, l := trayLayoutLabels(t, menu); rev <= rev0 || l != h+" · я тут|—|Офис|200 000 002|—|Отправить|Помочь кому-то…|—|Выйти" {
		t.Errorf("в пространстве: ревизия %d, %s", rev, l)
	}
	if err := menu.Call(menuIface+".Event", 0, int32(trayPCID("200000002")), "clicked", dbus.MakeVariant(""), uint32(0)).Err; err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-pcs:
		if id != "200000002" {
			t.Errorf("щелчок по ПК: %s", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("щелчок по ПК не открыл его")
	}
}

// TestTrayNav — ПК и «Я тут» из трея: JS берёт только загрузка главного окна со своей меткой g (её кладёт trayGo в
// адрес — trayNavQuery; обмен ?n= → ?t= её переносит), с хэшем в CSP, один раз; окно «ПК как монитор» (тот же адрес
// без метки), вкладка ПК (embed), чужая и просроченная метка — нет. Без Chrome AnyPC trayGo только открывает окно.
func TestTrayNav(t *testing.T) {
	defer func(p func(*http.Request) bool) { peerOK = p }(peerOK)
	peerOK = func(*http.Request) bool { return true }
	cfg, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	page, err := shimmed("wss://example/ws", "tok123")
	if err != nil {
		t.Fatal(err)
	}
	once := &onceCode{}
	h := handler("127.0.0.1:5000", "tok123", page, cfg, &agent.Agent{}, nil, func() map[string]any { return nil }, newFiles(t.TempDir()), once)
	get := func(path string) (string, string) {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = "127.0.0.1:5000"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Body.String(), w.Header().Get("Location")
	}
	if trayJSPC("12345") != "" || trayJSPC(`200000001"); x(1)//`) != "" {
		t.Fatal("trayJSPC пропустил не ID")
	}
	js := "addEventListener('DOMContentLoaded', () => { " + trayJSPC("200000001") + " });"
	sum := sha256.Sum256([]byte(js))
	hash := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	t.Cleanup(func() { trayNavTake("") })
	if trayNavQuery() != "" {
		t.Fatal("метка без JS трея")
	}
	trayNavSet(trayJSPC("200000001"))
	q := trayNavQuery()
	g := strings.TrimPrefix(q, "&g=")
	if !trayMarkRe.MatchString(g) {
		t.Fatalf("метка: %q", q)
	}
	// окно «ПК как монитор» в те же 30 с: тот же обмен кода, но без метки — JS не берёт
	if _, loc := get("/?n=" + once.issue()); loc != "/?t=tok123" {
		t.Fatalf("обмен кода без метки: %q", loc)
	} else if b, _ := get(loc); strings.Contains(b, js) {
		t.Error("JS трея ушёл в окно без метки")
	}
	for _, path := range []string{"/?t=tok123&g=" + g + "&embed=200000002", "/?t=tok123&g=0123456789abcdef"} {
		if b, _ := get(path); strings.Contains(b, js) {
			t.Errorf("%s: JS трея выполнен", path)
		}
	}
	_, loc := get("/?n=" + once.issue() + q + "&g=x") // лишняя негодная метка — мимо (берётся первая)
	if loc != "/?t=tok123&g="+g {
		t.Fatalf("обмен кода не перенёс метку: %q", loc)
	}
	if _, loc := get("/?n=" + once.issue() + "&g=%22%3E"); loc != "/?t=tok123" {
		t.Errorf("негодная метка перенесена: %q", loc)
	}
	if b, _ := get(loc); !strings.Contains(b, "<script>"+js+"</script>") || !strings.Contains(b, hash) {
		t.Error("главное окно с меткой без JS трея или без хэша в CSP")
	}
	if b, _ := get(loc); strings.Contains(b, js) {
		t.Error("JS трея выполнен дважды")
	}
	trayNavSet(trayJSHere)
	g = strings.TrimPrefix(trayNavQuery(), "&g=")
	trayNav.Lock()
	trayNav.at = time.Now().Add(-trayNavFor - time.Second)
	trayNav.Unlock()
	if b, _ := get("/?t=tok123&g=" + g); strings.Contains(b, "() => { "+trayJSHere) || trayNavQuery() != "" {
		t.Error("просроченный JS трея выполнен или метка ещё выдаётся")
	}

	oldRaise, oldWin, oldFb := raiseWindow, pcWin, pcFallback
	t.Cleanup(func() { raiseWindow, pcWin, pcFallback = oldRaise, oldWin, oldFb })
	var opened []string
	setupWindows("http://b", func() string { return "code" }, t.TempDir(), func(string) (string, error) { return "", os.ErrNotExist },
		func(u string) { opened = append(opened, u) }, &agent.Agent{})
	pcWin = nil
	trayGo(trayJSHere) // без Chrome AnyPC: окно прежним способом — с меткой; JS ждёт страницу
	if len(opened) != 1 || !strings.HasPrefix(opened[0], "http://b/?n=code&g=") {
		t.Fatalf("окно из trayGo: %q", opened)
	}
	if trayNavTake(strings.SplitN(opened[0], "&g=", 2)[1]) != trayJSHere {
		t.Error("JS для страницы не оставлен под меткой адреса")
	}
	trayGo("")
	if len(opened) != 2 || opened[1] != "http://b/?n=code" {
		t.Errorf("trayGo без JS: %q", opened)
	}
}

// trayHungWatcher — Watcher, который не отвечает.
type trayHungWatcher struct{ block chan struct{} }

func (h trayHungWatcher) RegisterStatusNotifierItem(s string) *dbus.Error { <-h.block; return nil }

// TestTrayHungWatcher: молчащий Watcher не мешает выйти по ctx.
func TestTrayHungWatcher(t *testing.T) {
	addr := privateBus(t)
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	h := trayHungWatcher{make(chan struct{})}
	defer close(h.block)
	conn.Export(h, watcherPath, watcherName)
	conn.RequestName(watcherName, dbus.NameFlagDoNotQueue)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveTray(ctx, addr, trayDeps{open: func() {}, quit: func() {}}) }()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveTray не вышел по ctx при молчащем Watcher")
	}
}

// TestTrayNoWatcher: Watcher нет — serveTray работает без ошибок и выходит по ctx; появится — зарегистрируется.
func TestTrayNoWatcher(t *testing.T) {
	addr := privateBus(t)
	done := startTestTray(t, addr, func() {}, func() {})
	select {
	case err := <-done:
		t.Fatal("serveTray вышел без Watcher: ", err)
	case <-time.After(300 * time.Millisecond):
	}
	w := newWatcher(t, addr)
	w.next(t)
}

// TestTrayNoBus: без DBUS_SESSION_BUS_ADDRESS (служба без графического сеанса) трей молча не поднимается — и не ищет
// шину сам (godbus без переменной взял бы $XDG_RUNTIME_DIR/bus или dbus-launch).
func TestTrayNoBus(t *testing.T) {
	dir := t.TempDir()
	addr := privateBus(t, "--address=unix:path="+filepath.Join(dir, "bus"))
	w := newWatcher(t, addr)
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	ret := make(chan struct{})
	go func() {
		runTray(context.Background(), trayDeps{id: "123456789", open: func() {}, quit: func() {}})
		close(ret)
	}()
	select {
	case <-ret:
	case <-time.After(2 * time.Second):
		t.Fatal("runTray без шины не вернулся сразу")
	}
	w.none(t, "пустая DBUS_SESSION_BUS_ADDRESS")
}

// TestOnceCodeIssue: окно из трея — каждый раз свой одноразовый код; невостребованный прежний не сгорает;
// срок onceTTL, живых не больше onceMax (старые вытесняются).
func TestOnceCodeIssue(t *testing.T) {
	o := &onceCode{}
	a, b := o.issue(), o.issue()
	if a == b || len(a) != 32 {
		t.Fatalf("коды: %q %q", a, b)
	}
	if !o.use(b) || o.use(b) || !o.use(a) || o.use(a) || o.use("") {
		t.Error("каждый код годен ровно один раз")
	}
	old := o.issue()
	o.codes[0].at = time.Now().Add(-onceTTL - time.Second)
	if o.use(old) {
		t.Error("просроченный код принят")
	}
	var all []string
	for i := 0; i < 3000; i++ {
		all = append(all, o.issue())
	}
	if len(o.codes) != onceMax || o.use(all[0]) || !o.use(all[len(all)-1]) || !o.use(all[len(all)-onceMax]) {
		t.Errorf("живых %d (ждали %d), старые должны вытесняться, новые — жить", len(o.codes), onceMax)
	}
}

// TestPeerUID: код окна гасит только процесс того же пользователя — партнёр на loopback ищется в /proc/net/tcp.
func TestPeerUID(t *testing.T) {
	// разбор таблицы на фиксированных строках (x86/arm — порядок байт машины младшим вперёд)
	if binary.NativeEndian.Uint16([]byte{1, 0}) == 1 {
		const tab = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1 1 0000000000000000 100 0 0 10 0
   1: 0100007F:D431 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1234        0 2 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 3 1 0000000000000000 20 4 30 10 -1`
		cli, srv := netip.MustParseAddrPort("127.0.0.1:54321"), netip.MustParseAddrPort("127.0.0.1:8080")
		if uid, ok := tcpUID(tab, cli, srv, false); !ok || uid != 1234 {
			t.Errorf("сокет клиента: uid %d %v, ждали 1234", uid, ok)
		}
		if _, ok := tcpUID(tab, netip.MustParseAddrPort("127.0.0.1:1"), srv, false); ok {
			t.Error("несуществующий сокет найден")
		}
		const tab6 = `  sl  local_address                         remote_address                        st
   0: 0000000000000000FFFF00000100007F:D431 0000000000000000FFFF00000100007F:1F90 01 00000000:00000000 00:00000000 00000000  1001 0 4`
		if uid, ok := tcpUID(tab6, cli, srv, true); !ok || uid != 1001 {
			t.Errorf("tcp6, IPv4 двойного стека: uid %d %v", uid, ok)
		}
	}

	// настоящий loopback: свой uid проходит; запрос без адресов соединения (подделать /proc нельзя) — отказ
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	addr := l.Addr().String()
	cfg, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	once := &onceCode{}
	go http.Serve(l, handler(addr, "tok123", []byte("page"), cfg, &agent.Agent{}, nil, nil, newFiles(t.TempDir()), once))
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := cl.Get("http://" + addr + "/?n=" + once.issue())
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 303 || r.Header.Get("Location") != "/?t=tok123" {
		t.Errorf("свой uid: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	if samePeerUID(&http.Request{RemoteAddr: "127.0.0.1:1"}) {
		t.Error("не найдено → должен быть отказ")
	}
}

// TestLaunchCmd: под службой (cgroup anypc.service) браузер — в своём scope с описанием (не командной строкой с кодом);
// systemd-run упал — браузер напрямую; отработал — второго запуска нет. INVOCATION_ID без службы (app-gnome-*.scope) — напрямую.
func TestLaunchCmd(t *testing.T) {
	t.Setenv("INVOCATION_ID", "abc")
	setCgroup(t, "0::/user.slice/app.slice/app-gnome-nemo-tabs-1.scope\n")
	if c, scoped := launchCmd("/usr/bin/chrome", "--app=x"); scoped || strings.Join(c.Args, " ") != "/usr/bin/chrome --app=x" {
		t.Errorf("без systemd: %q", c.Args)
	}
	for _, rc := range []string{"1", "0"} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "systemd-run"), []byte("#!/bin/sh\nexit "+rc+"\n"), 0o755)
		mark := filepath.Join(dir, "started")
		browser := filepath.Join(dir, "browser")
		os.WriteFile(browser, []byte("#!/bin/sh\necho \"$@\" > "+mark+"\n"), 0o755)
		t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
		setCgroup(t, "0::/user.slice/user@1000.service/app.slice/anypc.service\n")
		c, scoped := launchCmd(browser, "--app=x")
		if !scoped || c.Args[0] != filepath.Join(dir, "systemd-run") ||
			strings.Join(c.Args[1:], " ") != "--user --scope --quiet --description=AnyPC window -- "+browser+" --app=x" {
			t.Errorf("служба: %q", c.Args)
		}
		if err := launch(browser, "--app=x"); err != nil {
			t.Fatal(err)
		}
		started := false
		for i := 0; i < 30 && !started; i++ {
			time.Sleep(100 * time.Millisecond)
			b, _ := os.ReadFile(mark)
			started = strings.TrimSpace(string(b)) == "--app=x"
		}
		if started != (rc == "1") {
			t.Errorf("systemd-run вышел с %s: браузер напрямую запущен = %v", rc, started)
		}
	}
}

// TestPeerHandler: обработчик кода зовёт peerOK — отказ партнёру не тратит код; неизвестный код /proc не читает.
func TestPeerHandler(t *testing.T) {
	defer func(p func(*http.Request) bool) { peerOK = p }(peerOK)
	var calls atomic.Int32
	allow := false
	peerOK = func(*http.Request) bool { calls.Add(1); return allow }
	cfg, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	once := &onceCode{}
	h := handler("127.0.0.1:5000", "tok123", []byte("page"), cfg, &agent.Agent{}, nil, nil, newFiles(t.TempDir()), once)
	get := func(path string) int {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = "127.0.0.1:5000"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if c := get("/?n=nosuch"); c != 403 || calls.Load() != 0 {
		t.Errorf("неизвестный код: %d, peerOK вызван %d раз (ждали 0)", c, calls.Load())
	}
	code := once.issue()
	if c := get("/?n=" + code); c != 403 || calls.Load() != 1 || !once.has(code) {
		t.Errorf("чужой uid: %d, peerOK %d, код цел %v", c, calls.Load(), once.has(code))
	}
	allow = true
	if c := get("/?n=" + code); c != 303 || once.has(code) {
		t.Errorf("свой uid: %d, код погашен %v", c, !once.has(code))
	}
}

// TestPeerUIDTable: samePeerUID на фиксированной таблице — свой uid да, чужой нет, не найдено — нет.
func TestPeerUIDTable(t *testing.T) {
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		t.Skip("таблица записана для порядка байт младшим вперёд")
	}
	const tab = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   1: 0100007F:D431 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1234        0 2 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 3 1 0000000000000000 20 4 30 10 -1`
	read := func(p string) ([]byte, error) {
		if p == "/proc/net/tcp" {
			return []byte(tab), nil
		}
		return nil, os.ErrNotExist
	}
	req := func(remote string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		return r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}))
	}
	if !peerUIDIs(req("127.0.0.1:54321"), read, 1234) {
		t.Error("свой uid не прошёл")
	}
	if peerUIDIs(req("127.0.0.1:54321"), read, 1000) { // сокет сервера (uid 1000) — не партнёр
		t.Error("чужой uid прошёл")
	}
	if peerUIDIs(req("127.0.0.1:1"), read, 1234) {
		t.Error("не найдено → должен быть отказ")
	}
	if peerUIDIs(req("127.0.0.1:54321"), func(string) ([]byte, error) { return nil, os.ErrPermission }, 1234) {
		t.Error("/proc не читается → должен быть отказ")
	}
}
