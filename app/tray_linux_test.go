package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"net"
	"net/http"
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

// startTestTray — serveTray на шине addr; open и quit — подменённые. Возвращает канал выхода serveTray.
func startTestTray(t *testing.T, addr string, open, quit func()) <-chan error {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveTray(ctx, addr, trayMenu("host · 123 456 789", open, quit), open) }()
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
	if want := []string{"host · 123 456 789", "Помочь кому-то…", "Выйти"}; strings.Join(labels, "|") != strings.Join(want, "|") || seps != 1 {
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
	go func() { done <- serveTray(ctx, addr, trayMenu("h", func() {}, func() {}), nil) }()
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
	go func() { runTray(context.Background(), "123456789", func() {}, func() {}); close(ret) }()
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

// TestLaunchCmd: под systemd (INVOCATION_ID) браузер — в своём scope, не в cgroup службы.
func TestLaunchCmd(t *testing.T) {
	t.Setenv("INVOCATION_ID", "")
	if c := launchCmd("/usr/bin/chrome", "--app=x"); strings.Join(c.Args, " ") != "/usr/bin/chrome --app=x" {
		t.Errorf("без systemd: %q", c.Args)
	}
	t.Setenv("INVOCATION_ID", "abc")
	c := launchCmd("/usr/bin/chrome", "--app=x")
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Skip("нет systemd-run")
	}
	if !strings.HasSuffix(c.Args[0], "systemd-run") || strings.Join(c.Args[1:], " ") != "--user --scope --quiet -- /usr/bin/chrome --app=x" {
		t.Errorf("служба: %q", c.Args)
	}
}

func TestTrayTitleIcon(t *testing.T) {
	h, _ := os.Hostname()
	if got := trayTitle("123456789"); got != h+" · 123 456 789" {
		t.Errorf("trayTitle: %q", got)
	}
	for _, n := range []int{22, 44} {
		p := trayIcon(n)
		if p.W != int32(n) || p.H != int32(n) || len(p.Data) != n*n*4 {
			t.Fatalf("значок %d: %dx%d, %d байт", n, p.W, p.H, len(p.Data))
		}
		c := n * 3 / 4 // центр красного ПК — непрозрачный красный
		if o := (c*n + c) * 4; p.Data[o] != 0xff || p.Data[o+1] != 0xef {
			t.Errorf("значок %d: точка %d,%d = % x", n, c, c, p.Data[o:o+4])
		}
	}
}
