package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"
)

// privateBus — своя сессионная шина (dbus-daemon --session), не шина владельца.
func privateBus(t *testing.T) string {
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("нет dbus-daemon")
	}
	out, err := exec.Command("dbus-daemon", "--session", "--print-address=1", "--print-pid=1", "--fork").Output()
	if err != nil {
		t.Skip("dbus-daemon не запустился: ", err)
	}
	f := strings.Fields(string(out))
	if len(f) < 2 {
		t.Fatalf("dbus-daemon: %q", out)
	}
	t.Cleanup(func() { exec.Command("kill", f[1]).Run() })
	return f[0]
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

// startTestTray — serveTray на шине addr; quit — подменённое завершение. Возвращает канал выхода serveTray.
func startTestTray(t *testing.T, addr string, quit func()) <-chan error {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveTray(ctx, addr, trayMenu("host · 123 456 789", func() {}, quit), nil) }()
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

// TestTray: регистрация у Watcher, меню из трёх пунктов и разделителя, «Выйти» вызывает завершение,
// перерегистрация, когда Watcher пропал и вернулся (блокировка экрана).
func TestTray(t *testing.T) {
	addr := privateBus(t)
	w := newWatcher(t, addr)
	var once sync.Once
	quit := make(chan struct{})
	startTestTray(t, addr, func() { once.Do(func() { close(quit) }) })
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

	var rev uint32
	var root trayLayout
	if err := w.conn.Object(name, menuPath).Call(menuIface+".GetLayout", 0, int32(0), int32(-1), []string{}).Store(&rev, &root); err != nil {
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

	if err := w.conn.Object(name, menuPath).Call(menuIface+".Event", 0, int32(4), "clicked", dbus.MakeVariant(""), uint32(0)).Err; err != nil {
		t.Fatal("Event: ", err)
	}
	select {
	case <-quit:
	case <-time.After(5 * time.Second):
		t.Error("«Выйти» не вызвал завершение")
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
}

// TestTrayNoWatcher: Watcher нет — serveTray работает без ошибок и выходит по ctx; появится — зарегистрируется.
func TestTrayNoWatcher(t *testing.T) {
	addr := privateBus(t)
	done := startTestTray(t, addr, func() {})
	select {
	case err := <-done:
		t.Fatal("serveTray вышел без Watcher: ", err)
	case <-time.After(300 * time.Millisecond):
	}
	w := newWatcher(t, addr)
	w.next(t)
}

// TestTrayNoBus: без DBUS_SESSION_BUS_ADDRESS (служба без графического сеанса) трей молча не поднимается.
func TestTrayNoBus(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	ret := make(chan struct{})
	go func() { runTray(context.Background(), "123456789", func() {}, func() {}); close(ret) }()
	select {
	case <-ret:
	case <-time.After(2 * time.Second):
		t.Fatal("runTray без шины не вернулся сразу")
	}
}

// TestOnceCodeIssue: окно из трея — каждый раз свой одноразовый код; невостребованный прежний не сгорает.
func TestOnceCodeIssue(t *testing.T) {
	o := &onceCode{}
	a, b := o.issue(), o.issue()
	if a == b || len(a) != 32 {
		t.Fatalf("коды: %q %q", a, b)
	}
	if !o.use(b) || o.use(b) || !o.use(a) || o.use(a) || o.use("") {
		t.Error("каждый код годен ровно один раз")
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
