// Spike (выбрасываемый): значок в трее на чистом Go через godbus —
// org.kde.StatusNotifierItem + com.canonical.dbusmenu. Без cgo, без новых зависимостей.
// Запуск: tray [-t 25s]. Все входящие вызовы оболочки логируются в stderr.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
)

const (
	watcherName = "org.kde.StatusNotifierWatcher"
	watcherPath = dbus.ObjectPath("/StatusNotifierWatcher")
	sniIface    = "org.kde.StatusNotifierItem"
	sniPath     = dbus.ObjectPath("/StatusNotifierItem")
	menuIface   = "com.canonical.dbusmenu"
	menuPath    = dbus.ObjectPath("/MenuBar")
)

type vmap = map[string]dbus.Variant

// layout — (ia{sv}av) из спецификации dbusmenu.
type layout struct {
	ID       int32
	Props    vmap
	Children []dbus.Variant
}

type item struct {
	id       int32
	label    string
	check    bool // пункт-флажок
	on       bool
	sep      bool
	children []*item
	act      func()
}

type menu struct {
	mu   sync.Mutex
	conn *dbus.Conn
	rev  uint32
	root *item
	byID map[int32]*item
	quit chan struct{}
}

func (m *menu) index(it *item) {
	m.byID[it.id] = it
	for _, c := range it.children {
		m.index(c)
	}
}

func (it *item) props() vmap {
	p := vmap{}
	if it.sep {
		p["type"] = dbus.MakeVariant("separator")
		return p
	}
	if it.id != 0 {
		p["label"] = dbus.MakeVariant(it.label)
	}
	if it.check {
		p["toggle-type"] = dbus.MakeVariant("checkmark")
		st := int32(0)
		if it.on {
			st = 1
		}
		p["toggle-state"] = dbus.MakeVariant(st)
	}
	if len(it.children) > 0 {
		p["children-display"] = dbus.MakeVariant("submenu")
	}
	return p
}

func (it *item) layout(depth int32) layout {
	l := layout{ID: it.id, Props: it.props(), Children: []dbus.Variant{}}
	if depth == 0 {
		return l
	}
	for _, c := range it.children {
		l.Children = append(l.Children, dbus.MakeVariant(c.layout(depth-1)))
	}
	return l
}

// --- com.canonical.dbusmenu ---

func (m *menu) GetLayout(parent, depth int32, names []string) (uint32, layout, *dbus.Error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	log.Printf("IN  GetLayout(parent=%d, depth=%d, props=%v)", parent, depth, names)
	it, ok := m.byID[parent]
	if !ok {
		return 0, layout{}, dbus.MakeFailedError(fmt.Errorf("no item %d", parent))
	}
	return m.rev, it.layout(depth), nil
}

type idProps struct {
	ID    int32
	Props vmap
}

func (m *menu) GetGroupProperties(ids []int32, names []string) ([]idProps, *dbus.Error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	log.Printf("IN  GetGroupProperties(ids=%v)", ids)
	out := []idProps{}
	for _, id := range ids {
		if it, ok := m.byID[id]; ok {
			out = append(out, idProps{id, it.props()})
		}
	}
	return out, nil
}

func (m *menu) GetProperty(id int32, name string) (dbus.Variant, *dbus.Error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	log.Printf("IN  GetProperty(%d, %q)", id, name)
	if it, ok := m.byID[id]; ok {
		if v, ok := it.props()[name]; ok {
			return v, nil
		}
	}
	return dbus.Variant{}, dbus.MakeFailedError(fmt.Errorf("no property"))
}

func (m *menu) Event(id int32, ev string, data dbus.Variant, ts uint32) *dbus.Error {
	log.Printf("IN  Event(id=%d, %q)", id, ev)
	m.event(id, ev)
	return nil
}

type evt struct {
	ID   int32
	Ev   string
	Data dbus.Variant
	TS   uint32
}

func (m *menu) EventGroup(evs []evt) ([]int32, *dbus.Error) {
	log.Printf("IN  EventGroup(%d событий)", len(evs))
	for _, e := range evs {
		m.event(e.ID, e.Ev)
	}
	return []int32{}, nil
}

func (m *menu) AboutToShow(id int32) (bool, *dbus.Error) {
	log.Printf("IN  AboutToShow(%d)", id)
	return false, nil
}

func (m *menu) AboutToShowGroup(ids []int32) ([]int32, []int32, *dbus.Error) {
	log.Printf("IN  AboutToShowGroup(%v)", ids)
	return []int32{}, []int32{}, nil
}

func (m *menu) event(id int32, ev string) {
	if ev != "clicked" {
		return
	}
	m.mu.Lock()
	it, ok := m.byID[id]
	if !ok {
		m.mu.Unlock()
		return
	}
	if it.check {
		it.on = !it.on
		m.rev++
		rev, p := m.rev, it.props()
		log.Printf("    флажок %d (%s) -> %v", id, it.label, it.on)
		m.conn.Emit(menuPath, menuIface+".ItemsPropertiesUpdated",
			[]idProps{{id, p}}, []struct {
				ID    int32
				Names []string
			}{})
		m.conn.Emit(menuPath, menuIface+".LayoutUpdated", rev, int32(0))
		log.Printf("OUT ItemsPropertiesUpdated + LayoutUpdated(rev=%d)", rev)
	}
	act := it.act
	m.mu.Unlock()
	if act != nil {
		act()
	}
}

// --- org.kde.StatusNotifierItem (методы; свойства — через prop) ---

type sni struct{}

func (sni) Activate(x, y int32) *dbus.Error          { log.Printf("IN  Activate(%d,%d)", x, y); return nil }
func (sni) SecondaryActivate(x, y int32) *dbus.Error { log.Printf("IN  SecondaryActivate"); return nil }
func (sni) ContextMenu(x, y int32) *dbus.Error       { log.Printf("IN  ContextMenu"); return nil }
func (sni) Scroll(d int32, o string) *dbus.Error     { log.Printf("IN  Scroll(%d,%s)", d, o); return nil }

type pixmap struct {
	W, H int32
	Data []byte
}

// icon — квадрат n×n, ARGB32 в сетевом порядке байт (A,R,G,B), как требует SNI.
func icon(n int) []pixmap {
	b := make([]byte, 0, n*n*4)
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if x < 2 || y < 2 || x >= n-2 || y >= n-2 {
				b = append(b, 0xff, 0xff, 0xff, 0xff)
			} else {
				b = append(b, 0xff, 0x20, 0x90, 0xf0)
			}
		}
	}
	return []pixmap{{int32(n), int32(n), b}}
}

func register(conn *dbus.Conn, name string) {
	w := conn.Object(watcherName, watcherPath)
	if err := w.Call(watcherName+".RegisterStatusNotifierItem", 0, name).Err; err != nil {
		log.Printf("регистрация у Watcher не удалась: %v", err)
		return
	}
	host, _ := w.GetProperty(watcherName + ".IsStatusNotifierHostRegistered")
	items, _ := w.GetProperty(watcherName + ".RegisteredStatusNotifierItems")
	log.Printf("зарегистрирован; HostRegistered=%v; Items=%v", host, items)
}

func main() {
	ttl := flag.Duration("t", 25*time.Second, "время жизни")
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	m := &menu{conn: conn, rev: 1, byID: map[int32]*item{}, quit: make(chan struct{})}
	m.root = &item{id: 0, children: []*item{
		{id: 1, label: "Управляющий ПК: spike", act: func() { log.Print("    нажат обычный пункт") }},
		{id: 2, label: "Рядом: ПК-1", check: true},
		{id: 3, label: "Отправить", children: []*item{
			{id: 31, label: "Файл…", act: func() { log.Print("    Отправить: Файл") }},
			{id: 32, label: "Текст…", act: func() { log.Print("    Отправить: Текст") }},
		}},
		{id: 4, sep: true},
		{id: 5, label: "Выйти", act: func() { close(m.quit) }},
	}}
	m.index(m.root)

	if err := conn.Export(m, menuPath, menuIface); err != nil {
		log.Fatal(err)
	}
	if err := conn.Export(sni{}, sniPath, sniIface); err != nil {
		log.Fatal(err)
	}
	ro := func(v any) *prop.Prop { return &prop.Prop{Value: v, Emit: prop.EmitFalse} }
	props, err := prop.Export(conn, sniPath, prop.Map{sniIface: {
		"Category":   ro("ApplicationStatus"),
		"Id":         ro("anypc-spike"),
		"Title":      ro("AnyPC (spike)"),
		"Status":     ro("Active"),
		"IconName":   ro(""),
		"IconPixmap": ro(icon(22)),
		"ItemIsMenu": ro(true),
		"Menu":       ro(menuPath),
	}})
	if err != nil {
		log.Fatal(err)
	}
	mprops, err := prop.Export(conn, menuPath, prop.Map{menuIface: {
		"Version":       ro(uint32(3)),
		"Status":        ro("normal"),
		"TextDirection": ro("ltr"),
		"IconThemePath": ro([]string{}),
	}})
	if err != nil {
		log.Fatal(err)
	}
	conn.Export(introspect.NewIntrospectable(&introspect.Node{Name: string(sniPath), Interfaces: []introspect.Interface{
		introspect.IntrospectData, prop.IntrospectData,
		{Name: sniIface, Methods: introspect.Methods(sni{}), Properties: props.Introspection(sniIface)},
	}}), sniPath, "org.freedesktop.DBus.Introspectable")
	conn.Export(introspect.NewIntrospectable(&introspect.Node{Name: string(menuPath), Interfaces: []introspect.Interface{
		introspect.IntrospectData, prop.IntrospectData,
		{Name: menuIface, Methods: introspect.Methods(m), Properties: mprops.Introspection(menuIface)},
	}}), menuPath, "org.freedesktop.DBus.Introspectable")

	// Имя по традиции SNI; Watcher'у годится и уникальное имя соединения.
	name := fmt.Sprintf("org.kde.StatusNotifierItem-%d-1", os.Getpid())
	if r, err := conn.RequestName(name, dbus.NameFlagDoNotQueue); err != nil || r != dbus.RequestNameReplyPrimaryOwner {
		log.Fatalf("имя %s: %v %v", name, r, err)
	}
	log.Printf("на шине: %s (%s)", name, conn.Names()[0])

	// Watcher может отсутствовать (нет расширения AppIndicator, экран заблокирован) и появиться позже.
	sig := make(chan *dbus.Signal, 8)
	conn.Signal(sig)
	conn.AddMatchSignal(dbus.WithMatchInterface("org.freedesktop.DBus"), dbus.WithMatchMember("NameOwnerChanged"),
		dbus.WithMatchArg(0, watcherName))
	var has bool
	conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, watcherName).Store(&has)
	if has {
		register(conn, name)
	} else {
		log.Printf("НЕТ %s на шине — значок показать некому; жду появления", watcherName)
	}

	timeout := time.After(*ttl)
	for {
		select {
		case s := <-sig:
			if s.Name == "org.freedesktop.DBus.NameOwnerChanged" && len(s.Body) == 3 {
				if owner, _ := s.Body[2].(string); owner != "" {
					log.Printf("Watcher появился (%s) — регистрируюсь", owner)
					register(conn, name)
				} else {
					log.Print("Watcher исчез")
				}
			}
		case <-m.quit:
			log.Print("выход по пункту «Выйти»")
			return
		case <-timeout:
			log.Print("выход по таймеру")
			return
		}
	}
}
