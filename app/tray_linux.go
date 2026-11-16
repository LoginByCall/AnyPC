// Значок в трее Linux чистым Go (без cgo): org.kde.StatusNotifierItem + меню com.canonical.dbusmenu на сессионной
// шине. Проба — spike/tray/main.go (V2 владельца 2026-11-13: значок и меню в Ubuntu видны). Окно открывается при
// запуске как раньше; трей — дополнительный вход, его отсутствие ничего не ломает.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
)

func init() { startTray = runTray }

const (
	watcherName = "org.kde.StatusNotifierWatcher"
	watcherPath = dbus.ObjectPath("/StatusNotifierWatcher")
	sniIface    = "org.kde.StatusNotifierItem"
	sniPath     = dbus.ObjectPath("/StatusNotifierItem")
	menuIface   = "com.canonical.dbusmenu"
	menuPath    = dbus.ObjectPath("/MenuBar")
)

// runTray — значок, пока жив ctx. Нет сессионной шины (служба без графического сеанса) — молча ничего.
// Адрес только из переменной: godbus без неё запустил бы dbus-launch.
func runTray(ctx context.Context, d trayDeps) {
	addr := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	if addr == "" {
		return
	}
	if err := serveTray(ctx, addr, d); err != nil {
		log.Printf("трей: %v — значка не будет, окно — как обычно", err)
	}
}

// trayPoll — как часто трей перечитывает состояние (состав пространства, «я тут»): как окно опрашивает hostInfo.
var trayPoll = time.Second

// trayTree — дерево dbusmenu из пунктов rows.
func trayTree(rows []trayRow) *trayItem {
	root := &trayItem{}
	for _, r := range rows {
		it := &trayItem{id: int32(r.ID), label: trayText(r, " · "), sep: r.Label == ""}
		if len(r.Sub) > 0 { // Ч10.5 «Отправить ›»: children-display "submenu"
			it.children = trayTree(r.Sub).children
		}
		root.children = append(root.children, it)
	}
	return root
}

// trayMenuState — текущее меню: пункты, дерево и номер ревизии (растёт при каждой смене — LayoutUpdated).
type trayMenuState struct {
	mu   sync.Mutex
	rev  uint32
	rows []trayRow
	root *trayItem
}

// set — новые пункты; true — меню изменилось (ревизия выросла).
func (s *trayMenuState) set(rows []trayRow) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root != nil && trayRowsEqual(rows, s.rows) {
		return false
	}
	s.rev++
	s.rows, s.root = rows, trayTree(rows)
	return true
}

func (s *trayMenuState) get() (uint32, []trayRow, *trayItem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rev, s.rows, s.root
}

type vmap = map[string]dbus.Variant

// trayLayout — (ia{sv}av) из спецификации dbusmenu.
type trayLayout struct {
	ID       int32
	Props    vmap
	Children []dbus.Variant
}

// trayItem — пункт меню; дерево неизменно после создания (смена меню — новое дерево, trayMenuState).
type trayItem struct {
	id       int32
	label    string
	sep      bool
	children []*trayItem
}

func (it *trayItem) props() vmap {
	p := vmap{}
	switch {
	case it.sep:
		p["type"] = dbus.MakeVariant("separator")
	case it.id != 0:
		p["label"] = dbus.MakeVariant(strings.ReplaceAll(it.label, "_", "__")) // «_» в dbusmenu — мнемоника
	}
	if len(it.children) > 0 {
		p["children-display"] = dbus.MakeVariant("submenu")
	}
	return p
}

func (it *trayItem) layout(depth int32) trayLayout {
	l := trayLayout{ID: it.id, Props: it.props(), Children: []dbus.Variant{}}
	if depth == 0 {
		return l
	}
	for _, c := range it.children {
		l.Children = append(l.Children, dbus.MakeVariant(c.layout(depth-1)))
	}
	return l
}

func (it *trayItem) find(id int32) *trayItem {
	if it.id == id {
		return it
	}
	for _, c := range it.children {
		if f := c.find(id); f != nil {
			return f
		}
	}
	return nil
}

// trayMenuObj — com.canonical.dbusmenu; gate — общий с traySNI предел открытий окна.
type trayMenuObj struct {
	st   *trayMenuState
	gate func() bool
	d    trayDeps
}

func (m trayMenuObj) GetLayout(parent, depth int32, names []string) (uint32, trayLayout, *dbus.Error) {
	rev, _, root := m.st.get()
	it := root.find(parent)
	if it == nil {
		return 0, trayLayout{}, dbus.MakeFailedError(fmt.Errorf("no item %d", parent))
	}
	return rev, it.layout(depth), nil
}

type trayIDProps struct {
	ID    int32
	Props vmap
}

func (m trayMenuObj) GetGroupProperties(ids []int32, names []string) ([]trayIDProps, *dbus.Error) {
	out := []trayIDProps{}
	_, _, root := m.st.get()
	for _, id := range ids {
		if it := root.find(id); it != nil {
			out = append(out, trayIDProps{id, it.props()})
		}
	}
	return out, nil
}

func (m trayMenuObj) GetProperty(id int32, name string) (dbus.Variant, *dbus.Error) {
	_, _, root := m.st.get()
	if it := root.find(id); it != nil {
		if v, ok := it.props()[name]; ok {
			return v, nil
		}
	}
	return dbus.Variant{}, dbus.MakeFailedError(fmt.Errorf("no property"))
}

func (m trayMenuObj) Event(id int32, ev string, data dbus.Variant, ts uint32) *dbus.Error {
	m.event(id, ev)
	return nil
}

type trayEvt struct {
	ID   int32
	Ev   string
	Data dbus.Variant
	TS   uint32
}

func (m trayMenuObj) EventGroup(evs []trayEvt) ([]int32, *dbus.Error) {
	for _, e := range evs {
		m.event(e.ID, e.Ev)
	}
	return []int32{}, nil
}

func (m trayMenuObj) AboutToShow(id int32) (bool, *dbus.Error) { return false, nil }

func (m trayMenuObj) AboutToShowGroup(ids []int32) ([]int32, []int32, *dbus.Error) {
	return []int32{}, []int32{}, nil
}

func (m trayMenuObj) event(id int32, ev string) {
	if ev != "clicked" {
		return
	}
	_, rows, _ := m.st.get()
	if f := trayPick(int(id), rows, m.gate, m.d); f != nil {
		go f() // не держать обработчик шины (открытие окна запускает процесс)
	}
}

// traySNI — методы org.kde.StatusNotifierItem; щелчок по значку там, где оболочка его передаёт, — главное окно.
type traySNI struct {
	open func()
	gate func() bool
}

func (s traySNI) Activate(x, y int32) *dbus.Error {
	if s.open != nil && s.gate() {
		go s.open()
	}
	return nil
}
func (traySNI) SecondaryActivate(x, y int32) *dbus.Error { return nil }
func (traySNI) ContextMenu(x, y int32) *dbus.Error       { return nil }
func (traySNI) Scroll(d int32, o string) *dbus.Error     { return nil }

var trayN atomic.Int32 // номер значка в имени на шине (уникальность в пределах процесса)

// serveTray — подключиться к шине addr, выставить значок и меню и держать их до ctx.Done. Watcher может
// отсутствовать (GNOME без расширения AppIndicator) и пропадать (блокировка экрана, измерено) — тогда ждём
// его появления по NameOwnerChanged и регистрируемся заново.
// Меню перечитывается раз в trayPoll; сменилось — LayoutUpdated.
func serveTray(ctx context.Context, addr string, d trayDeps) error {
	conn, err := dbus.Connect(addr, dbus.WithContext(ctx)) // отмена ctx закрывает соединение и рвёт ждущие вызовы
	if err != nil {
		return err
	}
	defer conn.Close()
	// call — вызов с пределом 5 с: молчащий Watcher не вешает трей
	call := func(o dbus.BusObject, method string, args ...any) *dbus.Call {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return o.CallWithContext(c, method, 0, args...)
	}
	gate := trayGate(trayOpenGap)
	st := &trayMenuState{}
	st.set(d.rows())
	m := trayMenuObj{st, gate, d}
	if err := conn.Export(m, menuPath, menuIface); err != nil {
		return err
	}
	if err := conn.Export(traySNI{d.open, gate}, sniPath, sniIface); err != nil {
		return err
	}
	ro := func(v any) *prop.Prop { return &prop.Prop{Value: v, Emit: prop.EmitFalse} }
	props, err := prop.Export(conn, sniPath, prop.Map{sniIface: {
		"Category":   ro("ApplicationStatus"),
		"Id":         ro("anypc"),
		"Title":      ro("AnyPC"),
		"Status":     ro("Active"),
		"IconName":   ro(""),
		"IconPixmap": ro([]trayPixmap{trayIcon(22), trayIcon(44)}),
		"ItemIsMenu": ro(true),
		"Menu":       ro(menuPath),
	}})
	if err != nil {
		return err
	}
	mprops, err := prop.Export(conn, menuPath, prop.Map{menuIface: {
		"Version":       ro(uint32(3)),
		"Status":        ro("normal"),
		"TextDirection": ro("ltr"),
		"IconThemePath": ro([]string{}),
	}})
	if err != nil {
		return err
	}
	conn.Export(introspect.NewIntrospectable(&introspect.Node{Name: string(sniPath), Interfaces: []introspect.Interface{
		introspect.IntrospectData, prop.IntrospectData,
		{Name: sniIface, Methods: introspect.Methods(traySNI{}), Properties: props.Introspection(sniIface)},
	}}), sniPath, "org.freedesktop.DBus.Introspectable")
	conn.Export(introspect.NewIntrospectable(&introspect.Node{Name: string(menuPath), Interfaces: []introspect.Interface{
		introspect.IntrospectData, prop.IntrospectData,
		{Name: menuIface, Methods: introspect.Methods(m), Properties: mprops.Introspection(menuIface),
			Signals: []introspect.Signal{{Name: "LayoutUpdated", Args: []introspect.Arg{{Name: "revision", Type: "u"}, {Name: "parent", Type: "i"}}}}},
	}}), menuPath, "org.freedesktop.DBus.Introspectable")

	name := fmt.Sprintf("org.kde.StatusNotifierItem-%d-%d", os.Getpid(), trayN.Add(1))
	var r uint32
	if err := call(conn.BusObject(), "org.freedesktop.DBus.RequestName", name, uint32(dbus.NameFlagDoNotQueue)).Store(&r); err != nil ||
		r != uint32(dbus.RequestNameReplyPrimaryOwner) {
		return fmt.Errorf("имя %s: %v %v", name, r, err)
	}
	sig := make(chan *dbus.Signal, 8)
	conn.Signal(sig)
	mctx, mcancel := context.WithTimeout(ctx, 5*time.Second)
	err = conn.AddMatchSignalContext(mctx, dbus.WithMatchSender("org.freedesktop.DBus"), dbus.WithMatchInterface("org.freedesktop.DBus"),
		dbus.WithMatchMember("NameOwnerChanged"), dbus.WithMatchArg(0, watcherName))
	mcancel()
	if err != nil {
		return err
	}
	register := func() {
		w := conn.Object(watcherName, watcherPath)
		if err := call(w, watcherName+".RegisterStatusNotifierItem", name).Err; err != nil {
			log.Printf("трей: регистрация у %s не удалась: %v", watcherName, err)
			return
		}
		var v dbus.Variant
		if call(w, "org.freedesktop.DBus.Properties.Get", watcherName, "IsStatusNotifierHostRegistered").Store(&v) == nil && v.Value() == false {
			log.Print("трей: нет хоста значков (StatusNotifierHost) — значка не видно, окно — как обычно")
			return
		}
		log.Print("трей: значок зарегистрирован")
	}
	var has bool
	call(conn.BusObject(), "org.freedesktop.DBus.NameHasOwner", watcherName).Store(&has)
	if has {
		register()
	} else {
		log.Printf("трей: нет %s (GNOME без расширения AppIndicator?) — значка не будет, окно — как обычно", watcherName)
	}
	tick := time.NewTicker(trayPoll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			if d.state != nil && st.set(d.rows()) { // состав пространства или «я тут» сменились
				rev, _, _ := st.get()
				conn.Emit(menuPath, menuIface+".LayoutUpdated", rev, int32(0))
			}
		case s, ok := <-sig:
			if !ok {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("сессионная шина закрыта")
			}
			// только настоящий сигнал шины о Watcher: адресный «NameOwnerChanged» может прислать любой клиент
			if s.Sender != "org.freedesktop.DBus" || s.Name != "org.freedesktop.DBus.NameOwnerChanged" || len(s.Body) != 3 || s.Body[0] != watcherName {
				continue
			}
			if owner, _ := s.Body[2].(string); owner != "" {
				register() // Watcher вернулся (после блокировки экрана) — он нас забыл
			}
		}
	}
}
