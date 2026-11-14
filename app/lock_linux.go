// Блокировка экрана мастера (Э3, UI-REDESIGN.md, решение владельца 5): по ней мастер снимает выданные пропуска.
// Чистый Go через godbus, как трей (tray_linux.go). Два источника, любой из них: GNOME —
// org.gnome.ScreenSaver.ActiveChanged(true) на сессионной шине; logind — свойство LockedHint сеанса
// (org.freedesktop.login1.Session, его ставит рабочий стол через SetLockedHint) на системной. Сигнал принимается
// только от текущего владельца имени службы: адресный сигнал с тем же путём и именем может прислать любой клиент шины.
// Ложная блокировка лишь снимает пропуска (строже); разблокировка ничего не открывает.
package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/godbus/dbus/v5"
)

func init() { startLock = runLock }

// lockSrc — откуда сигнал блокировки.
type lockSrc struct {
	owner  string          // имя службы на шине: сигнал — только от его текущего владельца
	path   dbus.ObjectPath // объект, который шлёт сигнал
	iface  string
	member string
	locked func(body []any) bool // сигнал — блокировка (не разблокировка и не другое свойство)
}

var gnomeLock = lockSrc{owner: "org.gnome.ScreenSaver", path: "/org/gnome/ScreenSaver", iface: "org.gnome.ScreenSaver", member: "ActiveChanged",
	locked: func(b []any) bool { return len(b) == 1 && b[0] == true }}

// logindLock — PropertiesChanged сеанса path с LockedHint = true.
func logindLock(path dbus.ObjectPath) lockSrc {
	return lockSrc{owner: "org.freedesktop.login1", path: path, iface: "org.freedesktop.DBus.Properties", member: "PropertiesChanged",
		locked: func(b []any) bool {
			if len(b) < 2 || b[0] != "org.freedesktop.login1.Session" {
				return false
			}
			ch, _ := b[1].(map[string]dbus.Variant)
			v, ok := ch["LockedHint"]
			return ok && v.Value() == true
		}}
}

// runLock — startLock на Linux. Нет шины (служба без графического сеанса) — без детектора, в журнал.
func runLock(ctx context.Context, on func()) {
	if addr := os.Getenv("DBUS_SESSION_BUS_ADDRESS"); addr != "" { // без переменной godbus запустил бы dbus-launch
		go func() {
			conn, err := dbus.Connect(addr, dbus.WithContext(ctx))
			if err == nil {
				defer conn.Close()
				err = watchLock(ctx, conn, gnomeLock, on)
			}
			if err != nil {
				log.Printf("блокировка экрана (GNOME): %v", err)
			}
		}()
	}
	go func() {
		conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
		if err != nil {
			log.Printf("блокировка экрана (logind): %v", err)
			return
		}
		defer conn.Close()
		id := os.Getenv("XDG_SESSION_ID")
		if id == "" {
			id = "auto" // сеанс вызывающего (или графический сеанс пользователя)
		}
		var path dbus.ObjectPath
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = conn.Object("org.freedesktop.login1", "/org/freedesktop/login1").CallWithContext(c, "org.freedesktop.login1.Manager.GetSession", 0, id).Store(&path)
		cancel()
		if err == nil {
			err = watchLock(ctx, conn, logindLock(path), on)
		}
		if err != nil {
			log.Printf("блокировка экрана (logind): %v", err)
		}
	}()
}

// watchLock — до конца ctx звать on() на каждый сигнал блокировки src от владельца его имени.
func watchLock(ctx context.Context, conn *dbus.Conn, src lockSrc, on func()) error {
	sig := make(chan *dbus.Signal, 8)
	conn.Signal(sig)
	defer conn.RemoveSignal(sig)
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	err := conn.AddMatchSignalContext(c, dbus.WithMatchObjectPath(src.path), dbus.WithMatchInterface(src.iface), dbus.WithMatchMember(src.member))
	cancel()
	if err != nil {
		return err
	}
	name := src.iface + "." + src.member
	for {
		select {
		case <-ctx.Done():
			return nil
		case s, ok := <-sig:
			if !ok {
				if ctx.Err() != nil {
					return nil
				}
				return dbus.ErrClosed
			}
			if s.Path != src.path || s.Name != name || !src.locked(s.Body) {
				continue
			}
			var owner string
			c, cancel := context.WithTimeout(ctx, 5*time.Second)
			conn.BusObject().CallWithContext(c, "org.freedesktop.DBus.GetNameOwner", 0, src.owner).Store(&owner)
			cancel()
			if owner == "" || s.Sender != owner {
				log.Printf("блокировка экрана: сигнал %s не от %s — пропущен", name, src.owner)
				continue
			}
			log.Printf("блокировка экрана (%s)", src.owner)
			on()
		}
	}
}
