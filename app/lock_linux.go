// Блокировка экрана мастера (Э3, UI-REDESIGN.md, решение владельца 5): по ней мастер снимает выданные пропуска.
// Чистый Go через godbus, как трей (tray_linux.go). Источники, любой из них — блокировка:
//   - сессионная шина: org.gnome.ScreenSaver.ActiveChanged(true) (GNOME), org.freedesktop.ScreenSaver.ActiveChanged(true)
//     (KDE и другие);
//   - системная шина, logind: свойство LockedHint сеанса = true, сигнал Session.Lock, Manager.PrepareForSleep(true)
//     (сон), Manager.PrepareForShutdown(true) (выключение), SessionRemoved этого сеанса (выход из сеанса).
//
// Сигнал принимается от текущего владельца имени службы: адресный сигнал с тем же именем может прислать любой клиент
// шины. Сомнение — в сторону снятия: не узнали владельца (сбой GetNameOwner) — блокировка; потеря шины — блокировка
// и переподключение с паузой (сеанс logind ищется заново). Ложное снятие лишь просит ввести код снова.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/godbus/dbus/v5"
)

func init() { startLock = runLock }

// lockSrc — откуда сигнал блокировки.
type lockSrc struct {
	owner  string          // имя службы на шине: сигнал — только от его текущего владельца
	path   dbus.ObjectPath // объект, который шлёт сигнал; "" — любой (KDE шлёт с /ScreenSaver и /org/freedesktop/ScreenSaver)
	iface  string
	member string
	locked func(body []any) bool // сигнал — блокировка (не разблокировка и не другое свойство)
}

func activeTrue(b []any) bool { return len(b) == 1 && b[0] == true }

var (
	gnomeLock = lockSrc{owner: "org.gnome.ScreenSaver", path: "/org/gnome/ScreenSaver", iface: "org.gnome.ScreenSaver", member: "ActiveChanged", locked: activeTrue}
	fdoLock   = lockSrc{owner: "org.freedesktop.ScreenSaver", iface: "org.freedesktop.ScreenSaver", member: "ActiveChanged", locked: activeTrue}
)

const login1 = "org.freedesktop.login1"

// logindLocks — сигналы logind для сеанса path.
func logindLocks(path dbus.ObjectPath) []lockSrc {
	mgr := func(member string) lockSrc {
		return lockSrc{owner: login1, path: "/org/freedesktop/login1", iface: login1 + ".Manager", member: member, locked: activeTrue}
	}
	removed := mgr("SessionRemoved")
	removed.locked = func(b []any) bool { return len(b) == 2 && b[1] == path }
	return []lockSrc{
		{owner: login1, path: path, iface: "org.freedesktop.DBus.Properties", member: "PropertiesChanged", locked: func(b []any) bool {
			if len(b) < 2 || b[0] != login1+".Session" {
				return false
			}
			ch, _ := b[1].(map[string]dbus.Variant)
			v, ok := ch["LockedHint"]
			return ok && v.Value() == true
		}},
		{owner: login1, path: path, iface: login1 + ".Session", member: "Lock", locked: func([]any) bool { return true }},
		mgr("PrepareForSleep"), mgr("PrepareForShutdown"), removed,
	}
}

// lockRetry, lockRetryMax — пауза переподключения к шине (растёт вдвое).
var lockRetry, lockRetryMax = 2 * time.Second, 5 * time.Minute

// runLock — startLock на Linux: alive(источник, жив) — детектор подписан на шину или потерял её.
func runLock(ctx context.Context, on func(), alive func(string, bool)) {
	if addr := os.Getenv("DBUS_SESSION_BUS_ADDRESS"); addr != "" { // без переменной godbus запустил бы dbus-launch
		go lockLoop(ctx, "сессионная шина", func(ctx context.Context) (*dbus.Conn, []lockSrc, error) {
			conn, err := dbus.Connect(addr, dbus.WithContext(ctx))
			return conn, []lockSrc{gnomeLock, fdoLock}, err
		}, on, alive)
	}
	go lockLoop(ctx, "logind", func(ctx context.Context) (*dbus.Conn, []lockSrc, error) {
		conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
		if err != nil {
			return nil, nil, err
		}
		id := os.Getenv("XDG_SESSION_ID")
		if id == "" {
			id = "auto" // сеанс вызывающего (или графический сеанс пользователя)
		}
		var path dbus.ObjectPath
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = conn.Object(login1, "/org/freedesktop/login1").CallWithContext(c, login1+".Manager.GetSession", 0, id).Store(&path)
		cancel()
		if err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("сеанс %s: %w", id, err)
		}
		return conn, logindLocks(path), nil
	}, on, alive)
}

// lockLoop — до конца ctx: подключиться (open), слушать; шина пропала после подписки — блокировка, alive(false),
// пауза и заново.
func lockLoop(ctx context.Context, name string, open func(context.Context) (*dbus.Conn, []lockSrc, error), on func(), alive func(string, bool)) {
	wait := lockRetry
	for ctx.Err() == nil {
		conn, srcs, err := open(ctx)
		up := false
		if err == nil {
			err = watchLock(ctx, conn, srcs, func() { up, wait = true, lockRetry; alive(name, true) }, on)
			conn.Close()
		}
		if ctx.Err() != nil {
			return
		}
		if up {
			alive(name, false)
			log.Printf("блокировка экрана (%s): шина потеряна (%v) — считаю блокировкой", name, err)
			on()
		} else {
			log.Printf("блокировка экрана (%s): %v — повтор через %v", name, err, wait)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(2*wait, lockRetryMax)
	}
}

// watchLock — до конца ctx звать on() на каждый сигнал блокировки srcs от владельца его имени (сбой проверки
// владельца — тоже блокировка). ready — подписка на шине есть. Шина закрылась — ошибка.
func watchLock(ctx context.Context, conn *dbus.Conn, srcs []lockSrc, ready, on func()) error {
	sig := make(chan *dbus.Signal, 16)
	conn.Signal(sig)
	defer conn.RemoveSignal(sig)
	for _, s := range srcs {
		opts := []dbus.MatchOption{dbus.WithMatchInterface(s.iface), dbus.WithMatchMember(s.member)}
		if s.path != "" {
			opts = append(opts, dbus.WithMatchObjectPath(s.path))
		}
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := conn.AddMatchSignalContext(c, opts...)
		cancel()
		if err != nil {
			return err
		}
	}
	if ready != nil {
		ready()
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case s, ok := <-sig:
			if !ok {
				return dbus.ErrClosed
			}
			for _, src := range srcs {
				if s.Name != src.iface+"."+src.member || src.path != "" && s.Path != src.path || !src.locked(s.Body) {
					continue
				}
				var owner string
				c, cancel := context.WithTimeout(ctx, 5*time.Second)
				err := conn.BusObject().CallWithContext(c, "org.freedesktop.DBus.GetNameOwner", 0, src.owner).Store(&owner)
				cancel()
				if err == nil && s.Sender != owner {
					log.Printf("блокировка экрана: сигнал %s не от %s — пропущен", s.Name, src.owner)
					break
				}
				log.Printf("блокировка экрана (%s)", s.Name) // владелец не узнан (err) — тоже блокировка: строже
				on()
				break
			}
		}
	}
}
