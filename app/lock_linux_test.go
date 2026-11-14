package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// TestLockWatch — детектор блокировки на частной шине: сигнал от владельца имени службы — блокировка; тот же сигнал
// от другого клиента шины, разблокировка и другое свойство — нет. GNOME ScreenSaver и logind LockedHint.
func TestLockWatch(t *testing.T) {
	for _, c := range []struct {
		name string
		src  lockSrc
		lock []any // тело сигнала блокировки
		not  [][]any
	}{
		{"gnome", gnomeLock, []any{true}, [][]any{{false}}},
		{"logind", logindLock("/org/freedesktop/login1/session/_31"),
			[]any{"org.freedesktop.login1.Session", map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(true)}, []string{}},
			[][]any{
				{"org.freedesktop.login1.Session", map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(false)}, []string{}},
				{"org.freedesktop.login1.Session", map[string]dbus.Variant{"Active": dbus.MakeVariant(true)}, []string{}},
				{"org.freedesktop.login1.User", map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(true)}, []string{}},
			}},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr := privateBus(t)
			conn := func() *dbus.Conn {
				k, err := dbus.Connect(addr)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { k.Close() })
				return k
			}
			w, svc, fake := conn(), conn(), conn()
			if r, err := svc.RequestName(c.src.owner, dbus.NameFlagDoNotQueue); err != nil || r != dbus.RequestNameReplyPrimaryOwner {
				t.Fatalf("имя %s: %v %v", c.src.owner, r, err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var n atomic.Int32
			go watchLock(ctx, w, c.src, func() { n.Add(1) })
			emit := func(k *dbus.Conn, body []any) {
				t.Helper()
				if err := k.Emit(c.src.path, c.src.iface+"."+c.src.member, body...); err != nil {
					t.Fatal(err)
				}
				// круг до шины: сигнал разослан раньше, чем следующий от другого клиента
				if err := k.BusObject().Call("org.freedesktop.DBus.Peer.Ping", 0).Err; err != nil {
					t.Fatal(err)
				}
			}
			wait := func(want int32) {
				t.Helper()
				for range 100 {
					if n.Load() >= want {
						break
					}
					time.Sleep(20 * time.Millisecond)
				}
				time.Sleep(200 * time.Millisecond) // лишний вызов — успел бы
				if got := n.Load(); got != want {
					t.Fatalf("блокировок %d, ждали %d", got, want)
				}
			}
			for n.Load() == 0 { // подписка детектора готова — первый сигнал службы дошёл
				emit(svc, c.lock)
				time.Sleep(50 * time.Millisecond)
				if ctx.Err() != nil {
					t.Fatal(ctx.Err())
				}
			}
			time.Sleep(200 * time.Millisecond)
			base := n.Load()
			emit(fake, c.lock) // тот же путь и имя, но не владелец службы
			for _, b := range c.not {
				emit(svc, b)
			}
			emit(svc, c.lock)
			wait(base + 1)
		})
	}
}
