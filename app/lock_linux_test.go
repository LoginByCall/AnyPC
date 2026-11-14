package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func lockConn(t *testing.T, addr string) *dbus.Conn {
	t.Helper()
	k, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { k.Close() })
	return k
}

// TestLockWatch — детектор блокировки на частной шине: сигнал от владельца имени службы — блокировка; тот же сигнал
// от другого клиента шины, разблокировка и другое свойство — нет. Источники: GNOME и freedesktop ScreenSaver,
// logind LockedHint, Session.Lock, PrepareForSleep, SessionRemoved своего сеанса.
func TestLockWatch(t *testing.T) {
	sess := dbus.ObjectPath("/org/freedesktop/login1/session/_31")
	ld := logindLocks(sess)
	hint, lock, sleep, removed := ld[0], ld[1], ld[2], ld[4]
	for _, c := range []struct {
		name string
		src  lockSrc
		lock []any // тело сигнала блокировки
		not  [][]any
	}{
		{"gnome", gnomeLock, []any{true}, [][]any{{false}}},
		{"freedesktop", fdoLock, []any{true}, [][]any{{false}}},
		{"logind-hint", hint,
			[]any{"org.freedesktop.login1.Session", map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(true)}, []string{}},
			[][]any{
				{"org.freedesktop.login1.Session", map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(false)}, []string{}},
				{"org.freedesktop.login1.Session", map[string]dbus.Variant{"Active": dbus.MakeVariant(true)}, []string{}},
				{"org.freedesktop.login1.User", map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(true)}, []string{}},
			}},
		{"logind-lock", lock, nil, nil},
		{"logind-sleep", sleep, []any{true}, [][]any{{false}}},
		{"logind-removed", removed, []any{"31", sess}, [][]any{{"32", dbus.ObjectPath("/org/freedesktop/login1/session/_32")}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr := privateBus(t)
			w, svc, fake := lockConn(t, addr), lockConn(t, addr), lockConn(t, addr)
			if r, err := svc.RequestName(c.src.owner, dbus.NameFlagDoNotQueue); err != nil || r != dbus.RequestNameReplyPrimaryOwner {
				t.Fatalf("имя %s: %v %v", c.src.owner, r, err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var n atomic.Int32
			ready := make(chan struct{})
			go watchLock(ctx, w, []lockSrc{c.src}, func() { close(ready) }, func() { n.Add(1) })
			<-ready
			path := c.src.path
			if path == "" { // KDE: путь в источнике не задан — годится любой
				path = "/ScreenSaver"
			}
			emit := func(k *dbus.Conn, body []any) {
				t.Helper()
				if err := k.Emit(path, c.src.iface+"."+c.src.member, body...); err != nil {
					t.Fatal(err)
				}
				// круг до шины: сигнал разослан раньше, чем следующий от другого клиента
				if err := k.BusObject().Call("org.freedesktop.DBus.Peer.Ping", 0).Err; err != nil {
					t.Fatal(err)
				}
			}
			emit(fake, c.lock) // тот же путь и имя, но не владелец службы
			for _, b := range c.not {
				emit(svc, b)
			}
			emit(svc, c.lock)
			lockWait(t, &n, 1)
		})
	}
}

// lockWait — блокировок ровно want (лишняя успела бы прийти за 200 мс).
func lockWait(t *testing.T, n *atomic.Int32, want int32) {
	t.Helper()
	for range 100 {
		if n.Load() >= want {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if got := n.Load(); got != want {
		t.Fatalf("блокировок %d, ждали %d", got, want)
	}
}

// TestLockNoOwner — владельца имени службы нет (GetNameOwner — ошибка): сигнал — блокировка (строже).
func TestLockNoOwner(t *testing.T) {
	addr := privateBus(t)
	w, fake := lockConn(t, addr), lockConn(t, addr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var n atomic.Int32
	ready := make(chan struct{})
	go watchLock(ctx, w, []lockSrc{gnomeLock}, func() { close(ready) }, func() { n.Add(1) })
	<-ready
	fake.Emit(gnomeLock.path, "org.gnome.ScreenSaver.ActiveChanged", true)
	lockWait(t, &n, 1)
}

// TestLockBusLost — шина пропала после подписки: блокировка, источник не жив, переподключение с паузой.
func TestLockBusLost(t *testing.T) {
	addr := privateBus(t)
	old := lockRetry
	lockRetry = 100 * time.Millisecond
	defer func() { lockRetry = old }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conns := make(chan *dbus.Conn, 4)
	var opens, locks atomic.Int32
	var alive atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		lockLoop(ctx, "тест", func(context.Context) (*dbus.Conn, []lockSrc, error) {
			opens.Add(1)
			k, err := dbus.Connect(addr)
			if err == nil {
				conns <- k
			}
			return k, []lockSrc{gnomeLock}, err
		}, func() { locks.Add(1) }, func(_ string, ok bool) { alive.Store(ok) })
	}()
	k := <-conns
	for range 100 {
		if alive.Load() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !alive.Load() {
		t.Fatal("источник не ожил")
	}
	k.Close() // шина пропала
	<-conns   // переподключился
	if locks.Load() != 1 {
		t.Errorf("потеря шины: блокировок %d, ждали 1", locks.Load())
	}
	for range 100 {
		if alive.Load() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !alive.Load() || opens.Load() != 2 {
		t.Errorf("после переподключения: жив %v, подключений %d", alive.Load(), opens.Load())
	}
	cancel()
	<-done
}
