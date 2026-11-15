//go:build linux

package agent

import (
	"bufio"
	"errors"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// plaqueGJS — плашка сессии на Linux: узкая полоса «AnyPC: удалённая сессия <кто> · … [Разорвать]», как на Windows и
// Маке. gjs + GTK 3 — части GNOME (gnome-shell зависит от gjs), ничего не ставим; лицензии не наши (системные программы).
// X11: правый нижний угол рабочей области основного монитора, поверх всех окон, на всех рабочих столах, фокус не берёт.
// Wayland: при XWayland (есть DISPLAY) — то же через GDK_BACKEND=x11 (в GTK 3 на Wayland keep_above, stick, move и
// accept_focus пустые — приёмка M1); без XWayland — место, «поверх» и фокус решает mutter, полосу можно утащить за фон.
// Кнопка без фокуса: Enter/пробел оператора, попавшие в плашку, сессию не рвут; закрытие окна (Alt+F4) — рвёт.
// stdout: «ready» — окно на экране (иначе запасной путь — zenity).
const plaqueGJS = `imports.gi.versions.Gtk = '3.0';
const { Gtk, Gdk, GLib } = imports.gi;
Gtk.init(null);
const [label, btn, title] = ARGV;
const w = new Gtk.Window({ title: title, decorated: false, resizable: false, accept_focus: false, focus_on_map: false });
const css = new Gtk.CssProvider();
css.load_from_data('window { border: 1px solid alpha(currentColor, 0.35); } box { padding: 4px 6px 4px 10px; } button { padding: 2px 12px; }');
Gtk.StyleContext.add_provider_for_screen(Gdk.Screen.get_default(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION);
const ev = new Gtk.EventBox();
const box = new Gtk.Box({ orientation: Gtk.Orientation.HORIZONTAL, spacing: 12 });
const t = new Gtk.Label({ label: label, xalign: 0 });
const b = new Gtk.Button({ label: btn, can_focus: false, focus_on_click: false });
b.connect('clicked', () => Gtk.main_quit());
box.pack_start(t, true, true, 0); box.pack_end(b, false, false, 0);
ev.add(box); w.add(ev);
ev.connect('button-press-event', (_, e) => { // перетаскивание за фон, как на Маке
  const [, n] = e.get_button(), [, x, y] = e.get_root_coords();
  if (n === 1) w.begin_move_drag(n, x, y, e.get_time());
  return false;
});
w.connect('delete-event', () => { Gtk.main_quit(); return false; });
w.set_keep_above(true); w.stick();
w.show_all();
const d = Gdk.Display.get_default(), m = d.get_primary_monitor() || d.get_monitor(0);
if (m && d.constructor.$gtype.name.indexOf('X11') >= 0) { // на Wayland move не действует
  const a = m.get_workarea(), [W, H] = w.get_size();
  w.move(a.x + a.width - W - 8, a.y + a.height - H - 8);
}
print('ready');
switch (GLib.getenv('ANYPC_PLAQUE_PROBE')) { // только тесты: кнопка, закрытие окна, фокус — без человека
case 'click': GLib.idle_add(0, () => { b.clicked(); return false; }); break;
case 'close': GLib.idle_add(0, () => { w.close(); return false; }); break;
case 'focus': if (b.get_can_focus() || b.get_focus_on_click() || w.get_accept_focus() || w.get_focus_on_map()) imports.system.exit(3); break;
}
Gtk.main();`

// plaqueReady — сколько ждать окна gjs, прежде чем перейти на zenity; plaqueEnv — окружение gjs (nil — своё; тест и
// снимок ставят своё окно broadway, чтобы не выводить плашку на экран человека).
var (
	plaqueReady = 5 * time.Second
	plaqueEnv   []string
)

// showIndicator — плашка REQ-F-15: полоса gjs; нет gjs/GTK 3 — окно zenity, как раньше. Закрыл человек → разорвать.
func showIndicator(cid string, mode plaqueMode, onUserClose func()) (func(), error) {
	if fakeDesktop {
		return func() {}, nil
	}
	lang := sysLang()
	if stop, err := gjsPlaque(lang, cid, mode, onUserClose); err == nil {
		return stop, nil
	} else {
		log.Printf("плашка gjs: %v — окно zenity", err)
	}
	return zenityPlaque(lang, cid, mode, onUserClose)
}

func gjsPlaque(lang, cid string, mode plaqueMode, onUserClose func()) (func(), error) {
	bin, err := exec.LookPath("gjs")
	if err != nil {
		return nil, err
	}
	label, btn := plaqueBar(lang, cid, mode)
	title, _ := plaqueText(lang, cid, 0)
	cmd := exec.Command(bin, "-c", plaqueGJS, label, btn, title)
	cmd.Env = plaqueEnv
	if cmd.Env == nil && Wayland && os.Getenv("DISPLAY") != "" {
		cmd.Env = append(os.Environ(), "GDK_BACKEND=x11") // XWayland: угол, поверх всех, без фокуса
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL} // AnyPC упал — плашка не висит сиротой
	var errb strings.Builder
	cmd.Stderr = &errb
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	ready := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(out)
		ready <- sc.Scan() && sc.Text() == "ready"
		for sc.Scan() {
		}
	}()
	var why string
	select {
	case ok := <-ready:
		if !ok {
			why = "нет окна"
		}
	case <-time.After(plaqueReady):
		why = "окно не появилось за " + plaqueReady.String()
	}
	if why != "" {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, errors.New(why + ": " + strings.TrimSpace(errb.String()))
	}
	var byUs atomic.Bool
	go func() {
		cmd.Wait()
		if !byUs.Load() {
			onUserClose()
		}
	}()
	return func() { byUs.Store(true); cmd.Process.Kill() }, nil
}

// zenityPlaque — запасная плашка: окно zenity --warning (крупное; без gjs, напр. не GNOME).
func zenityPlaque(lang, cid string, mode plaqueMode, onUserClose func()) (func(), error) {
	bin, err := exec.LookPath("zenity")
	if err != nil {
		return nil, errors.New("нет ни gjs, ни zenity — установите пакет zenity")
	}
	title, text := plaqueText(lang, cid, mode)
	cmd := exec.Command(bin, "--warning", "--no-wrap", "--title="+title, "--text="+pangoEscape(text))
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	var byUs atomic.Bool
	go func() {
		cmd.Wait()
		if !byUs.Load() {
			onUserClose()
		}
	}()
	return func() { byUs.Store(true); cmd.Process.Kill() }, nil
}
