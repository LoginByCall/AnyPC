//go:build darwin

package agent

// Хост на macOS: захват — ffmpeg avfoundation, ввод — CGEventPost (CoreGraphics, cgo), буфер — pbcopy/pbpaste,
// окна «Разрешить / Отклонить», плашка и выбор файла — osascript. Разрешения «Запись экрана» и «Универсальный доступ»
// выдаёт человек (Системные настройки → Конфиденциальность); выдаются приложению, из которого запущен AnyPC (Терминал).

/*
#cgo LDFLAGS: -framework CoreGraphics -framework ApplicationServices
#include <ApplicationServices/ApplicationServices.h>

static void anyMouse(int type, double x, double y, int btn, int clicks, unsigned long long flags) {
	CGEventRef e = CGEventCreateMouseEvent(NULL, type, CGPointMake(x, y), btn);
	if (!e) return;
	if (clicks > 0) CGEventSetIntegerValueField(e, kCGMouseEventClickState, clicks);
	CGEventSetFlags(e, flags);
	CGEventPost(kCGHIDEventTap, e);
	CFRelease(e);
}
static void anyKey(int code, int down, unsigned long long flags) {
	CGEventRef e = CGEventCreateKeyboardEvent(NULL, code, down);
	if (!e) return;
	CGEventSetFlags(e, flags);
	CGEventPost(kCGHIDEventTap, e);
	CFRelease(e);
}
static void anyScroll(int v, int h) {
	CGEventRef e = CGEventCreateScrollWheelEvent2(NULL, kCGScrollEventUnitLine, 2, v, h, 0);
	if (!e) return;
	CGEventPost(kCGHIDEventTap, e);
	CFRelease(e);
}
// anyCursor — позиция курсора в точках (как CGDisplayBounds и CGEvent).
// ponytail: форма не определяется — NSCursor.currentSystemCursor отдаёт копию, сравнивать пришлось бы картинки;
// клиент показывает стрелку. Когда понадобится I-beam: при смене размера/горячей точки сравнивать TIFF со стандартными.
static int anyCursor(double *x, double *y) {
	CGEventRef e = CGEventCreate(NULL);
	if (!e) return 0;
	CGPoint p = CGEventGetLocation(e);
	CFRelease(e);
	*x = p.x; *y = p.y;
	return 1;
}
static int anyDisplays(CGDirectDisplayID *ids, int max) {
	uint32_t n = 0;
	if (CGGetActiveDisplayList(max, ids, &n) != kCGErrorSuccess) return 0;
	return n;
}
// anyAsk — запросить разрешения (окна системы появляются один раз); 1 — уже выдано.
static int anyScreenOK(int ask) { return ask ? CGRequestScreenCaptureAccess() : CGPreflightScreenCaptureAccess(); }
static int anyInputOK(int ask) {
	const void *k[] = { kAXTrustedCheckOptionPrompt }, *v[] = { ask ? kCFBooleanTrue : kCFBooleanFalse };
	CFDictionaryRef d = CFDictionaryCreate(NULL, k, v, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	int r = AXIsProcessTrustedWithOptions(d);
	CFRelease(d);
	return r;
}
// anyFlag — значение-флаг словаря сеанса: 1/0, -1 — нет ключа или не флаг.
static int anyFlag(CFDictionaryRef d, CFStringRef k) {
	CFTypeRef v = CFDictionaryGetValue(d, k);
	if (!v) return -1;
	if (CFGetTypeID(v) == CFBooleanGetTypeID()) return CFBooleanGetValue((CFBooleanRef)v) ? 1 : 0;
	if (CFGetTypeID(v) == CFNumberGetTypeID()) {
		int i = 0;
		CFNumberGetValue((CFNumberRef)v, kCFNumberIntType, &i);
		return i != 0;
	}
	return -1;
}
// anyLocked — экран заблокирован или сеанс не на консоли (быстрое переключение пользователей).
// Нет словаря (запуск из ssh/службы) — не блокировка: решать нечем, захват пробует сам.
// Ключ CGSSessionScreenIsLocked недокументирован (стоит, пока заблокировано; после разблокировки исчезает).
static int anyLocked(void) {
	CFDictionaryRef d = CGSessionCopyCurrentDictionary();
	if (!d) return 0;
	int r = anyFlag(d, CFSTR("CGSSessionScreenIsLocked")) == 1 || anyFlag(d, kCGSessionOnConsoleKey) == 0;
	CFRelease(d);
	return r;
}
*/
import "C"

import (
	"bufio"
	"context"
	"errors"
	"hash/crc32"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// fakeDesktop — только для тестов (agent_darwin_test.go): не двигать мышь и не открывать окна у человека за этим Маком.
var fakeDesktop bool

// ScreenLocked — Agent.Locked для macOS (F7): экран заблокирован — ffmpeg avfoundation кадров не даст.
func ScreenLocked() bool { return C.anyLocked() != 0 }

// Permissions — есть ли разрешения «Запись экрана» и «Универсальный доступ»; ask — показать запрос системы.
func Permissions(ask bool) (screen, input bool) {
	a := C.int(b2i(ask))
	return C.anyScreenOK(a) != 0, C.anyInputOK(a) != 0
}

// MacCapture — Agent.Capture для macOS: экран c.Mon (порядок — как в CGGetActiveDisplayList, его же берёт avfoundation).
func MacCapture(enc string) func(ctx context.Context, c Cap) (*exec.Cmd, error) {
	return func(ctx context.Context, c Cap) (*exec.Cmd, error) {
		return exec.CommandContext(ctx, "ffmpeg", FFArgs("avf:"+strconv.Itoa(max(c.Mon, 0)), enc, c)...), nil
	}
}

func init() { cursorInfo = macCursor }

func macCursor() (int, int, string, bool) {
	var x, y C.double
	if fakeDesktop || C.anyCursor(&x, &y) == 0 {
		return 0, 0, "", false
	}
	return int(x), int(y), "default", true
}

func monitors() []Monitor {
	var ids [16]C.CGDirectDisplayID
	n := int(C.anyDisplays(&ids[0], 16))
	out := make([]Monitor, 0, n)
	for i := range n {
		b := C.CGDisplayBounds(ids[i]) // в точках — как координаты CGEvent (Retina: пикселей вдвое больше)
		out = append(out, Monitor{Name: "Display " + strconv.Itoa(i+1), X: int(b.origin.x), Y: int(b.origin.y),
			W: int(b.size.width), H: int(b.size.height), Primary: C.CGDisplayIsMain(ids[i]) != 0})
	}
	return out
}

// Модификаторы CGEventFlags: у событий, выданных программой, флаги ставим сами (иначе Cmd+C приходит как «c»).
const (
	fShift, fCtrl, fAlt, fCmd = 0x20000, 0x40000, 0x80000, 0x100000
)

var modFlag = map[uint16]uint64{0x38: fShift, 0x3C: fShift, 0x3B: fCtrl, 0x3E: fCtrl, 0x3A: fAlt, 0x3D: fAlt, 0x37: fCmd, 0x36: fCmd}

var mac struct {
	sync.Mutex
	x, y           float64
	flags          uint64
	btns           [3]bool
	lastBtn        int
	lastDown       time.Time
	clicks         int
	wheelV, wheelH int32
}

// mouseTypes — [кнопка][отпущена, нажата, тащим]: kCGEventLeftMouseUp… (CGEventTypes.h).
var mouseTypes = [3][3]C.int{{2, 1, 6}, {26, 25, 27}, {4, 3, 7}}

// cgButton — номер кнопки CGEvent: левая 0, правая 1, средняя 2 (у нас средняя — 1).
var cgButton = [3]C.int{0, 2, 1}

func sendInput(e event, m *Monitor) error {
	if fakeDesktop {
		return nil
	}
	mac.Lock()
	defer mac.Unlock()
	if e.key {
		sc := e.scan
		if e.flags&kExtended != 0 {
			sc |= 0xE000
		}
		code, ok := macKeys[sc]
		if !ok {
			return errors.New("клавиша без кода macOS")
		}
		down := e.flags&kUp == 0
		if f := modFlag[code]; f != 0 {
			if down {
				mac.flags |= f
			} else {
				mac.flags &^= f
			}
		}
		C.anyKey(C.int(code), C.int(b2i(down)), C.ulonglong(mac.flags))
		return nil
	}
	switch f := e.flags; {
	case f&mMove != 0:
		if m == nil {
			if ms := monitors(); len(ms) > 0 {
				m = &ms[primaryIndex(ms)]
			} else {
				return errors.New("нет мониторов")
			}
		}
		px, py := monPoint(m, e.x, e.y)
		mac.x, mac.y = float64(px), float64(py)
		typ, btn := C.int(5), C.int(0) // kCGEventMouseMoved; с зажатой кнопкой — «тащим», иначе не работает перетаскивание
		for i, d := range mac.btns {
			if d {
				typ, btn = mouseTypes[i][2], cgButton[i]
				break
			}
		}
		C.anyMouse(typ, C.double(mac.x), C.double(mac.y), btn, 0, C.ulonglong(mac.flags))
	case f&mWheel != 0: // строка на щелчок (WHEEL_DELTA = 120); вверх — положительно и там, и тут
		if n := notches(&mac.wheelV, e.data); n != 0 {
			C.anyScroll(C.int(n), 0)
		}
	case f&mHWheel != 0: // у Windows вправо — плюс, у macOS — минус
		if n := notches(&mac.wheelH, e.data); n != 0 {
			C.anyScroll(0, C.int(-n))
		}
	default:
		for i := range 3 {
			down := f&btnFlags[i][1] != 0
			if !down && f&btnFlags[i][0] == 0 {
				continue
			}
			mac.btns[i] = down
			if down { // двойной щелчок macOS узнаёт по счётчику в событии, а не по времени
				if i == mac.lastBtn && time.Since(mac.lastDown) < 500*time.Millisecond {
					mac.clicks++
				} else {
					mac.clicks = 1
				}
				mac.lastBtn, mac.lastDown = i, time.Now()
			}
			C.anyMouse(mouseTypes[i][b2i(down)], C.double(mac.x), C.double(mac.y), cgButton[i], C.int(max(mac.clicks, 1)), C.ulonglong(mac.flags))
		}
	}
	return nil
}

func hideWindow(*exec.Cmd) {}

func sysLang() string {
	for _, v := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if l := os.Getenv(v); len(l) >= 2 && l != "C" && l != "POSIX" {
			return strings.ToLower(l[:2])
		}
	}
	if out, err := exec.Command("defaults", "read", "-g", "AppleLocale").Output(); err == nil && len(out) >= 2 { // ru_RU
		return strings.ToLower(string(out[:2]))
	}
	return "en"
}

// osa — AppleScript; строки передаются аргументами (argv), а не вклеиваются в текст скрипта: ID и IP приходят из сети.
func osa(script string, args ...string) *exec.Cmd {
	return exec.Command("osascript", append([]string{"-e", "on run argv", "-e", script, "-e", "end run"}, args...)...)
}

// plaqueJS — плашка REQ-F-15: полоса поверх остальных окон (на всех рабочих столах и над полноэкранными), без рамки —
// ни «свернуть», ни «закрыть», перетаскивается за фон; фокус и значок в Dock не берёт. argv: подпись, кнопка, «x y» прежнего
// места (пусто — правый нижний угол). Перемещение печатается в stdout. «Разорвать» → osascript выходит → сессия рвётся.
const plaqueJS = `ObjC.import('Cocoa'); ObjC.import('stdlib');
function run(argv) {
  const app = $.NSApplication.sharedApplication;
  app.setActivationPolicy(1); // без значка в Доке; фокус не забирать
  const out = $.NSFileHandle.fileHandleWithStandardOutput;
  ObjC.registerSubclass({ name: 'AnyPCPlaque', protocols: ['NSWindowDelegate'], methods: {
    'windowDidMove:': { types: ['void', ['id']], implementation: function (n) {
      const o = n.object.frame.origin;
      out.writeData($(Math.round(o.x) + ' ' + Math.round(o.y) + '\n').dataUsingEncoding($.NSUTF8StringEncoding)); } },
    'ok:': { types: ['void', ['id']], implementation: function () { $.exit(0); } } } });
  const d = $.AnyPCPlaque.alloc.init;
  const t = $.NSTextField.labelWithString(argv[0]); t.font = $.NSFont.systemFontOfSize(12); t.sizeToFit;
  const b = $.NSButton.buttonWithTitleTargetAction(argv[1], d, 'ok:'); b.sizeToFit;
  const tw = t.frame.size.width, bw = b.frame.size.width, W = 10 + tw + 10 + bw + 6, H = 34;
  const vf = $.NSScreen.mainScreen.visibleFrame;
  let x = vf.origin.x + vf.size.width - W - 8, y = vf.origin.y + 8;
  if (argv[2]) { // прежнее место — если оно на каком-нибудь экране
    const [px, py] = argv[2].split(' ').map(Number), ss = $.NSScreen.screens;
    for (let i = 0; i < ss.count; i++) if ($.NSPointInRect($.NSMakePoint(px + 5, py + 5), ss.objectAtIndex(i).frame)) { x = px; y = py; }
  }
  const w = $.NSWindow.alloc.initWithContentRectStyleMaskBackingDefer($.NSMakeRect(x, y, W, H), 0, 2, false);
  w.delegate = d; w.releasedWhenClosed = false; w.level = 3; w.movableByWindowBackground = true; w.hasShadow = true;
  w.collectionBehavior = 1 | 256; // на всех рабочих столах и поверх полноэкранных
  t.frameOrigin = $.NSMakePoint(10, (H - t.frame.size.height) / 2);
  b.frameOrigin = $.NSMakePoint(W - bw - 6, (H - b.frame.size.height) / 2);
  w.contentView.addSubview(t); w.contentView.addSubview(b);
  w.orderFrontRegardless;
  app.run;
}`

// plaquePos — где человек оставил плашку («x y» в координатах Cocoa): новая плашка (включение микрофона, следующая
// сессия) встаёт туда же, а не в угол заново (владелец, 2026-11-11: прежняя каждый раз вставала в центр экрана).
var plaquePos atomic.Value

// showIndicator — плашка: полоса с подписью и «Разорвать» (как на Windows), без фокуса, перетаскивается за фон.
// Закрыл её человек (или osascript упал — тогда без плашки сессии не быть) → разорвать сессию.
func showIndicator(cid string, mode plaqueMode, onUserClose func()) (func(), error) {
	if fakeDesktop {
		return func() {}, nil
	}
	label, btn := plaqueBar(sysLang(), cid, mode)
	pos, _ := plaquePos.Load().(string)
	cmd := exec.Command("osascript", "-l", "JavaScript", "-e", plaqueJS, label, btn, pos)
	var errb strings.Builder
	cmd.Stderr = &errb
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	var byUs atomic.Bool
	go func() {
		for sc := bufio.NewScanner(out); sc.Scan(); { // windowDidMove: «x y»
			plaquePos.Store(sc.Text())
		}
		err := cmd.Wait()
		if !byUs.Load() {
			if err != nil {
				log.Printf("плашка: %v %s", err, errb.String())
			}
			onUserClose()
		}
	}()
	return func() { byUs.Store(true); cmd.Process.Kill() }, nil
}

// AskAccept — окно «Разрешить / Отклонить» (REQ-F-03); без ответа AskTimeout или ошибка → отказ.
// Кнопка 1 «Отклонить» — и по умолчанию (Enter), и отмена (Esc): случайный Enter не даёт доступ.
func AskAccept(cid, peer string) Answer {
	if fakeDesktop {
		return Allow
	}
	lang := sysLang()
	title, text, yes, no, view := askText(lang, cid, peer, true)
	// display dialog кнопку на время не выключает: согласие раньше AskDelay — окно снова (askLoop)
	return askLoop(func(left time.Duration, again bool) Answer {
		text := againText(text, lang, false, again)
		out, err := osa(`set r to display dialog (item 2 of argv) with title (item 1 of argv) buttons {item 4 of argv, item 6 of argv, item 3 of argv} default button 1 cancel button 1 giving up after ((item 5 of argv) as integer) with icon caution
if gave up of r then return "no"
if button returned of r is (item 3 of argv) then return "yes"
if button returned of r is (item 6 of argv) then return "view"
return "no"`, title, text, yes, no, strconv.Itoa(int(left.Seconds())), view).Output()
		if err != nil {
			return Deny
		}
		return map[string]Answer{"yes": Allow, "view": ViewOnly}[strings.TrimSpace(string(out))]
	})
}

// AskControl — окно «Разрешить управление?» (смена режима сессии «Спрашивать»): как AskAccept, без «Только просмотр».
func AskControl(cid, peer string) bool {
	if fakeDesktop {
		return true
	}
	lang := sysLang()
	title, text, yes, no := askControlText(lang, cid, peer, true)
	return askLoop(func(left time.Duration, again bool) Answer {
		text := againText(text, lang, true, again)
		out, err := osa(`set r to display dialog (item 2 of argv) with title (item 1 of argv) buttons {item 4 of argv, item 3 of argv} default button 1 cancel button 1 giving up after ((item 5 of argv) as integer) with icon caution
if gave up of r then return "no"
if button returned of r is (item 3 of argv) then return "yes"
return "no"`, title, text, yes, no, strconv.Itoa(int(left.Seconds()))).Output()
		return map[bool]Answer{true: Allow}[err == nil && strings.TrimSpace(string(out)) == "yes"]
	}) == Allow
}

// pickFile — окно выбора файла на хосте; ctx кончился — окно закрывается.
func pickFile(ctx context.Context) (string, bool) {
	if fakeDesktop {
		return "", false
	}
	out, err := exec.CommandContext(ctx, "osascript", osa(`POSIX path of (choose file with prompt (item 1 of argv))`, "AnyPC").Args[1:]...).Output()
	p := strings.TrimRight(string(out), "\n")
	return p, err == nil && p != ""
}

// utf8 — pbcopy/pbpaste перекодируют по LANG; без UTF-8 кириллица превращается в «?».
func utf8(c *exec.Cmd) *exec.Cmd { c.Env = append(os.Environ(), "LANG=en_US.UTF-8"); return c }

func ClipText() (string, error) {
	if fakeDesktop {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := utf8(exec.CommandContext(ctx, "pbpaste")).Output()
	if err != nil {
		return "", nil
	}
	return string(out), nil
}

func SetClipText(s string) error {
	if fakeDesktop {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c := utf8(exec.CommandContext(ctx, "pbcopy"))
	c.Stdin = strings.NewReader(s)
	if err := c.Run(); err != nil {
		log.Printf("буфер обмена: %v", err)
		return err
	}
	return nil
}

// ClipSeq — контрольная сумма текста, как на Linux. ponytail: NSPasteboard.changeCount — если опрос начнёт мешать.
func ClipSeq() uint32 {
	t, _ := ClipText()
	return crc32.ChecksumIEEE([]byte(t))
}

// macKeys — скан-код set 1 (0xE0xx — extended) → виртуальный код macOS (kVK_*, HIToolbox/Events.h): раскладка ANSI.
// Win — Command, Alt — Option; Insert — Help; ContextMenu, PrintScreen, ScrollLock — нет аналога.
var macKeys = func() map[uint16]uint16 {
	byCode := map[string]uint16{
		"KeyA": 0x00, "KeyS": 0x01, "KeyD": 0x02, "KeyF": 0x03, "KeyH": 0x04, "KeyG": 0x05, "KeyZ": 0x06, "KeyX": 0x07,
		"KeyC": 0x08, "KeyV": 0x09, "IntlBackslash": 0x0A, "KeyB": 0x0B, "KeyQ": 0x0C, "KeyW": 0x0D, "KeyE": 0x0E, "KeyR": 0x0F,
		"KeyY": 0x10, "KeyT": 0x11, "Digit1": 0x12, "Digit2": 0x13, "Digit3": 0x14, "Digit4": 0x15, "Digit6": 0x16,
		"Digit5": 0x17, "Equal": 0x18, "Digit9": 0x19, "Digit7": 0x1A, "Minus": 0x1B, "Digit8": 0x1C, "Digit0": 0x1D,
		"BracketRight": 0x1E, "KeyO": 0x1F, "KeyU": 0x20, "BracketLeft": 0x21, "KeyI": 0x22, "KeyP": 0x23, "Enter": 0x24,
		"KeyL": 0x25, "KeyJ": 0x26, "Quote": 0x27, "KeyK": 0x28, "Semicolon": 0x29, "Backslash": 0x2A, "Comma": 0x2B,
		"Slash": 0x2C, "KeyN": 0x2D, "KeyM": 0x2E, "Period": 0x2F, "Tab": 0x30, "Space": 0x31, "Backquote": 0x32,
		"Backspace": 0x33, "Escape": 0x35, "MetaRight": 0x36, "MetaLeft": 0x37, "ShiftLeft": 0x38, "CapsLock": 0x39,
		"AltLeft": 0x3A, "ControlLeft": 0x3B, "ShiftRight": 0x3C, "AltRight": 0x3D, "ControlRight": 0x3E,
		"NumpadDecimal": 0x41, "NumpadMultiply": 0x43, "NumpadAdd": 0x45, "NumLock": 0x47, "NumpadDivide": 0x4B,
		"NumpadEnter": 0x4C, "NumpadSubtract": 0x4E, "Numpad0": 0x52, "Numpad1": 0x53, "Numpad2": 0x54, "Numpad3": 0x55,
		"Numpad4": 0x56, "Numpad5": 0x57, "Numpad6": 0x58, "Numpad7": 0x59, "Numpad8": 0x5B, "Numpad9": 0x5C,
		"F5": 0x60, "F6": 0x61, "F7": 0x62, "F3": 0x63, "F8": 0x64, "F9": 0x65, "F11": 0x67, "F10": 0x6D, "F12": 0x6F,
		"Insert": 0x72, "Home": 0x73, "PageUp": 0x74, "Delete": 0x75, "F4": 0x76, "End": 0x77, "F2": 0x78,
		"PageDown": 0x79, "F1": 0x7A, "ArrowLeft": 0x7B, "ArrowRight": 0x7C, "ArrowDown": 0x7D, "ArrowUp": 0x7E,
	}
	m := map[uint16]uint16{}
	for name, sc := range scancodes {
		if k, ok := byCode[name]; ok {
			m[sc] = k
		}
	}
	return m
}()
