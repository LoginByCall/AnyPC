package agent

import (
	"encoding/json"
	"fmt"
	"sync"
)

// Канал данных "input" (ТЗ §7). JSON:
//
//	{"t":"m","x":0..65535,"y":0..65535}  мышь, абсолютно по захватываемому монитору
//	{"t":"b","b":0|1|2,"d":true}         кнопка: 0 левая, 1 средняя, 2 правая; d — нажата
//	{"t":"w","v":±120} / {"t":"h","v":…} колесо вертикальное / горизонтальное
//	{"t":"k","c":"KeyA","d":true}        клавиша по KeyboardEvent.code → скан-код set 1
type inputMsg struct {
	T string `json:"t"`
	X int    `json:"x"`
	Y int    `json:"y"`
	B int    `json:"b"`
	D bool   `json:"d"`
	V int    `json:"v"`
	C string `json:"c"`
}

// event — готовая к SendInput запись: флаги — константы Win32.
type event struct {
	key   bool
	x, y  int32
	data  int32 // колесо
	scan  uint16
	flags uint32
}

const (
	mMove, mLeftDown, mLeftUp, mRightDown, mRightUp = 0x1, 0x2, 0x4, 0x8, 0x10
	mMiddleDown, mMiddleUp, mWheel, mHWheel, mAbs   = 0x20, 0x40, 0x800, 0x1000, 0x8000
	kExtended, kUp, kScancode                       = 0x1, 0x2, 0x8
)

var btnFlags = [3][2]uint32{{mLeftUp, mLeftDown}, {mMiddleUp, mMiddleDown}, {mRightUp, mRightDown}}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// decode валидирует сообщение (REQ-S-07) и переводит в событие Win32.
func decode(raw []byte) (event, error) {
	var m inputMsg
	if err := json.Unmarshal(raw, &m); err != nil {
		return event{}, err
	}
	switch m.T {
	case "m":
		if m.X < 0 || m.X > 65535 || m.Y < 0 || m.Y > 65535 {
			return event{}, fmt.Errorf("координаты вне 0..65535: %d,%d", m.X, m.Y)
		}
		return event{x: int32(m.X), y: int32(m.Y), flags: mMove | mAbs}, nil
	case "b":
		if m.B < 0 || m.B > 2 {
			return event{}, fmt.Errorf("кнопка %d", m.B)
		}
		return event{flags: btnFlags[m.B][b2i(m.D)]}, nil
	case "w", "h":
		v := max(-1200, min(1200, m.V))
		f := uint32(mWheel)
		if m.T == "h" {
			f = mHWheel
		}
		return event{data: int32(v), flags: f}, nil
	case "k":
		k, ok := scancodes[m.C]
		if !ok {
			return event{}, fmt.Errorf("неизвестная клавиша %q", m.C)
		}
		f := uint32(kScancode)
		if k > 0xff {
			f |= kExtended
		}
		if !m.D {
			f |= kUp
		}
		return event{key: true, scan: uint16(k & 0xff), flags: f}, nil
	}
	return event{}, fmt.Errorf("тип %q", m.T)
}

// held — зажатые клавиши и кнопки: при разрыве сессии отпускаются, чтобы на хосте не «залип» Ctrl.
type held struct {
	mu   sync.Mutex
	keys map[uint16]uint32 // скан-код → флаг extended
	btns [3]bool
}

func (h *held) track(e event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if e.key {
		if h.keys == nil {
			h.keys = map[uint16]uint32{}
		}
		if e.flags&kUp != 0 {
			delete(h.keys, e.scan)
		} else {
			h.keys[e.scan] = e.flags & kExtended
		}
		return
	}
	for i, f := range btnFlags {
		if e.flags&f[1] != 0 {
			h.btns[i] = true
		}
		if e.flags&f[0] != 0 {
			h.btns[i] = false
		}
	}
}

// release возвращает события отпускания всего зажатого и очищает состояние.
func (h *held) release() []event {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []event
	for s, ext := range h.keys {
		out = append(out, event{key: true, scan: s, flags: kScancode | kUp | ext})
	}
	for i, down := range h.btns {
		if down {
			out = append(out, event{flags: btnFlags[i][0]})
		}
	}
	h.keys, h.btns = nil, [3]bool{}
	return out
}

// scancodes: KeyboardEvent.code → скан-код PC/AT set 1; 0xE0xx — extended.
var scancodes = map[string]uint16{
	"Escape": 0x01, "Digit1": 0x02, "Digit2": 0x03, "Digit3": 0x04, "Digit4": 0x05, "Digit5": 0x06,
	"Digit6": 0x07, "Digit7": 0x08, "Digit8": 0x09, "Digit9": 0x0A, "Digit0": 0x0B, "Minus": 0x0C,
	"Equal": 0x0D, "Backspace": 0x0E, "Tab": 0x0F, "KeyQ": 0x10, "KeyW": 0x11, "KeyE": 0x12,
	"KeyR": 0x13, "KeyT": 0x14, "KeyY": 0x15, "KeyU": 0x16, "KeyI": 0x17, "KeyO": 0x18, "KeyP": 0x19,
	"BracketLeft": 0x1A, "BracketRight": 0x1B, "Enter": 0x1C, "ControlLeft": 0x1D, "KeyA": 0x1E,
	"KeyS": 0x1F, "KeyD": 0x20, "KeyF": 0x21, "KeyG": 0x22, "KeyH": 0x23, "KeyJ": 0x24, "KeyK": 0x25,
	"KeyL": 0x26, "Semicolon": 0x27, "Quote": 0x28, "Backquote": 0x29, "ShiftLeft": 0x2A,
	"Backslash": 0x2B, "KeyZ": 0x2C, "KeyX": 0x2D, "KeyC": 0x2E, "KeyV": 0x2F, "KeyB": 0x30,
	"KeyN": 0x31, "KeyM": 0x32, "Comma": 0x33, "Period": 0x34, "Slash": 0x35, "ShiftRight": 0x36,
	"NumpadMultiply": 0x37, "AltLeft": 0x38, "Space": 0x39, "CapsLock": 0x3A, "F1": 0x3B, "F2": 0x3C,
	"F3": 0x3D, "F4": 0x3E, "F5": 0x3F, "F6": 0x40, "F7": 0x41, "F8": 0x42, "F9": 0x43, "F10": 0x44,
	"NumLock": 0xE045, "ScrollLock": 0x46, "Numpad7": 0x47, "Numpad8": 0x48, "Numpad9": 0x49,
	"NumpadSubtract": 0x4A, "Numpad4": 0x4B, "Numpad5": 0x4C, "Numpad6": 0x4D, "NumpadAdd": 0x4E,
	"Numpad1": 0x4F, "Numpad2": 0x50, "Numpad3": 0x51, "Numpad0": 0x52, "NumpadDecimal": 0x53,
	"IntlBackslash": 0x56, "F11": 0x57, "F12": 0x58,
	"NumpadEnter": 0xE01C, "ControlRight": 0xE01D, "NumpadDivide": 0xE035, "PrintScreen": 0xE037,
	"AltRight": 0xE038, "Home": 0xE047, "ArrowUp": 0xE048, "PageUp": 0xE049, "ArrowLeft": 0xE04B,
	"ArrowRight": 0xE04D, "End": 0xE04F, "ArrowDown": 0xE050, "PageDown": 0xE051, "Insert": 0xE052,
	"Delete": 0xE053, "MetaLeft": 0xE05B, "MetaRight": 0xE05C, "ContextMenu": 0xE05D,
}

// plaques — плашка сессии (REQ-F-15): заголовок, текст, подсказка; ключ — язык интерфейса ОС.
var plaques = map[string][3]string{
	"en": {"remote session", "A remote session is in progress.", "Click “OK” to disconnect."},
	"ru": {"удалённая сессия", "Идёт удалённая сессия.", "Нажмите «ОК», чтобы разорвать."},
	"zh": {"远程会话", "正在进行远程会话。", "点击“确定”断开连接。"},
	"es": {"sesión remota", "Hay una sesión remota en curso.", "Pulse «Aceptar» para desconectar."},
	"de": {"Fernsitzung", "Eine Fernsitzung ist aktiv.", "Klicken Sie auf „OK“, um zu trennen."},
	"fr": {"session à distance", "Une session à distance est en cours.", "Cliquez sur « OK » pour déconnecter."},
	"it": {"sessione remota", "È in corso una sessione remota.", "Fai clic su «OK» per disconnettere."},
}

func plaqueText(lang, cid string) (title, text string) {
	pl, ok := plaques[lang]
	if !ok {
		pl = plaques["en"]
	}
	return "AnyPC — " + pl[0] + " " + cid, pl[1] + "\n" + cid + "\n\n" + pl[2]
}

// evdevExt — коды evdev (linux/input-event-codes.h) для extended-клавиш set 1; у остальных evdev = скан-код.
var evdevExt = map[uint16]uint16{
	0x1C: 96, 0x1D: 97, 0x35: 98, 0x37: 99, 0x38: 100, 0x45: 69, 0x47: 102, 0x48: 103, 0x49: 104,
	0x4B: 105, 0x4D: 106, 0x4F: 107, 0x50: 108, 0x51: 109, 0x52: 110, 0x53: 111, 0x5B: 125, 0x5C: 126, 0x5D: 127,
}

// evdevCode — код клавиши для Linux (X11: +8, Wayland-портал: как есть).
func evdevCode(e event) uint16 {
	if e.flags&kExtended != 0 {
		return evdevExt[e.scan]
	}
	return e.scan
}

// Monitor — монитор хоста; X, Y — левый верхний угол в пикселях виртуального экрана.
type Monitor struct {
	Name    string `json:"name"`
	X       int    `json:"x"`
	Y       int    `json:"y"`
	W       int    `json:"w"`
	H       int    `json:"h"`
	Primary bool   `json:"primary"`
}

// monPoint — точка 0..65535 внутри монитора → пиксель виртуального экрана.
func monPoint(m *Monitor, x, y int32) (int, int) {
	return m.X + int(x)*(m.W-1)/65535, m.Y + int(y)*(m.H-1)/65535
}

// listMonitors — мониторы хоста; переменная, чтобы тесты подставляли свой список.
var listMonitors = monitors

// primaryIndex — индекс основного монитора (0, если не отмечен).
func primaryIndex(ms []Monitor) int {
	for i, m := range ms {
		if m.Primary {
			return i
		}
	}
	return 0
}
