// Общее для значка в трее Linux (tray_linux.go), строке меню Мака (window_darwin.go) и области уведомлений
// Windows (tray_windows.go): пункты меню по экрану 6 макета (Ч9 UI-REDESIGN.md) из состояния пространства, подписи на
// 7 языках, номера пунктов, дроссель открытия окна, рисунок значка.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"anypc/agent"
)

// Номера пунктов меню; одинаковы на всех ОС. Разделители — traySep, traySep1, traySep2.
const (
	trayOpen = 1   // первая строка: этот ПК или ПК с «я тут» — главное окно
	trayHelp = 2   // «Помочь кому-то…»
	traySep  = 3   // перед «Выйти»
	trayQuit = 4   // «Выйти»: единственный, кто не открывает окно
	trayHere = 5   // «Я тут — управлять с <этот ПК>» (живой «Я тут» на другом ПК): главное окно у кнопки «Я тут»
	traySep1 = 6   // после первой строки (в пространстве)
	traySep2 = 7   // после списка ПК пространства
	trayPC0  = 100 // ПК пространства: trayPC0 + номер в списке
)

// trayPC — член M (кроме этого ПК): ID и имя из «Моих ПК» окна ("" — имени нет).
type trayPC struct{ ID, Name string }

// trayState — то, из чего строится меню: состав M и где живой «Я тут».
type trayState struct {
	Self string   // ID этого ПК
	In   bool     // в пространстве (состав читается)
	Here string   // ID ПК с живым «Я тут»: Self — пропуска выдал этот ПК как мастер; другой член M — у этого ПК его пропуск; "" — нигде
	PCs  []trayPC // члены M, кроме этого ПК, в порядке состава
}

// trayStateOf — состояние трея из настроек (перечитываются, как hostInfo окна) и пропусков: выданных этим ПК
// (passes, pass.go) и выданных ему мастером (master). Имена — из «Моих ПК» окна (config.json, ключ ui.mine).
// master — ключ мастера с живым пропуском на этом ПК (Agent.PassMaster; nil — не спрашивать).
func trayStateOf(c *config, master func() []byte) trayState {
	c.mu.Lock()
	c.reload()
	m := c.spaceLocked()
	self := ed25519.PrivateKey(c.Key).Public().(ed25519.PublicKey)
	s := trayState{Self: c.ID, In: m != nil}
	mine := c.UI["mine"]
	c.mu.Unlock()
	if m == nil {
		return s
	}
	names := trayNames(mine)
	var mk []byte
	if master != nil {
		mk = master()
	}
	other := ""
	for _, x := range m.Members {
		if bytes.Equal(x.Pub, self) {
			continue
		}
		if passes.until(x.ID, x.Pub) > 0 {
			s.Here = s.Self
		}
		if mk != nil && bytes.Equal(x.Pub, mk) {
			other = x.ID
		}
		s.PCs = append(s.PCs, trayPC{x.ID, names[x.ID]})
	}
	if s.Here == "" {
		s.Here = other
	}
	return s
}

// trayNames — ID → имя из «Моих ПК» (JSON окна: [{id, name}] или прежний [ID]); имя = ID или пустое — без имени.
func trayNames(mine string) map[string]string {
	var l []json.RawMessage
	out := map[string]string{}
	if json.Unmarshal([]byte(mine), &l) != nil {
		return out
	}
	for _, r := range l {
		var x struct{ ID, Name string }
		if json.Unmarshal(r, &x) != nil || !trayIDre.MatchString(x.ID) {
			continue
		}
		n := strings.TrimSpace(x.Name)
		for utf8.RuneCountInString(n) > 40 { // NAME_MAX окна
			_, sz := utf8.DecodeLastRuneInString(n)
			n = n[:len(n)-sz]
		}
		if _, ok := out[x.ID]; !ok && n != "" && n != x.ID {
			out[x.ID] = n
		}
	}
	return out
}

var trayIDre = regexp.MustCompile(`^\d{9}$`)

// trayGroup — ID группами по 3 цифры, как в окне.
func trayGroup(id string) string {
	var b strings.Builder
	for i, r := range id {
		if i > 0 && i%3 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// trayTitle — первая строка меню вне пространства (и подсказка значка Windows): имя этого ПК и его ID, как в окне.
func trayTitle(id string) string { h, _ := os.Hostname(); return trayTitleOf(h, id) }

func trayTitleOf(host, id string) string {
	if host == "" {
		return trayGroup(id)
	}
	return host + " · " + trayGroup(id)
}

// trayTexts — подписи меню на языке ОС.
type trayTexts struct{ help, quit, here, move string }

// trayWords — язык → «Помочь кому-то…», «Выйти» (Linux), (Мак), (Windows), подпись «я тут», «Я тут — управлять с %s».
// Слова «я тут» — как m_ishere окна (ui/index.html).
var trayWords = map[string][6]string{
	"en": {"Help someone…", "Quit", "Quit AnyPC", "Exit", "I'm here", "I'm here — control from %s"},
	"ru": {"Помочь кому-то…", "Выйти", "Завершить AnyPC", "Выход", "я тут", "Я тут — управлять с %s"},
	"zh": {"帮助他人…", "退出", "退出 AnyPC", "退出", "我在这里", "我在这里 — 从 %s 控制"},
	"es": {"Ayudar a alguien…", "Salir", "Salir de AnyPC", "Salir", "estoy aquí", "Estoy aquí — controlar desde %s"},
	"de": {"Jemandem helfen…", "Beenden", "AnyPC beenden", "Beenden", "ich bin hier", "Ich bin hier — von %s steuern"},
	"fr": {"Aider quelqu’un…", "Quitter", "Quitter AnyPC", "Quitter", "je suis ici", "Je suis ici — contrôler depuis %s"},
	"it": {"Aiuta qualcuno…", "Esci", "Esci da AnyPC", "Esci", "sono qui", "Sono qui — controlla da %s"},
}

// trayTextsFor — подписи для языка lang и ОС goos (у «Выйти» свои слова на Маке и в Windows); неизвестный — en.
func trayTextsFor(lang, goos string) trayTexts {
	w, ok := trayWords[lang]
	if !ok {
		w = trayWords["en"]
	}
	q := w[1]
	switch goos {
	case "darwin":
		q = w[2]
	case "windows":
		q = w[3]
	}
	return trayTexts{help: w[0], quit: q, here: w[4], move: w[5]}
}

// trayRow — пункт меню: ID — номер; Label "" — разделитель; Note — подпись после имени («я тут»); PC — ID ПК пункта.
type trayRow struct {
	ID          int
	Label, Note string
	PC          string
}

// trayText — подпись пункта: имя и через sep подпись (Windows — табуляция: подпись прижата вправо, как в макете).
func trayText(r trayRow, sep string) string {
	if r.Note == "" {
		return r.Label
	}
	return r.Label + sep + r.Note
}

// trayRows — меню экрана 6 макета (design-x Tray) из состояния s; host — имя этого ПК в ОС.
// Вне пространства — как раньше: «имя · ID», «Помочь кому-то…», «Выйти». В пространстве: первая строка — ПК с «я тут»
// (нет «я тут» — этот ПК без подписи); «я тут» на другом ПК — он первой строкой и ниже «Я тут — управлять с <этот>»;
// дальше остальные ПК пространства по именам (имени нет — ID группами).
func trayRows(s trayState, host string, tx trayTexts) []trayRow {
	tail := []trayRow{
		// TODO(Ч10): подменю «Отправить ›» (Файл…, Папку…, Текст…, Буфер обмена) — здесь, над «Помочь кому-то…», когда будет Ч10
		{ID: trayHelp, Label: tx.help}, {ID: traySep}, {ID: trayQuit, Label: tx.quit}}
	if !s.In {
		return append([]trayRow{{ID: trayOpen, Label: trayTitleOf(host, s.Self)}}, tail...)
	}
	me := host
	if me == "" {
		me = trayGroup(s.Self)
	}
	name := func(p trayPC) string {
		if p.Name != "" {
			return p.Name
		}
		return trayGroup(p.ID)
	}
	rows, pcs := []trayRow{{ID: trayOpen, Label: me}}, s.PCs
	switch s.Here {
	case "":
	case s.Self:
		rows[0].Note = tx.here
	default: // макет, меню на «Офисе»: первой строкой — ПК с «я тут», ниже — перенести «я тут» сюда
		rows[0] = trayRow{ID: trayOpen, Label: trayGroup(s.Here), Note: tx.here}
		if i := slices.IndexFunc(pcs, func(p trayPC) bool { return p.ID == s.Here }); i >= 0 {
			rows[0].Label = name(pcs[i])
			pcs = slices.Delete(slices.Clone(pcs), i, i+1)
		}
		rows = append(rows, trayRow{ID: trayHere, Label: fmt.Sprintf(tx.move, me)})
	}
	rows = append(rows, trayRow{ID: traySep1})
	// TODO(Ч11): заголовок «Рядом со мной» и флажки «рядом»/«слева»/«стол N» у ПК — здесь, когда будет Ч11 (макет: курсор за край)
	for i, p := range pcs {
		rows = append(rows, trayRow{ID: trayPC0 + i, Label: name(p), PC: p.ID})
	}
	if len(pcs) > 0 {
		rows = append(rows, trayRow{ID: traySep2})
	}
	return append(rows, tail...)
}

// trayDeps — что трей показывает и делает. state nil — вне пространства; here и pc nil — как open.
type trayDeps struct {
	id    string
	state func() trayState
	open  func()          // главное окно
	here  func()          // главное окно у кнопки «Я тут» (ввод пароля и кода — там, не в трее)
	pc    func(id string) // ПК id вкладкой главного окна — как «Открыть» плитки
	quit  func()
	tx    trayTexts // пустые — язык ОС (agent.Lang)
}

func (d trayDeps) texts() trayTexts {
	if d.tx.help == "" {
		return trayTextsFor(agent.Lang(), runtime.GOOS)
	}
	return d.tx
}

// rows — меню сейчас (состояние перечитывается).
func (d trayDeps) rows() []trayRow {
	s := trayState{Self: d.id}
	if d.state != nil {
		s = d.state()
	}
	h, _ := os.Hostname()
	return trayRows(s, h, d.texts())
}

// trayPick — что делать по пункту id меню rows: «Выйти» — всегда, окно — не чаще gate; прочее (0 — меню закрыто
// мимо, разделитель, пункт не из rows) — nil.
// TODO(ui): «Помочь кому-то…» — главное окно, пока в ui/index.html нет адреса экрана подключения.
func trayPick(id int, rows []trayRow, gate func() bool, d trayDeps) func() {
	if id == trayQuit {
		return d.quit
	}
	var f func()
	switch i := slices.IndexFunc(rows, func(r trayRow) bool { return r.ID == id }); {
	case id == trayOpen || id == trayHelp:
		f = d.open
	case i < 0:
	case id == trayHere && d.here != nil:
		f = d.here
	case id == trayHere:
		f = d.open
	case rows[i].PC != "" && d.pc != nil:
		pc := rows[i].PC
		f = func() { d.pc(pc) }
	case rows[i].PC != "":
		f = d.open
	}
	if f == nil || !gate() {
		return nil
	}
	return f
}

// trayJSPC — в главном окне открыть ПК id вкладкой «Моих ПК»: тот же myPcAdd, что у «Открыть» плитки (ui/index.html,
// mOpen); вход — по пропуску или код в самой вкладке. "" — не ID.
func trayJSPC(id string) string {
	if !trayIDre.MatchString(id) {
		return ""
	}
	return `window.myPcAdd && myPcAdd("` + id + `")`
}

// trayJSHere — в главном окне к полю пароля «Я тут» (ввод пароля и кода — там).
const trayJSHere = `(e => { if (e) { e.scrollIntoView({block: 'center'}); e.focus(); } })(document.getElementById('shpw'))`

// trayOpenGap — окно открывается не чаще; лишние щелчки (или поток вызовов от любого клиента шины) — мимо.
var trayOpenGap = time.Second

// trayGate — true не чаще раза в gap.
func trayGate(gap time.Duration) func() bool {
	var mu sync.Mutex
	var last time.Time
	return func() bool {
		mu.Lock()
		defer mu.Unlock()
		if now := time.Now(); last.IsZero() || now.Sub(last) >= gap {
			last = now
			return true
		}
		return false
	}
}

type trayPixmap struct {
	W, H int32
	Data []byte
}

// trayIcon — значок программы (favicon ui/index.html: контур ПК и красный ПК поверх, viewBox 26×26) n×n точек
// выборкой по центрам пикселей; цвета тёмной темы — панель Ubuntu тёмная. ARGB32, байты A,R,G,B (как требует SNI).
// Скруглённые углы (rx=2) не рисуются — на 22 точках их не видно.
func trayIcon(n int) trayPixmap { return trayIconIn(n, false) }

// trayIconIn — то же; light — цвета светлой темы favicon (светлая панель задач Windows 11).
func trayIconIn(n int, light bool) trayPixmap {
	red, line := [4]byte{0xff, 0xef, 0x6a, 0x52}, [4]byte{0xff, 0xec, 0xea, 0xe4}
	if light {
		red, line = [4]byte{0xff, 0xd2, 0x45, 0x2d}, [4]byte{0xff, 0x17, 0x18, 0x1c}
	}
	in := func(x, y, x0, y0, x1, y1 float64) bool { return x >= x0 && x < x1 && y >= y0 && y < y1 }
	b := make([]byte, 0, n*n*4)
	s := 26 / float64(n)
	for py := 0; py < n; py++ {
		for px := 0; px < n; px++ {
			x, y := (float64(px)+.5)*s, (float64(py)+.5)*s
			switch {
			case in(x, y, 10, 12, 25, 23): // <rect class='b' x='10' y='12' width='15' height='11'/>
				b = append(b, red[:]...)
			case in(x, y, 0.2, 1.7, 17.8, 15.3) && !in(x, y, 2.8, 4.3, 15.2, 12.7): // контур x=1.5 y=3 15×11, штрих 2.6
				b = append(b, line[:]...)
			default:
				b = append(b, 0, 0, 0, 0)
			}
		}
	}
	return trayPixmap{int32(n), int32(n), b}
}

// trayBGRA — те же точки в порядке байт 32-битного DIB Windows (B,G,R,A; альфа не домножена — так берёт CreateIconIndirect).
func trayBGRA(p trayPixmap) []byte {
	b := make([]byte, len(p.Data))
	for i := 0; i+3 < len(p.Data); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = p.Data[i+3], p.Data[i+2], p.Data[i+1], p.Data[i]
	}
	return b
}
