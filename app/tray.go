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
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"anypc/agent"
)

// Номера пунктов меню; одинаковы на всех ОС. Разделители — traySep, traySep1, traySep2.
const (
	trayOpen = 1       // первая строка: этот ПК или ПК с «я тут» — главное окно
	trayHelp = 2       // «Помочь кому-то…»
	traySep  = 3       // перед «Выйти»
	trayQuit = 4       // «Выйти»: единственный, кто не открывает окно
	trayHere = 5       // «Я тут — управлять с <этот ПК>» (живой «Я тут» на другом ПК): главное окно у кнопки «Я тут»
	traySep1 = 6       // после первой строки (в пространстве)
	traySep2 = 7       // после списка ПК пространства
	traySend = 8       // Ч10.5: подменю «Отправить ›» (сам пункт ничего не делает)
	traySWin = 9       // в подменю: «Папку, текст, буфер… — в окне» (экран «Отправить» главного окна)
	traySep3 = 10      // в подменю: перед traySWin
	trayDst0 = 64      // в подменю: «отправить файл на ПК» — trayDst0 + его ID числом (64 + 10^9 < trayPC0) — см. trayDstID
	trayPC0  = 1 << 30 // ПК пространства: trayPC0 + его ID числом (до 2^31: int32 dbusmenu) — см. trayPCID
)

// trayPCID — номер пункта ПК id: из самого ID, а не из места в списке — щелчок по меню, открытому до смены состава,
// откроет тот ПК, что был под мышью (или ничего, если его уже нет в M), а не соседа.
func trayPCID(id string) int {
	n, _ := strconv.Atoi(id) // id — 9 цифр (trayIDre): < 10^9 < 2^30
	return trayPC0 + n
}

// trayDstID — номер пункта «отправить файл на ПК id» в подменю «Отправить ›»: из ID, как trayPCID (меню, открытое до
// смены списка, отправит тому, кто был под мышью, или никому).
func trayDstID(id string) int {
	n, _ := strconv.Atoi(id)
	return trayDst0 + n
}

// trayIsDst — номер — пункт «отправить файл на ПК».
func trayIsDst(id int) bool { return id >= trayDst0 && id < trayDst0+1_000_000_000 }

// trayPC — член M (кроме этого ПК): ID и имя из «Моих ПК» окна ("" — имени нет).
type trayPC struct{ ID, Name string }

// trayState — то, из чего строится меню: состав M и где живой «Я тут».
type trayState struct {
	Self string   // ID этого ПК
	In   bool     // в пространстве (состав читается)
	Here string   // ID ПК с живым «Я тут»: Self — пропуска выдал этот ПК как мастер; другой член M — у этого ПК его пропуск; "" — нигде
	PCs  []trayPC // члены M, кроме этого ПК, в порядке состава
	Dst  []trayPC // Ч10.5: кому «Отправить ›» — свои ПК (PCs), затем избранные (Ч10.4)
}

// trayStateOf — состояние трея из настроек в памяти (файл не перечитывается: правки других процессов подхватывает
// опрос настроек раз в 2 с, pollConfig и окно) и пропусков: выданных этим ПК (passes, pass.go) и выданных ему
// мастером (master). Имена — из «Моих ПК» окна (config.json, ключ ui.mine).
// master — ключ мастера с живым пропуском на этом ПК (Agent.PassMaster; nil — не спрашивать).
func trayStateOf(c *config, master func() []byte) trayState {
	c.mu.Lock()
	m := c.spaceLocked()
	self := ed25519.PrivateKey(c.Key).Public().(ed25519.PublicKey)
	s := trayState{Self: c.ID, In: m != nil}
	mine := c.UI["mine"]
	var favs []trayPC // как favList, но без перечитывания файла (см. выше)
	for _, f := range c.Favs {
		if n, ok := favName(f.Name); ok && trayIDre.MatchString(f.ID) && f.ID != c.ID && !c.favMemberLocked(f.ID) {
			favs = append(favs, trayPC{f.ID, n})
		}
	}
	c.mu.Unlock()
	if m == nil {
		s.Dst = favs
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
	s.Dst = append(slices.Clone(s.PCs), favs...)
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
type trayTexts struct{ help, quit, here, move, send, swin, file string }

// trayWords — язык → «Помочь кому-то…», «Выйти» (Linux), (Мак), (Windows), подпись «я тут», «Я тут — управлять с %s».
// Слова «я тут» — как m_ishere окна (ui/index.html). Ч10.5: «Отправить», «Папку, текст, буфер… — в окне», «файл…».
var trayWords = map[string][9]string{
	"en": {"Help someone…", "Quit", "Quit AnyPC", "Exit", "I'm here", "I'm here — control from %s", "Send", "Folder, text, clipboard, another PC…", "file…"},
	"ru": {"Помочь кому-то…", "Выйти", "Завершить AnyPC", "Выход", "я тут", "Я тут — управлять с %s", "Отправить", "Папку, текст, буфер, другой ПК…", "файл…"},
	"zh": {"帮助他人…", "退出", "退出 AnyPC", "退出", "我在这里", "我在这里 — 从 %s 控制", "发送", "文件夹、文本、剪贴板、其他电脑…", "文件…"},
	"es": {"Ayudar a alguien…", "Salir", "Salir de AnyPC", "Salir", "estoy aquí", "Estoy aquí — controlar desde %s", "Enviar", "Carpeta, texto, portapapeles, otro PC…", "archivo…"},
	"de": {"Jemandem helfen…", "Beenden", "AnyPC beenden", "Beenden", "ich bin hier", "Ich bin hier — von %s steuern", "Senden", "Ordner, Text, Zwischenablage, anderer PC…", "Datei…"},
	"fr": {"Aider quelqu’un…", "Quitter", "Quitter AnyPC", "Quitter", "je suis ici", "Je suis ici — contrôler depuis %s", "Envoyer", "Dossier, texte, presse-papiers, autre PC…", "fichier…"},
	"it": {"Aiuta qualcuno…", "Esci", "Esci da AnyPC", "Esci", "sono qui", "Sono qui — controlla da %s", "Invia", "Cartella, testo, appunti, altro PC…", "file…"},
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
	return trayTexts{help: w[0], quit: q, here: w[4], move: w[5], send: w[6], swin: w[7], file: w[8]}
}

// trayRow — пункт меню: ID — номер; Label "" — разделитель; Note — подпись после имени («я тут»); PC — ID ПК пункта;
// Sub — подменю (Ч10.5 «Отправить ›»; одного уровня хватает).
type trayRow struct {
	ID          int
	Label, Note string
	PC          string
	Sub         []trayRow
}

// trayRowsEqual — меню не изменилось (trayRow с подменю несравним через ==).
func trayRowsEqual(a, b []trayRow) bool { return reflect.DeepEqual(a, b) }

// trayFlat — пункты меню и подменю одним списком (поиск по номеру, номера Windows).
func trayFlat(rows []trayRow) []trayRow {
	var out []trayRow
	for _, r := range rows {
		out = append(out, r)
		out = append(out, trayFlat(r.Sub)...)
	}
	return out
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
	// Ч10.5 «Отправить ›»: свои ПК и избранные — выбор файла окном ОС и отправка без главного окна; папка, текст, буфер
	// и другой ПК (ID + код) — экран «Отправить» окна. TODO(Ч11): «Рядом» в подменю — когда будет отметка «рядом».
	var sub []trayRow
	for _, p := range s.Dst {
		sub = append(sub, trayRow{ID: trayDstID(p.ID), Label: trayName(p), Note: tx.file, PC: p.ID})
	}
	if len(sub) > 0 {
		sub = append(sub, trayRow{ID: traySep3})
	}
	sub = append(sub, trayRow{ID: traySWin, Label: tx.swin})
	tail := []trayRow{{ID: traySend, Label: tx.send, Sub: sub},
		{ID: trayHelp, Label: tx.help}, {ID: traySep}, {ID: trayQuit, Label: tx.quit}}
	if !s.In {
		return append([]trayRow{{ID: trayOpen, Label: trayTitleOf(host, s.Self)}}, tail...)
	}
	me := host
	if me == "" {
		me = trayGroup(s.Self)
	}
	name := trayName
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
	for _, p := range pcs {
		rows = append(rows, trayRow{ID: trayPCID(p.ID), Label: name(p), PC: p.ID})
	}
	if len(pcs) > 0 {
		rows = append(rows, trayRow{ID: traySep2})
	}
	return append(rows, tail...)
}

// trayName — подпись ПК: имя, без имени — ID группами.
func trayName(p trayPC) string {
	if p.Name != "" {
		return p.Name
	}
	return trayGroup(p.ID)
}

// trayDeps — что трей показывает и делает. state nil — вне пространства; here и pc nil — как open.
type trayDeps struct {
	id    string
	state func() trayState
	open  func()          // главное окно
	here  func()          // главное окно у кнопки «Я тут» (ввод пароля и кода — там, не в трее)
	pc    func(id string) // ПК id вкладкой главного окна — как «Открыть» плитки
	help  func()          // главное окно на экране «Другой ПК» (форма подключения, «+» главного экрана)
	send  func(id string) // Ч10.5: выбрать файл окном ОС и отправить на ПК id (sendOps.startTray)
	swin  func()          // главное окно на экране «Отправить»
	quit  func()
	tx    trayTexts // пустые — язык ОС (agent.Lang)
}

// trayLang — язык ОС один раз: на Маке без LANG agent.Lang запускает `defaults read`, а меню перечитывается раз в 1 с.
var trayLang = sync.OnceValue(agent.Lang)

func (d trayDeps) texts() trayTexts {
	if d.tx.help == "" {
		return trayTextsFor(trayLang(), runtime.GOOS)
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
// «Помочь кому-то…» — экран «Другой ПК» (d.help), без него — просто окно.
func trayPick(id int, rows []trayRow, gate func() bool, d trayDeps) func() {
	if id == trayQuit {
		return d.quit
	}
	var f func()
	rows = trayFlat(rows)
	switch i := slices.IndexFunc(rows, func(r trayRow) bool { return r.ID == id }); {
	case id == traySWin && d.swin != nil:
		f = d.swin
	case id == traySWin:
		f = d.open
	case i >= 0 && trayIsDst(id) && d.send != nil && rows[i].PC != "":
		pc := rows[i].PC
		f = func() { d.send(pc) }
	case i >= 0 && trayIsDst(id):
		f = d.open
	case id == trayHelp && d.help != nil:
		f = d.help
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
	return `window.myPcHome && myPcHome() !== false && window.myPcAdd && myPcAdd("` + id + `")` // своя сессия в окне (false) — окно только поднято
}

// trayJSHere — в главном окне к кнопке «Я тут» (системная авторизация — там): сначала на главный экран (myPcHome —
// из вкладки ПК, «Другого ПК», «Настроек», «Доступа»); false — в окне идёт своя сессия: окно только поднято, фокус не трогаем.
// Свежее окно: строка «Я тут» видна только после первого hostInfo — фокус ждёт её до 5 с (getClientRects: и в старом WKWebView).
const trayJSHere = `(() => { if (window.myPcHome && myPcHome() === false) return; let n = 0; const go = () => { const e = document.getElementById('shgo');` +
	` if (e && e.getClientRects().length) { e.scrollIntoView({block: 'center'}); e.focus(); } else if (++n < 50) setTimeout(go, 100); }; go(); })()`

// trayJSHelp — «Помочь кому-то…»: экран «Другой ПК» с фокусом в поле ID (connGo — «+» главного экрана, ui/index.html);
// сначала главный (из вкладки ПК — не поверх вкладок); своя сессия в окне (myPcHome false) — окно только поднято.
const trayJSHelp = `window.myPcHome && myPcHome() !== false && window.connGo && connGo()`

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

// trayJSSend — «Отправить › Папку, текст, буфер, другой ПК…»: экран «Отправить» (sendGo, ui/index.html); сначала
// главный; своя сессия в окне (myPcHome false) — окно только поднято.
const trayJSSend = `window.myPcHome && myPcHome() !== false && window.sendGo && sendGo()`
