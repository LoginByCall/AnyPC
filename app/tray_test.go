package main

import (
	"log"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"anypc/totp"
)

func TestTrayTitleIcon(t *testing.T) {
	h, _ := os.Hostname()
	if got := trayTitle("123456789"); got != h+" · 123 456 789" {
		t.Errorf("trayTitle: %q", got)
	}
	for _, n := range []int{16, 22, 44} {
		p := trayIcon(n)
		if p.W != int32(n) || p.H != int32(n) || len(p.Data) != n*n*4 {
			t.Fatalf("значок %d: %dx%d, %d байт", n, p.W, p.H, len(p.Data))
		}
		c := n * 3 / 4 // центр красного ПК — непрозрачный красный
		if o := (c*n + c) * 4; p.Data[o] != 0xff || p.Data[o+1] != 0xef {
			t.Errorf("значок %d: точка %d,%d = % x", n, c, c, p.Data[o:o+4])
		}
	}
}

// TestTrayBGRA: ARGB → B,G,R,A для DIB Windows; прозрачные точки остаются нулями.
func TestTrayBGRA(t *testing.T) {
	p := trayIcon(16)
	b := trayBGRA(p)
	if len(b) != len(p.Data) {
		t.Fatalf("длина %d, ждали %d", len(b), len(p.Data))
	}
	o := (12*16 + 12) * 4 // красный ПК
	if got := b[o : o+4]; got[0] != 0x52 || got[1] != 0x6a || got[2] != 0xef || got[3] != 0xff {
		t.Errorf("красная точка: % x", got)
	}
	if got := b[0:4]; got[0]|got[1]|got[2]|got[3] != 0 { // угол — прозрачный
		t.Errorf("угол: % x", got)
	}
	l := trayBGRA(trayIconIn(16, true)) // светлая панель: красный #d2452d, контур #17181c
	if got := l[o : o+4]; got[0] != 0x2d || got[2] != 0xd2 || got[3] != 0xff {
		t.Errorf("светлая, красная точка: % x", got)
	}
	if o := (2*16 + 1) * 4; l[o] != 0x1c || l[o+2] != 0x17 || l[o+3] != 0xff { // точка контура (1,2)
		t.Errorf("светлая, контур: % x", l[o:o+4])
	}
	if len(trayBGRA(trayPixmap{Data: []byte{1, 2, 3}})) != 3 { // неполная точка — без паники
		t.Error("неполная точка")
	}
}

// TestTrayPick: «Выйти» — всегда и без дросселя; окно (обе строки) — только когда дроссель пускает; прочее — ничего.
func TestTrayPick(t *testing.T) {
	var opened, quitted, gated int
	d := trayDeps{open: func() { opened++ }, quit: func() { quitted++ }}
	rows := trayRows(trayState{Self: "123456789"}, "h", trayTextsFor("ru", "linux"))
	yes := func() bool { gated++; return true }
	no := func() bool { gated++; return false }
	for _, c := range []struct {
		id         int
		gate       func() bool
		open, quit int
	}{
		{trayOpen, yes, 1, 0}, {trayHelp, yes, 1, 0}, {trayOpen, no, 0, 0}, {trayHelp, no, 0, 0},
		{trayQuit, no, 0, 1}, {trayQuit, yes, 0, 1}, {traySep, yes, 0, 0}, {0, yes, 0, 0}, {99, yes, 0, 0},
		{trayHere, yes, 0, 0}, {trayPC0, yes, 0, 0}, // вне пространства таких пунктов нет
	} {
		opened, quitted, gated = 0, 0, 0
		if f := trayPick(c.id, rows, c.gate, d); f != nil {
			f()
		}
		if opened != c.open || quitted != c.quit {
			t.Errorf("пункт %d: окно %d, выход %d; ждали %d, %d", c.id, opened, quitted, c.open, c.quit)
		}
		if c.id == trayQuit && gated != 0 {
			t.Errorf("«Выйти» тратит дроссель")
		}
	}
}

// TestTrayPickHelp: «Помочь кому-то…» с d.help — экран «Другой ПК» (trayJSHelp), не просто окно; дроссель тот же.
func TestTrayPickHelp(t *testing.T) {
	var opened, helped int
	d := trayDeps{open: func() { opened++ }, help: func() { helped++ }, quit: func() {}}
	rows := trayRows(trayState{Self: "123456789"}, "h", trayTextsFor("ru", "linux"))
	if f := trayPick(trayHelp, rows, func() bool { return true }, d); f != nil {
		f()
	}
	if trayPick(trayHelp, rows, func() bool { return false }, d) != nil {
		t.Error("«Помочь» мимо дросселя")
	}
	if helped != 1 || opened != 0 {
		t.Errorf("«Помочь»: экран подключения %d, окно %d", helped, opened)
	}
}

// trayLabels — меню строкой: подписи через «|», разделитель — «—».
func trayLabels(rows []trayRow) string {
	var l []string
	for _, r := range rows {
		if r.Label == "" {
			l = append(l, "—")
			continue
		}
		l = append(l, trayText(r, " · "))
	}
	return strings.Join(l, "|")
}

// TestTrayRows — пункты по экрану 6 макета: вне пространства — как раньше; в пространстве с двумя членами — этот ПК
// и они по именам (без имени — ID группами); «я тут» здесь — подпись у первой строки; «я тут» на другом ПК — он
// первой строкой и ниже «Я тут — управлять с <этот>». Номера: первая — trayOpen, ПК — trayPCID(своего ID).
func TestTrayRows(t *testing.T) {
	ru := trayTextsFor("ru", "linux")
	pcs := []trayPC{{"200000001", "Офис"}, {"200000002", ""}}
	for _, c := range []struct {
		name string
		s    trayState
		want string
	}{
		{"вне пространства", trayState{Self: "123456789"}, "Ноутбук · 123 456 789|Отправить|Помочь кому-то…|—|Выйти"},
		{"в пространстве, «я тут» нигде", trayState{Self: "123456789", In: true, PCs: pcs},
			"Ноутбук|—|Офис|200 000 002|—|Отправить|Помочь кому-то…|—|Выйти"},
		{"«я тут» здесь", trayState{Self: "123456789", In: true, Here: "123456789", PCs: pcs},
			"Ноутбук · я тут|—|Офис|200 000 002|—|Отправить|Помочь кому-то…|—|Выйти"},
		{"«я тут» на другом ПК", trayState{Self: "123456789", In: true, Here: "200000001", PCs: pcs},
			"Офис · я тут|Я тут — управлять с Ноутбук|—|200 000 002|—|Отправить|Помочь кому-то…|—|Выйти"},
		{"один в пространстве", trayState{Self: "123456789", In: true}, "Ноутбук|—|Отправить|Помочь кому-то…|—|Выйти"},
	} {
		rows := trayRows(c.s, "Ноутбук", ru)
		if got := trayLabels(rows); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
		ids := map[int]bool{}
		for _, r := range rows {
			if ids[r.ID] {
				t.Errorf("%s: номер %d дважды", c.name, r.ID)
			}
			ids[r.ID] = true
			if r.ID >= trayPC0 && (!trayIDre.MatchString(r.PC) || r.ID != trayPCID(r.PC)) || r.ID < trayPC0 && r.PC != "" {
				t.Errorf("%s: пункт %d с ПК %q", c.name, r.ID, r.PC)
			}
		}
		if rows[0].ID != trayOpen || rows[len(rows)-1].ID != trayQuit {
			t.Errorf("%s: первая %d, последняя %d", c.name, rows[0].ID, rows[len(rows)-1].ID)
		}
	}
	if got := trayLabels(trayRows(trayState{Self: "123456789", In: true}, "", ru)); !strings.HasPrefix(got, "123 456 789|") {
		t.Errorf("без имени ПК: %s", got)
	}
}

// TestTrayPickPC — щелчок по ПК пространства зовёт pc с его ID (не главное окно); «Я тут — управлять с …» — here;
// без pc и here — главное окно; дроссель общий.
func TestTrayPickPC(t *testing.T) {
	var got []string
	d := trayDeps{open: func() { got = append(got, "open") }, quit: func() { got = append(got, "quit") },
		here: func() { got = append(got, "here") }, pc: func(id string) { got = append(got, "pc "+id) }}
	s := trayState{Self: "123456789", In: true, Here: "200000001", PCs: []trayPC{{"200000001", "Офис"}, {"200000002", ""}, {"200000003", "Дом"}}}
	rows := trayRows(s, "Ноутбук", trayTextsFor("ru", "linux"))
	yes := func() bool { return true }
	for _, id := range []int{trayOpen, trayHere, trayPCID("200000001"), trayPCID("200000002"), trayPCID("200000003"), traySep1, traySep2, trayPC0} {
		if f := trayPick(id, rows, yes, d); f != nil {
			f()
		}
	}
	if want := "open|here|pc 200000002|pc 200000003"; strings.Join(got, "|") != want {
		t.Errorf("щелчки: %q, ждали %q", got, want)
	}
	got = nil
	bare := trayDeps{open: d.open, quit: d.quit}
	for _, id := range []int{trayHere, trayPCID("200000002")} {
		if f := trayPick(id, rows, yes, bare); f != nil {
			f()
		}
	}
	if strings.Join(got, "|") != "open|open" {
		t.Errorf("без here и pc: %q", got)
	}
	if trayPick(trayPCID("200000002"), rows, func() bool { return false }, d) != nil {
		t.Error("ПК мимо дросселя")
	}

	// меню открыто до смены состава (Линукс и Мак перестраивают его раз в 1 с): щелчок по пункту старого меню —
	// тот же ПК при новом порядке, ничего — если его больше нет в M
	shown := trayRows(s, "Ноутбук", trayTextsFor("ru", "linux"))
	click := shown[slices.IndexFunc(shown, func(r trayRow) bool { return r.PC == "200000003" })].ID
	now := s
	now.PCs = []trayPC{{"200000003", "Дом"}, {"200000002", ""}} // 200000001 исключён, порядок другой
	got = nil
	if f := trayPick(click, trayRows(now, "Ноутбук", trayTextsFor("ru", "linux")), yes, d); f != nil {
		f()
	}
	if strings.Join(got, "|") != "pc 200000003" {
		t.Errorf("щелчок по старому меню после смены порядка: %q", got)
	}
	now.PCs = []trayPC{{"200000002", ""}}
	if trayPick(click, trayRows(now, "Ноутбук", trayTextsFor("ru", "linux")), yes, d) != nil {
		t.Error("щелчок по ПК, которого уже нет в M, что-то открыл")
	}
	if trayPCID("999999999") > 1<<31-1 || trayPCID("000000001") <= traySep2 {
		t.Error("номер пункта ПК вне int32 или среди служебных")
	}
}

// TestUILogOnce — испорченное поле ui перечитывается раз в 1–2 с: одна и та же строка в журнал один раз, новая — снова.
func TestUILogOnce(t *testing.T) {
	var buf strings.Builder
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	uiLogLast.Store("")
	var m uiMap
	for range 3 {
		m.UnmarshalJSON([]byte(`{"mine": 5}`))
	}
	m.UnmarshalJSON([]byte(`{"recent": 5}`))
	m.UnmarshalJSON([]byte(`{"recent": 5}`))
	if n := strings.Count(buf.String(), "отброшены негодные ключи"); n != 2 {
		t.Errorf("строк в журнале %d, ждали 2:\n%s", n, buf.String())
	}
}

// TestTrayTexts — 7 языков, у каждого все подписи; «Выйти» на Маке и в Windows — как в макете; неизвестный — en.
func TestTrayTexts(t *testing.T) {
	for _, l := range []string{"en", "ru", "zh", "es", "de", "fr", "it"} {
		w, ok := trayWords[l]
		if !ok {
			t.Fatalf("нет языка %s", l)
		}
		for i, x := range w {
			if x == "" {
				t.Errorf("%s: пустая подпись %d", l, i)
			}
		}
		if strings.Count(w[5], "%s") != 1 || strings.Count(w[5], "%") != 1 {
			t.Errorf("%s: «управлять с»: %q", l, w[5])
		}
	}
	if len(trayWords) != 7 {
		t.Errorf("языков %d", len(trayWords))
	}
	if q := trayTextsFor("ru", "darwin").quit; q != "Завершить AnyPC" {
		t.Errorf("Мак: %q", q)
	}
	if q := trayTextsFor("ru", "windows").quit; q != "Выход" {
		t.Errorf("Windows: %q", q)
	}
	if x := trayTextsFor("xx", "linux"); x.help != "Help someone…" || x.quit != "Quit" {
		t.Errorf("неизвестный язык: %+v", x)
	}
}

// TestTrayNames — имена из «Моих ПК»: новый и прежний формат, мусор и чужие ключи — мимо, имя = ID — без имени.
func TestTrayNames(t *testing.T) {
	long := strings.Repeat("я", 50)
	got := trayNames(`["200000009", {"id":"200000001","name":" Офис "}, {"id":"200000002","name":"200000002"}, {"id":"x","name":"y"},
		{"id":"200000003","name":"` + long + `"}, 5, null, {"id":"200000001","name":"второй"}]`)
	if len(got) != 2 || got["200000001"] != "Офис" || got["200000003"] != strings.Repeat("я", 40) {
		t.Errorf("имена: %q", got)
	}
	if len(trayNames("")) != 0 || len(trayNames("{")) != 0 {
		t.Error("пустой или битый mine")
	}
}

// TestTrayStateOf — состояние из настроек: вне пространства; члены M без себя по именам из ui.mine; «я тут» здесь —
// пропуск выдан этим ПК (passes); «я тут» на другом — у этого ПК пропуск мастера с ключом члена.
func TestTrayStateOf(t *testing.T) {
	out := spaceCfg(t, spacePass, totp.NewSecret())
	if s := trayStateOf(out, nil); s.In || s.Here != "" || len(s.PCs) != 0 || s.Self != out.ID {
		t.Errorf("вне пространства: %+v", s)
	}
	c, keys, _ := passSpace(t, totp.NewSecret(), "200000001", "200000002")
	if err := c.uiSet("mine", `[{"id":"200000001","name":"Офис"}]`); err != nil {
		t.Fatal(err)
	}
	s := trayStateOf(c, nil)
	slices.SortFunc(s.PCs, func(a, b trayPC) int { return strings.Compare(a.ID, b.ID) }) // порядок — как в составе M
	if !s.In || s.Here != "" || len(s.PCs) != 2 || s.PCs[0] != (trayPC{"200000001", "Офис"}) || s.PCs[1] != (trayPC{"200000002", ""}) {
		t.Errorf("в пространстве: %+v", s)
	}
	if s := trayStateOf(c, func() []byte { return keys["200000002"] }); s.Here != "200000002" {
		t.Errorf("«я тут» на другом: %q", s.Here)
	}
	if s := trayStateOf(c, func() []byte { return cfgPub(out) }); s.Here != "" { // ключ не из M
		t.Errorf("чужой мастер: %q", s.Here)
	}
	passes.mu.Lock()
	old := passes.issued
	passes.issued = map[string]passIssued{"200000001": {pub: keys["200000001"], at: time.Now()}}
	passes.mu.Unlock()
	t.Cleanup(func() { passes.mu.Lock(); passes.issued = old; passes.mu.Unlock() })
	if s := trayStateOf(c, func() []byte { return keys["200000002"] }); s.Here != c.ID {
		t.Errorf("«я тут» здесь: %q", s.Here)
	}
}

// TestTrayGate: раз в gap; нулевой gap пускает всех. Дроссель общий для щелчка по значку и пунктов меню.
func TestTrayGate(t *testing.T) {
	g := trayGate(time.Hour)
	if !g() || g() || g() {
		t.Error("час: ждали true, false, false")
	}
	g = trayGate(30 * time.Millisecond)
	g()
	time.Sleep(40 * time.Millisecond)
	if !g() {
		t.Error("после gap не пустил")
	}
	z := trayGate(0)
	if !z() || !z() {
		t.Error("gap 0 должен пускать всех")
	}
	d, n := trayDeps{open: func() {}}, 0
	gate := trayGate(time.Hour)
	for range 10 { // поток щелчков (Enter на значке Windows приходит и дважды) — одно окно
		if trayPick(trayOpen, nil, gate, d) != nil {
			n++
		}
	}
	if n != 1 {
		t.Errorf("10 щелчков за час открыли окно %d раз", n)
	}
}
