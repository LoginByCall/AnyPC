package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"anypc/agent"
	"anypc/pake"
	"anypc/totp"
)

func favCfg(t *testing.T) *config {
	t.Helper()
	c, err := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func favPub(t *testing.T) ed25519.PublicKey {
	p, _, _ := ed25519.GenerateKey(nil)
	return p
}

// TestSendFavs — Ч10.4: добавить, переименовать, убрать; негодные ID и имя, этот ПК, свой ПК из M, потолок; запись
// переживает перечитывание файла; негодная запись из файла не показывается.
func TestSendFavs(t *testing.T) {
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	withSpaceNet(t, spaceNet(p, nil))
	if _, err := n.spaceEnter(context.Background(), p.id(), spacePass, spaceCode(p, sec), ph); err != nil {
		t.Fatal(err)
	}
	if _, err := callSend(n, "sendFavSet", map[string]any{"id": "555666777", "name": "  Ноутбук мамы ", "add": true}); err != nil {
		t.Fatal(err)
	}
	if _, err := callSend(n, "sendFavSet", map[string]any{"id": "555666777", "name": "Мама"}); err != nil { // переименовать
		t.Fatal(err)
	}
	if _, err := callSend(n, "sendFavSet", map[string]any{"id": "444555666", "name": "x"}); err == nil || err.Error() != "send:favnone" {
		t.Fatalf("переименовать несуществующее: %v", err)
	}
	for _, c := range []struct{ id, name, code string }{
		{"12345", "", "send:id"}, {n.id(), "", "send:self"}, {p.id(), "", "send:favown"},
		{"111222333", "a‮b", "send:favname"}, {"111222333", "a\nb", "send:favname"},
		{"111222333", strings.Repeat("я", 41), "send:favname"},
	} {
		if _, err := callSend(n, "sendFavSet", map[string]any{"id": c.id, "name": c.name, "add": true}); err == nil || err.Error() != c.code {
			t.Errorf("%q %q: %v, ждали %s", c.id, c.name, err, c.code)
		}
	}
	n.mu.Lock()
	n.Favs = append(n.Favs, sendFav{ID: "bad", Name: "x"}, sendFav{ID: "222333444", Name: "a\u0000"}) // как правленный руками файл
	n.save()
	n.mu.Unlock()
	l := n.favList()
	if len(l) != 1 || l[0]["id"] != "555666777" || l[0]["name"] != "Мама" || l[0]["fp"] != "" || l[0]["pinned"] != false {
		t.Fatalf("избранные: %v", l)
	}
	m, _ := loadConfig(n.path) // с диска
	if f := m.favList(); len(f) != 1 || f[0]["name"] != "Мама" {
		t.Fatalf("после перечитывания: %v", f)
	}
	v, _ := callSend(n, "sendTargets")
	if f := v.(map[string]any)["favs"].([]map[string]any); len(f) != 1 {
		t.Fatalf("sendTargets.favs: %v", v)
	}
	n.mu.Lock()
	n.Favs = nil
	n.save()
	n.mu.Unlock()
	for i := range maxSendFavs {
		if err := n.favSet(fmt.Sprintf("3%08d", i), "", true); err != nil {
			t.Fatal(i, err)
		}
	}
	if err := n.favSet("399999999", "", true); !errors.Is(err, errFavMax) {
		t.Fatalf("сверх потолка: %v", err)
	}
	if _, err := callSend(n, "sendFavDel", map[string]any{"id": "300000000"}); err != nil {
		t.Fatal(err)
	}
	if _, err := callSend(n, "sendFavDel", map[string]any{"id": "300000000"}); err == nil || err.Error() != "send:favnone" {
		t.Fatalf("убрать дважды: %v", err)
	}
}

// TestSendFavUnpin — «Убрать» с unpin снимает закрепление ТОГО ПК как отправителя сюда — по доказанному ключу (known
// того ID = отпечаток закреплённого), а не по ID, заявленному при закреплении: чужой ключ, заявивший тот же ID, не
// снимается; без unpin — закрепления не трогаются; без known — снимать нечего.
func TestSendFavUnpin(t *testing.T) {
	c := favCfg(t)
	k, l := favPub(t), favPub(t)
	c.recvPin(l, "555666777", "Самозванец") // заявил ID избранного, ключ — другой (первым в списке)
	c.recvPin(k, "999888777", "Заявил другой ID")
	c.knownSet("555666777", pake.KeyFingerprint(k))
	c.favSet("555666777", "Друг", true)
	c.favSet("111222333", "Без ключа", true)
	if f := c.favList(); f[0]["pinned"] != true || f[1]["pinned"] != false || f[0]["fp"] != pake.KeyFingerprint(k) {
		t.Fatalf("pinned: %v", f)
	}
	if v, err := callSend(c, "sendFavDel", map[string]any{"id": "111222333", "unpin": true}); err != nil || v.(map[string]any)["unpinned"] != false {
		t.Fatalf("без known: %v %v", v, err)
	}
	v, err := callSend(c, "sendFavDel", map[string]any{"id": "555666777", "unpin": true})
	if err != nil || v.(map[string]any)["unpinned"] != true {
		t.Fatalf("убрать с отзывом: %v %v", v, err)
	}
	if _, _, ok := c.recvPinned(k); ok {
		t.Fatal("ключ избранного остался закреплённым")
	}
	if _, _, ok := c.recvPinned(l); !ok {
		t.Fatal("снят чужой ключ, заявивший тот же ID")
	}
	if c.knownGet("555666777") == "" {
		t.Fatal("known стёрт: он общий с подключением для управления")
	}
	c.favSet("555666777", "", true) // без unpin закрепление не трогается
	c.recvPin(k, "", "")
	if v, _ := callSend(c, "sendFavDel", map[string]any{"id": "555666777"}); v.(map[string]any)["unpinned"] != false {
		t.Fatal(v)
	}
	if _, _, ok := c.recvPinned(k); !ok {
		t.Fatal("«Убрать» без отзыва сняло закрепление")
	}
}

// TestRecvPinsAPI — «Доступ к этому ПК»: список закреплённых, «Отозвать» по отпечатку, уведомление о новом
// закреплении (hostInfo.recvNew) — до «прочитано» или отзыва.
func TestRecvPinsAPI(t *testing.T) {
	c := favCfg(t)
	recvPinNew.Store(nil)
	if recvPinNewJSON(c) != nil {
		t.Fatal("уведомление без закрепления")
	}
	k := favPub(t)
	c.recvPin(k, "555666777", "Друг")
	nw, _ := recvPinNewJSON(c).(map[string]any)
	if nw == nil || nw["name"] != "Друг" || nw["fp"] != pake.KeyFingerprint(k) {
		t.Fatalf("новое закрепление: %v", nw)
	}
	callSend(c, "recvPinSeen")
	if recvPinNewJSON(c) != nil {
		t.Fatal("прочитанное уведомление осталось")
	}
	v, _ := callSend(c, "recvPins")
	if l := v.(map[string]any)["pins"].([]map[string]any); len(l) != 1 || l[0]["id"] != "555666777" {
		t.Fatalf("список: %v", v)
	}
	if _, err := callSend(c, "recvUnpin", "нет такого"); err == nil || err.Error() != "send:pinnone" {
		t.Fatalf("чужой отпечаток: %v", err)
	}
	if _, err := callSend(c, "recvUnpin", ""); err == nil || err.Error() != "send:pinnone" {
		t.Fatalf("пустой отпечаток: %v", err)
	}
	c.recvPin(favPub(t), "", "") // новое — и сразу отозвано: уведомлять не о чем
	nw2 := recvPinNew.Load()
	if _, err := callSend(c, "recvUnpin", pake.KeyFingerprint(nw2.Pub)); err != nil {
		t.Fatal(err)
	}
	if recvPinNewJSON(c) != nil {
		t.Fatal("уведомление об отозванном")
	}
	if _, err := callSend(c, "recvUnpin", pake.KeyFingerprint(k)); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := c.recvPinned(k); ok {
		t.Fatal("не отозван")
	}
}

// TestSendKeptPicks — остаток Ч10.2–3: неудача до первого байта (код, связь, отмена до начала) метки не расходует —
// окно повторяет без нового выбора (kept); ушли байты — метки израсходованы. «Добавить в избранные» — только когда
// ключ того ПК доказан и не для своего ПК.
func TestSendKeptPicks(t *testing.T) {
	c := favCfg(t)
	_, other, _ := ed25519.GenerateKey(nil)
	var mode string
	sendRun = func(ctx context.Context, d agent.SendDial) (agent.SendResult, error) {
		switch mode {
		case "code": // неверный код: ни байта
			return agent.SendResult{}, agent.ErrRecvCode
		case "half": // половина файла и обрыв
			d.Progress(agent.SendProgress{Item: 1, Items: 1, Done: 5, Total: 10})
			return agent.SendResult{HostPub: other.Public().(ed25519.PublicKey)}, agent.ErrRecvGone
		}
		return agent.SendResult{HostPub: other.Public().(ed25519.PublicKey), Files: 1, Bytes: 10}, nil
	}
	sendPickFile = func(context.Context) (string, bool) { return "/tmp/x.txt", true }
	defer func() { sendRun = agent.SendTo; sendPickFile = agent.PickFile; sendOps.clear() }()
	v, _ := callSend(c, "sendPick", "file")
	tok := v.(map[string]any)["token"].(string)
	start := func(req map[string]any) error {
		t.Helper()
		_, err := callSend(c, "sendStart", req)
		sendIdle(t)
		return err
	}
	mode = "code"
	if err := start(map[string]any{"id": "555666777", "code": "000000", "picks": []string{tok}, "fav": true, "name": "Мама"}); err != nil {
		t.Fatal(err)
	}
	if s := sendOps.snap(); s["err"] != "code" || s["kept"] != true {
		t.Fatalf("после неверного кода: %v", s)
	}
	if len(c.favList()) != 0 {
		t.Fatal("в избранных ПК, чей ключ не доказан")
	}
	mode = "half"
	if err := start(map[string]any{"id": "555666777", "code": "123456", "picks": []string{tok}}); err != nil {
		t.Fatalf("метка после неудачи до первого байта: %v", err)
	}
	if s := sendOps.snap(); s["kept"] != false {
		t.Fatalf("байты ушли, а метка возвращена: %v", s)
	}
	if err := start(map[string]any{"id": "555666777", "code": "123456", "picks": []string{tok}}); err == nil || err.Error() != "send:pick" {
		t.Fatalf("израсходованная метка: %v", err)
	}
	mode = ""
	v, _ = callSend(c, "sendPick", "file")
	tok = v.(map[string]any)["token"].(string)
	if err := start(map[string]any{"id": "555666777", "picks": []string{tok}, "fav": true, "name": "Мама"}); err != nil {
		t.Fatal(err)
	}
	if f := c.favList(); len(f) != 1 || f[0]["name"] != "Мама" || f[0]["fp"] != pake.KeyFingerprint(other.Public().(ed25519.PublicKey)) {
		t.Fatalf("«Добавить в избранные»: %v", f)
	}
	if s := sendOps.snap(); s["kept"] != nil {
		t.Fatalf("kept у удачной: %v", s)
	}
}

// TestTraySend — Ч10.5, трей: подменю «Отправить ›» над «Помочь кому-то…» — свои ПК, избранные, «в окне»; пункт ПК —
// выбор файла окном ОС и отправка (d.send с ID); пункт, которого уже нет в меню, — ничего; сам «Отправить» — ничего.
func TestTraySend(t *testing.T) {
	ru := trayTextsFor("ru", "linux")
	s := trayState{Self: "123456789", In: true, PCs: []trayPC{{"200000001", "Офис"}}}
	s.Dst = append(s.PCs, trayPC{"555666777", ""})
	rows := trayRows(s, "Ноутбук", ru)
	i := len(rows) - 4
	if rows[i].ID != traySend || rows[i].Label != "Отправить" || rows[i+1].ID != trayHelp {
		t.Fatalf("место «Отправить»: %s", trayLabels(rows))
	}
	if got := trayLabels(rows[i].Sub); got != "Офис · файл…|555 666 777 · файл…|—|Папку, текст, буфер, другой ПК…" {
		t.Fatalf("подменю: %s", got)
	}
	var sent []string
	var mu sync.Mutex
	d := trayDeps{open: func() { sent = append(sent, "open") }, send: func(id string) { mu.Lock(); sent = append(sent, id); mu.Unlock() },
		swin: func() { sent = append(sent, "swin") }}
	open := func() bool { return true }
	for _, id := range []int{trayDstID("555666777"), traySWin} {
		if f := trayPick(id, rows, open, d); f != nil {
			f()
		}
	}
	for _, id := range []int{trayDstID("999999999"), traySend, traySep3} {
		if f := trayPick(id, rows, open, d); f != nil {
			t.Errorf("пункт %d: не nil", id)
		}
	}
	if strings.Join(sent, ",") != "555666777,swin" {
		t.Fatalf("действия: %v", sent)
	}
	if trayIsDst(trayPCID("200000001")) || !trayIsDst(trayDstID("999999999")) || trayDstID("999999999") >= trayPC0 {
		t.Fatal("диапазоны номеров пересекаются")
	}
	// вне пространства: только избранные и «в окне»
	if got := trayLabels(trayRows(trayState{Self: "123456789"}, "Ноутбук", ru)[1].Sub); got != "Папку, текст, буфер, другой ПК…" {
		t.Fatalf("без адресатов: %s", got)
	}
	c := favCfg(t)
	c.favSet("555666777", "Мама", true)
	if st := trayStateOf(c, nil); len(st.Dst) != 1 || st.Dst[0] != (trayPC{"555666777", "Мама"}) {
		t.Fatalf("trayStateOf.Dst: %+v", st.Dst)
	}
	for l := range trayWords {
		if w := trayTextsFor(l, "linux"); w.send == "" || w.swin == "" || w.file == "" {
			t.Errorf("%s: нет слов подменю", l)
		}
	}
}

// TestSendTrayNotice — из трея: выбор файла окном ОС → отправка → итог уведомлением (успех и ошибка с «что делать»);
// отмена выбора — ни отправки, ни уведомления; ошибка до начала — тоже уведомлением.
func TestSendTrayNotice(t *testing.T) {
	c := favCfg(t)
	c.favSet("555666777", "Мама", true)
	c.knownSet("555666777", "отпечаток")
	var notes []string
	var mu sync.Mutex
	sendNotice = func(_, b string) { mu.Lock(); notes = append(notes, b); mu.Unlock() }
	fail := false
	sendRun = func(ctx context.Context, d agent.SendDial) (agent.SendResult, error) {
		if fail {
			return agent.SendResult{}, agent.ErrSpaceOffline
		}
		return agent.SendResult{Files: 1, Bytes: 3}, nil
	}
	picked := "/tmp/Отчёт.pdf"
	sendPickFile = func(context.Context) (string, bool) { return picked, picked != "" }
	defer func() { sendRun, sendPickFile, sendNotice = agent.SendTo, agent.PickFile, noticeOS; sendOps.clear() }()
	run := func() { sendOps.startTray(c, "555666777"); sendIdle(t) }
	run()
	fail = true
	run()
	picked = ""
	run()
	picked = "/tmp/a"
	sendOps.startTray(c, "111222333") // без known и кода — до начала
	mu.Lock()
	defer mu.Unlock()
	lg := trayLang() // язык ОС, как у трея
	want := []string{sendNoticeText(lg, "Мама", "Отчёт.pdf", nil), sendNoticeText(lg, "Мама", "", agent.ErrSpaceOffline),
		sendNoticeText(lg, "111 222 333", "", agent.ErrRecvKnown)}
	if len(notes) != 3 || strings.Join(notes, "\n") != strings.Join(want, "\n") {
		t.Fatalf("уведомления:\n%q\nждали\n%q", notes, want)
	}
	if got := sendNoticeText("ru", "Мама", "", agent.ErrRecvNoKey); got != "Не отправлено на «Мама»: первый раз нужен код с экрана того ПК. Что делать — в окне AnyPC: «Отправить»." {
		t.Errorf("ru: %q", got)
	}
	for l, w := range sendNoticeWords {
		for _, k := range []string{"ok", "fail", "files", "known", "offline", "denied", "cancel", "running", "busy", "other"} {
			if w[k] == "" {
				t.Errorf("%s: нет %s", l, k)
			}
		}
	}
	if got := sendNoticeText("xx", "PC", "", errors.New("?")); got != "Not sent to “PC”: error. What to do — in the AnyPC window: “Send”." {
		t.Errorf("неизвестный язык: %q", got)
	}
}
