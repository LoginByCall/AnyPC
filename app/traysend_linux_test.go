package main

import "testing"

// TestTrayTreeSub — Ч10.5: подменю «Отправить ›» в dbusmenu — пункт с детьми и children-display "submenu"; номера
// детей ищутся (find) — щелчок по ним доходит до trayPick.
func TestTrayTreeSub(t *testing.T) {
	s := trayState{Self: "123456789", Dst: []trayPC{{"555666777", "Мама"}}}
	root := trayTree(trayRows(s, "Ноутбук", trayTextsFor("ru", "linux")))
	it := root.find(int32(traySend))
	if it == nil || len(it.children) != 3 || it.props()["children-display"].Value() != "submenu" {
		t.Fatalf("подменю: %+v", it)
	}
	if c := root.find(int32(trayDstID("555666777"))); c == nil || c.label != "Мама · файл…" {
		t.Fatalf("пункт ПК: %+v", c)
	}
	if !it.children[1].sep || root.find(int32(traySWin)) == nil {
		t.Fatal("разделитель и «в окне»")
	}
}

// TestNoticeEsc — замечание 5 приёмки: тело notify-send — разметка (KDE, dunst): & < > экранируются.
func TestNoticeEsc(t *testing.T) {
	if got := noticeEsc("a<b>&c.txt"); got != "a&lt;b&gt;&amp;c.txt" {
		t.Fatal(got)
	}
}
