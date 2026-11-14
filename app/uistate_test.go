package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestUIState: настройки окна (mine, users…) в config.json — только ключи из списка, только своей формы, пределы
// 64/256 КБ; запись атомарная (0600, без хвостов .tmp), одновременные записи не теряются, второй процесс видит их с диска.
func TestUIState(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	c, _ := loadConfig(p)
	if g := c.uiGet(); g == nil || len(g) != 0 {
		t.Errorf("пустые: %v", g)
	}
	pad := func(n int) string { return strings.Repeat("x", n) }
	for _, bad := range [][2]string{
		{"pass", `{"123456789":"x"}`}, // пароли — не сюда (Saved)
		{"ckeys", `{}`},               // ключи клиента — тоже
		{"mine", `[{"id":`},           // не JSON
		{"mine", ""},
		{"mine", `["` + pad(uiKeyMax-3) + `"]`}, // 64 КБ + 1
		// форма: значение другой формы роняло основной скрипт страницы при каждом запуске (приёмка: recent=5)
		{"recent", `5`}, {"recent", `[1]`}, {"recent", `null`}, {"mine", `{}`}, {"mine", `null`}, {"users", `[]`},
		{"users", `{"123456789":5}`}, {"stats", `null`}, {"stats", `"true"`}, {"turbo", `2`}, {"turbo", `"1"`},
		{"tour_home", `true`}, {"turn", `5`},
	} {
		if err := c.uiSet(bad[0], bad[1]); err == nil {
			t.Errorf("принято %s=%.40s", bad[0], bad[1])
		}
	}
	for _, good := range [][2]string{{"mine", `["123456789"]`}, {"recent", `[]`}, {"users", `{}`}, {"stats", `true`},
		{"turbo", `0`}, {"tour_sess", `1`}, {"turn", `"auto"`}} {
		if err := c.uiSet(good[0], good[1]); err != nil {
			t.Errorf("%s=%s: %v", good[0], good[1], err)
		}
	}
	if err := c.uiSet("mine", `["`+pad(uiKeyMax-4)+`"]`); err != nil { // ровно 64 КБ
		t.Errorf("64 КБ: %v", err)
	}
	for _, kv := range [][2]string{{"users", `{"a":"` + pad(uiKeyMax-8) + `"}`}, {"recent", `["` + pad(uiKeyMax-4) + `"]`}} {
		if err := c.uiSet(kv[0], kv[1]); err != nil {
			t.Fatalf("%s: %v", kv[0], err)
		}
	}
	// ровно 256 КБ всего: mine, users, recent по 64 КБ + stats true, turbo 0, tour_sess 1 (6 байт) + turn
	if err := c.uiSet("turn", `"`+pad(uiKeyMax-8)+`"`); err != nil {
		t.Fatalf("256 КБ: %v", err)
	}
	if err := c.uiSet("tour_home", "1"); err == nil { // ещё байт сверх 256 КБ
		t.Error("всего больше 256 КБ принято")
	}
	if err := c.uiSet("mine", `[{"id":"123456789","name":"Офис"}]`); err != nil { // замена ключа считает его новую длину
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, kv := range [][2]string{{"stats", "false"}, {"turbo", "1"}, {"tour_home", "1"}, {"tour_sess", "0"}} {
		wg.Add(1)
		go func() { defer wg.Done(); c.uiSet(kv[0], kv[1]) }()
	}
	wg.Wait()
	other, err := loadConfig(p) // окно другого процесса (CLI, новый запуск) — с диска
	if err != nil {
		t.Fatal(err)
	}
	g := other.uiGet()
	if g["mine"] != `[{"id":"123456789","name":"Офис"}]` || g["turbo"] != "1" || g["tour_sess"] != "0" || g["stats"] != "false" || len(g) != 8 {
		t.Errorf("с диска: %d ключей, mine=%s", len(g), g["mine"])
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("права файла: %v %v", fi, err)
	}
	if l, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(l) > 0 {
		t.Errorf("хвосты записи: %v", l)
	}
}

// TestUIStateCorrupt: испорченное поле ui в файле не мешает запуску (приёмка: «"ui":5» — программа не стартовала):
// негодное отбрасывается, годное и остальные настройки остаются; запись после порчи на диске проходит.
func TestUIStateCorrupt(t *testing.T) {
	for body, want := range map[string]string{
		`{"id":"123456789","ui":5}`:          "",
		`{"id":"123456789","ui":[]}`:         "",
		`{"id":"123456789","ui":null}`:       "",
		`{"id":"123456789","ui":{"mine":5}}`: "",
		`{"id":"123456789","ui":{"evil":"x","mine":"not json","stats":"null","recent":"5","turbo":"1"}}`: "turbo=1",
	} {
		p := filepath.Join(t.TempDir(), "config.json")
		os.WriteFile(p, []byte(body), 0o600)
		c, err := loadConfig(p)
		if err != nil {
			t.Errorf("%s: не запустилось: %v", body, err)
			continue
		}
		got := ""
		for k, v := range c.uiGet() {
			got += k + "=" + v
		}
		if got != want || c.ID != "123456789" {
			t.Errorf("%s: ui %q, ID %s", body, got, c.ID)
		}
	}
	p := filepath.Join(t.TempDir(), "config.json")
	c, _ := loadConfig(p)
	c.uiSet("mine", `[]`)
	b, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(b), `"ui": {`, `"ui": 7, "x": {`, 1)), 0o600)
	if err := c.uiSet("turbo", "0"); err != nil || c.uiGet()["turbo"] != "0" {
		t.Errorf("запись после порчи ui на диске: %v", err)
	}
}
