package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestUIState: настройки окна (mine, users…) в config.json — только ключи из списка, только JSON, пределы 64/256 КБ;
// запись атомарная (0600, без хвостов .tmp), одновременные записи не теряются, второй процесс видит их с диска.
func TestUIState(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	c, _ := loadConfig(p)
	if g := c.uiGet(); g == nil || len(g) != 0 {
		t.Errorf("пустые: %v", g)
	}
	for _, bad := range [][2]string{
		{"pass", `{"123456789":"x"}`}, // пароли — не сюда (Saved)
		{"ckeys", `{}`},               // ключи клиента — тоже
		{"mine", `[{"id":`},           // не JSON
		{"mine", ""},
		{"mine", `"` + strings.Repeat("x", uiKeyMax-1) + `"`}, // 64 КБ + 1
	} {
		if err := c.uiSet(bad[0], bad[1]); err == nil {
			t.Errorf("принято %s=%.40s", bad[0], bad[1])
		}
	}
	if err := c.uiSet("mine", `"`+strings.Repeat("x", uiKeyMax-2)+`"`); err != nil { // ровно 64 КБ
		t.Errorf("64 КБ: %v", err)
	}
	for _, k := range []string{"users", "recent", "stats"} {
		if err := c.uiSet(k, `"`+strings.Repeat("y", uiKeyMax-2)+`"`); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
	}
	if err := c.uiSet("turbo", "1"); err == nil { // пятый ключ сверх 256 КБ
		t.Error("всего больше 256 КБ принято")
	}
	if err := c.uiSet("mine", `[{"id":"123456789","name":"Офис"}]`); err != nil { // замена ключа считает его новую длину
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, k := range []string{"turbo", "turn", "tour_home", "tour_sess"} {
		wg.Add(1)
		go func() { defer wg.Done(); c.uiSet(k, `"`+k+`"`) }()
	}
	wg.Wait()
	other, err := loadConfig(p) // окно другого процесса (CLI, новый запуск) — с диска
	if err != nil {
		t.Fatal(err)
	}
	g := other.uiGet()
	if g["mine"] != `[{"id":"123456789","name":"Офис"}]` || g["turbo"] != `"turbo"` || g["tour_sess"] != `"tour_sess"` || len(g) != 8 {
		t.Errorf("с диска: %d ключей, mine=%s", len(g), g["mine"])
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("права файла: %v %v", fi, err)
	}
	if l, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(l) > 0 {
		t.Errorf("хвосты записи: %v", l)
	}
}
