package ui

import (
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// TestCSPHash: CSP разрешает встроенный скрипт только по хэшу — любая правка скрипта без
// обновления хэша в <meta http-equiv="Content-Security-Policy"> ломает страницу целиком.
func TestCSPHash(t *testing.T) {
	b, err := fs.ReadFile(FS, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	// Ровно два <script: внешний embed.js (того же источника, разрешён 'self', хэша не требует) и один
	// встроенный (в CSP по хэшу). Иначе новый встроенный скрипт прошёл бы мимо проверки хэша.
	if n := strings.Count(html, "<script"); n != 2 {
		t.Fatalf("тегов <script: %d — ожидалось 2 (embed.js + один встроенный)", n)
	}
	if !strings.Contains(html, `<script src="embed.js"></script>`) {
		t.Fatal("нет внешнего <script src=\"embed.js\"> — фрейму «Мои ПК» нужны привязки родителя")
	}
	if n := strings.Count(html, "<script>"); n != 1 {
		t.Fatalf("встроенных <script>: %d — каждому нужен свой хэш в CSP", n)
	}
	if m := regexp.MustCompile(`\son[a-z]+=["']`).FindString(html); m != "" {
		t.Fatalf("атрибут-обработчик %q: CSP его заблокирует", m)
	}
	csp := regexp.MustCompile(`<meta http-equiv="Content-Security-Policy" content="([^"]+)">`).FindStringSubmatch(html)
	if csp == nil {
		t.Fatal("нет CSP")
	}
	i := strings.Index(html, "<script>")
	j := strings.Index(html[i:], "</script>") + i // закрытие именно встроенного скрипта (внешний embed.js закрыт раньше)
	sum := sha256.Sum256([]byte(html[i+len("<script>") : j]))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if !strings.Contains(csp[1], "script-src 'self' "+want) {
		t.Fatalf("хэш скрипта в CSP устарел: нужен script-src 'self' %s", want)
	}
}
