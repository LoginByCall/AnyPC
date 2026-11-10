package site

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestPrivacyPage — страница /privacy.html собрана из актуального PRIVACY.md (python3 site/privacy.py) и встроена.
func TestPrivacyPage(t *testing.T) {
	md, err := os.ReadFile("../PRIVACY.md")
	if err != nil {
		t.Fatal(err)
	}
	page, err := FS.ReadFile("privacy.html")
	if err != nil {
		t.Fatal("privacy.html не встроен:", err)
	}
	for _, h := range regexp.MustCompile(`(?m)^#{1,2} (.+)$|^(Редакция от .+|Effective .+)$`).FindAllString(string(md), -1) {
		h = strings.TrimLeft(h, "# ")
		if !strings.Contains(string(page), h) {
			t.Errorf("в privacy.html нет %q — запустите python3 site/privacy.py", h)
		}
	}
	if idx, _ := FS.ReadFile("index.html"); !strings.Contains(string(idx), `href="/privacy.html"`) {
		t.Error("на лендинге нет ссылки на /privacy.html")
	}
}

// TestCSPHash — заголовок CSP лендинга (CSP) пропускает встроенный скрипт только по хешу: второй <script>
// или атрибут-обработчик (onclick=) CSP заблокирует, и страница молча перестанет работать.
func TestCSPHash(t *testing.T) {
	for _, f := range []string{"index.html", "privacy.html"} {
		b, err := FS.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		html := string(b)
		want := 1
		if f == "privacy.html" {
			want = 0
		}
		if n := strings.Count(html, "<script"); n != want {
			t.Fatalf("%s: встроенных <script>: %d, ждали %d — у каждого должен быть хеш в site.CSP", f, n, want)
		}
		if strings.Contains(html, "<script ") || strings.Contains(html, "<script\n") {
			t.Fatalf("%s: <script> с атрибутами (src=?) — внешние скрипты CSP не пропустит", f)
		}
		if m := regexp.MustCompile(`\son[a-z]+=["']`).FindString(html); m != "" {
			t.Fatalf("%s: атрибут-обработчик %q: CSP его заблокирует", f, m)
		}
	}
	b, _ := FS.ReadFile("index.html")
	html := string(b)
	i, j := strings.Index(html, "<script>"), strings.Index(html, "</script>")
	sum := sha256.Sum256([]byte(html[i+len("<script>") : j]))
	want := "script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "';"
	if !strings.Contains(CSP, want) || !strings.Contains(CSP, "frame-ancestors 'none'") || !strings.HasPrefix(CSP, "default-src 'none';") {
		t.Fatalf("CSP: %q, ждали %s", CSP, want)
	}
}
