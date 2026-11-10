package site

import (
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
