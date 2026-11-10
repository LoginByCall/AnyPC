package main

import (
	"encoding/xml"
	"strings"
	"testing"
)

// TestLaunchPlist — LaunchAgent: путь с пробелами, кириллицей и XML-символами экранирован, plist разбирается, ключи на месте.
func TestLaunchPlist(t *testing.T) {
	exe := `/Users/я/Программы & <AnyPC>/AnyPC-macos`
	p := launchPlist(exe)
	d := xml.NewDecoder(strings.NewReader(p))
	d.Strict = true
	var strs []string
	for {
		tok, err := d.Token()
		if err != nil {
			if err.Error() != "EOF" {
				t.Fatalf("plist не XML: %v\n%s", err, p)
			}
			break
		}
		if cd, ok := tok.(xml.CharData); ok && strings.TrimSpace(string(cd)) != "" {
			strs = append(strs, string(cd))
		}
	}
	for _, want := range []string{launchLabel, exe, "--no-browser", "Aqua", "Interactive"} {
		found := false
		for _, s := range strs {
			found = found || s == want
		}
		if !found {
			t.Errorf("в plist нет %q: %v", want, strs)
		}
	}
	for _, key := range []string{"<key>RunAtLoad</key><true/>", "<key>SuccessfulExit</key><false/>"} {
		if !strings.Contains(p, key) {
			t.Errorf("нет %s", key)
		}
	}
}

// TestBrewPath — регрессия: из LaunchAgent хост не находил ffmpeg (PATH launchd без /usr/local/bin).
func TestBrewPath(t *testing.T) {
	if got := brewPath("/usr/bin:/bin"); got != "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin" {
		t.Error(got)
	}
	if got := brewPath("/opt/homebrew/bin:/usr/local/bin:/usr/bin"); got != "/opt/homebrew/bin:/usr/local/bin:/usr/bin" {
		t.Error("дубли:", got)
	}
	if got := brewPath(""); got != "/usr/local/bin:/opt/homebrew/bin" {
		t.Error("пустой:", got)
	}
}
