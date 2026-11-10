package main

import (
	"encoding/xml"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
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

// TestInstallAfterBootout — N4: bootout завершает службу асинхронно, bootstrap сразу за ним launchd отвергает
// (ошибка 5). Повтор --install-service при работающей службе должен дождаться её ухода и загрузить заново.
func TestInstallAfterBootout(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	old, oldWait := launchctl, launchWait
	t.Cleanup(func() { launchctl, launchWait = old, oldWait })
	launchWait = time.Millisecond
	for _, c := range []struct {
		name         string
		left, refuse int // сколько print ещё находят службу после bootout; сколько bootstrap отказывают и после её ухода
	}{{"служба уходит не сразу", 3, 0}, {"launchd отказывает и после ухода", 0, 1}} {
		loaded, left, refuse, boots := true, 0, c.refuse, 0
		launchctl = func(args ...string) error {
			switch args[0] {
			case "bootout":
				left = c.left
			case "print":
				if left > 0 {
					left--
					return nil
				}
				loaded = false
			case "bootstrap":
				boots++
				if loaded || refuse > 0 {
					refuse--
					return errors.New("Bootstrap failed: 5: Input/output error")
				}
				loaded = true
			}
			return nil
		}
		if err := installService("/Applications/AnyPC-macos"); err != nil || !loaded {
			t.Errorf("%s: %v (bootstrap %d раз)", c.name, err, boots)
		}
		if _, err := os.Stat(launchPath()); err != nil {
			t.Errorf("%s: plist: %v", c.name, err)
		}
	}
}
