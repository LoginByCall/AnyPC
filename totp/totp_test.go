package totp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// TestRFC6238 — векторы приложения B RFC 6238 (SHA1, ключ "12345678901234567890", 8 цифр) и они же в 6 цифрах.
func TestRFC6238(t *testing.T) {
	k := []byte("12345678901234567890")
	for ts, want := range map[int64]string{59: "94287082", 1111111109: "07081804", 1111111111: "14050471",
		1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130"} {
		if got := hotp(k, uint64(ts/Period), 8); got != want {
			t.Errorf("T=%d: %s, ждали %s", ts, got, want)
		}
		sec := base32.StdEncoding.EncodeToString(k)
		if c, _ := Code(sec, time.Unix(ts, 0)); c != want[2:] {
			t.Errorf("T=%d, 6 цифр: %s, ждали %s", ts, c, want[2:])
		}
	}
}

// TestCheck — окно ±1 шаг, защита от повтора, неверный код и испорченный секрет.
func TestCheck(t *testing.T) {
	sec := NewSecret()
	if len(sec) != 32 || strings.Contains(sec, "=") || !Valid(sec) {
		t.Fatalf("секрет %q: ждали 20 байт base32 без '='", sec)
	}
	if NewSecret() == sec {
		t.Fatal("секрет не случайный")
	}
	now := time.Unix(1_800_000_000, 0)
	at := func(d time.Duration) string { c, _ := Code(sec, now.Add(d)); return c }
	s := Step(now)
	for _, d := range []time.Duration{-Period * time.Second, 0, Period * time.Second} {
		if st, ok := Check(sec, at(d), now, 0); !ok || st != Step(now.Add(d)) {
			t.Errorf("код шага %+v не принят", d)
		}
	}
	for _, d := range []time.Duration{-2 * Period * time.Second, 2 * Period * time.Second} {
		if _, ok := Check(sec, at(d), now, 0); ok {
			t.Errorf("код вне окна (%v) принят", d)
		}
	}
	if _, ok := Check(sec, at(0), now, s); ok {
		t.Error("повтор кода того же шага принят")
	}
	if _, ok := Check(sec, at(-Period*time.Second), now, s); ok {
		t.Error("код более раннего шага, чем принятый, принят")
	}
	if _, ok := Check(sec, at(Period*time.Second), now, s); !ok {
		t.Error("код следующего шага после принятого отвергнут")
	}
	bad := []byte(at(0))
	bad[0] = '0' + (bad[0]-'0'+1)%10
	for _, c := range []string{string(bad), "", "12345", "1234567", "abcdef"} {
		if _, ok := Check(sec, c, now, 0); ok {
			t.Errorf("неверный код %q принят", c)
		}
	}
	if _, ok := Check("не-base32!", at(0), now, 0); ok || Valid("AAAA") || Valid("") {
		t.Error("испорченный или короткий секрет принят")
	}
}

// TestQR — URI в формате приложений; SVG и полублоки строятся (вид — V3 телефоном).
func TestQR(t *testing.T) {
	u := URI("123456789", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
	if u != "otpauth://totp/AnyPC:123456789?secret=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567&issuer=AnyPC&digits=6&period=30" {
		t.Fatal(u)
	}
	svg, err := SVG(u)
	if err != nil || !strings.HasPrefix(svg, "<svg") || !strings.Contains(svg, "M4 4h1v1h-1z") { // угловой узор — с (4,4)
		t.Fatalf("SVG: %v %.80s", err, svg)
	}
	term, err := Terminal(u)
	lines := strings.Split(strings.TrimSuffix(term, "\n"), "\n")
	if err != nil || len(lines) < 15 || !strings.Contains(term, "▀") {
		t.Fatalf("полублоки: %v, %d строк", err, len(lines))
	}
}
