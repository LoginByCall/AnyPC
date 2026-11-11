// Package totp — второй фактор входа без подтверждения (PLAN.md «TOTP»): RFC 6238, HMAC-SHA1, 6 цифр,
// шаг 30 с, окно ±1 шаг. Секрет — 20 случайных байт, base32 без '='. Требует ревью человеком (A13, A2 #10).
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"rsc.io/qr"
)

const (
	Period = 30 // с
	Digits = 6
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret — новый секрет: 20 байт crypto/rand (как у HMAC-SHA1), base32 без '='.
func NewSecret() string {
	k := make([]byte, 20)
	rand.Read(k)
	return b32.EncodeToString(k)
}

// key — байты секрета; ошибка — не base32 или короче 16 байт (чужой или испорченный конфиг).
func key(secret string) ([]byte, error) {
	k, err := b32.DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil || len(k) < 16 {
		return nil, fmt.Errorf("неверный секрет TOTP")
	}
	return k, nil
}

// hotp — RFC 4226: HMAC-SHA1 счётчика, динамическое усечение, digits десятичных цифр.
func hotp(k []byte, counter uint64, digits int) string {
	m := hmac.New(sha1.New, k)
	binary.Write(m, binary.BigEndian, counter)
	h := m.Sum(nil)
	o := h[len(h)-1] & 0xf
	v := binary.BigEndian.Uint32(h[o:]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

// Step — номер шага TOTP для момента t.
func Step(t time.Time) int64 { return t.Unix() / Period }

// Check — код верный для шага now±1 и новее last (шаг последнего принятого кода: тот же или более ранний —
// повтор, отказ). Сравнение всех трёх кодов — постоянное время. step — шаг принятого кода (запомнить как last).
func Check(secret, code string, now time.Time, last int64) (step int64, ok bool) {
	k, err := key(secret)
	if err != nil || len(code) != Digits {
		return 0, false
	}
	s := Step(now)
	for d := int64(-1); d <= 1; d++ {
		if subtle.ConstantTimeCompare([]byte(hotp(k, uint64(s+d), Digits)), []byte(code)) == 1 && s+d > last {
			step, ok = s+d, true
		}
	}
	return step, ok
}

// Code — код для момента t (тесты, проверка настройки).
func Code(secret string, t time.Time) (string, error) {
	k, err := key(secret)
	if err != nil {
		return "", err
	}
	return hotp(k, uint64(Step(t)), Digits), nil
}

// Valid — секрет пригоден (настройка из окна приходит строкой со страницы).
func Valid(secret string) bool { _, err := key(secret); return err == nil }

// URI — otpauth для приложения-аутентификатора (Google Authenticator и др.); ID — без пробелов.
func URI(id, secret string) string {
	return "otpauth://totp/AnyPC:" + id + "?secret=" + secret + "&issuer=AnyPC&digits=6&period=30"
}

// SVG — QR-код текста для окна хоста: белое поле в 4 модуля (иначе на тёмной теме не читается), модуль — 1 единица.
func SVG(text string) (string, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	n := c.Size + 8
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n, n, n)
	for y := range c.Size {
		for x := range c.Size {
			if c.Black(x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+4, y+4)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}

// Terminal — QR-код полублоками (▀▄█) для терминала: две строки модулей на строку текста. Цвета — явно
// (белый на чёрном): светлые модули рисуются блоками, тёмные — фоном; поле — 4 модуля, как требует QR.
func Terminal(text string) (string, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	white := func(x, y int) bool { return !c.Black(x, y) } // за краем Black — false: поле светлое само
	var b strings.Builder
	for y := -4; y < c.Size+4; y += 2 {
		b.WriteString("\x1b[97;40m")
		for x := -4; x < c.Size+4; x++ {
			switch top, bot := white(x, y), white(x, y+1); {
			case top && bot:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bot:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\x1b[0m\n")
	}
	return b.String(), nil
}
