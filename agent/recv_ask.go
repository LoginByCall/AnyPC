package agent

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// recvAsks — окно «Принять?» (Ч10.1, recv.go): заголовок, вопрос (%s — от кого), файл (%s — имя, %s — размер),
// «и остальные файлы», текст (%d — символов), кнопки, сноска, задержка 3 с и 5 с, подсказка к «Да / Нет».
// Остальные языки — английский (NOTIFY).
var recvAsks = map[string][11]string{
	"en": {"incoming files", "Accept from %s?", "File: %s (%s)", "Further files of this transfer will be accepted too.", "Text, %d characters — goes to the clipboard after “Accept”:",
		"Accept", "Decline", "No answer within 30 s — declined.", "“Accept” works 3 seconds after this window appears.", "“Accept” works 5 seconds after this window appears.", "“Yes” — accept, “No” — decline."},
	"ru": {"входящие файлы", "Принять от %s?", "Файл: %s (%s)", "Остальные файлы этой передачи примутся тоже.", "Текст, символов: %d — после «Принять» попадёт в буфер обмена:",
		"Принять", "Отклонить", "Без ответа 30 с — отказ.", "«Принять» срабатывает через 3 секунды после появления окна.", "«Принять» срабатывает через 5 секунд после появления окна.", "«Да» — принять, «Нет» — отклонить."},
}

func recvAsksOf(lang string) [11]string {
	if s, ok := recvAsks[lang]; ok {
		return s
	}
	return recvAsks["en"]
}

// recvPreview — текст для окна: не больше 600 символов и 12 строк; управляющие и форматные (U+202E) — заменены.
func recvPreview(t string) string {
	r := []rune(t)
	cut := len(r) > 600
	if cut {
		r = r[:600]
	}
	lines := strings.Split(strings.Map(func(c rune) rune {
		switch {
		case c == '\n' || c == '\t':
			return c
		case unicode.Is(unicode.Cc, c) || unicode.Is(unicode.Cf, c) || c == utf8.RuneError:
			return '�'
		}
		return c
	}, string(r)), "\n")
	if len(lines) > 12 {
		lines, cut = lines[:12], true
	}
	out := strings.Join(lines, "\n")
	if cut {
		out += "\n…"
	}
	return out
}

// recvSize — размер для окна.
func recvSize(n int64, lang string) string {
	u := []string{"B", "KB", "MB", "GB", "TB"}
	if lang == "ru" {
		u = []string{"Б", "КБ", "МБ", "ГБ", "ТБ"}
	}
	f, i := float64(n), 0
	for f >= 1024 && i < len(u)-1 {
		f, i = f/1024, i+1
	}
	if i == 0 {
		return fmt.Sprintf("%d %s", n, u[0])
	}
	return fmt.Sprintf("%.1f %s", f, u[i])
}

// recvAskText — окно «Принять?»; loop — окно askLoop (задержка 5 с), иначе TaskDialog (3 с).
func recvAskText(lang string, q RecvReq, loop bool) (title, text, yes, no, hint string) {
	s := recvAsksOf(lang)
	body := fmt.Sprintf(s[1], q.From) + "\n\n"
	if q.IsText {
		body += fmt.Sprintf(s[4], utf8.RuneCountInString(q.Text)) + "\n\n" + recvPreview(q.Text)
	} else {
		body += fmt.Sprintf(s[2], recvPreview(q.Name), recvSize(q.Size, lang)) + "\n" + s[3]
	}
	delay := s[8]
	if loop {
		delay = s[9]
	}
	return "AnyPC — " + s[0], body + "\n\n" + s[7] + "\n" + delay, s[5], s[6], s[10]
}
