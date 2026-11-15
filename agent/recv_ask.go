package agent

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// recvAsks — окно «Принять?» (Ч10.1, recv.go): заголовок, вопрос (%s — от кого), файл (%s — имя, %s — размер),
// «и остальные файлы», текст (%d — символов), кнопки, сноска, задержка 3 с и 5 с, подсказка к «Да / Нет»,
// текст обрезан (%d из %d). Языки — как у остальных окон хоста (asks).
var recvAsks = map[string][12]string{
	"en": {"incoming files", "Accept from %s?", "File: %s (%s)", "Further files of this transfer will be accepted too.", "Text, %d characters — goes to the clipboard after “Accept”:",
		"Accept", "Decline", "No answer within 30 s — declined.", "“Accept” works 3 seconds after this window appears.", "“Accept” works 5 seconds after this window appears.", "“Yes” — accept, “No” — decline.",
		"Shown: %d of %d characters."},
	"ru": {"входящие файлы", "Принять от %s?", "Файл: %s (%s)", "Остальные файлы этой передачи примутся тоже.", "Текст, символов: %d — после «Принять» попадёт в буфер обмена:",
		"Принять", "Отклонить", "Без ответа 30 с — отказ.", "«Принять» срабатывает через 3 секунды после появления окна.", "«Принять» срабатывает через 5 секунд после появления окна.", "«Да» — принять, «Нет» — отклонить.",
		"Показано символов: %d из %d."},
	"zh": {"传入文件", "接受来自 %s 的内容吗？", "文件：%s（%s）", "本次传输的其余文件也将被接受。", "文本，%d 个字符——点击“接受”后放入剪贴板：",
		"接受", "拒绝", "30 秒内未响应将自动拒绝。", "“接受”在窗口出现 3 秒后才生效。", "“接受”在窗口出现 5 秒后才生效。", "“是”——接受，“否”——拒绝。",
		"已显示 %d / %d 个字符。"},
	"es": {"archivos entrantes", "¿Aceptar de %s?", "Archivo: %s (%s)", "Los demás archivos de esta transferencia también se aceptarán.", "Texto, %d caracteres; tras «Aceptar» irá al portapapeles:",
		"Aceptar", "Rechazar", "Sin respuesta en 30 s — se rechaza.", "«Aceptar» funciona 3 segundos después de que aparezca esta ventana.", "«Aceptar» funciona 5 segundos después de que aparezca esta ventana.", "«Sí»: aceptar; «No»: rechazar.",
		"Se muestran %d de %d caracteres."},
	"de": {"eingehende Dateien", "Von %s annehmen?", "Datei: %s (%s)", "Weitere Dateien dieser Übertragung werden ebenfalls angenommen.", "Text, %d Zeichen – kommt nach „Annehmen“ in die Zwischenablage:",
		"Annehmen", "Ablehnen", "Ohne Antwort in 30 s — abgelehnt.", "„Annehmen“ wirkt erst 3 Sekunden nach Erscheinen dieses Fensters.", "„Annehmen“ wirkt erst 5 Sekunden nach Erscheinen dieses Fensters.", "„Ja“ – annehmen, „Nein“ – ablehnen.",
		"Angezeigt: %d von %d Zeichen."},
	"fr": {"fichiers entrants", "Accepter de %s ?", "Fichier : %s (%s)", "Les autres fichiers de ce transfert seront aussi acceptés.", "Texte, %d caractères — ira dans le presse-papiers après « Accepter » :",
		"Accepter", "Refuser", "Sans réponse sous 30 s — refusé.", "« Accepter » ne fonctionne que 3 secondes après l’apparition de cette fenêtre.", "« Accepter » ne fonctionne que 5 secondes après l’apparition de cette fenêtre.", "« Oui » : accepter, « Non » : refuser.",
		"Affichés : %d caractères sur %d."},
	"it": {"file in arrivo", "Accettare da %s?", "File: %s (%s)", "Anche gli altri file di questo trasferimento saranno accettati.", "Testo, %d caratteri — dopo «Accetta» andrà negli appunti:",
		"Accetta", "Rifiuta", "Senza risposta entro 30 s — rifiutata.", "«Accetta» funziona 3 secondi dopo la comparsa di questa finestra.", "«Accetta» funziona 5 secondi dopo la comparsa di questa finestra.", "«Sì»: accetta, «No»: rifiuta.",
		"Mostrati %d caratteri su %d."},
}

func recvAsksOf(lang string) [12]string {
	if s, ok := recvAsks[lang]; ok {
		return s
	}
	return recvAsks["en"]
}

// recvPreview — текст для окна: не больше 600 символов и 12 строк; управляющие и форматные (U+202E) — заменены.
// shown — сколько символов показано (меньше всех — текст обрезан).
func recvPreview(t string) (out string, shown int) {
	r := []rune(t)
	if len(r) > 600 {
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
		lines = lines[:12]
	}
	out = strings.Join(lines, "\n")
	shown = utf8.RuneCountInString(out)
	if shown < utf8.RuneCountInString(t) {
		out += "\n…"
	}
	return out, shown
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

// recvAskText — окно «Принять?»; loop — окно askLoop (задержка 5 с), иначе TaskDialog (3 с). Имя файла — уже после
// safeName (receiveFile), здесь ещё раз без управляющих и форматных символов.
func recvAskText(lang string, q RecvReq, loop bool) (title, text, yes, no, hint string) {
	s := recvAsksOf(lang)
	body := fmt.Sprintf(s[1], q.From) + "\n\n"
	if q.IsText {
		all := utf8.RuneCountInString(q.Text)
		p, shown := recvPreview(q.Text)
		body += fmt.Sprintf(s[4], all) + "\n\n" + p
		if shown < all {
			body += "\n" + fmt.Sprintf(s[11], shown, all)
		}
	} else {
		name, _ := recvPreview(q.Name)
		body += fmt.Sprintf(s[2], name, recvSize(q.Size, lang)) + "\n" + s[3]
	}
	delay := s[8]
	if loop {
		delay = s[9]
	}
	return "AnyPC — " + s[0], body + "\n\n" + s[7] + "\n" + delay, s[5], s[6], s[10]
}
