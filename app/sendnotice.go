package main

// Ч10.5: итог отправки из трея — уведомлением рабочего стола (окна нет). Текст короткий: что и куда, или почему нет
// и куда смотреть дальше (подробности и шаги — экран «Отправить» окна: там то же состояние, sendState).

import (
	"errors"
	"fmt"
	"strings"

	"anypc/agent"
)

// sendNotice — уведомление (подмена — в тестах); ОС — noticeOS (notice_unix.go, tray_windows.go).
var sendNotice = func(title, body string) { noticeOS(title, body) }

// sendNoticeWords — язык → ok «%[1]s — имя ПК, %[2]s — что», fail «%[1]s — ПК, %[2]s — причина», что по умолчанию,
// причины: код, причина первого раза, нет связи, отказ, отмена, идёт другая, занят, прочее.
var sendNoticeWords = map[string]map[string]string{
	"ru": {"run": "Отправляю «%[1]s» на «%[2]s»…", "runask": "Ждём «Принять?» на том ПК.", "ok": "Отправлено на «%[1]s»: %[2]s", "fail": "Не отправлено на «%[1]s»: %[2]s. Что делать — в окне AnyPC: «Отправить».", "files": "файл",
		"known": "первый раз нужен код с экрана того ПК", "offline": "тот ПК не в сети", "denied": "на том ПК отказались",
		"cancel": "отменено", "running": "уже идёт другая отправка", "busy": "тот ПК занят — повторите позже", "other": "ошибка"},
	"en": {"run": "Sending “%[1]s” to “%[2]s”…", "runask": "Waiting for “Accept?” on that PC.", "ok": "Sent to “%[1]s”: %[2]s", "fail": "Not sent to “%[1]s”: %[2]s. What to do — in the AnyPC window: “Send”.", "files": "file",
		"known": "the first time needs the code from that PC’s screen", "offline": "that PC is offline", "denied": "declined on that PC",
		"cancel": "cancelled", "running": "another transfer is in progress", "busy": "that PC is busy — try again later", "other": "error"},
	"zh": {"run": "正在发送“%[1]s”到“%[2]s”…", "runask": "等待那台电脑上的“接收？”。", "ok": "已发送到“%[1]s”：%[2]s", "fail": "未发送到“%[1]s”：%[2]s。下一步 — 在 AnyPC 窗口的“发送”中。", "files": "文件",
		"known": "第一次需要那台电脑屏幕上的代码", "offline": "那台电脑不在线", "denied": "那台电脑拒绝了",
		"cancel": "已取消", "running": "另一个发送正在进行", "busy": "那台电脑正忙 — 请稍后重试", "other": "错误"},
	"es": {"run": "Enviando «%[1]s» a «%[2]s»…", "runask": "Esperando «¿Aceptar?» en ese PC.", "ok": "Enviado a «%[1]s»: %[2]s", "fail": "No enviado a «%[1]s»: %[2]s. Qué hacer — en la ventana de AnyPC: «Enviar».", "files": "archivo",
		"known": "la primera vez necesita el código de la pantalla de ese PC", "offline": "ese PC no está en línea", "denied": "rechazado en ese PC",
		"cancel": "cancelado", "running": "ya hay otro envío en curso", "busy": "ese PC está ocupado — inténtelo más tarde", "other": "error"},
	"de": {"run": "Sende „%[1]s“ an „%[2]s“…", "runask": "Warte auf „Annehmen?“ auf jenem PC.", "ok": "Gesendet an „%[1]s“: %[2]s", "fail": "Nicht gesendet an „%[1]s“: %[2]s. Was tun — im AnyPC-Fenster: „Senden“.", "files": "Datei",
		"known": "beim ersten Mal ist der Code vom Bildschirm jenes PCs nötig", "offline": "jener PC ist nicht online", "denied": "auf jenem PC abgelehnt",
		"cancel": "abgebrochen", "running": "eine andere Übertragung läuft", "busy": "jener PC ist beschäftigt — später erneut", "other": "Fehler"},
	"fr": {"run": "Envoi de « %[1]s » à « %[2]s »…", "runask": "En attente de « Accepter ? » sur ce PC.", "ok": "Envoyé à « %[1]s » : %[2]s", "fail": "Non envoyé à « %[1]s » : %[2]s. Que faire — dans la fenêtre AnyPC : « Envoyer ».", "files": "fichier",
		"known": "la première fois, il faut le code affiché sur ce PC", "offline": "ce PC n’est pas en ligne", "denied": "refusé sur ce PC",
		"cancel": "annulé", "running": "un autre envoi est en cours", "busy": "ce PC est occupé — réessayez plus tard", "other": "erreur"},
	"it": {"run": "Invio di «%[1]s» a «%[2]s»…", "runask": "In attesa di «Accettare?» su quel PC.", "ok": "Inviato a «%[1]s»: %[2]s", "fail": "Non inviato a «%[1]s»: %[2]s. Cosa fare — nella finestra di AnyPC: «Invia».", "files": "file",
		"known": "la prima volta serve il codice dallo schermo di quel PC", "offline": "quel PC non è online", "denied": "rifiutato su quel PC",
		"cancel": "annullato", "running": "è già in corso un altro invio", "busy": "quel PC è occupato — riprova più tardi", "other": "errore"},
}

// sendNoticeRun — уведомление о начале отправки из трея; ask — чужой ПК: там спросят «Принять?».
func sendNoticeRun(lang, who, what string, ask bool) string {
	w, ok := sendNoticeWords[lang]
	if !ok {
		w = sendNoticeWords["en"]
	}
	t := fmt.Sprintf(w["run"], what, who)
	if ask {
		t += " " + w["runask"]
	}
	return t
}

// sendNoticeText — текст уведомления: who — имя ПК, what — имя файла ("" — «файл»), err — nil при успехе.
func sendNoticeText(lang, who, what string, err error) string {
	w, ok := sendNoticeWords[lang]
	if !ok {
		w = sendNoticeWords["en"]
	}
	if what == "" {
		what = w["files"]
	}
	if err == nil {
		return fmt.Sprintf(w["ok"], who, what)
	}
	why := "other"
	switch code := sendErrCode(err); {
	case code == "known" || code == "nokey" || code == "nocode" || errors.Is(err, agent.ErrRecvKnown):
		why = "known"
	case code == "offline":
		why = "offline"
	case code == "denied":
		why = "denied"
	case code == "cancel":
		why = "cancel"
	case code == "running":
		why = "running"
	case code == "busy" || code == "rate":
		why = "busy"
	}
	return fmt.Sprintf(w["fail"], who, w[why])
}

// sendTargetName — имя ПК id для уведомления: избранное, «Мои ПК» окна, иначе ID группами.
func sendTargetName(c *config, id string) string {
	for _, f := range c.favList() {
		if f["id"] == id && f["name"] != "" {
			return f["name"].(string)
		}
	}
	c.mu.Lock()
	mine := c.UI["mine"]
	c.mu.Unlock()
	if n := trayNames(mine)[id]; n != "" {
		return n
	}
	return strings.TrimSpace(trayGroup(id))
}
