package agent

// Ч12б — вступление нового ПК в пространство через поручителя (решения владельца B и A', TZ.md §16):
// «ПК в пространстве, через который идёт вступление (поручитель, ID введён на новом ПК), показывает «Пустить ПК …
// в пространство?» (ID, имя, отпечаток ключа) и ждёт «Разрешить» до 2 мин; нет ответа или «Отклонить» — отказ.»
// «A' (без пароля): новый ПК вводит ID поручителя, код из приложения и фразу; доказывает фразу подписью ключом из
// фразы над отпечатками DTLS этого соединения (отдельный домен) + код; окно «Разрешить» у поручителя — только после
// верных фразы и кода; поручитель ≤ v0.3.1 — запасной путь с паролем.»
// ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (CLAUDE.md A13: вход без пароля, ключ владельца, протокол).
//
// Протокол — только добавления (канал "auth"; хост объявляет join:true в первом "a", старый хост поля не шлёт):
//
//	клиент → {"t":"b","join":true,cpub,csig,from,name}  ключ клиента доказан (clientMsg), ID и имя — заявленные
//	хост   → {"t":"otp","join":true,pub,sig}            ключ хоста (identityMsg): код — только этому хосту
//	клиент → {"t":"otp",code}                           код TOTP записи по умолчанию (один на сессию)
//	хост   → {"t":"join",salt:osalt}                    код верный, хост — ПК пространства: соль ключа владельца
//	клиент → {"t":"join",sig}                           pake.SpaceJoinSign(ключ из фразы и osalt, это соединение, cpub)
//	хост   → {"t":"admit"}                              фраза верна — окно «Пустить?» открыто (до AdmitTimeout)
//	хост   → {"t":"ok","join":true,pub,sig}             «Разрешить»: сессия вступления (только ctl "sp", без экрана)
//
// Отказы: "fail" why code|phrase (неудача входа: счёт как у пароля, REQ-S-04/S-22, окна нет); "denied" why no
// («Отклонить») | timeout (нет ответа) | wait (LoginShut, решение 12 A); "later" — окно этому ID или ключу уже
// показывали меньше admitEvery назад; "nojoin" why none|ask|rights — хост сейчас не пускает в пространство;
// "locked", "busy" — как у входа. Вход паролем (клиенты ≤ v0.3.1): то же окно до выдачи состава (spaceCtl).

import (
	"crypto/ed25519"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"anypc/pake"
)

// AdmitTimeout — окно «Пустить ПК в пространство?» ждёт ответа (решение B: «до 2 мин»).
const AdmitTimeout = 2 * time.Minute

// admitWait — срок окна для разбора «нет ответа» и для клиента; admitEvery — после отказа тому же ID или ключу окно
// не раньше; joinLive — сессия вступления после «Разрешить» (состав и «Это все ваши ПК?» на новом ПК); proofWait —
// доказательство фразы после соли (Argon2 на клиенте). Переменные — для тестов.
var (
	admitWait  = AdmitTimeout
	admitEvery = 30 * time.Second
	joinLive   = 4 * time.Minute
	proofWait  = 30 * time.Second
)

// joinBadHostSig — испытательная подмена (admit_test.go): хост подписывает "otp" вступления не над этим соединением.
var joinBadHostSig atomic.Bool

// AdmitReq — что показать в окне «Пустить ПК в пространство?»: ID и имя — заявленные новым ПК (rxClaim; ID "" —
// не сообщил: вход паролем, AnyPC ≤ v0.3.1), FP — отпечаток его ключа (pake.KeyFingerprint), доказанного в "b".
type AdmitReq struct{ ID, Name, FP string }

// joinOn — хост пускает в пространство без пароля (объявляет join в "a").
func (a *Agent) joinOn() bool { return a.SpaceOwner != nil && a.SpaceAdmit != nil && !a.noJoin }

// admitWho — для журнала: ID и начало отпечатка (имя — строка клиента, в журнал не идёт).
func admitWho(q AdmitReq) string {
	fp := q.FP
	if len(fp) > 9 {
		fp = fp[:9]
	}
	if q.ID == "" {
		return "ПК (ID не сообщён) с ключом " + fp
	}
	return "ПК " + q.ID + " с ключом " + fp
}

// admitAsk — окно «Пустить?» (решение B) на сессию s: ID или ключ pub получали отказ меньше admitEvery назад —
// "later" без окна; «Разрешить» — true; иначе "no" или "timeout" (окно ждало почти весь admitWait). Одно окно за
// раз: зовут только из сессии a.sess (вступление — после promote, вход паролем — уже вошедшая).
func (a *Agent) admitAsk(s *session, q AdmitReq, pub []byte) (bool, string) {
	keys := []string{"k" + string(pub)}
	if q.ID != "" {
		keys = append(keys, "i"+q.ID)
	}
	now := time.Now()
	a.mu.Lock()
	for k, t := range a.admitAt {
		if now.Sub(t) >= admitEvery {
			delete(a.admitAt, k)
		}
	}
	for _, k := range keys {
		if _, ok := a.admitAt[k]; ok {
			a.mu.Unlock()
			log.Printf("сессия %s: %s — окно «Пустить?» уже было меньше %v назад, отказ без окна", s.label(), admitWho(q), admitEvery)
			return false, "later"
		}
	}
	a.mu.Unlock()
	log.Printf("сессия %s: %s просит вступить в пространство — окно «Пустить?»", s.label(), admitWho(q))
	t0 := time.Now()
	yes := a.SpaceAdmit(q)
	switch {
	case yes && !s.gone.Load():
		log.Printf("сессия %s: вступление разрешено на этом ПК", s.label())
		return true, ""
	case yes:
		return false, "no" // клиент ушёл, пока окно было открыто: отвечать некому
	}
	why := "no"
	if time.Since(t0) >= admitWait*95/100 {
		why = "timeout"
	}
	a.mu.Lock()
	if a.admitAt == nil {
		a.admitAt = map[string]time.Time{}
	}
	for _, k := range keys {
		a.admitAt[k] = time.Now()
	}
	a.mu.Unlock()
	log.Printf("сессия %s: вступление отклонено на этом ПК (%s)", s.label(), map[string]string{"no": "«Отклонить»", "timeout": "нет ответа"}[why])
	return false, why
}

// joinCode — код TOTP вступления записи user (под a.mu): лестницы кодов и паролей — те же, что у входа паролем и
// кодом для чужого (не закреплённого) ключа (authChannel, check). Неверный — неудача и в общий счёт. locked — вход
// заперт: код не проверялся.
func (a *Agent) joinCode(cid, user, code string) (ok, locked bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	lock := func() bool {
		now := time.Now()
		n := a.nameOf(user, false)
		return now.Before(a.otpLock) || n != nil && now.Before(n.otpUntil) || a.pwLocked(user, now)
	}
	if lock() {
		return false, true
	}
	if _, ok = a.OTP(user, code); ok {
		if n := a.names[user]; n != nil {
			n.otpFails = 0
		}
		return true, false
	}
	n := a.nameOf(user, true)
	lockStep(&n.otpFails, &n.otpUntil, 5)
	n.at = time.Now()
	hostStep(&a.otpFails, &a.otpLock, &a.otpAt)
	a.countAuth(cid, user, false)
	return false, false
}

// joinB — "b" вступления без пароля (решение A'). keyOK — ключ m.CPub доказан подписью над этим соединением;
// salt — соль записи user при входе; waitCode, waitProof — повесить обработчик следующего "otp" и "join" канала.
// Порядок: код (счёт неудач) → соль ключа владельца → доказательство фразы (счёт неудач) → promote → окно.
func (a *Agent) joinB(s *session, m authMsg, keyOK bool, user string, salt []byte, fpc, fph string, send func(authMsg),
	waitCode func(func(string)), waitProof func(func(authMsg))) {
	var step atomic.Int32 // 0 — ждём код, 1 — ждём доказательство, 2 — окно и дальше, 3 — отказ
	reject := func(t string, why ...string) {
		step.Store(3)
		send(authMsg{T: t, Why: strings.Join(why, "")})
		a.release(s)
		time.AfterFunc(500*time.Millisecond, func() { s.pc.Close() })
	}
	switch {
	case !a.joinOn() || user != "" || s.offOnly: // только запись по умолчанию (запись пространства)
		reject("nojoin", "none")
		return
	case !keyOK: // ключ нового члена M — только доказанный (им P сверит ключ в составе)
		reject("fail")
		return
	case a.LoginShut != nil && a.LoginShut(user): // решение 12 A: этот ПК сам ещё не сверен после вступления
		reject("denied", "wait")
		return
	}
	a.mu.Lock()
	locked := a.pwLocked(user, time.Now())
	a.mu.Unlock()
	if locked {
		reject("locked")
		return
	}
	id, name := rxClaim(m)
	cpub := ed25519.PublicKey(append([]byte(nil), m.CPub...))
	s.asking.Store(true) // общий таймер входа не закрывает: свои сроки на код, доказательство и окно
	waitCode(func(code string) {
		if !step.CompareAndSwap(0, 1) {
			return
		}
		ok, locked := a.joinCode(s.cid, user, code)
		switch {
		case locked:
			reject("locked")
			return
		case !ok:
			log.Printf("сессия %s: вступление — неверный код TOTP", s.cid)
			reject("fail", "code")
			return
		}
		osalt, opub, why := a.SpaceOwner(salt)
		if why == "" && a.ViewOnly != nil && a.ViewOnly() {
			why = "rights" // «Только показ экрана» — никаких правок через сессию (как spaceCtl)
		}
		if why != "" {
			reject("nojoin", why)
			return
		}
		waitProof(func(p authMsg) {
			if !step.CompareAndSwap(1, 2) {
				return
			}
			if !pake.SpaceJoinVerify(opub, p.Sig, a.ID, fpc, fph, cpub) {
				a.mu.Lock()
				a.countAuth(s.cid, user, false)
				a.mu.Unlock()
				log.Printf("сессия %s: вступление — фраза пространства не доказана", s.cid)
				reject("fail", "phrase")
				return
			}
			a.authResult(s.cid, user, true) // код и фраза верны — счёт имени сброшен, как после верного входа
			s.mu.Lock()
			s.cpub = cpub
			s.mu.Unlock()
			if !a.promote(s) { // одна сессия: идёт сеанс или другое вступление
				reject("busy")
				return
			}
			send(authMsg{T: "admit"})
			go func() {
				ok, why := a.admitAsk(s, AdmitReq{ID: id, Name: name, FP: pake.KeyFingerprint(cpub)}, cpub)
				if !ok {
					if why == "later" {
						reject("later")
					} else {
						reject("denied", why)
					}
					return
				}
				s.mu.Lock()
				s.joinID = id
				s.mu.Unlock()
				s.admitted.Store(true)
				s.spaceOK.Store(true) // ctl "sp": запрос состава и M с этим ПК
				s.joinIn.Store(true)
				s.asking.Store(false)
				send(authMsg{T: "ok", Join: true, Pub: a.Key.Public().(ed25519.PublicKey), Sig: pake.HostSign(a.Key, a.ID, fpc, fph)})
				time.AfterFunc(joinLive, func() { s.pc.Close() })
			}()
		})
		send(authMsg{T: "join", Salt: osalt})
		time.AfterFunc(proofWait, func() {
			if step.CompareAndSwap(1, 3) {
				reject("denied")
			}
		})
	})
	hsig := pake.HostSign(a.Key, a.ID, fpc, fph)
	if joinBadHostSig.Load() { // тест: подпись не над этим соединением — клиент кода не отдаёт
		hsig = pake.HostSign(a.Key, a.ID, fph, fpc)
	}
	send(authMsg{T: "otp", Join: true, Pub: a.Key.Public().(ed25519.PublicKey), Sig: hsig})
	time.AfterFunc(time.Duration(otpWait90.Load()), func() {
		if step.CompareAndSwap(0, 3) {
			log.Printf("сессия %s: вступление — код TOTP не введён", s.cid)
			reject("denied")
		}
	})
}

// admitAsks — окно «Пустить ПК в пространство?» (Ч12б): заголовок, вопрос (%s — имя), «без имени», ID (%s), ID не
// сообщён, ключ (%s), пояснение, срок, кнопки, задержка 3 с и 5 с, подсказка к системным «Да / Нет».
var admitAsks = map[string][13]string{
	"en": {"joining your space", "Let PC “%s” into your space?", "no name", "ID: %s", "ID not reported — that PC runs an old AnyPC", "Key: %s",
		"Press “Allow” only if you are adding this PC yourself right now (you entered this PC’s ID, the code and the space phrase on it). Not expecting it — press “Deny”: someone knows your phrase and code; set a new code with the phrase (“Anew”).",
		"No answer within 2 min — denied.", "Allow", "Deny", "“Allow” works 3 seconds after this window appears.", "“Allow” works 5 seconds after this window appears.", "“Yes” — allow, “No” — deny."},
	"ru": {"вступление в пространство", "Пустить ПК «%s» в ваше пространство?", "без имени", "ID: %s", "ID не сообщён — на том ПК старая версия AnyPC", "Ключ: %s",
		"Нажмите «Разрешить», только если вы сами сейчас добавляете этот ПК (ввели на нём ID этого ПК, код и фразу пространства). Не ожидали — «Отклонить»: кто-то знает вашу фразу и код; задайте новый код фразой («Заново»).",
		"Без ответа 2 мин — отказ.", "Разрешить", "Отклонить", "«Разрешить» срабатывает через 3 секунды после появления окна.", "«Разрешить» срабатывает через 5 секунд после появления окна.", "«Да» — разрешить, «Нет» — отклонить."},
	"zh": {"加入您的空间", "允许电脑“%s”加入您的空间吗？", "无名称", "ID：%s", "未报告 ID——那台电脑运行的是旧版 AnyPC", "密钥：%s",
		"只有当您本人正在添加这台电脑（在它上面输入了本机 ID、代码和空间短语）时才点击“允许”。如果没有预料到——点击“拒绝”：有人知道您的短语和代码；请用短语设置新代码（“重新生成”）。",
		"2 分钟内未响应将自动拒绝。", "允许", "拒绝", "“允许”在窗口出现 3 秒后才生效。", "“允许”在窗口出现 5 秒后才生效。", "“是”——允许，“否”——拒绝。"},
	"es": {"unirse a su espacio", "¿Dejar entrar el PC «%s» en su espacio?", "sin nombre", "ID: %s", "ID no comunicado: ese PC tiene una versión antigua de AnyPC", "Clave: %s",
		"Pulse «Permitir» solo si usted mismo está añadiendo este PC ahora (introdujo en él el ID de este PC, el código y la frase del espacio). Si no lo esperaba, pulse «Rechazar»: alguien conoce su frase y su código; defina un código nuevo con la frase («De nuevo»).",
		"Sin respuesta en 2 min — se rechaza.", "Permitir", "Rechazar", "«Permitir» funciona 3 segundos después de que aparezca esta ventana.", "«Permitir» funciona 5 segundos después de que aparezca esta ventana.", "«Sí»: permitir; «No»: rechazar."},
	"de": {"Beitritt zu Ihrem Bereich", "PC „%s“ in Ihren Bereich lassen?", "ohne Namen", "ID: %s", "ID nicht übermittelt – auf jenem PC läuft ein altes AnyPC", "Schlüssel: %s",
		"Drücken Sie „Erlauben“ nur, wenn Sie diesen PC gerade selbst hinzufügen (dort die ID dieses PCs, den Code und die Bereichsphrase eingegeben). Nicht erwartet – „Ablehnen“: jemand kennt Ihre Phrase und Ihren Code; legen Sie mit der Phrase einen neuen Code fest („Neu“).",
		"Ohne Antwort in 2 min — abgelehnt.", "Erlauben", "Ablehnen", "„Erlauben“ wirkt erst 3 Sekunden nach Erscheinen dieses Fensters.", "„Erlauben“ wirkt erst 5 Sekunden nach Erscheinen dieses Fensters.", "„Ja“ – erlauben, „Nein“ – ablehnen."},
	"fr": {"rejoindre votre espace", "Laisser le PC « %s » entrer dans votre espace ?", "sans nom", "ID : %s", "ID non communiqué — ce PC utilise une ancienne version d’AnyPC", "Clé : %s",
		"Appuyez sur « Autoriser » seulement si vous ajoutez ce PC vous-même en ce moment (vous y avez saisi l’ID de ce PC, le code et la phrase de l’espace). Vous ne vous y attendiez pas — « Refuser » : quelqu’un connaît votre phrase et votre code ; définissez un nouveau code avec la phrase (« À nouveau »).",
		"Sans réponse sous 2 min — refusé.", "Autoriser", "Refuser", "« Autoriser » ne fonctionne que 3 secondes après l’apparition de cette fenêtre.", "« Autoriser » ne fonctionne que 5 secondes après l’apparition de cette fenêtre.", "« Oui » : autoriser, « Non » : refuser."},
	"it": {"ingresso nel tuo spazio", "Far entrare il PC «%s» nel tuo spazio?", "senza nome", "ID: %s", "ID non comunicato: quel PC ha una versione vecchia di AnyPC", "Chiave: %s",
		"Premi «Consenti» solo se stai aggiungendo tu questo PC adesso (vi hai inserito l’ID di questo PC, il codice e la frase dello spazio). Non te lo aspettavi: premi «Rifiuta»; qualcuno conosce la tua frase e il tuo codice: imposta un nuovo codice con la frase («Di nuovo»).",
		"Senza risposta entro 2 min — rifiutata.", "Consenti", "Rifiuta", "«Consenti» funziona 3 secondi dopo la comparsa di questa finestra.", "«Consenti» funziona 5 secondi dopo la comparsa di questa finestra.", "«Sì»: consenti, «No»: rifiuta."},
}

func admitAsksOf(lang string) [13]string {
	if s, ok := admitAsks[lang]; ok {
		return s
	}
	return admitAsks["en"]
}

// admitText — окно «Пустить?»; loop — окно askLoop (задержка 5 с), иначе TaskDialog (3 с). Имя — уже очищенное
// rxClaim (без управляющих и форматных символов), ID — 9 цифр (hub.IsHostID) или "".
func admitText(lang string, q AdmitReq, loop bool) (title, text, yes, no, hint string) {
	s := admitAsksOf(lang)
	name := q.Name
	if name == "" {
		name = s[2]
	}
	id := fmt.Sprintf(s[3], groupID(q.ID))
	if q.ID == "" {
		id = s[4]
	}
	delay := s[10]
	if loop {
		delay = s[11]
	}
	return "AnyPC — " + s[0], fmt.Sprintf(s[1], name) + "\n\n" + id + "\n" + fmt.Sprintf(s[5], q.FP) + "\n\n" + s[6] + "\n\n" + s[7] + "\n" + delay, s[8], s[9], s[12]
}

// groupID — ID тройками, как на главном экране («142 226 863»).
func groupID(id string) string {
	if len(id) != 9 {
		return id
	}
	return id[:3] + " " + id[3:6] + " " + id[6:]
}
