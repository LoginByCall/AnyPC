package main

// Этап «окна пространства», Ч2: API окна для пространства (UI-REDESIGN.md, «API»). Одни и те же имена (spaceNames) —
// в api() (Linux, Мак: POST /api/<имя> с X-Token) и в w.Bind (Windows). Долгие операции — в фоне (spaceops.go).
// Ошибки окну — только коды space:<код> (spaceErrCode), текст ядра в окно не идёт. В hostInfo.space нет секретов
// (TOTP, соль и хэш пароля, osalt, фраза); QR кода — только после системной авторизации в мастере создания
// и в итоге правки фразой (spaceOp).
// ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (CLAUDE.md A13: вход и ключевой материал).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/url"
	"slices"
	"strconv"

	"anypc/agent"
	"anypc/pake"
	"anypc/totp"
)

var spaceNames = []string{"spaceCreate", "spaceCreateOK", "spaceCreateNo", "spaceEnter", "spaceOp", "spaceConfirm",
	"spaceOpClear", "spaceCancel", "workHere", "passOff", "spaceExclude", "spaceLogin", "spaceLeave", "spaceSync", "spaceSign"}

// spaceCodes — ошибка ядра → код окна (первое совпадение по errors.Is). change — настройки или показанное в превью
// сменились до применения: повторить.
var spaceCodes = []struct {
	err  error
	code string
}{
	{errSpaceBusy, "busy"}, {errSpaceNoOp, "noop"}, {errSpaceDamaged, "damaged"}, {errSpaceCompromised, "compromised"},
	{errSpaceHeads, "over"}, {errSpacePhraseCount, "phrase_count"}, {errSpacePhraseASCII, "phrase_ascii"},
	{errSpacePhraseLogin, "phrase_login"}, {errSpacePhrase, "phrase"}, {errSpacePassword, "password"}, {errPassCode, "code"},
	{errPassShort, "short"},
	{agent.ErrSpaceJoinLocked, "joinlocked"}, {agent.ErrSpaceSlowHere, "late"}, {agent.ErrSpaceViewOnlyThere, "viewonly"}, // Ч12б, круг 3
	{agent.ErrSpaceNeedPass, "needpw"}, {agent.ErrSpaceBadCode, "badcode"}, {agent.ErrSpaceBadPhrase, "badphrase"}, // Ч12б: до auth
	{agent.ErrSpaceDeclined, "declined"}, {agent.ErrSpaceNoAnswer, "noanswer"}, {agent.ErrSpaceNoWindow, "nowin"}, {agent.ErrSpaceLater, "later"}, // Ч12б: до refused
	{agent.ErrSpaceNotThere, "nospace"}, {agent.ErrSpaceWaitThere, "waitthere"},
	{agent.ErrSpaceBusyThere, "busythere"}, {agent.ErrSpaceLockedThere, "lockedthere"}, {agent.ErrSpaceNoPassThere, "nopassthere"}, // до auth и refused
	{agent.ErrSpaceAuth, "auth"}, {agent.ErrSpaceOffline, "offline"},
	{agent.ErrSpaceNoUDP, "noudp"}, {agent.ErrSpaceNoLink, "nolink"}, {agent.ErrSpaceClosed, "closed"}, {agent.ErrSpaceOld, "old"},
	{agent.ErrSpaceAsk, "ask"}, {agent.ErrSpaceHostKey, "hostkey"}, {agent.ErrSpaceIDKey, "badid"}, {agent.ErrSpaceSkew, "clock"},
	{agent.ErrPassNone, "nopass"}, {agent.ErrSpaceRefused, "refused"}, {errNoLockDetector, "nolock"}, {errSpaceNo, "no"},
	{errSpaceSlow, "slow"}, {errSpaceDraft, "draft"}, {errSpaceLogin, "login"}, {errSpaceVia, "via"}, {errSpaceIn, "in"},
	{errSpaceNotIn, "notin"}, {errSpaceChange, "change"}, {errSpaceSelf, "self"}, {errSpaceNoMember, "nomember"},
	{errSpaceLast, "last"}, {errSpaceNoChange, "nochange"}, {errSpaceForeign, "foreign"}, {errSpaceHostID, "id"},
	{errSpaceSDP, "sdp"},
	{context.Canceled, "cancel"}, {context.DeadlineExceeded, "timeout"},
}

// spaceErrCode — код ошибки для окна; слово фразы не из словаря — phrase_word:N (N с 1); отказ окна «Пустить?» с
// паузой — <код>:N (N — секунд до нового окна, Ч12б); неизвестная — other.
func spaceErrCode(err error) string {
	var w spacePhraseWordError
	if errors.As(err, &w) {
		return "phrase_word:" + strconv.Itoa(w.N)
	}
	var sw agent.SpaceWaitError
	wait := ""
	if errors.As(err, &sw) && sw.Secs > 0 {
		wait = ":" + strconv.Itoa(sw.Secs)
	}
	for _, x := range spaceCodes {
		if errors.Is(err, x.err) {
			return x.code + wait
		}
	}
	return "other"
}

// spaceAuthNames — вызовы, изменяющие доступ или состав пространства: требуется системная авторизация.
var spaceAuthNames = []string{"spaceCreate", "spaceCreateOK", "spaceEnter", "spaceConfirm", "spaceOp", "spaceExclude", "spaceLogin", "spaceLeave", "passOff"}

// spaceCall — вызов окна name (из spaceNames) с аргументами JSON; ошибка — только space:<код>.
func spaceCall(c *config, name string, args []json.RawMessage) (any, error) {
	if slices.Contains(spaceAuthNames, name) {
		if err := systemAuth(); err != nil {
			return nil, err
		}
	}
	str := func(i int) (s string) {
		if i < len(args) {
			json.Unmarshal(args[i], &s)
		}
		return
	}
	flag := func(i int) (b bool) {
		if i < len(args) {
			json.Unmarshal(args[i], &b)
		}
		return
	}
	res, err := spaceDo(c, name, str, flag)
	if err != nil {
		code := spaceErrCode(err)
		if code == "other" { // текст — в журнал (ошибки ядра секретов не содержат), окну — только код
			log.Printf("пространство: %s: %v", name, err)
		}
		return nil, errors.New("space:" + code)
	}
	return res, nil
}

func spaceDo(c *config, name string, str func(int) string, flag func(int) bool) (any, error) {
	switch name {
	case "spaceCreate": // после системной авторизации: создать и сохранить фразу в файл
		var path string
		err := spaceOps.hold("create", func() (err error) { path, err = c.spaceCreateFile(); return })
		if err != nil {
			return nil, err
		}
		return map[string]string{"path": path}, nil
	case "spaceCreateOK":
		err := spaceOps.hold("create", func() error { return c.spaceCreateOK(str(0)) })
		if errors.Is(err, errSpaceForeign) { // у черновика ключ из этой же фразы: не совпал — опечатка, не чужое пространство
			err = errSpacePhrase
		}
		return nil, err
	case "spaceCreateNo":
		c.spaceCreateNo()
		return nil, nil
	case "spaceEnter":
		id, pw, code, ph := str(0), str(1), str(2), str(3)
		return nil, spaceOps.start("enter", func(ctx context.Context, preview func(spacePreview), ok <-chan bool) (any, error) {
			ch, err := c.spaceEnterAsk(ctx, id, pw, code, ph, preview, ok)
			if err != nil {
				return nil, err
			}
			return changesJSON(ch), nil
		})
	case "spaceOp":
		return spaceOps.snap(true), nil
	case "spaceConfirm":
		return nil, spaceOps.confirm(flag(0))
	case "spaceOpClear":
		return nil, spaceOps.clear()
	case "spaceCancel":
		return nil, spaceOps.stop()
	case "workHere":
		if passes.cfg != c {
			return nil, errSpaceNotIn
		}
		return nil, spaceOps.start("workHere", func(ctx context.Context, _ func(spacePreview), _ <-chan bool) (any, error) {
			rs, err := passes.workHere(ctx, "", "")
			if err != nil {
				return nil, err
			}
			out := []map[string]string{}
			for _, r := range rs {
				out = append(out, rowJSON(r.ID, r.State, r.Err))
			}
			return out, nil
		})
	case "passOff": // «снять» — в фоне: первые попытки идут по сети, повторы и так фоновые
		if passes.cfg == c {
			go passes.offAll(context.Background())
		}
		return nil, nil
	case "spaceExclude":
		pub, err := base64.StdEncoding.DecodeString(str(1))
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, errSpaceNoMember
		}
		ph, pw := str(0), str(2)
		return nil, spaceOps.start("exclude", func(ctx context.Context, _ func(spacePreview), _ <-chan bool) (any, error) {
			return spaceEditJSON(c, func(s *spaceSyncer) ([]spaceResult, error) { return s.spaceExclude(ctx, ph, pub, pw) })
		})
	case "spaceLogin":
		ph, pw, code := str(0), str(1), flag(2)
		return nil, spaceOps.start("login", func(ctx context.Context, _ func(spacePreview), _ <-chan bool) (any, error) {
			return spaceEditJSON(c, func(s *spaceSyncer) ([]spaceResult, error) { return s.spaceChangeLogin(ctx, ph, pw, code) })
		})
	case "spaceLeave":
		err := spaceOps.hold("leave", func() error { return c.spaceLeave(str(0), str(1)) })
		if err == nil { // вне пространства итог прежней операции (QR нового кода) больше не читается
			spaceOps.clear()
		}
		return nil, err
	case "spaceSign":
		return spaceSign(c, str(0), str(1), str(2))
	case "spaceSync":
		return nil, spaceOps.start("sync", func(ctx context.Context, _ func(spacePreview), _ <-chan bool) (any, error) {
			if c.spaceDamaged() {
				return nil, errSpaceDamaged
			}
			if c.spaceOthers() == nil {
				return nil, errSpaceNotIn
			}
			return syncRows(spaceSyncerOf(c).spread(ctx, false)), nil
		})
	}
	return nil, errors.New("неизвестный вызов")
}

var errSpaceSDP = errors.New("пространство: в SDP нет DTLS-отпечатка")

// spaceSign — вход «b» по пропуску из окна (Ч4): подпись ключом этого хоста над DTLS-отпечатками сессии окна с целью
// id (localSDP — окна, remoteSDP — цели), как signB мастера (agent/space.go) и как цель её проверяет (pake.ClientVerify
// в "b" с key и pass, agent/agent.go). Подпись привязана к этой сессии: в другой отпечатки другие. Только цели — члену M
// (не себе) с живым пропуском (passUntil): без пропуска подпись ключом хоста окну не нужна. Окну — {pub, sig}, seed не
// уходит. ТРЕБУЕТ РЕВЬЮ ЧЕЛОВЕКОМ (A13: ключ хоста подписывает по просьбе окна).
func spaceSign(c *config, id, localSDP, remoteSDP string) (any, error) {
	c.mu.Lock()
	c.reload()
	m, key, bad := c.spaceLocked(), ed25519.PrivateKey(bytes.Clone(c.Key)), c.spaceDamagedLocked()
	c.mu.Unlock()
	defer clear(key)
	if bad {
		return nil, errSpaceDamaged
	}
	self := key.Public().(ed25519.PublicKey)
	if m == nil || !m.member(self) {
		return nil, errSpaceNotIn
	}
	var pub ed25519.PublicKey
	for _, x := range m.Members {
		if x.ID == id && !bytes.Equal(x.Pub, self) {
			pub = x.Pub
		}
	}
	if pub == nil {
		return nil, errSpaceNoMember
	}
	if passes.until(id, pub) == 0 {
		return nil, agent.ErrPassNone
	}
	if pake.Fingerprint(localSDP) == "" || pake.Fingerprint(remoteSDP) == "" {
		return nil, errSpaceSDP
	}
	k, err := pake.ClientSignB64(base64.StdEncoding.EncodeToString(key.Seed()), id, localSDP, remoteSDP)
	if err != nil {
		return nil, err
	}
	return map[string]string{"pub": k["pub"], "sig": k["sig"]}, nil
}

// spaceSyncerOf — рассыльщик процесса (startSpaceSync); без него (тест, CLI) — без фоновых повторов.
func spaceSyncerOf(c *config) *spaceSyncer {
	if c.syn != nil {
		return c.syn
	}
	return &spaceSyncer{cfg: c}
}

// spaceEditJSON — правка фразой: {results, qr}; qr ({uri, svg}) — только если секрет кода сменился.
func spaceEditJSON(c *config, f func(s *spaceSyncer) ([]spaceResult, error)) (any, error) {
	before := spaceTOTP(c)
	rs, err := f(spaceSyncerOf(c))
	if err != nil {
		return nil, err
	}
	out := map[string]any{"results": syncRows(rs)}
	if sec := spaceTOTP(c); sec != "" && sec != before {
		u := totp.URI(url.PathEscape("AnyPC пространство"), sec)
		svg, err := totp.SVG(u)
		if err != nil {
			return nil, err
		}
		out["qr"] = map[string]string{"uri": u, "svg": svg}
	}
	return out, nil
}

func spaceTOTP(c *config) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reload()
	if m := c.spaceLocked(); m != nil {
		return m.TOTP
	}
	return ""
}

func syncRows(rs []spaceResult) []map[string]string {
	out := []map[string]string{}
	for _, r := range rs {
		out = append(out, rowJSON(r.ID, r.State, r.Err))
	}
	return out
}

func rowJSON(id, state string, err error) map[string]string {
	m := map[string]string{"id": id, "state": state}
	if err != nil {
		if m["err"] = spaceErrCode(err); m["err"] == "other" {
			log.Printf("пространство: %s: %v", id, err)
		}
	}
	return m
}

func changesJSON(s spaceChanges) map[string]any {
	return map[string]any{"password": s.Password, "code": s.TOTP, "trusted": s.Trusted, "keyLogin": s.KeyLogin,
		"ask": s.Ask, "already": s.Already, "fresh": s.Fresh}
}

func previewJSON(p spacePreview) map[string]any {
	m := changesJSON(p.spaceChanges)
	pcs := []map[string]string{}
	for _, x := range p.Members {
		pcs = append(pcs, map[string]string{"id": x.ID, "fp": x.FP})
	}
	m["members"] = pcs
	m["gone"] = append([]string{}, p.Gone...) // отпечатки исключённых
	delete(m, "fresh")                        // до сверки — всегда false
	return m
}

// until — до какого времени (мс Unix) пропуск на цели id с ключом pub может жить; 0 — нет.
func (p *passMaster) until(id string, pub ed25519.PublicKey) int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if t, ok := p.issued[id]; ok && bytes.Equal(t.pub, pub) && t.live() {
		return t.at.Add(agent.PassTTL).UnixMilli()
	}
	return 0
}

// spaceInfo — hostInfo.space: состояние пространства без секретов. wait — ID поручителя до сверки; clock — ID
// членов с расходящимися часами; ask — режим «Спрашивать»; lock — детектор блокировки жив; op — вид и состояние
// операции (итог — только spaceOp).
func spaceInfo(c *config) map[string]any {
	c.mu.Lock()
	c.reload()
	m := c.spaceLocked()
	self := ed25519.PrivateKey(c.Key).Public().(ed25519.PublicKey)
	out := map[string]any{"in": len(c.Space) > 0, "damaged": c.spaceDamagedLocked(), "over": c.SpaceOver != "",
		"pend": len(c.SpacePend), "wait": c.SpaceWait, "clock": append([]string{}, c.SpaceClock...), "ask": !c.spaceAllowedLocked()}
	c.mu.Unlock()
	pcs, gone, bad := []map[string]any{}, 0, false
	if m != nil {
		gone, bad = len(m.Gone), m.Compromised
		for _, x := range m.Members {
			pcs = append(pcs, map[string]any{"id": x.ID, "fp": pake.KeyFingerprint(x.Pub), "pub": base64.StdEncoding.EncodeToString(x.Pub),
				"self": bytes.Equal(x.Pub, self), "passUntil": passes.until(x.ID, x.Pub)})
		}
	}
	out["members"], out["gone"], out["compromised"] = pcs, gone, bad
	out["lock"] = passes.detector()
	out["op"] = spaceOps.snap(false)
	return out
}
