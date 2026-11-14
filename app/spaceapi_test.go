//go:build linux || darwin

package main

// Этап «окна пространства», Ч2: API окна (spaceapi.go) и фоновая операция (spaceops.go) через handler — как окно.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"anypc/agent"
	"anypc/totp"
)

const apiAddr, apiTok = "127.0.0.1:5000", "tok123"

func apiHandler(c *config) func(name string, args ...any) (int, any, string) {
	h := handler(apiAddr, apiTok, nil, c, &agent.Agent{}, nil, func() map[string]any { return nil }, newFiles(c.path+".dl"), nil)
	return func(name string, args ...any) (int, any, string) {
		if args == nil {
			args = []any{}
		}
		b, _ := json.Marshal(args)
		r := httptest.NewRequest("POST", "/api/"+name, strings.NewReader(string(b)))
		r.Host = apiAddr
		r.Header.Set("X-Token", apiTok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out struct {
			Result any
			Error  string
		}
		json.NewDecoder(w.Result().Body).Decode(&out)
		return w.Code, out.Result, out.Error
	}
}

// opsReset — дождаться фоновых операций прошлых шагов и забыть итог.
func opsReset(t *testing.T) {
	t.Helper()
	spaceOps.wg.Wait()
	spaceOps.mu.Lock()
	spaceOps.cur = nil
	spaceOps.mu.Unlock()
	t.Cleanup(func() {
		spaceOps.wg.Wait()
		spaceOps.mu.Lock()
		spaceOps.cur = nil
		spaceOps.mu.Unlock()
	})
}

// opWait — spaceOp, пока состояние не станет state (≤ 10 с).
func opWait(t *testing.T, call func(string, ...any) (int, any, string), state string) map[string]any {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if _, r, _ := call("spaceOp"); r != nil && r.(map[string]any)["state"] == state {
			return r.(map[string]any)
		}
	}
	_, r, _ := call("spaceOp")
	t.Fatalf("операция не дошла до %s: %v", state, r)
	return nil
}

// TestSpaceAPIGate — каждое новое имя: без токена, с чужим токеном, с чужим Host, не POST — 403; с токеном —
// маршрут есть (не 404), ошибки — только space:<код>. Имена — в привязках страницы.
func TestSpaceAPIGate(t *testing.T) {
	opsReset(t)
	cfg := spaceCfg(t, spacePass, totp.NewSecret())
	page, err := shimmed("wss://example/ws", apiTok)
	if err != nil {
		t.Fatal(err)
	}
	h := handler(apiAddr, apiTok, page, cfg, &agent.Agent{}, nil, func() map[string]any { return nil }, newFiles(t.TempDir()), nil)
	names, _ := json.Marshal(spaceNames)
	if !strings.Contains(string(page), "'uiSet'].concat("+string(names)+")) window[n] = ") {
		t.Error("имён пространства нет в привязках страницы")
	}
	for _, n := range spaceNames {
		for _, c := range []struct{ method, host, token string }{
			{"POST", apiAddr, ""}, {"POST", apiAddr, "wrong"}, {"POST", "evil.example:5000", apiTok}, {"GET", apiAddr, apiTok},
		} {
			r := httptest.NewRequest(c.method, "/api/"+n, strings.NewReader("[]"))
			r.Host = c.host
			if c.token != "" {
				r.Header.Set("X-Token", c.token)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Errorf("%s %+v → %d, ждали 403", n, c, w.Code)
			}
		}
		r := httptest.NewRequest("POST", "/api/"+n, strings.NewReader("[]"))
		r.Host = apiAddr
		r.Header.Set("X-Token", apiTok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		b, _ := io.ReadAll(w.Result().Body)
		if w.Code == 404 || (w.Code == 400 && !strings.Contains(string(b), `"error":"space:`)) {
			t.Errorf("%s с токеном: %d %s", n, w.Code, b)
		}
	}
}

// TestSpaceErrCode — коды ошибок; неизвестная — other, текст ядра в окно не идёт.
func TestSpaceErrCode(t *testing.T) {
	for _, c := range []struct {
		err  error
		code string
	}{
		{spacePhraseOK(strings.Join(strings.Fields(spacePhraseNew())[:9], " ") + " zzzz"), "phrase_word:10"},
		{fmt.Errorf("%w: none", agent.ErrSpaceRefused), "refused"}, {agent.ErrSpaceAuth, "auth"}, {errSpaceSlow, "slow"},
		{errSpaceBusy, "busy"}, {errSpaceChange, "change"}, {errNoLockDetector, "nolock"}, {context.Canceled, "cancel"}, {errSpaceHostID, "id"},
		{fmt.Errorf("пространство: нет ответа вовремя (%w)", context.DeadlineExceeded), "timeout"}, // agent/space.go
		{errors.New("тайна ядра"), "other"},
	} {
		if got := spaceErrCode(c.err); got != c.code {
			t.Errorf("%v → %s, ждали %s", c.err, got, c.code)
		}
	}
	if _, err := spaceCall(spaceCfg(t, spacePass, totp.NewSecret()), "spaceCreateOK", []json.RawMessage{[]byte(`"x"`)}); err == nil || err.Error() != "space:draft" {
		t.Errorf("spaceCreateOK без черновика: %v", err)
	}
	if g := previewJSON(spacePreview{Gone: []string{"ab12"}})["gone"].([]string); len(g) != 1 || g[0] != "ab12" {
		t.Errorf("превью: gone %v", g)
	}
	var logs syncLog // неизвестная ошибка: окну — только код, текст — в журнал
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	if _, err := spaceCall(spaceCfg(t, spacePass, totp.NewSecret()), "нет-такого", nil); err == nil || err.Error() != "space:other" ||
		!strings.Contains(logs.String(), "неизвестный вызов") {
		t.Errorf("неизвестная ошибка: %v; журнал %q", err, logs.String())
	}
	if r := rowJSON("200000001", "refused", errors.New("тайна строки")); r["err"] != "other" || !strings.Contains(logs.String(), "тайна строки") {
		t.Errorf("строка итога: %v; журнал %q", r, logs.String())
	}
}

// TestSpaceOpOtherLogged — ошибка other фоновой операции: окну — код, текст — в журнал; испорченное пространство —
// damaged и у сверки.
func TestSpaceOpOtherLogged(t *testing.T) {
	opsReset(t)
	var logs syncLog
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	n := spaceCfg(t, spacePass, totp.NewSecret())
	host := spaceCfg(t, spacePass, totp.NewSecret()).id()
	call := apiHandler(n)
	withSpaceNet(t, func(context.Context, agent.SpaceDial) ([]byte, error) { return nil, errors.New("тайна обмена") })
	call("spaceEnter", host, spacePass, "123456", spacePhraseNew())
	if op := opWait(t, call, "err"); op["err"] != "other" || !strings.Contains(logs.String(), "тайна обмена") {
		t.Errorf("итог %v; журнал %q", op, logs.String())
	}
	n.mu.Lock()
	n.Space = []byte("мусор")
	n.save()
	n.mu.Unlock()
	call("spaceSync")
	if op := opWait(t, call, "err"); op["err"] != "damaged" {
		t.Errorf("сверка испорченного: %v", op)
	}
}

// TestSpaceOpZombie — превью после конца операции (обмен оборвался, пока Sign шёл к превью) её не воскрешает:
// состояние err, подтверждать нечего (регрессия приёмки Ч2, B1).
func TestSpaceOpZombie(t *testing.T) {
	opsReset(t)
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	call := apiHandler(n)
	signed := make(chan struct{})
	withSpaceNet(t, func(_ context.Context, d agent.SpaceDial) ([]byte, error) {
		salt, _, _ := p.secret("")
		ms := p.spaceGet(salt)
		go func() { d.Sign(ms[0], cfgPub(p), ms[1:]...); close(signed) }() // Sign — в своей горутине, как agent
		return nil, fmt.Errorf("%w: разрыв", agent.ErrSpaceRefused)
	})
	if code, _, e := call("spaceEnter", p.id(), spacePass, spaceCode(p, sec), ph); code != 200 {
		t.Fatal(e)
	}
	spaceOps.wg.Wait()
	within(t, "Sign", signed)
	_, r, _ := call("spaceOp")
	if op := r.(map[string]any); op["state"] != "err" || op["preview"] != nil {
		t.Errorf("после конца: %v", op)
	}
	if _, _, e := call("spaceConfirm", true); e != "space:noop" {
		t.Errorf("подтверждение кончившейся операции: %q", e)
	}
	if op := spaceOps.snap(false); op["state"] != "err" {
		t.Errorf("кончившаяся операция «идёт»: %v", op)
	}
}

// TestSpaceLeaveHolds — выход занимает операцию, пока идёт: «Работаю тут» и создание в это время — busy (регрессия
// приёмки Ч2, M1).
func TestSpaceLeaveHolds(t *testing.T) {
	opsReset(t)
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	withSpaceNet(t, spaceNet(p, nil))
	if _, err := n.spaceEnter(context.Background(), p.id(), spacePass, spaceCode(p, sec), ph); err != nil {
		t.Fatal(err)
	}
	in, release := make(chan struct{}), make(chan struct{})
	oldOff, oldCfg := passOffFn, passes.cfg
	passOffFn = func(context.Context, agent.PassDial) error { close(in); <-release; return nil } // выход снимает пропуск
	passes.cfg = n
	passes.mu.Lock()
	passes.issued = map[string]passIssued{p.id(): {cfgPub(p), time.Now(), []byte("pid")}}
	passes.mu.Unlock()
	t.Cleanup(func() { passOffFn, passes.cfg = oldOff, oldCfg })
	call := apiHandler(n)
	leave := make(chan string, 1)
	go func() { _, _, e := call("spaceLeave", spacePass, spaceCode(n, sec)); leave <- e }()
	within(t, "«снять» при выходе", in)
	for _, x := range [][]any{{"workHere", spacePass, "123456"}, {"spaceCreate", spacePass}, {"spaceCreateOK", ph}, {"spaceOpClear"}} {
		if _, _, e := call(x[0].(string), x[1:]...); e != "space:busy" {
			t.Errorf("%v во время выхода: %q", x[0], e)
		}
	}
	close(release)
	if e := within(t, "выход", leave); e != "" {
		t.Fatal(e)
	}
	if _, r, _ := call("spaceOp"); r != nil {
		t.Errorf("след выхода: %v", r)
	}
}

// TestSpaceAPIFlow — create → enter (отказ, затем подтверждение) → «Работаю тут» → «снять» → exclude (QR нового
// кода) → leave через API на подменах сети; hostInfo без секретов на каждом шаге.
func TestSpaceAPIFlow(t *testing.T) {
	opsReset(t)
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	n := spaceCfg(t, "n-local-pass", totp.NewSecret())
	callP, callN := apiHandler(p), apiHandler(n)
	var phrases []string
	noSecrets := func(c *config, what string) {
		t.Helper()
		j, _ := json.Marshal(hostInfo(c, &agent.Agent{}, true, "", ""))
		s := string(j)
		c.mu.Lock()
		m := c.spaceLocked()
		c.mu.Unlock()
		bad := append([]string{sec, strings.ToLower(sec)}, phrases...)
		if m != nil {
			for _, b := range [][]byte{m.PHash, m.PSalt, m.OSalt} {
				bad = append(bad, base64.StdEncoding.EncodeToString(b), hex.EncodeToString(b))
			}
			bad = append(bad, m.TOTP)
		}
		for _, x := range bad {
			if strings.Contains(s, x) {
				t.Errorf("%s: в hostInfo секрет %q", what, x)
			}
		}
		if !strings.Contains(s, `"space":{`) {
			t.Errorf("%s: нет hostInfo.space", what)
		}
	}

	code, res, e := callP("spaceCreate", spacePass)
	if code != 200 {
		t.Fatalf("spaceCreate: %d %s", code, e)
	}
	ph := res.(map[string]any)["phrase"].(string)
	phrases = append(phrases, ph)
	noSecrets(p, "черновик")
	if _, _, e := callP("spaceCreateOK", spacePhraseNew()); e != "space:phrase" { // опечатка во фразе черновика
		t.Errorf("чужая фраза: %q", e)
	}
	if code, _, e := callP("spaceCreateOK", ph); code != 200 {
		t.Fatalf("spaceCreateOK: %s", e)
	}
	noSecrets(p, "создано")

	withSpaceNet(t, spaceNet(p, nil))
	if _, _, e := callN("spaceConfirm", true); e != "space:noop" {
		t.Errorf("spaceConfirm без операции: %q", e)
	}
	if code, _, e := callN("spaceEnter", p.id(), spacePass, spaceCode(p, sec), ph); code != 200 {
		t.Fatalf("spaceEnter: %s", e)
	}
	opWait(t, callN, "confirm")
	callN("spaceConfirm", false)
	if op := opWait(t, callN, "err"); op["err"] != "no" || spaceOf(n) != nil {
		t.Fatalf("отказ: %v", op)
	}
	callN("spaceEnter", p.id(), spacePass, spaceCode(p, sec), ph)
	op := opWait(t, callN, "confirm")
	pv := op["preview"].(map[string]any)
	if g, ok := pv["gone"].([]any); !ok || len(g) != 0 { // исключённых ещё нет
		t.Errorf("превью: gone %v", pv["gone"])
	}
	if pcs := pv["members"].([]any); len(pcs) != 1 || pcs[0].(map[string]any)["id"] != p.id() || pv["password"] != true {
		t.Errorf("превью: %v", pv)
	}
	if code, _, e := callN("spaceConfirm", true); code != 200 {
		t.Fatal(e)
	}
	op = opWait(t, callN, "done")
	if r := op["result"].(map[string]any); r["fresh"] != true || r["code"] != true || op["kind"] != "enter" {
		t.Errorf("итог вступления: %v", op)
	}
	noSecrets(n, "вступил")
	in := spaceInfo(p)
	if pcs := in["members"].([]map[string]any); in["in"] != true || len(pcs) != 2 {
		t.Fatalf("состав P: %v", in)
	}

	// «Работаю тут» на P, «снять»
	oldOpen, oldOff, oldCfg := passOpenFn, passOffFn, passes.cfg
	var offs sync.WaitGroup
	offs.Add(1)
	passOpenFn = func(_ context.Context, d agent.PassDial) ([]byte, error) { return []byte("pid"), nil }
	passOffFn = func(context.Context, agent.PassDial) error { offs.Done(); return nil }
	passes.cfg = p
	passes.lockAlive("тест", true)
	t.Cleanup(func() { passOpenFn, passOffFn, passes.cfg = oldOpen, oldOff, oldCfg; passes.lockAlive("тест", false) })
	if code, _, e := callP("workHere", spacePass, "000000x"); code != 200 {
		t.Fatal(e)
	}
	if op := opWait(t, callP, "err"); op["err"] != "code" {
		t.Errorf("неверный код: %v", op)
	}
	c, _ := totp.Code(sec, time.Now())
	callP("workHere", spacePass, c)
	op = opWait(t, callP, "done")
	if rs := op["result"].([]any); len(rs) != 1 || rs[0].(map[string]any)["id"] != n.id() || rs[0].(map[string]any)["state"] != "ok" {
		t.Errorf("итог «Работаю тут»: %v", op)
	}
	until := func() float64 {
		for _, x := range spaceInfo(p)["members"].([]map[string]any) {
			if x["id"] == n.id() {
				return float64(x["passUntil"].(int64))
			}
		}
		return -1
	}
	if u := until(); u < float64(time.Now().Add(agent.PassTTL-time.Minute).UnixMilli()) {
		t.Errorf("passUntil %v", u)
	}
	callP("passOff")
	offs.Wait()
	if u := until(); u != 0 {
		t.Errorf("после «снять» passUntil %v", u)
	}

	// исключить N с P: новый код — QR только в итоге spaceOp, не в hostInfo
	ctx, cancel := context.WithCancel(context.Background())
	p.syn = &spaceSyncer{cfg: p, ctx: ctx}
	t.Cleanup(func() { cancel(); p.syn.bg.Wait() })
	oldSync := spaceSyncFn
	spaceSyncFn = func(context.Context, agent.SyncDial) ([]byte, error) { return nil, agent.ErrSpaceOffline }
	t.Cleanup(func() { spaceSyncFn = oldSync })
	if _, _, e := callP("spaceExclude", ph, "не base64", "new-pass-123"); e != "space:nomember" {
		t.Errorf("ключ не base64: %q", e)
	}
	callP("spaceExclude", ph, base64.StdEncoding.EncodeToString(cfgPub(n)), "new-pass-123")
	op = opWait(t, callP, "done")
	r := op["result"].(map[string]any)
	m := spaceOf(p)
	if m == nil || m.TOTP == sec || len(m.Members) != 1 || len(m.Gone) != 1 {
		t.Fatalf("после исключения: %v", m)
	}
	qr, _ := r["qr"].(map[string]any)
	if qr == nil || !strings.Contains(qr["uri"].(string), m.TOTP) || !strings.HasPrefix(qr["svg"].(string), "<svg") {
		t.Error("QR нового кода не тот")
	}
	if rs, ok := r["results"].([]any); !ok || len(rs) != 0 { // исключённому не рассылается, других нет
		t.Errorf("итог рассылки: %v", r["results"])
	}
	noSecrets(p, "исключил")
	if in := spaceInfo(p); in["gone"] != 1 {
		t.Errorf("gone: %v", in["gone"])
	}
	if code, _, e := callP("spaceOpClear"); code != 200 { // «Готово» после QR — итога нет
		t.Fatal(e)
	}
	if _, r, _ := callP("spaceOp"); r != nil {
		t.Error("после spaceOpClear итог остался") // итог с QR — не в журнал теста
	}
	callP("spaceLogin", ph, "", false)
	if op := opWait(t, callP, "err"); op["err"] != "nochange" {
		t.Errorf("правка без изменений: %v", op)
	}
	callP("spaceLogin", ph, "other-pass-12", false) // новый пароль, код прежний — QR нет
	if op := opWait(t, callP, "done"); op["result"].(map[string]any)["qr"] != nil {
		t.Error("QR без смены кода")
	}
	callP("spaceLogin", ph, "", true)
	if op := opWait(t, callP, "done"); op["result"].(map[string]any)["qr"] == nil {
		t.Errorf("новый код без QR: %v", op)
	}

	// N выходит (о своём исключении он не знает)
	if _, _, e := callN("spaceLeave", spacePass, "000000"); e != "space:code" {
		t.Errorf("выход с неверным кодом: %q", e)
	}
	if code, _, e := callN("spaceLeave", spacePass, spaceCode(n, sec)); code != 200 {
		t.Fatal(e)
	}
	if in := spaceInfo(n); in["in"] != false {
		t.Errorf("после выхода: %v", in)
	}
}

// TestSpaceOpBusy — вторая операция при идущей — busy (и выход тоже); подтверждать нечего, пока операция не
// спрашивает; итог живёт 5 мин по часам операций, после — операции нет и новая стартует.
func TestSpaceOpBusy(t *testing.T) {
	opsReset(t)
	var mu sync.Mutex
	now := time.Now()
	oldNow := spaceOpNow
	spaceOpNow = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	t.Cleanup(func() { spaceOpNow = oldNow })
	step := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }

	n := spaceCfg(t, spacePass, totp.NewSecret())
	host := spaceCfg(t, spacePass, totp.NewSecret()).id()
	call := apiHandler(n)
	release := make(chan struct{})
	withSpaceNet(t, func(ctx context.Context, d agent.SpaceDial) ([]byte, error) { <-release; return nil, agent.ErrSpaceOffline })
	if code, _, e := call("spaceEnter", host, spacePass, "123456", spacePhraseNew()); code != 200 {
		t.Fatal(e)
	}
	for _, x := range [][]any{{"spaceSync"}, {"spaceEnter", host, spacePass, "123456", spacePhraseNew()}, {"spaceLogin", "x", "", true},
		{"spaceLeave", spacePass, "123456"}, {"spaceCreate", spacePass}, {"spaceCreateOK", "x"}, {"spaceOpClear"}} {
		if _, _, e := call(x[0].(string), x[1:]...); e != "space:busy" {
			t.Errorf("%v во время операции: %q", x[0], e)
		}
	}
	if _, _, e := call("spaceConfirm", true); e != "space:noop" {
		t.Errorf("подтверждение без вопроса: %q", e)
	}
	if op := spaceOps.snap(false); op["state"] != "run" || op["kind"] != "enter" {
		t.Errorf("hostInfo.op: %v", op)
	}
	close(release)
	if op := opWait(t, call, "err"); op["err"] != "offline" {
		t.Errorf("итог: %v", op)
	}
	step(spaceOpKeep - time.Second)
	if _, r, _ := call("spaceOp"); r == nil {
		t.Error("итог пропал раньше 5 мин")
	}
	step(2 * time.Second)
	if _, r, _ := call("spaceOp"); r != nil {
		t.Errorf("итог живёт дольше 5 мин: %v", r)
	}
	if code, _, e := call("spaceSync"); code != 200 {
		t.Errorf("новая операция после итога: %s", e)
	}
	if op := opWait(t, call, "err"); op["err"] != "notin" {
		t.Errorf("сверка вне пространства: %v", op)
	}
}

