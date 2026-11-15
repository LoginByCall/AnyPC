package agent

import (
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"anypc/hub"
	"anypc/totp"
	"anypc/ui"
)

// cdpConnect — экран «Другой ПК» по макету (Ч7) в окне программы (привязки подменены, CPace — pake.wasm): шаг 2 —
// только у ПК с TOTP, отправка на шестой цифре; ожидание «Разрешить» — отсчёт; шаг 3 «Это ваш компьютер?» поверх
// сессии после входа паролем: ПК пускает по ключу — «Добавить» = имя в `mine` и повторный вход с trust (новый код),
// дальше по ключу; не пускает — «Добавить» с галочкой «Запомнить пароль» (снята по умолчанию); «Не сейчас» — больше
// не спрашивать; не спрашивать у члена пространства и после кода разовой помощи.
const cdpConnect = `
const [, , port, url] = process.argv;
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const tab = await (await fetch('http://127.0.0.1:' + port + '/json/new?about:blank', { method: 'PUT' })).json();
  const ws = new WebSocket(tab.webSocketDebuggerUrl); await new Promise(r => ws.onopen = r);
  let id = 0; const wait = {};
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && wait[m.id]) wait[m.id](m); };
  const call = (method, params) => new Promise(r => { const i = ++id; wait[i] = r; ws.send(JSON.stringify({ id: i, method, params })); });
  const ev = async x => { const r = (await call("Runtime.evaluate", { expression: x, awaitPromise: true, returnByValue: true })).result; return r?.exceptionDetails ? "EXC " + JSON.stringify(r.exceptionDetails.exception?.description) : r?.result?.value; };
  await call('Page.enable', {});
  await call('Page.addScriptToEvaluateOnNewDocument', { source: ` + "`" + `(() => {
    if (window.parent !== window) return;
    localStorage.setItem('tour_home', '1'); localStorage.setItem('tour_sess', '1');
    window.st = { id: '987654321', confirm: false, otp: true, hasPass: true, users: [], keys: [], space: { in: false, members: [] } };
    window.hostInfo = async () => JSON.parse(JSON.stringify(st));
    const kv = n => [async id => JSON.parse(localStorage.getItem(n) || '{}')[id] || '', async (id, v) => { const k = JSON.parse(localStorage.getItem(n) || '{}'); if (v) k[id] = v; else delete k[id]; localStorage.setItem(n, JSON.stringify(k)); }];
    [window.knownGet, window.knownSet] = kv('known'); [window.savedGet, window.savedSet] = kv('sv'); [window.ckeyGet, window.ckeySet] = kv('ck');
  })();` + "`" + ` });
  await call('Page.navigate', { url }); await sleep(1500);
  console.log('app=' + await ev("(async () => APP + '|' + await loadPake())()"));
  await ev("document.getElementById('hadd').click(); 1"); await sleep(600); // «+» — экран «Другой ПК» (и его тур)
  console.log('tour1=' + await ev("!document.getElementById('tour').classList.contains('hidden')"));
  const vis = i => "document.getElementById('" + i + "').checkVisibility()";
  const state = () => ev("[document.getElementById('remote').dataset.st, document.getElementById('msg').textContent, " + vis('sess') + "].join('|')");
  const until = async f => { for (let i = 0; i < 100; i++) { const s = await state(); if (f(s)) return s; await sleep(150); } return await state(); };
  const code = () => fetch(url + 'code').then(r => r.text());
  const typeOtp = d => ev("(o => { o.value = " + JSON.stringify(d) + "; o.dispatchEvent(new Event('input')); return 1; })(document.getElementById('otp'))");
  const login = async (hid, pw) => { await ev("document.getElementById('id').value = '" + hid + "'; document.getElementById('pw').value = '" + pw + "'; document.getElementById('go').click(); 1"); };
  const bye = async () => { await ev("document.getElementById('bye').click(); 1"); await sleep(400); };
  // вопрос шага 3: виден, вариант (key — вход ключом, pw — без него), галочка «Запомнить пароль» видна и стоит, ☆ видна
  const q = () => ev("(() => { const d = i => document.getElementById(i), on = d('mineq').checkVisibility(), b = d('mineqb').textContent; return [on, !on ? '-' : b === t('c3_b_key') ? 'key' : b === t('c3_b') ? 'pw' : '?', d('mineqrl').checkVisibility(), d('mineqrl').checkVisibility() && d('mineqr').checked, d('starbtn').checkVisibility()].join(','); })()");
  const ls = k => ev("localStorage.getItem('" + k + "')");

  // 1. ПК с TOTP и входом по ключу: шаг 2, пять цифр — ждёт, шестая — отправка; шаг 3 «key»
  await login('123456789', 'secret123');
  console.log('s2=' + await until(s => s.startsWith('2|')) + '|' + await ev(vis('otp') + " + ',' + " + vis('id') + " + ',' + document.getElementById('otptxt').textContent") + '|tour=' + await ev("!document.getElementById('tour').classList.contains('hidden')"));
  const c = await code();
  await typeOtp(c.slice(0, 5)); await sleep(300);
  console.log('five=' + await state());
  await typeOtp(c);
  console.log('ok1=' + await until(s => s.endsWith('|true')));
  await sleep(300);
  console.log('q1=' + await q());
  await ev("document.getElementById('mineqn').value = 'Работа'; document.getElementById('mineqok').click(); 1");
  console.log('re1=' + await until(s => s.startsWith('2|')) + '|' + await ls('mine'));
  await typeOtp(await code());
  console.log('key1=' + await until(s => s.endsWith('|true')) + '|' + await ev("JSON.stringify(Object.values(JSON.parse(localStorage.getItem('ck') || '{}')).map(v => JSON.parse(v).login))") + '|' + await q());
  await bye();
  await login('123456789', ''); // по ключу: пароль не нужен, только код; вопроса нет — ПК уже в списке
  await until(s => s.startsWith('2|')); await typeOtp(await code());
  console.log('bykey=' + await until(s => s.endsWith('|true')) + '|' + await q());
  await bye();

  // 2. ПК без TOTP: шага 2 нет; шаг 3 «pw» с галочкой «Запомнить пароль» (снята); «Не сейчас» — больше не спрашивать
  await login('222333444', 'secret123');
  const seen2 = []; for (let i = 0; i < 60; i++) { const s = await state(); if (!seen2.includes(s.split('|')[0])) seen2.push(s.split('|')[0]); if (s.endsWith('|true')) break; await sleep(100); }
  await sleep(300);
  console.log('nos2=' + seen2.includes('2') + '|' + await q());
  await ev("document.getElementById('mineqno').click(); 1"); await sleep(300);
  console.log('no=' + await q() + '|' + await ls('mineno') + '|' + await ls('mine'));
  await bye();
  await login('222333444', 'secret123'); await until(s => s.endsWith('|true')); await sleep(500);
  console.log('noagain=' + await q());
  // ☆ — тот же вопрос; «Добавить» без галочки: в списке, пароль не сохранён
  await ev("document.getElementById('starbtn').click(); 1");
  console.log('star=' + await q());
  await ev("document.getElementById('mineqok').click(); 1"); await sleep(300);
  console.log('add=' + await ls('mine') + '|' + await ls('sv') + '|' + await ev("document.getElementById('starbtn').textContent"));
  // ★ снять, ☆ — «Добавить» с галочкой: пароль запомнен (как прежде — savedSet)
  await ev("document.getElementById('starbtn').click(); document.getElementById('starbtn').click(); document.getElementById('mineqn').value = 'Дача'; document.getElementById('mineqr').checked = true; document.getElementById('mineqok').click(); 1"); await sleep(300);
  console.log('rem=' + await ls('sv') + '|' + await ls('mine'));
  await bye();

  // 3. член пространства: вход паролем — вопроса нет, ★ «в моём пространстве» (снять нельзя)
  await ev("window.spMemberOf = id => id === '444555666'; 1");
  await login('444555666', 'secret123'); await until(s => s.endsWith('|true')); await sleep(500);
  console.log('member=' + await q() + '|' + await ev("document.getElementById('starbtn').textContent + ',' + document.getElementById('starbtn').disabled"));
  await bye();

  // 4. «Спрашивать» (код разовой помощи): вместо шага 2 — «Ждём ответа… N с» с отсчётом; после «Разрешить» вопроса нет
  await login('333444555', 'secret123');
  const w1 = await until(s => s.startsWith('w|'));
  const n1 = await ev("document.getElementById('askn').textContent"); await sleep(2100);
  const n2 = await ev("document.getElementById('askn').textContent");
  console.log('wait=' + w1 + '|' + n1 + '|' + n2 + '|' + await ev(vis('askwait') + " + ',' + " + vis('id') + " + ',' + " + vis('ccancel')));
  console.log('ok4=' + await until(s => s.endsWith('|true')));
  await sleep(500);
  console.log('code=' + await q());
  await bye();
  // отмена ожидания: «Отмена» — к шагу 1
  await login('333444555', 'secret123'); await until(s => s.startsWith('w|'));
  await ev("document.getElementById('ccancel').click(); 1"); await sleep(300);
  console.log('cancel=' + await state() + '|' + await ev(vis('id')));
  process.exit(0);
})();`

// TestBrowserConnect — «Другой ПК» по макету (Ч7): шаги 2/ожидание/3 в окне программы против настоящих хостов.
func TestBrowserConnect(t *testing.T) {
	chrome := browserNeed(t, "node", "ffmpeg")
	if _, err := fs.Stat(ui.FS, "pake.wasm"); err != nil {
		t.Skip("нет ui/pake.wasm — собрать через build.sh")
	}
	o := &otpHost{secret: totp.NewSecret()}
	ks := &keyStore{}
	ks.set("")
	mux := http.NewServeMux()
	mux.Handle("/ws", &hub.Hub{})
	mux.HandleFunc("/code", func(w http.ResponseWriter, _ *http.Request) { // каждый вход — свежий код: не ждать шага 30 с
		o.mu.Lock()
		o.last = 0
		o.mu.Unlock()
		w.Write([]byte(o.code()))
	})
	mux.Handle("/", http.FileServer(http.FS(ui.FS)))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	ff := func(a *Agent) *Agent {
		a.Capture = func(ctx context.Context, c Cap) (*exec.Cmd, error) {
			return exec.CommandContext(ctx, "ffmpeg", FFArgs("test", "libx264", c)...), nil
		}
		return a
	}
	var trusted atomic.Int32
	a := ff(newAgent(wsURL, "123456789", nil)) // TOTP и вход по ключу
	a.OTP = o.check
	a.KeyLogin = ks.login
	a.KeyTrust = func(p []byte, u string, salt []byte) {
		if salt != nil {
			trusted.Add(1)
		}
		ks.add(p, u, salt)
	}
	b := ff(newAgent(wsURL, "222333444", nil)) // без TOTP и подтверждения (встраивание без него): пароль — и вход
	m := ff(newAgent(wsURL, "444555666", nil)) // член пространства (у клиента)
	c := ff(newAgent(wsURL, "333444555", nil)) // «Спрашивать»: «Разрешить» через 4 с
	c.Confirm = func(string, string) Answer { time.Sleep(4 * time.Second); return Allow }
	for _, x := range []*Agent{a, b, m, c} {
		go x.Run(ctx)
	}
	out := string(runCDP(t, ctx, chrome, cdpConnect, srv.URL+"/"))
	for _, want := range []string{
		"app=true|true\n",
		"s2=2||false|true,false,This PC lets people in without confirmation, so it asks for a second step. Open the authenticator app and enter the 6 digits for “123 456 789”.|tour=false\n", // выноска тура шага 1 закрыта
		"tour1=true\n",
		"five=2||false\n",
		"ok1=1||true\n",
		"q1=true,key,false,false,false\n", // сам, поверх сессии; ключ — без галочки «Запомнить»; ☆ спрятана
		`re1=2|A new code is needed: the previous one has already been used.|false|[{"id":"123456789","name":"Работа"}]` + "\n",
		"key1=1||true|[true]|false,-,false,false,true\n",
		"bykey=1||true|false,-,false,false,true\n",
		"nos2=false|true,pw,true,false,false\n",
		`no=false,-,false,false,true|["222333444"]|[{"id":"123456789","name":"Работа"}]` + "\n",
		"noagain=false,-,false,false,true\n",
		"star=true,pw,true,false,false\n",
		`add=[{"id":"123456789","name":"Работа"},{"id":"222333444","name":"222333444"}]|null|★ In My space` + "\n",
		`rem={"222333444":"secret123"}|[{"id":"123456789","name":"Работа"},{"id":"222333444","name":"Дача"}]` + "\n",
		"member=false,-,false,false,true|★ In My space,true\n",
		"ok4=1||true\n",
		"code=false,-,false,false,true\n",
		"cancel=1||false|true\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if w := regexp.MustCompile(`wait=w\|\|false\|Waiting for an answer on that computer… (\d+) s\|Waiting for an answer on that computer… (\d+) s\|true,false,true`).FindStringSubmatch(out); w == nil {
		t.Error("нет ожидания «Разрешить» с отсчётом")
	} else if n1, _ := strconv.Atoi(w[1]); n1 < 28 || n1 > 30 {
		t.Errorf("отсчёт начался с %d, ждали ~%d", n1, int(AskTimeout.Seconds()))
	} else if n2, _ := strconv.Atoi(w[2]); n2 >= n1 || n1-n2 > 3 {
		t.Errorf("отсчёт не идёт: %d → %d", n1, n2)
	}
	if n := trusted.Load(); n != 1 { // ключ добавлен ровно раз — по «Добавить», не по первому входу паролем
		t.Errorf("ключей добавлено %d", n)
	}
	if t.Failed() {
		t.Log(out)
	}
}

// TestAskWaitMatchesHost — отсчёт «Ждём ответа на том компьютере… N с» на странице идёт от AskTimeout хоста.
func TestAskWaitMatchesHost(t *testing.T) {
	b, err := fs.ReadFile(ui.FS, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`const ASK_S = (\d+);`).FindSubmatch(b)
	if m == nil {
		t.Fatal("нет ASK_S в ui/index.html")
	}
	if n, _ := strconv.Atoi(string(m[1])); time.Duration(n)*time.Second != AskTimeout {
		t.Errorf("ASK_S = %d с, AskTimeout = %v", n, AskTimeout)
	}
}
