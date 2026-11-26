package agent

import (
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"anypc/hub"
	"anypc/pake"
	"anypc/totp"
	"anypc/ui"
)

// cdpKeyLogin: вход ключом (REQ-S-24) — после входа паролем ☆ (веб-клиент: сам вопрос не задаётся) → «Это ваш
// компьютер?» → «Добавить»: тот ПК пускает по ключу — повторный вход тем же паролем с trust и новым кодом, дальше без
// пароля (только код TOTP);
// ключ хоста не тот, что закреплён, или не закреплён вовсе — код не спрашивается; "ok" и "nokey" раньше своего «b» по
// ключу не принимаются; старый хост без keys — пароль не уходит; отзыв на хосте — понятная причина, метка снята;
// отпечаток своего ключа — в «Параметрах»; «Забыть» забывает ключ и просит отозвать его на хосте. Ч7б: хост с trust в
// «ok» — «Добавить» шлёт ctl trust в этой же сессии (без разрыва и нового кода); без поля (старый хост) — прежний путь.
const cdpKeyLogin = `
const [, , port, url] = process.argv;
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const tab = await (await fetch('http://127.0.0.1:' + port + '/json/new?' + url, { method: 'PUT' })).json();
  const ws = new WebSocket(tab.webSocketDebuggerUrl); await new Promise(r => ws.onopen = r);
  let id = 0; const wait = {};
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && wait[m.id]) wait[m.id](m); };
  const ev = x => new Promise(r => { const i = ++id; wait[i] = m => r(m.result?.result?.value); ws.send(JSON.stringify({ id: i, method: 'Runtime.evaluate', params: { expression: x, awaitPromise: true, returnByValue: true } })); });
  const state = () => ev("document.getElementById('msg').textContent + '|' + !document.getElementById('otpbox').classList.contains('hidden') + '|' + !document.getElementById('sess').classList.contains('hidden')");
  const until = async f => { for (let i = 0; i < 75; i++) { const s = await state(); if (f(s)) return s; await sleep(200); } return await state(); };
  const code = () => ev("fetch('/code').then(r => r.text())");
  const otp = async () => { await until(s => s.includes('|true|')); await ev("(o => { o.value = '" + await code() + "'; o.dispatchEvent(new Event('input')); return 1; })(document.getElementById('otp'))"); };
  const login = "JSON.stringify(Object.values(JSON.parse(localStorage.getItem('ckeys') || '{}')).map(k => [k.login, k.lu]))";
  const go = "document.getElementById('pw').value=''; document.getElementById('go').click()";
  const keyOn = "!document.getElementById('keyrow').classList.contains('hidden')";
  // вход паролем + код, затем ☆ (★ — сначала снять: ПК уже в списке) → «Добавить» → повторный вход с trust и новым кодом
  const trust = async () => {
    await ev("document.getElementById('pw').value='secret123'; document.getElementById('go').click()");
    await otp(); await until(s => s.endsWith('|true'));
    if (await ev("document.getElementById('starbtn').getAttribute('aria-pressed')") === 'true') await ev("document.getElementById('morem').click(); document.getElementById('mdel').click(); 1"); // Ч8: снять — «Ещё ▾ → Убрать»
    await ev("document.getElementById('starbtn').click(); 1");
    const q = await ev("[document.getElementById('mineq').checkVisibility(), document.getElementById('mineqb').textContent === t('c3_b_key'), document.getElementById('mineqrl').checkVisibility(), " + login + "].join(',')");
    await ev("document.getElementById('mineqn').value = 'Работа'; document.getElementById('mineqok').click(); 1");
    const re = await until(s => s.includes('|true|')); // повторный вход: шаг 2 с просьбой о новом коде
    await otp();
    return q + '|' + re;
  };
  await sleep(1000);
  // сначала — хост без ctl trust (старый, v0.3.0): поле trust из «ok» убирается, «Добавить» — повторным входом
  await ev("window.stripTrust = true; window.jp0 = JSON.parse; JSON.parse = (s, r) => { const m = jp0(s, r); if (stripTrust && m && m.t === 'ok') delete m.trust; return m; }; 1");
  await ev("document.getElementById('id').value='123456789'; 1");
  console.log('trustq=' + await trust());
  console.log('trust=' + await until(s => s.endsWith('|true')) + '|' + await ev(login) + '|' + await ev("document.getElementById('keyfp').textContent") + '|' + await ev("localStorage.getItem('mine')"));
  await ev("document.getElementById('bye').click()"); await sleep(300);
  await ev("document.getElementById('keyrow').classList.add('hidden'); const i = document.getElementById('id'); i.value = '123456789'; i.dispatchEvent(new Event('input'))"); await sleep(300);
  console.log('box=' + await ev(keyOn));
  await ev(go);
  console.log('ask=' + await until(s => s.includes('|true|')));
  await otp();
  console.log('key=' + await until(s => s.endsWith('|true')));
  await ev("document.getElementById('bye').click()"); await sleep(300);
  // "ok" и "nokey" до своего «b» по ключу (пока клиент читает «Известные хосты»): "ok" — отказ, "nokey" — мимо
  const slow = "window.kg = known.get; known.get = async id => { await new Promise(r => setTimeout(r, 2500)); return kg(id); }; 1";
  const inject = t => "onAuth({ send() {} }, { data: JSON.stringify({ t: '" + t + "' }) }, pc); 1";
  await ev(slow); await ev(go); await sleep(1200); await ev(inject('ok'));
  console.log('early=' + await until(s => s.includes('rror')));
  await sleep(2500); await ev("known.get = kg; 1");
  await ev(slow); await ev(go); await sleep(1200); await ev(inject('nokey')); await sleep(300);
  console.log('earlyno=' + (await state()).includes('rror') + '|' + await ev(login));
  console.log('earlyask=' + await until(s => s.includes('|true|')));
  await ev("known.get = kg; document.getElementById('bye').click()"); await sleep(300);
  // ключ хоста не тот, что в «Известных хостах» (хаб-самозванец): кода не просить, «Доверять новому ключу» не предлагать
  await ev("window.kn = localStorage.getItem('known'); localStorage.setItem('known', JSON.stringify({ '123456789': '0000 0000 0000 0000 0000 0000 0000 0000' })); 1");
  await ev(go);
  console.log('fake=' + await until(s => s.includes('rror')) + '|' + await ev("!document.getElementById('trust').classList.contains('hidden')"));
  await ev("localStorage.setItem('known', kn); 1");
  // ключ хоста не закреплён вовсе — по ключу ничего не слать
  await ev("localStorage.removeItem('known'); 1");
  await ev(go);
  console.log('noknown=' + await until(s => s.includes('rror')) + '|' + await ev(login));
  await ev("localStorage.setItem('known', kn); 1");
  // старый хост: первое «a» без keys — без пароля не входить и ничего не слать (неудачи в счётчике нет)
  await ev("window.op = JSON.parse; JSON.parse = s => { const m = op(s); if (m && m.t === 'a') delete m.keys; return m; }; 1");
  await ev(go);
  console.log('old=' + await until(s => s.includes('rror')) + '|' + await ev(login));
  await ev("JSON.parse = op; 1");
  await fetch(url + 'ask'); // на хосте ключ в списке, но вход им выключен: "nokey" без why — попросить отозвать там
  await ev(go);
  console.log('nokey=' + await until(s => s.includes('rror')) + '|' + await ev(login) + '|' + await ev(keyOn));
  await fetch(url + 'revoke');
  await ev(go); await sleep(300);
  console.log('nopw=' + await state());
  // снова вход ключом (новый ключ), отпечаток в «Параметрах»; «Забыть» — забыть и попросить отозвать
  await trust();
  await until(s => s.endsWith('|true'));
  await ev("document.getElementById('bye').click()"); await sleep(300);
  await ev("const i4 = document.getElementById('id'); i4.dispatchEvent(new Event('input')); 1");
  await sleep(300);
  console.log('fp=' + await ev("document.getElementById('keyfp').textContent + '|' + " + keyOn));
  await ev("document.getElementById('keyforget').click(); 1"); await sleep(300);
  console.log('forgot=' + await ev("document.getElementById('msg').textContent + '|' + localStorage.getItem('ckeys') + '|' + document.getElementById('keyfp').textContent"));
  // ключа на хосте нет (отозван там, сброшен вступлением в пространство): "nokey" why:"none" — отзывать нечего
  await trust();
  await until(s => s.endsWith('|true'));
  await ev("document.getElementById('bye').click()"); await sleep(300);
  await fetch(url + 'revoke');
  await ev(go);
  console.log('nonekey=' + await until(s => s.includes('rror')) + '|' + await ev(login));
  // Ч7б: хост с trust в «ok» — «Добавить» шлёт ctl trust в этой же сессии: ни разрыва, ни нового кода
  await ev("stripTrust = false; 1");
  const star = async () => {
    if (await ev("document.getElementById('starbtn').getAttribute('aria-pressed')") === 'true') await ev("document.getElementById('starbtn').click(); 1");
    await ev("document.getElementById('starbtn').click(); 1");
  };
  const card = "[document.getElementById('mineq').checkVisibility(), document.getElementById('mineqb').textContent === t('c3_b') ? 'pw' : document.getElementById('mineqb').textContent === t('c3_b_on') ? 'on' : '?', document.getElementById('mineqrl').checkVisibility(), document.getElementById('mineqn').value, document.getElementById('mineqw').checkVisibility() ? document.getElementById('mineqw').textContent : '-'].join(',')";
  const fake = r => "onCtl({ data: JSON.stringify(" + r + ") }, pc); 1";
  // ответ trust до входа (шаг кода, authed нет) — ключ не включается; отказ хоста — карточка вариантом «Запомнить
  // пароль» с тем же именем и причиной, ключ не включён; ☆ после отказа — тоже «Запомнить пароль»
  await ev("document.getElementById('pw').value='secret123'; document.getElementById('go').click()");
  await until(s => s.includes('|true|'));
  await ev(fake("{ t: 'trust', ok: true }")); await sleep(300);
  console.log('preauth=' + await ev(login));
  await otp(); await until(s => s.endsWith('|true'));
  await star();
  await ev("window.so0 = ctl.send.bind(ctl); ctl.send = x => JSON.parse(x).t === 'trust' ? undefined : so0(x); document.getElementById('mineqn').value = 'Дом'; document.getElementById('mineqok').click(); 1");
  await ev(fake("{ t: 'trust', why: 'ask' }")); await sleep(300);
  console.log('refused=' + await ev(card) + '|' + await ev(login) + '|' + await ev("pc.mq.key"));
  await ev("document.getElementById('mineqno').click(); 1"); await star();
  console.log('refstar=' + await ev(card));
  await ev("document.getElementById('bye').click()"); await sleep(300);
  await ev("document.getElementById('pw').value='secret123'; document.getElementById('go').click()");
  await otp(); await until(s => s.endsWith('|true'));
  if (await ev("document.getElementById('starbtn').getAttribute('aria-pressed')") === 'true') await ev("document.getElementById('starbtn').click(); 1");
  await ev("document.getElementById('starbtn').click(); 1");
  const cq = await ev("[document.getElementById('mineq').checkVisibility(), document.getElementById('mineqb').textContent, " + login + "].join(',')");
  await ev("window.p0 = pc; window.ts = []; const so = ctl.send.bind(ctl); ctl.send = x => { ts.push(JSON.parse(x).t); return so(x); }; document.getElementById('mineqn').value = 'Дом'; document.getElementById('mineqok').click(); 1");
  await sleep(1500);
  console.log('ctltrust=' + cq + '|' + await state() + '|' + await ev("pc === p0") + '|' + await ev("ts.join()") + '|' + await ev(login) + '|' + await ev(keyOn));
  await star();
  console.log('okstar=' + await ev(card) + '|' + await ev("pc.mq.key")); // после ключа ☆ — «уже включён», не «can»
  await ev("document.getElementById('bye').click()"); await sleep(300);
  await ev(go);
  console.log('ctlask=' + await until(s => s.includes('|true|')));
  await otp();
  console.log('ctlkey=' + await until(s => s.endsWith('|true')));
  process.exit(0);
})();`

// TestBrowserKeyLogin — веб-клиент и вход по ключу без пароля (REQ-S-24).
func TestBrowserKeyLogin(t *testing.T) {
	chrome, err := exec.LookPath("google-chrome")
	if err != nil {
		t.Skip("нет google-chrome")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("нет node")
	}
	if _, err := fs.Stat(ui.FS, "pake.wasm"); err != nil {
		t.Skip("нет ui/pake.wasm — собрать через build.sh")
	}
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("нет ffmpeg")
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
	mux.HandleFunc("/revoke", func(http.ResponseWriter, *http.Request) { ks.set(""); ks.mu.Lock(); ks.ask = false; ks.mu.Unlock() })
	mux.HandleFunc("/ask", func(http.ResponseWriter, *http.Request) { ks.mu.Lock(); ks.ask = true; ks.mu.Unlock() })
	mux.Handle("/", http.FileServer(http.FS(ui.FS)))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	a := newAgent("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", "123456789", nil)
	a.OTP = o.check
	var mu sync.Mutex
	var added []string // отпечатки ключей, добавленных по «Доверять»: клиент показывает свой у галочки
	a.KeyLogin = ks.login
	a.KeyTrust = func(p []byte, u string, salt []byte) {
		if salt != nil {
			mu.Lock()
			added = append(added, pake.KeyFingerprint(p)[:9])
			mu.Unlock()
		}
		ks.add(p, u, salt)
	}
	a.Capture = func(ctx context.Context, c Cap) (*exec.Cmd, error) {
		return exec.CommandContext(ctx, "ffmpeg", FFArgs("test", "libx264", c)...), nil
	}
	go a.Run(ctx)
	out := string(runCDP(t, ctx, chrome, cdpKeyLogin, srv.URL+"/"))
	mu.Lock()
	fps := slices.Clone(added)
	mu.Unlock()
	if len(fps) != 4 { // три — повторным входом (старый хост), один — ctl trust
		t.Fatalf("добавлено ключей %d: %v", len(fps), fps)
	}
	fp, fp2 := fps[0], fps[1]
	for _, want := range []string{
		"trustq=true,true,false,[[null,null]]|A new code is needed: the previous one has already been used.|true|false\n", // ключ есть, вход им — ещё нет
		"trust=|false|true|[[true,\"\"]]|🔑 " + fp + `|[{"id":"123456789","name":"Работа"}]` + "\n",
		"early=Error: the remote PC could not be verified — connection may be intercepted|false|false",
		"earlyno=false|[[true,\"\"]]",
		"earlyask=|true|false",
		"noknown=Error: the remote PC does not accept sign-in without a password — enter the password|false|false|[[true,\"\"]]",
		"fp=🔑 " + fp2 + "|true",
		"forgot=Sign-in without a password from this PC is off. Also revoke key " + fp2 + " in the remote PC’s window|{}|\n",
		"box=true",
		"ask=|true|false",
		"key=|false|true",
		"fake=Error: the remote PC key has changed. If AnyPC was not reinstalled there, do not connect|false|false|false",
		"old=Error: the remote PC does not accept sign-in without a password — enter the password|false|false|[[true,\"\"]]",
		"nokey=Error: this PC’s key was not accepted: it was revoked, or the remote PC has no TOTP code or has “Ask before each connection” on — sign in with the password. Sign-in without a password from this PC is off. Also revoke key " + fp + " in the remote PC’s window|false|false|[]|false",
		"nopw=Enter the password|false|false",
		"nonekey=Error: this PC’s key was not accepted: it was revoked, or the remote PC has no TOTP code or has “Ask before each connection” on — sign in with the password|false|false|[]\n",
		"ctltrust=true,Next time — one click, no password, only the code from the app.,[[null,null]]||false|true|true|trust|[[true,\"\"]]|true\n", // сессия та же, кода не просили, ключ — один раз
		"preauth=[[null,null]]\n", // trust до входа — мимо
		"refused=true,pw,true,Дом,Sign-in without a password was not turned on: that PC now asks before each connection or has no app code.|[[null,null]]|\n",
		"refstar=true,pw,true,,-\n",
		"okstar=true,on,false,,-|on\n",
		"ctlask=|true|false\n", // дальше — ключом: только код
		"ctlkey=|false|true\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if f, _ := lock(a); f != 1 { // засчитан только отозванный ключ (счёт записи сбросил последний вход, общий — нет)
		t.Errorf("неудач по хосту: %d", f)
	}
}

// cdpHostKeys — окно хоста: ключи входа без пароля (REQ-S-24) под своей записью (и под паролем этого ПК) —
// короткий отпечаток, даты; «Отозвать» зовёт keyDel(запись, полный отпечаток), строка исчезает. Ключ клиента,
// подложенный в localStorage окна программы, в настройки не переносится и стирается (галочка сама не встаёт).
const cdpHostKeys = `
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
  await call('Page.addScriptToEvaluateOnNewDocument', { source: ` + "`" + `
    const st = { id: '123456789', confirm: false, otp: true, hasPass: true, users: [{ name: 'ivan', view: false, otp: true }],
      keys: [{ user: '', fp: 'aaaa bbbb cccc dddd', added: '2026-11-10T10:00:00Z', last: '2026-11-12T10:00:00Z' },
             { user: 'ivan', fp: '<b>e</b>ee ffff 0000', added: '2026-11-11T10:00:00Z', last: '0001-01-01T00:00:00Z' }] };
    window.calls = []; window.confirm = () => true;
    window.hostInfo = async () => JSON.parse(JSON.stringify(st));
    localStorage.setItem('ckeys', JSON.stringify({ '123456789': { seed: 'S', pub: 'P', login: true, lu: '' } })); // подложенный в localStorage окна
    window.ck = {}; window.ckeyGet = async id => ck[id] || ''; window.ckeySet = async (id, v) => { if (v) ck[id] = v; else delete ck[id]; };
    window.keyDel = async (n, fp) => { calls.push('kdel:' + n + ':' + fp); st.keys = st.keys.filter(k => k.fp !== fp); };
  ` + "`" + ` });
  const list = () => ev("[...document.getElementById('ulist').children].map(r => r.classList.contains('urow') ? r.dataset.user + ':' + r.querySelector('select').value : r.textContent).join(';') + '|' + document.querySelectorAll('#ulist b b').length + '|' + calls.join(',')");
  await call('Page.navigate', { url }); await sleep(1500);
  console.log('keys=' + await list());
  await ev("const i = document.getElementById('id'); i.value = '123456789'; i.dispatchEvent(new Event('input')); 1"); await sleep(300);
  console.log('migr=' + await ev("localStorage.getItem('ckeys') + '|' + JSON.stringify(ck) + '|' + !document.getElementById('keyrow').classList.contains('hidden')"));
  await ev("[...document.querySelectorAll('#ulist button')].find(b => b.parentNode.textContent.includes('aaaa')).click(); 1"); await sleep(300);
  console.log('revoked=' + await list());
  process.exit(0);
})();`

// TestBrowserHostKeys — окно хоста: список ключей входа без пароля и «Отозвать».
func TestBrowserHostKeys(t *testing.T) {
	chrome, err := exec.LookPath("google-chrome")
	if err != nil {
		t.Skip("нет google-chrome")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("нет node")
	}
	srv := httptest.NewServer(http.FileServer(http.FS(ui.FS)))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out := string(runCDP(t, ctx, chrome, cdpHostKeys, srv.URL+"/"))
	for _, want := range []string{
		"keys=ivan:full;🔑 <b>e</b>e · added 11/11/2026 · last sign-in —Revoke;This PC’s password;🔑 aaaa bbbb · added 11/10/2026 · last sign-in 11/12/2026Revoke|0|\n",
		"migr=null|{}|false\n", // программа: ключ из localStorage окна в настройки не попал, стёрт; галочка не встала сама
		"revoked=ivan:full;🔑 <b>e</b>e · added 11/11/2026 · last sign-in —Revoke|0|kdel::aaaa bbbb cccc dddd\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if t.Failed() {
		t.Log(out)
	}
}
