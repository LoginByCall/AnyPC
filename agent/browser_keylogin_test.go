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

// cdpKeyLogin: «Доверять этому ПК» (REQ-S-24) — вход паролем с галочкой, дальше без пароля (только код TOTP);
// ключ хоста не тот, что закреплён, или не закреплён вовсе — код не спрашивается; "ok" и "nokey" раньше своего «b» по
// ключу не принимаются; старый хост без keys — пароль не уходит; отзыв на хосте — понятная причина, метка снята;
// отпечаток своего ключа — у галочки; снятие галочки забывает ключ и просит отозвать его на хосте.
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
  const otp = async () => { await until(s => s.includes('|true|')); await ev("document.getElementById('otp').value='" + await code() + "'; document.getElementById('otpgo').click()"); };
  const login = "JSON.stringify(Object.values(JSON.parse(localStorage.getItem('ckeys') || '{}')).map(k => [k.login, k.lu]))";
  const go = "document.getElementById('pw').value=''; document.getElementById('go').click()";
  await sleep(1000);
  await ev("document.getElementById('id').value='123456789'; document.getElementById('pw').value='secret123'; document.getElementById('keylogin').checked = true; document.getElementById('go').click()");
  await otp();
  console.log('trust=' + await until(s => s.endsWith('|true')) + '|' + await ev(login) + '|' + await ev("document.getElementById('keyfp').textContent"));
  await ev("document.getElementById('bye').click()"); await sleep(300);
  await ev("document.getElementById('keylogin').checked = false; const i = document.getElementById('id'); i.value = '123456789'; i.dispatchEvent(new Event('input'))"); await sleep(300);
  console.log('box=' + await ev("document.getElementById('keylogin').checked"));
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
  await fetch(url + 'revoke'); // на хосте ключ отозвали
  await ev(go);
  console.log('nokey=' + await until(s => s.includes('rror')) + '|' + await ev(login) + '|' + await ev("document.getElementById('keylogin').checked"));
  await ev(go); await sleep(300);
  console.log('nopw=' + await state());
  // снова «Доверять» (новый ключ), отпечаток у галочки; снятие галочки — забыть и попросить отозвать
  await ev("document.getElementById('pw').value='secret123'; document.getElementById('keylogin').checked = true; document.getElementById('go').click()");
  await otp();
  await until(s => s.endsWith('|true'));
  await ev("document.getElementById('bye').click()"); await sleep(300);
  await ev("const i4 = document.getElementById('id'); i4.dispatchEvent(new Event('input')); 1");
  await sleep(300);
  console.log('fp=' + await ev("document.getElementById('keyfp').textContent + '|' + document.getElementById('keylogin').checked"));
  await ev("const c = document.getElementById('keylogin'); c.checked = false; c.dispatchEvent(new Event('change')); 1"); await sleep(300);
  console.log('forgot=' + await ev("document.getElementById('msg').textContent + '|' + localStorage.getItem('ckeys') + '|' + document.getElementById('keyfp').textContent"));
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
	mux.HandleFunc("/revoke", func(http.ResponseWriter, *http.Request) { ks.set("") })
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
	if len(fps) != 2 {
		t.Fatalf("добавлено ключей %d: %v", len(fps), fps)
	}
	fp, fp2 := fps[0], fps[1]
	for _, want := range []string{
		"trust=|false|true|[[true,\"\"]]|🔑 " + fp + "\n",
		"early=Error: the remote PC could not be verified — connection may be intercepted|false|false",
		"earlyno=false|[[true,\"\"]]",
		"earlyask=Enter the 6-digit code from the authenticator app for this PC|true|false",
		"noknown=Error: the remote PC does not accept sign-in without a password — enter the password|false|false|[[true,\"\"]]",
		"fp=🔑 " + fp2 + "|true",
		"forgot=Sign-in without a password from this PC is off. Also revoke key " + fp2 + " in the remote PC’s window|{}|\n",
		"box=true",
		"ask=Enter the 6-digit code from the authenticator app for this PC|true|false",
		"key=|false|true",
		"fake=Error: the remote PC key has changed. If AnyPC was not reinstalled there, do not connect|false|false|false",
		"old=Error: the remote PC does not accept sign-in without a password — enter the password|false|false|[[true,\"\"]]",
		"nokey=Error: this PC’s key was not accepted: it was revoked, or the remote PC has no TOTP code or has “Ask before each connection” on — sign in with the password. Sign-in without a password from this PC is off. Also revoke key " + fp + " in the remote PC’s window|false|false|[]|false",
		"nopw=Enter the password|false|false",
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
  const list = () => ev("[...document.getElementById('ulist').children].map(r => r.textContent).join(';') + '|' + document.querySelectorAll('#ulist b b').length + '|' + calls.join(',')");
  await call('Page.navigate', { url }); await sleep(1500);
  console.log('keys=' + await list());
  await ev("const i = document.getElementById('id'); i.value = '123456789'; i.dispatchEvent(new Event('input')); 1"); await sleep(300);
  console.log('migr=' + await ev("localStorage.getItem('ckeys') + '|' + JSON.stringify(ck) + '|' + document.getElementById('keylogin').checked"));
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
		"keys=This PC’s password;🔑 aaaa bbbb · added 11/10/2026 · last sign-in 11/12/2026Revoke;ivanFull control · TOTPPasswordTurn off TOTPDelete;🔑 <b>e</b>e · added 11/11/2026 · last sign-in —Revoke|0|\n",
		"migr=null|{}|false\n", // программа: ключ из localStorage окна в настройки не попал, стёрт; галочка не встала сама
		"revoked=ivanFull control · TOTPPasswordTurn off TOTPDelete;🔑 <b>e</b>e · added 11/11/2026 · last sign-in —Revoke|0|kdel::aaaa bbbb cccc dddd\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if t.Failed() {
		t.Log(out)
	}
}
