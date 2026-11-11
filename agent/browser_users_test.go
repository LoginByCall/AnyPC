package agent

import (
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"anypc/hub"
	"anypc/ui"
)

// cdpUsers: веб-клиент с полем «Имя» (REQ-S-20): чужой пароль к имени — «неверное имя или пароль»; своим — сессия;
// имя запоминается вместе с паролем и подставляется по ID; снятие галочки забывает и его.
const cdpUsers = `
const [, , port, url] = process.argv;
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const tab = await (await fetch('http://127.0.0.1:' + port + '/json/new?' + url, { method: 'PUT' })).json();
  const ws = new WebSocket(tab.webSocketDebuggerUrl); await new Promise(r => ws.onopen = r);
  let id = 0; const wait = {};
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && wait[m.id]) wait[m.id](m); };
  const ev = x => new Promise(r => { const i = ++id; wait[i] = m => r(m.result?.result?.value); ws.send(JSON.stringify({ id: i, method: 'Runtime.evaluate', params: { expression: x, awaitPromise: true, returnByValue: true } })); });
  const state = () => ev("document.getElementById('msg').textContent + '|' + !document.getElementById('sess').classList.contains('hidden')");
  const until = async f => { for (let i = 0; i < 75; i++) { const s = await state(); if (f(s)) return s; await sleep(200); } return await state(); };
  await sleep(1000);
  // без пароля не подключаться: пустой пароль — гарантированный «fail» и лишняя неудача в счётчике перебора
  await ev("document.getElementById('id').value='123456789'; document.getElementById('user').value='ivan'; document.getElementById('go').click()");
  await sleep(300);
  console.log('nopw=' + await state());
  await ev("document.getElementById('id').value='123456789'; document.getElementById('user').value='ivan'; document.getElementById('pw').value='secret123'; document.getElementById('go').click()");
  console.log('wrong=' + await until(s => s.includes('rror')));
  await ev("document.getElementById('user').value=' Ivan'; document.getElementById('pw').value='ivan-pass1'; document.getElementById('remember').checked = true; document.getElementById('go').click()");
  console.log('ok=' + await until(s => s.endsWith('|true')));
  console.log('saved=' + await ev("localStorage.getItem('users')"));
  await ev("document.getElementById('bye').click()");
  await sleep(300);
  // после «Разорвать» ID в поле остался: запомненный пароль подставлен снова, повторный вход проходит (доска владельца:
  // «не запоминает пароль», «с именем не подключается» — пароль был пуст)
  console.log('refill=' + await ev("document.getElementById('user').value + '|' + (document.getElementById('pw').value === 'ivan-pass1')"));
  await ev("document.getElementById('go').click()");
  console.log('again=' + await until(s => s.endsWith('|true')));
  await ev("document.getElementById('bye').click()");
  await sleep(300);
  await ev("document.getElementById('pw').value = document.getElementById('user').value = ''; const i = document.getElementById('id'); i.value = '123456789'; i.dispatchEvent(new Event('input'))");
  await sleep(300);
  console.log('fill=' + await ev("document.getElementById('user').value + '|' + document.getElementById('remember').checked"));
  await ev("const r = document.getElementById('remember'); r.checked = false; r.dispatchEvent(new Event('change'))");
  await sleep(300);
  console.log('forgot=' + await ev("localStorage.getItem('users')"));
  // хост ответил «a» с чужим именем — подмена: клиент рвёт вход и CPace не начинает (выжившая мутация приёмки)
  await ev("window.op = JSON.parse; JSON.parse = s => { const m = op(s); if (m && m.t === 'a' && m.user) m.user = 'mallory'; return m; }; document.getElementById('id').value='123456789'; document.getElementById('user').value='ivan'; document.getElementById('pw').value='ivan-pass1'; document.getElementById('go').click()");
  console.log('echo=' + await until(s => s.includes('verified')));
  process.exit(0);
})();`

// TestBrowserUsers — веб-клиент и учётные записи: поле «Имя», отказ чужому паролю, вход, имя на плашке хоста,
// запоминание имени вместе с паролем.
func TestBrowserUsers(t *testing.T) {
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
	mux := http.NewServeMux()
	mux.Handle("/ws", &hub.Hub{})
	mux.Handle("/", http.FileServer(http.FS(ui.FS)))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	a := newAgent("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", "123456789", nil)
	usersHost(accounts)(a)
	var label atomic.Value
	a.OnState = func(_ bool, s string) {
		if s != "" {
			label.Store(s)
		}
	}
	a.Capture = func(ctx context.Context, c Cap) (*exec.Cmd, error) {
		return exec.CommandContext(ctx, "ffmpeg", FFArgs("test", "libx264", c)...), nil
	}
	go a.Run(ctx)
	out := string(runCDP(t, ctx, chrome, cdpUsers, srv.URL+"/"))
	for _, want := range []string{
		"nopw=Enter the password|false",
		"wrong=Error: wrong name or password|false",
		"ok=|true",
		`saved={"123456789":"Ivan"}`,
		"refill=Ivan|true",
		"again=|true",
		"fill=Ivan|true",
		"forgot={}",
		"echo=Error: the remote PC could not be verified — connection may be intercepted|false",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if l, _ := label.Load().(string); !strings.HasSuffix(l, " · ivan") {
		t.Errorf("окно хоста и плашка: %q", l)
	}
}

// cdpHostUsers — блок «Пользователи» в окне хоста с подменёнными привязками: список (имя — текстом), добавление
// (короткий пароль — отказ), «Пароль» заполняет форму, TOTP записи — окно настройки с её именем, удаление.
const cdpHostUsers = `
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
    const st = { id: '123456789', confirm: false, otp: true, hasPass: true, users: [{ name: '<b>x</b>', view: false, otp: false }, { name: 'olga', view: true, otp: true }] };
    window.calls = []; window.confirm = () => true;
    window.hostInfo = async () => JSON.parse(JSON.stringify(st));
    window.userSet = async (n, p, r) => { calls.push('set:' + n + ':' + p + ':' + r); st.users.push({ name: n, view: r === 'view', otp: false }); };
    window.userDel = async n => { calls.push('del:' + n); st.users = st.users.filter(u => u.name !== n); };
    window.otpOff = async n => { calls.push('off:' + n); st.users.find(u => u.name === n).otp = false; };
    window.otpNew = async u => { calls.push('new:' + u); return { secret: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', uri: 'otpauth://x', svg: '<svg xmlns="http://www.w3.org/2000/svg"/>' }; };
    window.otpEnable = async (s, c, u) => { calls.push('enable:' + c + ':' + u); st.users.find(x => x.name === u).otp = true; };
  ` + "`" + ` });
  const rows = () => ev("[...document.querySelectorAll('#ulist .row')].map(r => r.textContent).join(';') + '|' + document.querySelectorAll('#ulist b b').length + '|' + document.getElementById('ustate').textContent + '|' + calls.join(',')");
  const btn = (row, k) => ev("document.querySelectorAll('#ulist .row')[" + row + "].querySelectorAll('button')[" + k + "].click(); 1");
  await call('Page.navigate', { url }); await sleep(1500);
  console.log('list=' + await rows() + '|' + await ev("!document.getElementById('users').classList.contains('hidden')"));
  await ev("document.getElementById('uname').value = 'petr'; document.getElementById('upw').value = 'short'; document.getElementById('uadd').click(); 1"); await sleep(300);
  console.log('short=' + await rows());
  await ev("document.getElementById('upw').value = 'petr-pass1'; document.getElementById('uright').value = 'view'; document.getElementById('uadd').click(); 1"); await sleep(300);
  console.log('add=' + await rows() + '|' + await ev("document.getElementById('uname').value + document.getElementById('upw').value"));
  await btn(1, 0); await sleep(100);
  console.log('pw=' + await ev("document.getElementById('uname').value + '|' + document.getElementById('uright').value"));
  await btn(2, 1); await sleep(300);
  console.log('totp=' + await ev("document.getElementById('otph').textContent + '|' + !document.getElementById('otpset').classList.contains('hidden')"));
  await ev("document.getElementById('otpcode').value = '123456'; document.getElementById('otpok').click(); 1"); await sleep(300);
  await btn(1, 1); await sleep(300);
  await btn(1, 2); await sleep(300);
  console.log('done=' + await rows());
  await ev("window.hostInfo = async () => ({ id: '123456789', confirm: true, otp: false, hasPass: true, users: [] }); onHostState({ id: '123456789', confirm: true, otp: false, hasPass: true, users: [] }); 1");
  console.log('confirm=' + await ev("!document.getElementById('users').classList.contains('hidden')"));
  process.exit(0);
})();`

// TestBrowserHostUsers — окно хоста: блок «Пользователи».
func TestBrowserHostUsers(t *testing.T) {
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
	out := string(runCDP(t, ctx, chrome, cdpHostUsers, srv.URL+"/"))
	for _, want := range []string{
		"list=<b>x</b>Full controlPasswordSet up TOTPDelete;olgaView only · TOTPPasswordTurn off TOTPDelete|0|||true\n",
		"short=<b>x</b>Full controlPasswordSet up TOTPDelete;olgaView only · TOTPPasswordTurn off TOTPDelete|0|Password must be at least 8 characters.|\n",
		"|set:petr:petr-pass1:view|\n",
		"pw=olga|view\n",
		"totp=Second factor (TOTP) — petr|true\n",
		"confirm=false\n", // «Спрашивать перед каждым подключением» — блок скрыт
		"done=<b>x</b>Full controlPasswordSet up TOTPDelete;petrView only · TOTPPasswordTurn off TOTPDelete|0||set:petr:petr-pass1:view,new:petr,enable:123456:petr,off:olga,del:olga\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if t.Failed() {
		t.Log(out)
	}
}

// TestBrowserOldHost — клиент с именем и хост без учётных записей (первое "a" без users, как у fakeHost и v0.1.19):
// понятная причина сразу, имя хосту не уходит и CPace не начинается.
func TestBrowserOldHost(t *testing.T) {
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
	mux := http.NewServeMux()
	mux.Handle("/ws", &hub.Hub{})
	mux.Handle("/", http.FileServer(http.FS(ui.FS)))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	guesses := make(chan int, 10)
	go fakeHost(t, ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", "123456789", guesses)
	script := strings.Replace(cdpUsers, "document.getElementById('pw').value='secret123'; document.getElementById('go').click()\");\n  console.log('wrong=",
		"document.getElementById('pw').value='secret123'; document.getElementById('go').click()\");\n  console.log('old=", 1)
	script = script[:strings.Index(script, "  await ev(\"document.getElementById('user').value=' Ivan'")] + "  process.exit(0);\n})();"
	out := string(runCDP(t, ctx, chrome, script, srv.URL+"/"))
	if !strings.Contains(out, "old=Error: the remote PC does not know user names — update AnyPC there or leave “Name” empty|false") {
		t.Errorf("старый хост: %q", out)
	}
	select {
	case n := <-guesses: // fakeHost шлёт три "a" и через 4 с сообщает, сколько "b" получил
		if n != 0 {
			t.Errorf("клиент ответил старому хосту CPace (%d)", n)
		}
	case <-ctx.Done():
		t.Error("fakeHost не дождался")
	}
}
