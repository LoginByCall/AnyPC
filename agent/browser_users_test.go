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
  // учётная запись — под ссылкой (поле не принимают за подпись); запомненная — поле открыто
  const vis = "document.getElementById('user').classList.contains('hidden') + '|' + document.getElementById('userlink').classList.contains('hidden')";
  console.log('link=' + await ev(vis));
  // без пароля не подключаться: пустой пароль — гарантированный «fail» и лишняя неудача в счётчике перебора
  await ev("document.getElementById('id').value='123456789'; document.getElementById('user').value='ivan'; document.getElementById('go').click()");
  await sleep(300);
  console.log('nopw=' + await state());
  await ev("document.getElementById('id').value='123456789'; document.getElementById('user').value='ivan'; document.getElementById('pw').value='secret123'; document.getElementById('go').click()");
  console.log('wrong=' + await until(s => s.includes('rror')));
  await ev("document.getElementById('user').value=' Ivan'; document.getElementById('pw').value='ivan-pass1'; document.getElementById('go').click()");
  console.log('ok=' + await until(s => s.endsWith('|true')));
  // «Запомнить пароль» — теперь в вопросе шага 3 (веб-клиент: по ☆): пароль и имя записи
  await ev("document.getElementById('starbtn').click(); document.getElementById('mineqr').checked = true; document.getElementById('mineqok').click(); 1"); await sleep(300);
  console.log('saved=' + await ev("localStorage.getItem('users')"));
  await ev("document.getElementById('bye').click()");
  await sleep(300);
  // после «Разорвать» ID в поле остался: запомненный пароль подставлен снова, повторный вход проходит (доска владельца:
  // «не запоминает пароль», «с именем не подключается» — пароль был пуст)
  console.log('refill=' + await ev("document.getElementById('user').value + '|' + (document.getElementById('pw').value === 'ivan-pass1')"));
  console.log('shown=' + await ev(vis));
  await ev("document.getElementById('go').click()");
  console.log('again=' + await until(s => s.endsWith('|true')));
  await ev("document.getElementById('bye').click()");
  await sleep(300);
  await ev("document.getElementById('pw').value = document.getElementById('user').value = ''; const i = document.getElementById('id'); i.value = '123456789'; i.dispatchEvent(new Event('input'))");
  await sleep(300);
  console.log('fill=' + await ev("document.getElementById('user').value + '|' + !document.getElementById('pwsrow').classList.contains('hidden')"));
  await ev("document.getElementById('pwforget').click(); 1");
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
		"wrong=Error: wrong account or password. Accounts do not work if the remote PC has “Ask before each connection” on or no TOTP for its own password — then clear the account field and enter the one-time code|false",
		"link=true|false",
		"shown=false|true",
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

// cdpHostUsers — постоянные пользователи: inline draft сверху, required name/password/staged TOTP,
// атомарный userSave, blank password/TOTP у существующего = unchanged, Cancel snapshot, Delete, poll не затирает правку.
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
    const st = { id: '123456789', allowSpace: true, users: [{ name: '<b>x</b>', view: false, otp: false }, { name: 'olga', view: true, otp: true }] };
    window.calls = []; window.confirm = () => true;
    window.hostInfo = async () => JSON.parse(JSON.stringify(st));
    window.userSave = async (n, p, r, s, c) => {
      calls.push(['save', n, p, r, s, c].join(':'));
      if (p === 'reject') throw 'denied';
      const u = st.users.find(u => u.name === n) || (st.users.push({ name: n }), st.users.at(-1));
      if (p) u.password = p; u.view = r === 'view'; if (s) u.otp = true;
    };
    window.userDel = async n => { calls.push('del:' + n); st.users = st.users.filter(u => u.name !== n); };
    window.otpNew = async u => { calls.push('new:' + u); return { secret: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', uri: 'otpauth://x', svg: '<svg xmlns="http://www.w3.org/2000/svg"/>' }; };
  ` + "`" + ` });
  const row = name => "[...document.querySelectorAll('#ulist .urow')].find(r => r.dataset.user === " + JSON.stringify(name) + ")";
  const set = async (name, field, value) => ev("(() => { const r = " + row(name) + ", e = r.querySelector('[name=" + field + "]'); e.value = " + JSON.stringify(value) + "; e.dispatchEvent(new Event(e.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true })); })()");
  const act = async (name, action) => { await ev(row(name) + ".querySelector('[data-act=" + action + "]').click(); 1"); await sleep(250); };
  await call('Page.navigate', { url }); await sleep(1500);
  console.log('list=' + await ev("[document.querySelector('[data-user=\"<b>x</b>\"] input[name=name]').value, document.querySelector('[data-user=olga] select').value, document.querySelectorAll('#ulist b b').length, !![...document.querySelectorAll('#ulist button')].find(b => b.textContent.includes('Turn off TOTP'))].join('|')"));
  await ev("document.getElementById('useradd').click(); 1"); await sleep(100);
  console.log('draft=' + await ev("[document.querySelector('#ulist').firstElementChild.dataset.draft, !document.querySelector('[data-draft] .uacts').classList.contains('hidden')].join('|')"));
  await act('', 'save');
  console.log('required=' + await ev("document.getElementById('ustate').textContent + '|' + calls.join(',')"));
  await set('', 'name', 'petr'); await set('', 'password', 'petr-pass1'); await set('', 'rights', 'view');
  await ev("st.users.push({ name: 'polled', view: false, otp: true }); onHostState(await hostInfo()); 1"); await sleep(100);
  console.log('poll=' + await ev("[document.querySelector('[data-draft] input[name=name]').value, document.querySelector('[data-draft] input[name=password]').value, document.querySelector('[data-draft] select').value].join('|')"));
  await act('', 'totp');
  console.log('totp=' + await ev("document.getElementById('otph').textContent + '|' + !document.getElementById('otpset').classList.contains('hidden') + '|' + calls.join(',')"));
  await ev("document.getElementById('otpcode').value = '123456'; document.getElementById('otpok').click(); 1"); await sleep(100);
  console.log('staged=' + await ev("calls.join(',') + '|' + !document.querySelector('[data-draft] .uacts').classList.contains('hidden')"));
  await act('', 'save');
  console.log('add=' + await ev("calls.join(',') + '|' + !!document.querySelector('[data-draft]')"));
  await set('olga', 'password', 'changed-secret');
  console.log('dirty=' + await ev("!document.querySelector('[data-user=olga] .uacts').classList.contains('hidden')"));
  await act('olga', 'cancel');
  console.log('cancel=' + await ev("document.querySelector('[data-user=olga] input[name=password]').value + '|' + document.querySelector('[data-user=olga] .uacts').classList.contains('hidden')"));
  await set('olga', 'rights', 'full'); await act('olga', 'save');
  console.log('rights=' + await ev("calls.slice(-1)[0]"));
  await act('olga', 'totp'); await ev("document.getElementById('otpcode').value = '654321'; document.getElementById('otpok').click(); 1"); await act('olga', 'save');
  console.log('replace=' + await ev("calls.slice(-2).join(',')"));
  await set('olga', 'password', 'reject'); await act('olga', 'save');
  console.log('error=' + await ev("document.getElementById('ustate').textContent + '|' + document.querySelector('[data-user=olga] input[name=password]').value"));
  await act('olga', 'cancel'); await act('olga', 'delete');
  console.log('delete=' + await ev("calls.slice(-1)[0] + '|' + !!document.querySelector('[data-user=olga]')"));
  await ev("document.getElementById('useradd').click(); 1"); await act('', 'delete');
  console.log('draftdel=' + await ev("!!document.querySelector('[data-draft]')"));
  console.log('legacy=' + await ev("['confirm','newpw','setpw','otpwarn','otpfix','acccode'].every(i => !document.getElementById(i))"));
  process.exit(0);
})();`

// TestBrowserHostUsers — окно хоста: блок «Учётные записи AnyPC».
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
		"list=<b>x</b>|view|0|false\n",
		"draft=1|true\n",
		"required=Enter a name and password, then set up TOTP before saving.|\n",
		"poll=petr|petr-pass1|view\n",
		"totp=Second factor (TOTP) — petr|true|new:petr\n",
		"staged=new:petr|true\n",
		"add=new:petr,save:petr:petr-pass1:view:ABCDEFGHIJKLMNOPQRSTUVWXYZ234567:123456|false\n",
		"dirty=true\n",
		"cancel=|true\n",
		"rights=save:olga::full::\n",
		"replace=new:olga,save:olga::full:ABCDEFGHIJKLMNOPQRSTUVWXYZ234567:654321\n",
		"error=Error: denied|reject\n",
		"delete=del:olga|false\n",
		"draftdel=false\n",
		"legacy=true\n",
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
	if !strings.Contains(out, "old=Error: the remote PC does not know user accounts — update AnyPC there or clear the account field|false") {
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
