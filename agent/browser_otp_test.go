package agent

import (
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"anypc/hub"
	"anypc/totp"
	"anypc/ui"
)

// cdpOTP: вход в хост с TOTP — шаг 2 (поле кода; шестая цифра отправляет сама), неверный код (новый запрос), верный —
// сессия; веб-клиент сам не спрашивает «Это ваш компьютер?», по ☆ — спрашивает; хост без входа ключом — «Добавить» с
// галочкой «Запомнить пароль» (по умолчанию снята): сохранён, подставляется при вводе ID, «Забыть» забывает.
const cdpOTP = `
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
  const call = (method, params) => new Promise(r => { const i = ++id; wait[i] = r; ws.send(JSON.stringify({ id: i, method, params })); });
  await sleep(1000);
  await ev("document.getElementById('id').value='123456789'; document.getElementById('pw').value='secret123'; document.getElementById('go').click()");
  console.log('ask=' + await until(s => s.includes('|true|')) + '|' + await ev("document.getElementById('otptxt').textContent + '|' + document.getElementById('id').checkVisibility()"));
  const c = await code(), bad = String((+c[0] + 1) % 10) + c.slice(1);
  await ev("const o = document.getElementById('otp'); o.value='" + bad.slice(0, 5) + "'; o.dispatchEvent(new Event('input')); 1");
  console.log('five=' + await state()); // пять цифр — ещё не отправлено
  await ev("const o2 = document.getElementById('otp'); o2.value += '" + bad.slice(5) + "'; o2.dispatchEvent(new Event('input')); 1");
  await sleep(300);
  console.log('bad=' + await until(s => s.includes('|true|')));
  await ev("document.getElementById('otp').value='" + await code() + "'; document.getElementById('otp').dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }))");
  console.log('ok=' + await until(s => s.endsWith('|true')));
  const q = "[document.getElementById('mineq').checkVisibility(), document.getElementById('mineqb').textContent === t('c3_b'), document.getElementById('mineqrl').checkVisibility(), document.getElementById('mineqr').checked, document.getElementById('starbtn').checkVisibility()].join(',')";
  await sleep(300);
  console.log('webq=' + await ev(q)); // веб-клиент: вопрос сам не появился, ☆ видна
  await ev("document.getElementById('starbtn').click(); 1");
  console.log('starq=' + await ev(q)); // ☆ — тот же вопрос; галочка «Запомнить пароль» снята, ☆ спрятана
  await ev("document.getElementById('mineqn').value = 'Дача'; document.getElementById('mineqr').checked = true; document.getElementById('mineqok').click(); 1");
  await sleep(300);
  console.log('saved=' + await ev("localStorage.getItem('pass')") + '|' + await ev("localStorage.getItem('mine')") + '|' + await ev(q) + '|' + await ev("document.getElementById('starbtn').textContent"));
  // обрыв → автопереподключение кладёт пароль в поле: глазик его не показывает
  await ev("const p = pc; Object.defineProperty(p, 'connectionState', { get: () => 'failed' }); p.onconnectionstatechange(); 1");
  await sleep(200);
  await ev("document.querySelector('[data-eye=pw]').click(); 1");
  console.log('redial=' + await ev("document.getElementById('pw').type + '|' + document.querySelector('[data-eye=pw]').disabled + '|' + (document.getElementById('pw').value.length > 0)"));
  await until(s => s.includes('|true|')); // переподключение дошло до кода
  await ev("document.getElementById('bye').click()");
  await ev("document.getElementById('pw').value=''; const i = document.getElementById('id'); i.value = '123456789'; i.dispatchEvent(new Event('input'))");
  await sleep(300);
  console.log('fill=' + await ev("document.getElementById('pw').value + '|' + !document.getElementById('pwsrow').classList.contains('hidden')"));
  // подставленный пароль «глазиком» не открыть; правка человека начинается с пустого поля
  await ev("document.querySelector('[data-eye=pw]').click(); 1");
  console.log('eye=' + await ev("document.getElementById('pw').type + '|' + document.querySelector('[data-eye=pw]').disabled"));
  await ev("document.getElementById('pw').dispatchEvent(new InputEvent('beforeinput', { inputType: 'insertText', data: 'x', cancelable: true })); 1");
  console.log('edit=' + await ev("JSON.stringify(document.getElementById('pw').value) + '|' + document.querySelector('[data-eye=pw]').disabled"));
  await ev("const i2 = document.getElementById('id'); i2.dispatchEvent(new Event('input')); 1"); await sleep(300); // снова подставить для «забыть»
  await ev("document.getElementById('pwforget').click(); 1");
  await sleep(300);
  console.log('forgot=' + await ev("localStorage.getItem('pass') + '|' + document.getElementById('pwsrow').classList.contains('hidden') + '|' + JSON.stringify(document.getElementById('pw').value)")); // забытый пароль не остаётся в поле
  // Enter (настоящая клавиша) в поле с подставленным паролем входит с ним, а не с пустым
  await ev("localStorage.setItem('pass', JSON.stringify({ '123456789': 'secret123' })); document.getElementById('pw').value = ''; const i3 = document.getElementById('id'); i3.dispatchEvent(new Event('input')); 1");
  await sleep(300);
  await ev("document.getElementById('pw').focus(); 1");
  await call('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: '\r' });
  await call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
  console.log('enter=' + await until(s => s.includes('|true|') || s.includes('rror')));
  process.exit(0);
})();`

// TestBrowserOTP — веб-клиент и второй фактор: поле кода, неверный код, вход; «Запомнить пароль».
func TestBrowserOTP(t *testing.T) {
	out := otpBrowser(t, cdpOTP)
	for _, want := range []string{
		"ask=|true|false|This PC lets people in without confirmation, so it asks for a second step. Open the authenticator app and enter the 6 digits for “123 456 789”.|false",
		"five=|true|false",
		"bad=Wrong code. Check that the time on the phone is correct and try again|true|false",
		"ok=|false|true",
		"webq=false,false,false,false,true",
		"starq=true,true,true,false,false",
		`saved={"123456789":"secret123"}|[{"id":"123456789","name":"Дача"}]|false,true,false,true,false|★ In My space`,
		"fill=secret123|true",
		"eye=password|true",
		`edit=""|false`,
		`forgot={}|true|""`,
		"redial=password|true|true",
		"enter=|true|false",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
}

// cdpOTPLate: код не ввели вовремя — понятная причина, поле кода убрано; кнопка «Войти» ничего не ломает.
const cdpOTPLate = `
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
  await sleep(1000);
  await ev("document.getElementById('id').value='123456789'; document.getElementById('pw').value='secret123'; document.getElementById('go').click()");
  console.log('ask=' + await until(s => s.includes('|true|')));
  console.log('late=' + await until(s => s.includes('|false|')));
  await ev("const o = document.getElementById('otp'); o.value='123456'; o.dispatchEvent(new Event('input')); 1");
  await sleep(300);
  console.log('after=' + await state());
  process.exit(0);
})();`

// TestBrowserOTPLate — хост не дождался кода: клиент пишет причину (не «связь потеряна»), поле не остаётся мёртвым.
func TestBrowserOTPLate(t *testing.T) {
	otpWait90.Store(int64(2 * time.Second))
	defer otpWait90.Store(int64(90 * time.Second))
	out := otpBrowser(t, cdpOTPLate)
	late := "Error: the time to enter the code is over — connect again|false|false"
	if !strings.Contains(out, "late="+late) || !strings.Contains(out, "after="+late) {
		t.Error("опоздавший код: нет понятной причины или поле кода осталось")
	}
}

// otpBrowser — хост с TOTP (код — /code на том же сервере) и веб-клиент в Chrome по скрипту; вывод скрипта.
func otpBrowser(t *testing.T, script string) string {
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
	mux := http.NewServeMux()
	mux.Handle("/ws", &hub.Hub{})
	mux.HandleFunc("/code", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(o.code())) })
	mux.Handle("/", http.FileServer(http.FS(ui.FS)))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	a := newAgent("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", "123456789", nil)
	a.OTP = o.check
	a.Capture = func(ctx context.Context, c Cap) (*exec.Cmd, error) {
		return exec.CommandContext(ctx, "ffmpeg", FFArgs("test", "libx264", c)...), nil
	}
	go a.Run(ctx)
	return string(runCDP(t, ctx, chrome, script, srv.URL+"/"))
}

// cdpHostOTP — старые confirm/default-password/otp-warning controls удалены; общие ID copy и keyboard warning сохранены.
const cdpHostOTP = `
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
    window.st = { id: '123456789', allowSpace: false, users: [] };
    window.hostInfo = async () => ({ ...st });
  ` + "`" + ` });
  await call('Page.navigate', { url }); await sleep(1500);
  await ev("document.getElementById('accgo').click(); 1"); await sleep(200);
  console.log('screen=' + await ev("[document.querySelector('#acchead h2').textContent, document.getElementById('spaceallow').checked, ['confirm','newpw','setpw','otpwarn','otpfix','otpon','acccode'].every(i => !document.getElementById(i))].join('|')"));
  console.log('copyid=' + await ev("(() => { const d = new DataTransfer(); document.getElementById('myid').dispatchEvent(new ClipboardEvent('copy', { clipboardData: d, bubbles: true, cancelable: true })); return document.getElementById('myid').textContent + '>' + d.getData('text/plain'); })()"));
  console.log('kb=' + await ev("(() => { const i = document.getElementById('spcpw'), w = i.closest('.row').nextElementSibling; i.dispatchEvent(new KeyboardEvent('keydown', { key: 'ф', code: 'KeyA' })); const a = w.textContent; i.dispatchEvent(new KeyboardEvent('keydown', { key: 'a', code: 'KeyA' })); return a + '|' + w.classList.contains('hidden'); })()"));
  process.exit(0);
})();`

// TestBrowserHostOTP — экран permanent без legacy controls; ID copy и предупреждение раскладки сохранены.
func TestBrowserHostOTP(t *testing.T) {
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
	out := string(runCDP(t, ctx, chrome, cdpHostOTP, srv.URL+"/"))
	for _, want := range []string{
		"screen=Permanent access to this computer|false|true\n",
		"copyid=123 456 789>123456789\n",
		"kb=The keyboard layout is not Latin — check the password|true\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
}
