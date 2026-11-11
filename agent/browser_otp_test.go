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

// cdpOTP: вход в хост с TOTP — поле кода, неверный код (новый запрос), верный — сессия; «Запомнить пароль»:
// сохранён после входа, подставляется при вводе ID, снятие галочки забывает.
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
  await sleep(1000);
  await ev("document.getElementById('id').value='123456789'; document.getElementById('pw').value='secret123'; document.getElementById('remember').checked = true; document.getElementById('go').click()");
  console.log('ask=' + await until(s => s.includes('|true|')));
  const c = await code(), bad = String((+c[0] + 1) % 10) + c.slice(1);
  await ev("document.getElementById('otp').value='" + bad + "'; document.getElementById('otpgo').click()");
  await sleep(300);
  console.log('bad=' + await until(s => s.includes('|true|')));
  await ev("document.getElementById('otp').value='" + await code() + "'; document.getElementById('otp').dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }))");
  console.log('ok=' + await until(s => s.endsWith('|true')));
  console.log('saved=' + await ev("localStorage.getItem('pass')"));
  await ev("document.getElementById('bye').click()");
  await ev("document.getElementById('pw').value=''; document.getElementById('remember').checked = false; const i = document.getElementById('id'); i.value = '123456789'; i.dispatchEvent(new Event('input'))");
  await sleep(300);
  console.log('fill=' + await ev("document.getElementById('pw').value + '|' + document.getElementById('remember').checked"));
  await ev("const r = document.getElementById('remember'); r.checked = false; r.dispatchEvent(new Event('change'))");
  await sleep(300);
  console.log('forgot=' + await ev("localStorage.getItem('pass')"));
  process.exit(0);
})();`

// TestBrowserOTP — веб-клиент и второй фактор: поле кода, неверный код, вход; «Запомнить пароль».
func TestBrowserOTP(t *testing.T) {
	out := otpBrowser(t, cdpOTP)
	for _, want := range []string{
		"ask=Enter the 6-digit code from the authenticator app for this PC|true|false",
		"bad=Wrong code. Check that the time on the phone is correct and try again|true|false",
		"ok=|false|true",
		`saved={"123456789":"secret123"}`,
		"fill=secret123|true",
		"forgot={}",
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
  await ev("document.getElementById('otp').value='123456'; document.getElementById('otpgo').click()");
  await sleep(300);
  console.log('after=' + await state());
  process.exit(0);
})();`

// TestBrowserOTPLate — хост не дождался кода: клиент пишет причину (не «связь потеряна»), поле не остаётся мёртвым.
func TestBrowserOTPLate(t *testing.T) {
	otpWait90 = 2 * time.Second
	defer func() { otpWait90 = 90 * time.Second }()
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

// cdpHostOTP — окно хоста с подменёнными привязками программы: снять «Подтверждать вход» = настройка TOTP
// (галочка остаётся, пока нет верного кода); неверный код — сообщение; верный — включено. Хост после обновления
// (подтверждение выключено, TOTP нет) — галочка стоит и видно предупреждение.
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
    const st = JSON.parse(localStorage.getItem('st') || '{"id":"123456789","confirm":true,"otp":false}'); window.calls = [];
    window.hostInfo = async () => ({ ...st });
    window.setConfirm = async on => { calls.push('confirm:' + on); st.confirm = on; if (on) st.otp = false; };
    window.otpNew = async () => ({ secret: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', uri: 'otpauth://x', svg: '<svg xmlns="http://www.w3.org/2000/svg"/>' });
    window.otpEnable = async (s, c) => { calls.push('enable:' + c); if (c !== '123456') throw 'bad_code'; st.confirm = false; st.otp = true; };
  ` + "`" + ` });
  const vis = i => "!document.getElementById('" + i + "').classList.contains('hidden')";
  const show = () => ev("[document.getElementById('confirm').checked, " + vis('otpset') + ", " + vis('otpon') + ", " + vis('otpwarn') + ", document.getElementById('otpkey').textContent, document.getElementById('otpstate').textContent, calls.join(',')].join('|')");
  await call('Page.navigate', { url }); await sleep(1500);
  await ev("const c = document.getElementById('confirm'); c.click(); 1"); await sleep(300);
  console.log('setup=' + await show());
  await ev("document.getElementById('otpcode').value = '000000'; document.getElementById('otpok').click(); 1"); await sleep(300);
  console.log('bad=' + await show());
  await ev("document.getElementById('otpcode').value = '123456'; document.getElementById('otpok').click(); 1"); await sleep(300);
  console.log('on=' + await show());
  await ev("document.getElementById('confirm').click(); 1"); await sleep(300);
  console.log('off=' + await show());
  await ev("localStorage.setItem('st', JSON.stringify({ id: '123456789', confirm: false, otp: false })); 1");
  await call('Page.reload', {}); await sleep(1500);
  console.log('legacy=' + await show());
  process.exit(0);
})();`

// TestBrowserHostOTP — окно хоста: настройка TOTP при снятии «Подтверждать вход», предупреждение после обновления.
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
		"setup=true|true|false|false|ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567||\n", // галочка осталась, setConfirm(false) не звали
		"bad=true|true|false|false|ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567|Wrong code. Check that the time on the phone is correct and try again|enable:000000\n",
		"on=false|false|true|false|||enable:000000,enable:123456\n",
		"off=true|false|false|false|||enable:000000,enable:123456,confirm:true\n",
		"legacy=true|false|false|true|||\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
}
