package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"anypc/ui"
)

// cdpHostCode — окно хоста, режим «Спрашивать» (REQ-S-23): вместо пароля — одноразовый код по три цифры и ↻; ↻ зовёт
// newCode и показывает новый; галочку сняли (TOTP) — снова пароль, кода нет.
const cdpHostCode = `
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
    window.st = { id: '123456789', confirm: true, otp: false, hasPass: true, code: '482913', users: [] }; window.calls = [];
    window.hostInfo = async () => ({ ...st });
    window.newCode = async () => { calls.push('new'); st.code = '111222'; return st.code; };
  ` + "`" + ` });
  const vis = i => "!document.getElementById('" + i + "').classList.contains('hidden')";
  const show = () => ev("[" + vis('codebox') + ", document.getElementById('mycode').textContent, " + vis('pwrow') + ", calls.join(',')].join('|')");
  await call('Page.navigate', { url }); await sleep(1500);
  console.log('ask=' + await show());
  await ev("document.getElementById('newcode').click(); 1"); await sleep(300);
  console.log('new=' + await show());
  await ev("st.confirm = false; st.otp = true; st.code = ''; 1"); await sleep(1300); // опрос раз в 1 с
  console.log('pw=' + await show());
  process.exit(0);
})();`

// TestBrowserHostCode — окно хоста: блок одноразового кода в режиме «Спрашивать» и ↻.
func TestBrowserHostCode(t *testing.T) {
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
	out := string(runCDP(t, ctx, chrome, cdpHostCode, srv.URL+"/"))
	for _, want := range []string{"ask=true|482 913|false|\n", "new=true|111 222|false|new\n", "pw=false||true|new\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if t.Failed() {
		t.Log(out)
	}
}
