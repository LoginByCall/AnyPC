package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"anypc/ui"
)

// cdpHomeWeb — главный экран веб-клиента (привязок нет): «Передать управление» нет — справа форма входа; поле пароля
// и 👁 в одной строке внутри карточки; подпись без «Я тут»; «+» и ⚙ нет; тур — по форме на главном.
const cdpHomeWeb = `
const [, , port, url] = process.argv;
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const fs = require('fs');
  const tab = await (await fetch('http://127.0.0.1:' + port + '/json/new?about:blank', { method: 'PUT' })).json();
  const ws = new WebSocket(tab.webSocketDebuggerUrl); await new Promise(r => ws.onopen = r);
  let id = 0; const wait = {};
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && wait[m.id]) wait[m.id](m); };
  const call = (method, params) => new Promise(r => { const i = ++id; wait[i] = r; ws.send(JSON.stringify({ id: i, method, params })); });
  const ev = async x => { const r = (await call("Runtime.evaluate", { expression: x, awaitPromise: true, returnByValue: true })).result; return r?.exceptionDetails ? "EXC " + JSON.stringify(r.exceptionDetails.exception?.description) : r?.result?.value; };
  const shot = async n => { const f = process.env.ANYPC_SHOT; if (!f) return; const r = await call('Page.captureScreenshot', { format: 'png' }); fs.writeFileSync(f.replace(/\.png$/, '-' + n + '.png'), Buffer.from(r.result.data, 'base64')); console.log('shot ' + n); };
  await call('Page.enable', {});
  await call('Page.addScriptToEvaluateOnNewDocument', { source: "if (window.parent === window) { Object.defineProperty(navigator, 'languages', { get: () => ['ru'] }); localStorage.setItem('tour_home', '1'); localStorage.setItem('mine', JSON.stringify([{ id: '915020664', name: 'Ноутбук мамы' }, { id: '730554218', name: 'Дом' }])); }" });
  await call('Emulation.setDeviceMetricsOverride', { width: 1200, height: 760, deviceScaleFactor: 1, mobile: false });
  await call('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'light' }] });
  await call('Page.navigate', { url }); await sleep(1500);
  console.log('web=' + await ev("[document.getElementById('side').contains(document.getElementById('remote')), document.getElementById('me').checkVisibility(), !!document.getElementById('hadd'), document.getElementById('setgo').checkVisibility(), document.getElementById('mbweb').checkVisibility(), document.getElementById('mbapp').checkVisibility(), document.querySelectorAll('#sptiles .sptile').length].join('|')"));
  // B2: пароль и 👁 — одна строка, обе внутри карточки
  console.log('pwrow=' + await ev("(() => { const c = document.getElementById('remote').getBoundingClientRect(), p = document.getElementById('pw').getBoundingClientRect(), e = document.querySelector('[data-eye=pw]').getBoundingClientRect(); return [Math.abs(p.top - e.top) < 8, e.right <= c.right, p.right <= e.left].join('|'); })()"));
  console.log('webtour=' + await ev("TOURS.home.filter(s => tEls(s).length).map(s => s[1]).join(',')"));
  await shot('web');
  // вкладка к ПК без пароля в веб-клиенте: во фрейме — карточка входа
  await ev("document.querySelector('#sptiles .sptile[data-id=\"915020664\"] .mpcopen').click(); 1");
  const fr = "document.querySelector('#frames iframe').contentWindow.document";
  for (let k = 0; k < 50 && await ev(fr + "?.body?.classList.contains('needpw')") !== true; k++) await sleep(100);
  console.log('webframe=' + await ev("(() => { const d = " + fr + "; return [d.body.classList.contains('needpw'), d.getElementById('pw').checkVisibility(), d.getElementById('go').checkVisibility(), d.getElementById('home').checkVisibility()].join('|'); })()"));
  await shot('web-frame-nopw');
  process.exit(0);
})();`

// TestBrowserHomeWeb — главный экран веб-клиента (B2: строка пароля внутри карточки) и фрейм без пароля.
func TestBrowserHomeWeb(t *testing.T) {
	chrome := browserNeed(t, "node")
	hang := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(http.ResponseWriter, *http.Request) { <-hang })
	mux.HandleFunc("/hubs", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("[]")) })
	mux.Handle("/", http.FileServer(http.FS(ui.FS)))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	defer close(hang)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out := string(runCDP(t, ctx, chrome, cdpHomeWeb, srv.URL+"/"))
	for _, want := range []string{
		"web=true|false|false|false|true|false|2\n",
		"pwrow=true|true|true\n",
		"webtour=tour_go,tour_opts,tour_talk,tour_help\n",
		"webframe=true|true|true|false\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
}
