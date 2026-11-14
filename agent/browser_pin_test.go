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

	"anypc/ui"
)

// cdpPin — панель сессии во весь экран: без булавки прячется за край (мышь ушла, выждали дольше перехода),
// при наведении выезжает; с булавкой видна всегда и не накрывает видео; состояние переживает перезагрузку.
const cdpPin = `
const [, , port, url] = process.argv;
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const tab = await (await fetch('http://127.0.0.1:' + port + '/json/new?' + url, { method: 'PUT' })).json();
  const ws = new WebSocket(tab.webSocketDebuggerUrl); await new Promise(r => ws.onopen = r);
  let id = 0; const wait = {};
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && wait[m.id]) wait[m.id](m); };
  const cmd = (method, params = {}) => new Promise(r => { const i = ++id; wait[i] = m => r(m.result); ws.send(JSON.stringify({ id: i, method, params })); });
  const ev = async x => (await cmd('Runtime.evaluate', { expression: x, awaitPromise: true, returnByValue: true }))?.result?.value;
  const mouse = (x, y) => cmd('Input.dispatchMouseEvent', { type: 'mouseMoved', x, y });
  await cmd('Emulation.setDeviceMetricsOverride', { width: 1280, height: 800, deviceScaleFactor: 1, mobile: false });
  // переход выключен: в фоновой вкладке headless кадры не идут и анимация стоит на месте. Панель видна: низ #bar ниже 20 px (спрятанная оставляет полоску 4 px); видео не под ней
  const bar = async () => { await sleep(1200); return ev("(() => { const b = document.getElementById('bar').getBoundingClientRect(), v = document.getElementById('v').getBoundingClientRect(); return (b.bottom > 20) + ',' + (v.top >= b.bottom - 1); })()"); };
  const fs = async () => { await sleep(1500); await ev("document.getElementById('home').classList.add('hidden'); document.getElementById('sess').classList.remove('hidden'); document.head.appendChild(document.createElement('style')).textContent = '#bar { transition: none !important; }'; setFs(true); 1"); };
  const btn = () => ev("(b => b.getAttribute('aria-pressed') + ',' + b.title + ',' + b.getAttribute('aria-label') + ',' + document.body.classList.contains('fs'))(document.getElementById('pinbtn'))");
  await fs();
  await mouse(640, 600); const off = await bar();
  await mouse(300, 2); const hover = await bar();
  await mouse(640, 600); const away = await bar();
  console.log('unpinned=' + await btn() + '|' + off + '|' + hover + '|' + away);
  await ev("document.getElementById('pinbtn').click(); 1"); await mouse(640, 600);
  console.log('pinned=' + await btn() + '|' + await bar() + '|' + await ev("localStorage.getItem('pinbar') + ',' + (document.activeElement && document.activeElement.id)"));
  await ev("location.reload(); 1"); await fs(); await mouse(640, 600);
  console.log('reload=' + await btn() + '|' + await bar());
  await ev("document.getElementById('pinbtn').click(); 1"); await mouse(640, 600);
  console.log('unpin=' + await btn() + '|' + await bar());
  await ev("location.reload(); 1"); await fs(); await mouse(640, 600);
  console.log('reload2=' + await btn() + '|' + await bar());
  process.exit(0);
})();`

// TestBrowserPin — булавка слева от «Разорвать» (канбан): закреплённая панель во весь экран не прячется ни при
// уходе мыши, ни спустя время; откреплённая — прячется как раньше; pinbar переживает перезагрузку.
func TestBrowserPin(t *testing.T) {
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
	srv := httptest.NewServer(http.FileServer(http.FS(ui.FS)))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out := string(runCDP(t, ctx, chrome, cdpPin, srv.URL+"/"))
	for _, want := range []string{
		"unpinned=false,Pin the bar,Pin the bar,true|false,false|true,false|false,false", // прячется; наведение — выезжает поверх видео
		"pinned=true,Unpin the bar,Unpin the bar,true|true,true|1,v",                     // видна, видео под ней; фокус вернулся видео (перехват клавиш)
		"reload=true,Unpin the bar,Unpin the bar,true|true,true",
		"unpin=false,Pin the bar,Pin the bar,true|false,false",
		"reload2=false,Pin the bar,Pin the bar,true|false,false",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
}
