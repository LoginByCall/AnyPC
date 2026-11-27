package main

import (
	"context"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"anypc/agent"
	"anypc/ui"
)

// cdpTrayJS — JS трея (trayJSPC, trayJSHere, trayJSHelp) в настоящей странице программы (shimmed + handler):
// «я тут» с экрана «Настройки» и из вкладки ПК — главный экран и фокус в #shpw; «Помочь кому-то…» — «Другой ПК»
// с фокусом в ID; ПК из трея — вкладка «Моих ПК» к нему.
const cdpTrayJS = `
const [, , port, base, jsPC, jsHere, jsHelp] = process.argv;
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const tab = await (await fetch('http://127.0.0.1:' + port + '/json/new?about:blank', { method: 'PUT' })).json();
  const ws = new WebSocket(tab.webSocketDebuggerUrl); await new Promise(r => ws.onopen = r);
  let id = 0; const wait = {};
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && wait[m.id]) wait[m.id](m); };
  const call = (method, params) => new Promise(r => { const i = ++id; wait[i] = r; ws.send(JSON.stringify({ id: i, method, params })); });
  const ev = async x => { const r = (await call("Runtime.evaluate", { expression: x, awaitPromise: true, returnByValue: true })).result; return r?.exceptionDetails ? "EXC " + JSON.stringify(r.exceptionDetails.exception?.description) : r?.result?.value; };
  const vis = i => "document.getElementById('" + i + "').checkVisibility()";
  await call('Page.enable', {});
  await call('Page.addScriptToEvaluateOnNewDocument', { source: "localStorage.setItem('tour_home', '1'); localStorage.setItem('tour_connect', '1');" });
  await call('Page.navigate', { url: base + '/?t=tokui' });
  for (let i = 0; i < 50 && await ev("typeof myPcHome === 'function' && " + vis('mhere')) !== true; i++) await sleep(100);
  await ev("document.getElementById('setgo').click(); 1"); await sleep(200);
  const s0 = await ev(vis('settings'));
  await ev(jsHere); await sleep(200);
  console.log('here=' + s0 + '|' + await ev("[" + vis('home') + ", " + vis('settings') + ", document.activeElement.id].join('|')"));
  await ev(jsHelp); await sleep(200);
  console.log('help=' + await ev("[" + vis('connect') + ", " + vis('home') + ", document.activeElement.id].join('|')"));
  await ev(jsPC); await sleep(500);
  console.log('pc=' + await ev("[[...document.querySelectorAll('#frames iframe')].map(f => new URL(f.src, location.href).searchParams.get('embed')).join(','), " + vis('mypc') + ", " + vis('home') + "].join('|')"));
  await ev(jsHere); await sleep(200);
  console.log('here2=' + await ev("[" + vis('home') + ", " + vis('mypc') + ", document.activeElement.id, document.querySelectorAll('#frames iframe').length].join('|')"));
  // «Помочь кому-то…» из вкладки ПК: «Другой ПК» не поверх вкладок — вкладки спрятаны, «Назад» — главный
  await ev(jsPC); await sleep(300);
  const tabv = await ev(vis('mypc'));
  await ev(jsHelp); await sleep(200);
  const h1 = await ev("[" + vis('connect') + ", " + vis('mypc') + ", " + vis('home') + "].join('|')");
  await ev("document.getElementById('connback').click(); 1"); await sleep(200);
  console.log('helptab=' + tabv + '|' + h1 + '/' + await ev("[" + vis('home') + ", " + vis('mypc') + "].join('|')"));
  // своя сессия в окне (myPcHome() === false): ни один JS трея окно не меняет, фокус остаётся на видео
  await ev("show(true); document.getElementById('v').focus(); 1"); await sleep(200);
  const own = () => ev("[" + vis('sess') + ", " + vis('connect') + ", " + vis('home') + ", " + vis('mypc') + ", document.activeElement.id, document.querySelectorAll('#frames iframe').length].join('|')");
  const o0 = await own();
  const out = [];
  for (const js of [jsHelp, jsPC, jsHere]) { await ev(js); await sleep(300); out.push(await own()); }
  console.log('ownsess=' + o0 + '/' + out.join('/'));
  await ev("show(false); 1");
  // свежее окно из трея: JS — на DOMContentLoaded (как trayNav), строка «Я тут» появляется после первого hostInfo — фокус её дожидается
  await call('Page.addScriptToEvaluateOnNewDocument', { source: "addEventListener('DOMContentLoaded', () => { " + jsHere + " });" });
  await call('Page.navigate', { url: base + '/?t=tokui' }); await sleep(2500);
  console.log('fresh=' + await ev("[" + vis('home') + ", document.activeElement.id].join('|')"));
  process.exit(0);
})();`

// TestBrowserTrayJS — JS трея в настоящей странице программы (headless Chrome).
func TestBrowserTrayJS(t *testing.T) {
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
	cfg, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	addr := l.Addr().String()
	page, _ := shimmed("ws://127.0.0.1:1/ws", "tokui") // хабов нет: страница не выходит в сеть
	info := func() map[string]any {                    // в пространстве, есть детектор блокировки: строка «Я тут» (#shpw) видна
		return map[string]any{"id": cfg.ID, "users": []any{}, "keys": []any{}, "version": "test", "online": true,
			"space": map[string]any{"in": true, "lock": true, "members": []any{map[string]any{"id": cfg.ID, "self": true, "passUntil": 0}}}}
	}
	go http.Serve(l, handler(addr, "tokui", page, cfg, &agent.Agent{}, nil, info, newFiles(t.TempDir()), nil))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pl, _ := net.Listen("tcp", "127.0.0.1:0")
	port := strconv.Itoa(pl.Addr().(*net.TCPAddr).Port)
	pl.Close()
	prof, _ := os.MkdirTemp("", "anypc-chrome-")
	defer os.RemoveAll(prof)
	ch := exec.CommandContext(ctx, chrome, "--headless=new", "--disable-gpu", "--no-proxy-server", "--disable-background-networking", "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE localhost , EXCLUDE 127.0.0.1", "--remote-debugging-port="+port, "--user-data-dir="+prof, "about:blank")
	if err := ch.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { ch.Process.Kill(); ch.Wait() }()
	for end := time.Now().Add(15 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if r, err := http.Get("http://127.0.0.1:" + port + "/json/version"); err == nil {
			r.Body.Close()
			break
		}
		if time.Now().After(end) {
			t.Fatal("Chrome не открыл порт CDP")
		}
	}
	js := filepath.Join(t.TempDir(), "cdp.js")
	os.WriteFile(js, []byte(cdpTrayJS), 0o600)
	b, err := exec.CommandContext(ctx, "node", js, port, "http://"+addr, trayJSPC("915020664"), trayJSHere, trayJSHelp).CombinedOutput()
	out := string(b)
	t.Logf("%s", out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"here=true|true|false|shgo\n",                // «я тут» из «Настроек»: главный экран, фокус на кнопке
		"help=true|false|id\n",                       // «Помочь кому-то…»: «Другой ПК», фокус в ID
		"pc=915020664|true|false\n",                  // ПК из трея: вкладка «Моих ПК»
		"here2=true|false|shgo|1\n",                  // «я тут» из вкладки ПК: главный, вкладка жива
		"helptab=true|true|false|false/true|false\n", // B3: «Помочь» из вкладки ПК — «Другой ПК» без вкладок поверх
		"ownsess=true|false|false|false|v|1/true|false|false|false|v|1/true|false|false|false|v|1/true|false|false|false|v|1\n", // B3: своя сессия — окно не меняется
		"fresh=true|shgo\n", // свежее окно: фокус на кнопке «Я тут» после первой отрисовки
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
}
