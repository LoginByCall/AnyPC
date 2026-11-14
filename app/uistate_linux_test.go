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

// cdpUIState — два окна с разным localStorage (свои контексты браузера, как браузер и WKWebView / окно ПК).
// A: прежняя версия оставила в localStorage mine (старый формат — массив ID), users, turbo; новая страница отдаёт их в Go.
// B: пустое хранилище — видит то же из Go; переименовывает ПК. A после перезагрузки — с новым именем (Go побеждает).
const cdpUIState = `
const [, , port, base] = process.argv;
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const ver = await (await fetch('http://127.0.0.1:' + port + '/json/version')).json();
  const ws = new WebSocket(ver.webSocketDebuggerUrl); await new Promise(r => ws.onopen = r);
  let id = 0; const wait = {};
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && wait[m.id]) wait[m.id](m); };
  const call = (method, params = {}, sessionId) => new Promise(r => { const i = ++id; wait[i] = m => r(m.result); ws.send(JSON.stringify({ id: i, method, params, sessionId })); });
  const win = async () => {
    const { browserContextId } = await call('Target.createBrowserContext');
    const { targetId } = await call('Target.createTarget', { url: 'about:blank', browserContextId });
    const { sessionId } = await call('Target.attachToTarget', { targetId, flatten: true });
    const ev = async x => (await call('Runtime.evaluate', { expression: x, awaitPromise: true, returnByValue: true }, sessionId))?.result?.value;
    const go = async url => { await call('Page.navigate', { url }, sessionId);
      for (let i = 0; i < 50; i++) { await sleep(100); if (await ev("document.readyState === 'complete' && typeof myPcs === 'object'")) break; }
      await sleep(500); }; // записи в Go (uiQ) уходят после загрузки
    const hide = async () => await call('Page.enable', {}, sessionId) && call('Page.addScriptToEvaluateOnNewDocument', { source: "Object.defineProperty(window, 'ANYPC_UI', { set() {}, get() {} })" }, sessionId);
    return { ev, go, hide };
  };
  const a = await win(), b = await win();
  await a.go(base + '/blank');
  await a.ev("localStorage.setItem('mine', '[\"123456789\"]'); localStorage.setItem('users', '{\"123456789\":\"ivan\"}'); localStorage.setItem('turbo', '0'); 1");
  await a.go(base + '/?t=tokui');
  console.log('A=' + await a.ev("localStorage.getItem('mine')"));
  await b.go(base + '/?t=tokui');
  console.log('B=' + await b.ev("localStorage.getItem('mine') + '|' + localStorage.getItem('users') + '|' + document.getElementById('turbo').checked"));
  await b.ev("myPcs.rename('123456789', 'Office'); 1"); await sleep(500);
  await a.go(base + '/?t=tokui');
  console.log('A2=' + await a.ev("myPcs.label('123456789')"));
  // C — как на Windows: настроек в странице нет, страница берёт их uiGet; в localStorage старое имя — Go побеждает, одна перезагрузка
  const c = await win(); await c.go(base + '/blank'); await c.hide();
  await c.ev("localStorage.setItem('mine', JSON.stringify([{ id: '123456789', name: 'Old' }])); 1");
  await c.go(base + '/?t=tokui'); await sleep(1500);
  console.log('C=' + await c.ev("(window.ANYPC_UI === undefined) + '|' + myPcs.label('123456789') + '|' + uiOn"));
  process.exit(0);
})();`

// TestBrowserUIState: перенос localStorage окна прежней версии в config.json и одни данные во всех окнах
// (headless Chrome, свои контексты браузера — как разные профили).
func TestBrowserUIState(t *testing.T) {
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
	info := func() map[string]any {
		return map[string]any{"id": cfg.ID, "users": []any{}, "keys": []any{}, "version": "test"}
	}
	go http.Serve(l, handler(addr, "tokui", page, cfg, &agent.Agent{}, nil, info, newFiles(t.TempDir()), nil))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pl, _ := net.Listen("tcp", "127.0.0.1:0")
	port := strconv.Itoa(pl.Addr().(*net.TCPAddr).Port)
	pl.Close()
	prof, _ := os.MkdirTemp("", "anypc-chrome-")
	defer os.RemoveAll(prof)
	ch := exec.CommandContext(ctx, chrome, "--headless=new", "--disable-gpu", "--remote-debugging-port="+port, "--user-data-dir="+prof, "about:blank")
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
	os.WriteFile(js, []byte(cdpUIState), 0o600)
	b, err := exec.CommandContext(ctx, "node", js, port, "http://"+addr).CombinedOutput()
	out := string(b)
	t.Logf("%s", out)
	if err != nil {
		t.Fatal(err)
	}
	mine := `[{"id":"123456789","name":"123456789"}]` // старый формат страница переписала в новый — и он в Go
	if !strings.Contains(out, "A="+mine) {
		t.Error("окно A: mine не в новом формате")
	}
	if !strings.Contains(out, "B="+mine+`|{"123456789":"ivan"}|false`) {
		t.Error("окно B не видит mine, users и Турбо окна A")
	}
	if !strings.Contains(out, "A2=Office") {
		t.Error("правка окна B не видна в окне A после перезагрузки")
	}
	if !strings.Contains(out, "C=true|Office|true") {
		t.Error("окно без настроек в странице (Windows): Go не победил или запись в Go не включилась")
	}
	if g := cfg.uiGet(); g["mine"] != `[{"id":"123456789","name":"Office"}]` || g["turbo"] != "0" || g["users"] != `{"123456789":"ivan"}` {
		t.Errorf("в config.json: %v", g)
	}
}
