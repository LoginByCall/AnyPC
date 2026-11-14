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

// cdpUIState — окна с разным localStorage (свои контексты браузера, как браузер и WKWebView / окно ПК).
// A: прежняя версия оставила в localStorage mine (старый формат — массив ID), users, turbo; новая страница отдаёт их в Go.
// B: пустое хранилище — видит то же из Go; переименовывает ПК. A после перезагрузки — с новым именем (Go побеждает).
// C: как на Windows (настроек в странице нет, uiGet) — Go побеждает за одну перезагрузку.
// F/G: оба открыты, каждый добавляет ПК — обе правки остаются (приёмка: оставался только второй); F видит правку G по focus.
// W (base2): Windows, mine в Go с другим порядком полей и stats=null — не бесконечная перезагрузка (приёмка: 113 за 5 с).
// R (base3): recent=5 в Go — основной скрипт жив (приёмка: окно мертво при каждом запуске).
const cdpUIState = `
const [, , port, base, base2, base3] = process.argv;
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const ver = await (await fetch('http://127.0.0.1:' + port + '/json/version')).json();
  const ws = new WebSocket(ver.webSocketDebuggerUrl); await new Promise(r => ws.onopen = r);
  let id = 0; const wait = {}, loads = {};
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && wait[m.id]) wait[m.id](m);
    if (m.method === 'Page.loadEventFired') loads[m.sessionId] = (loads[m.sessionId] || 0) + 1; };
  const call = (method, params = {}, sessionId) => new Promise(r => { const i = ++id; wait[i] = m => r(m.result); ws.send(JSON.stringify({ id: i, method, params, sessionId })); });
  const win = async () => {
    const { browserContextId } = await call('Target.createBrowserContext');
    const { targetId } = await call('Target.createTarget', { url: 'about:blank', browserContextId });
    const { sessionId } = await call('Target.attachToTarget', { targetId, flatten: true });
    await call('Page.enable', {}, sessionId);
    const ev = async x => (await call('Runtime.evaluate', { expression: x, awaitPromise: true, returnByValue: true }, sessionId))?.result?.value;
    const go = async url => { await call('Page.navigate', { url }, sessionId);
      for (let i = 0; i < 50; i++) { await sleep(100); if (await ev("document.readyState === 'complete' && typeof myPcs === 'object'")) break; }
      await sleep(500); }; // записи в Go (uiQ) уходят после загрузки
    const hide = () => call('Page.addScriptToEvaluateOnNewDocument', { source: "Object.defineProperty(window, 'ANYPC_UI', { set() {}, get() {} })" }, sessionId);
    return { ev, go, hide, loads: () => loads[sessionId] || 0 };
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
  const c = await win(); await c.go(base + '/blank'); await c.hide();
  await c.ev("localStorage.setItem('mine', JSON.stringify([{ id: '123456789', name: 'Old' }])); 1");
  await c.go(base + '/?t=tokui'); await sleep(1500);
  console.log('C=' + await c.ev("(window.ANYPC_UI === undefined) + '|' + myPcs.label('123456789') + '|' + uiOn"));
  const f = await win(), g = await win(); await f.go(base + '/?t=tokui'); await g.go(base + '/?t=tokui');
  await f.ev("myPcs.add('111111111'); 1"); await sleep(500);
  await g.ev("myPcs.add('222222222'); 1"); await sleep(500);
  await f.ev("dispatchEvent(new Event('focus')); 1"); await sleep(500);
  console.log('F=' + await f.ev("myPcs.get().map(p => p.id).join() + '|' + document.getElementById('mine').textContent.includes('222 222 222')"));
  await g.ev("store.set('turn', 'x'.repeat(70000)); 1"); await sleep(500);
  console.log('Gerr=' + await g.ev("document.getElementById('msg').textContent.length > 0 && localStorage.getItem('turn').length > 70000"));
  const w = await win(); await w.go(base2 + '/blank'); await w.hide(); const n0 = w.loads();
  await w.go(base2 + '/?t=tokui'); await sleep(3000);
  console.log('W=' + (w.loads() - n0) + '|' + await w.ev("uiOn + '|' + myPcs.label('123456789')"));
  const r = await win(); await r.go(base3 + '/?t=tokui');
  console.log('R=' + await r.ev("(() => { try { return typeof myPcRender + '|' + document.getElementById('recentbox').classList.contains('hidden'); } catch (e) { return 'DEAD:' + e; } })()"));
  process.exit(0);
})();`

// TestBrowserUIState: перенос localStorage окна прежней версии в config.json и одни данные во всех окнах
// (headless Chrome, свои контексты браузера — как разные профили); регрессии приёмки (см. cdpUIState).
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
	serve := func() (*config, string) {
		cfg, _ := loadConfig(filepath.Join(t.TempDir(), "config.json"))
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		addr := l.Addr().String()
		page, _ := shimmed("ws://127.0.0.1:1/ws", "tokui") // хабов нет: страница не выходит в сеть
		info := func() map[string]any {
			return map[string]any{"id": cfg.ID, "users": []any{}, "keys": []any{}, "version": "test"}
		}
		go http.Serve(l, handler(addr, "tokui", page, cfg, &agent.Agent{}, nil, info, newFiles(t.TempDir()), nil))
		return cfg, "http://" + addr
	}
	cfg, base := serve()
	cfgW, base2 := serve()
	cfgW.uiSet("mine", `[{"name":"Office","id":"123456789"}]`) // порядок полей не тот, что у страницы
	cfgW.UI["stats"] = "null"                                  // в обход uiValid: как файл прежней сборки
	cfgR, base3 := serve()
	cfgR.UI = uiMap{"recent": "5"}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
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
	b, err := exec.CommandContext(ctx, "node", js, port, base, base2, base3).CombinedOutput()
	out := string(b)
	t.Logf("%s", out)
	if err != nil {
		t.Fatal(err)
	}
	mine := `[{"id":"123456789","name":"123456789"}]` // старый формат страница переписала в новый — и он в Go
	for _, c := range []struct{ want, why string }{
		{"A=" + mine, "окно A: mine не в новом формате"},
		{"B=" + mine + `|{"123456789":"ivan"}|false`, "окно B не видит mine, users и Турбо окна A"},
		{"A2=Office", "правка окна B не видна в окне A после перезагрузки"},
		{"C=true|Office|true", "окно без настроек в странице (Windows): Go не победил или запись в Go не включилась"},
		{"F=123456789,111111111,222222222|true", "правка одного из двух открытых окон потеряна или не видна по focus"},
		{"Gerr=true", "отказ uiSet не показан или правка ушла из кэша"},
		{"R=function|true", "recent=5 уронил основной скрипт"},
	} {
		if !strings.Contains(out, c.want) {
			t.Error(c.why)
		}
	}
	if !strings.Contains(out, "W=1|true|Office") && !strings.Contains(out, "W=2|true|Office") {
		t.Error("Windows: перезагрузок больше двух или запись в Go не включилась")
	}
	g := cfg.uiGet()
	if g["mine"] != `[{"id":"123456789","name":"Office"},{"id":"111111111","name":"111111111"},{"id":"222222222","name":"222222222"}]` ||
		g["turbo"] != "0" || g["users"] != `{"123456789":"ivan"}` {
		t.Errorf("в config.json: %v", g)
	}
	if _, ok := g["stats"]; ok { // statShow при загрузке не пишет (config.json с секретами — не на каждое открытие окна)
		t.Error("stats записан без действия пользователя")
	}
}
