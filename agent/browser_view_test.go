package agent

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"anypc/hub"
	"anypc/ui"
)

const cdpVisual = `
const [, , port, url] = process.argv; const dir = process.env.SHOTS;
const fs = require('fs');
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const tab = await (await fetch('http://127.0.0.1:' + port + '/json/new?' + url, { method: 'PUT' })).json();
  const ws = new WebSocket(tab.webSocketDebuggerUrl); await new Promise(r => ws.onopen = r);
  let id = 0; const wait = {};
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && wait[m.id]) wait[m.id](m); };
  const cmd = (method, params = {}) => new Promise(r => { const i = ++id; wait[i] = m => r(m.result); ws.send(JSON.stringify({ id: i, method, params })); });
  const ev = async x => (await cmd('Runtime.evaluate', { expression: x, awaitPromise: true, returnByValue: true }))?.result?.value;
  const shot = async n => { if (!dir) return; const r = await cmd('Page.captureScreenshot', { format: 'png' }); fs.writeFileSync(dir + '/' + n + '.png', Buffer.from(r.data, 'base64')); console.log('shot ' + n); };
  const dark = on => cmd('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: on ? 'dark' : 'light' }] });
  const vis = sel => ev("(e => !!e && e.getClientRects().length > 0)(document.querySelector('" + sel + "'))");
  const sess = () => ev("!document.getElementById('sess').classList.contains('hidden')");
  const until = async (f, n = 100) => { for (let i = 0; i < n; i++) { if (await f()) return true; await sleep(200); } return false; };
  await cmd('Emulation.setDeviceMetricsOverride', { width: 1280, height: 800, deviceScaleFactor: 1, mobile: false });
  await sleep(1500);
  console.log('tour_home=' + await vis('#tip'));
  await shot('01-home-tour');
  await ev("document.getElementById('tipnext').click()"); await sleep(300); await shot('02-home-tour-step2');
  await ev("document.getElementById('tipskip').click()"); await sleep(300);
  await ev("document.getElementById('helpbtn').click()"); await sleep(400);
  console.log('help=' + await vis('#help .dlg') + ' sections=' + await ev("document.querySelectorAll('#helpbody h3, #helpbody details, #helpbody section').length"));
  // Windows: ссылка на сайт из справки — openSite (главная), а не openUpdate (раздел загрузки)
  await ev("window.openSite = () => (window.opened = 'site'); window.openUpdate = () => (window.opened = 'update'); document.querySelector('#helpbody a').click(); 1");
  console.log('help_link=' + await ev("window.opened"));
  await shot('03-help-light'); await dark(true); await sleep(300); await shot('04-help-dark'); await dark(false);
  await ev("document.getElementById('helpx').click()");
  await ev("document.getElementById('id').value='123456789'; document.getElementById('pw').value='secret123'; document.getElementById('go').click()");
  console.log('session=' + await until(sess));
  await sleep(1500);
  console.log('tour_sess=' + await vis('#tip'));
  await shot('05-session-tour');
  await ev("document.getElementById('tipskip').click()"); await sleep(300);
  await ev("for (let k = 0; k < 6; k++) sendFile(new File([new Uint8Array(30e6).map((_, i) => i % 251)], 'big' + k + '.bin')); 1");
  await sleep(700);
  console.log('ring=' + await vis('#dl') + ' cnt=' + await ev("document.getElementById('dlcnt').textContent") + ' dash=' + await ev("getComputedStyle(document.getElementById('dlring')).strokeDashoffset"));
  await shot('06-ring-progress');
  await ev("document.getElementById('dlbtn').click()"); await sleep(300);
  await shot('07-list-progress');
  await until(async () => (await ev("document.getElementById('dlpop').textContent.split('✓').length - 1")) >= 6, 300);
  console.log('list=' + await ev("document.getElementById('dlpop').innerText.replace(/\\n/g, ' | ')"));
  await shot('08-list-done'); await dark(true); await sleep(300); await shot('09-list-done-dark'); await dark(false);
  // «Только просмотр»: выйти, включить галочку, войти снова
  await ev("document.getElementById('bye').click()"); await sleep(1500);
  console.log('eye=' + await ev("document.querySelector('[data-eye=pw]').click(); const a = document.getElementById('pw').type; document.querySelector('[data-eye=pw]').click(); a + '/' + document.getElementById('pw').type"));
  await ev("document.getElementById('view').checked = true; document.getElementById('pw').value='secret123'; document.getElementById('go').click()");
  console.log('view_session=' + await until(sess));
  await sleep(2500);
  console.log('view_body=' + await ev("document.body.classList.contains('view')") + ' keys_btn=' + await vis('[data-keys]') + ' fsend=' + await vis('#fsend') + ' clipbtn=' + await vis('#clipbtn'));
  console.log('view_status=' + await ev("document.getElementById('st').textContent"));
  console.log('stat_hidden=' + !(await vis('#csv')) + ' view_mark=' + await vis('#st')); // статистика по умолчанию скрыта, «только просмотр» видно
  await ev("document.getElementById('statbtn').click()"); await sleep(200);
  console.log('stat_shown=' + await vis('#csv'));
  await ev("document.getElementById('statbtn').click()"); await sleep(200);
  // залипший Super (отпускание забрала система) отпускается при следующем нажатии; Ctrl+Alt+Enter — полный экран, не на удалённый ПК
  console.log('mods=' + await ev("(() => { const out = [], o = dc.send; dc.send = x => { const m = JSON.parse(x); m.t === 'k' && out.push(m.c + (m.d ? '+' : '-')); }; try { const k = (code, mods = {}) => document.dispatchEvent(new KeyboardEvent('keydown', { code, ...mods, bubbles: true, cancelable: true })); k('MetaLeft', { metaKey: true }); k('KeyA'); k('ControlLeft', { ctrlKey: true }); k('AltLeft', { ctrlKey: true, altKey: true }); k('Enter', { ctrlKey: true, altKey: true }); return out.join(' ') + ' full=' + full; } finally { dc.send = o; setFs(false); } })()"));
  await ev("Object.defineProperty(navigator, 'clipboard', { value: { readText: async () => 'view-clip', writeText: async () => {} } }); clipBtn(); 1");
  await ev("sendFile(new File([new Uint8Array(1000)], 'view.bin'))");
  await until(async () => /view\.bin[^|]*[✓✗]/.test(await ev("document.getElementById('dlpop').innerText.replace(/\\n/g, ' | ')")), 50);
  await ev("document.getElementById('dlbtn').click()"); await sleep(300);
  console.log('view_list=' + await ev("document.getElementById('dlpop').innerText.replace(/\\n/g, ' | ')"));
  await shot('10-view-only');
  process.exit(0);
})();`

// TestBrowserView — тур, справка, индикатор передач (6 файлов: сверх 4 ждут очереди), «Только просмотр»:
// кнопки скрыты, буфер не уходит, отказ в файле — на языке интерфейса (регрессия: показывался русский текст хоста).
// SHOTS=<папка> — снимки экрана в светлой и тёмной теме для ручного осмотра.
func TestBrowserView(t *testing.T) {
	chrome, err := exec.LookPath("google-chrome")
	if err != nil {
		t.Skip("нет google-chrome")
	}
	for _, b := range []string{"node", "ffmpeg"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skip("нет " + b)
		}
	}
	if _, err := fs.Stat(ui.FS, "pake.wasm"); err != nil {
		t.Skip("нет ui/pake.wasm — собрать через build.sh")
	}
	mux := http.NewServeMux()
	mux.Handle("/ws", &hub.Hub{})
	mux.Handle("/", http.FileServer(http.FS(ui.FS)))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/hubs", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]string{"ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	var mu sync.Mutex
	var clips []string
	setClip = func(s string) error { mu.Lock(); clips = append(clips, s); mu.Unlock(); return nil }
	defer func() { setClip = SetClipText }()
	a := newAgent("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", "123456789", nil)
	a.FileDir = t.TempDir()
	a.Capture = func(ctx context.Context, c Cap) (*exec.Cmd, error) {
		return exec.CommandContext(ctx, "ffmpeg", FFArgs("test", "libx264", c)...), nil
	}
	go a.Run(ctx)
	out := string(runCDP(t, ctx, chrome, cdpVisual, srv.URL+"/"))
	for _, want := range []string{"tour_home=true", "tour_sess=true", "help=true sections=10", "help_link=site", "session=true", "ring=true cnt=6", "view_session=true",
		"view_body=true keys_btn=false fsend=false clipbtn=false", "view only",
		"eye=text/password", "stat_hidden=true view_mark=true", "stat_shown=true",
		"mods=MetaLeft+ MetaLeft- KeyA+ ControlLeft+ AltLeft+ KeyA- ControlLeft- AltLeft- full=true", "view.bin | ✗ View only: files are not sent"} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if n := strings.Count(out, "✓ saved to Downloads"); n < 6 {
		t.Errorf("передано %d файлов из 6 (очередь приёма на хосте)", n)
	}
	for k := 0; k < 6; k++ {
		if i, err := os.Stat(filepath.Join(a.FileDir, "big"+strconv.Itoa(k)+".bin")); err != nil || i.Size() != 30e6 {
			t.Errorf("big%d.bin на хосте: %v", k, err)
		}
	}
	if _, err := os.Stat(filepath.Join(a.FileDir, "view.bin")); err == nil {
		t.Error("в режиме просмотра файл дошёл до хоста")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(clips) > 0 {
		t.Errorf("в режиме просмотра буфер дошёл до хоста: %q", clips)
	}
}
