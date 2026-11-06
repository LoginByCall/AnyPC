package agent

import (
	"context"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"anypc/hub"
	"anypc/ui"
)

// cdpScript ведёт веб-клиент в headless Chrome через DevTools Protocol:
// неверный пароль → ошибка; затем верный → открыт экран сессии. Печатает итог каждого шага.
const cdpScript = `
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
  await ev("document.getElementById('id').value='123456789'; document.getElementById('pw').value='wrong-pass'; document.getElementById('go').click()");
  console.log('wrong=' + await until(s => s.includes('rror')));
  await ev("document.getElementById('pw').value='secret123'; document.getElementById('go').click()");
  console.log('right=' + await until(s => s.endsWith('|true')));
  process.exit(0);
})();`

// TestBrowserClient — регрессия: веб-клиент не входил (pake.wasm «не загружен»), и неудача запоминалась.
func TestBrowserClient(t *testing.T) {
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
	go newAgent("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", "123456789", FFArgs("test", "libx264", 30, "1M")).Run(ctx)

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	prof, _ := os.MkdirTemp("", "anypc-chrome-") // не t.TempDir: дочерние процессы Chrome пишут в профиль и после Kill
	defer os.RemoveAll(prof)
	ch := exec.CommandContext(ctx, chrome, "--headless=new", "--disable-gpu", "--lang=en-US",
		"--remote-debugging-port="+port, "--user-data-dir="+prof, "about:blank")
	if err := ch.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { ch.Process.Kill(); ch.Wait() }()
	time.Sleep(2 * time.Second)
	js := filepath.Join(t.TempDir(), "cdp.js")
	os.WriteFile(js, []byte(cdpScript), 0o600)
	out, err := exec.CommandContext(ctx, "node", js, port, srv.URL+"/").CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "wrong=Error: wrong password|false") {
		t.Error("неверный пароль: ждали «wrong password» и без сессии")
	}
	if !strings.Contains(string(out), "|true") || !strings.Contains(string(out), "right=") {
		t.Error("верный пароль после неверного: сессия не открылась")
	}
}
