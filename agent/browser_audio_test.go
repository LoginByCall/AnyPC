package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"anypc/hub"
	"anypc/ui"
)

// cdpAudio — вкладка «окно хоста» (hostInfo / audioAnswer / audioMic через /api теста) и вкладка клиента.
// Печатает байты звука, принятые каждой стороной: при выключенных микрофонах и после включения обоих.
const cdpAudio = `
const [, , port, url] = process.argv;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const open = async (u, shim) => {
  const tab = await (await fetch('http://127.0.0.1:' + port + '/json/new?about:blank', { method: 'PUT' })).json();
  const ws = new WebSocket(tab.webSocketDebuggerUrl); await new Promise(r => ws.onopen = r);
  let id = 0; const wait = {};
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && wait[m.id]) wait[m.id](m); };
  const cmd = (method, params = {}) => new Promise(r => { const i = ++id; wait[i] = m => r(m.result); ws.send(JSON.stringify({ id: i, method, params })); });
  await cmd('Page.enable');
  if (shim) await cmd('Page.addScriptToEvaluateOnNewDocument', { source: shim });
  await cmd('Page.navigate', { url: u });
  await sleep(1500);
  return async x => (await cmd('Runtime.evaluate', { expression: x, awaitPromise: true, returnByValue: true }))?.result?.value;
};
const shim = "for (const n of ['hostInfo', 'audioAnswer', 'audioMic']) window[n] = async (...a) => { const r = await fetch('/api/' + n, { method: 'POST', body: JSON.stringify(a) }); if (!r.ok) throw new Error(await r.text()); return r.json(); };" +
  "localStorage.setItem('tour_home','1'); localStorage.setItem('tour_sess','1');";
const bytes = "(async () => { let b = 0; if (au.pc) (await au.pc.getStats()).forEach(s => { if (s.type === 'inbound-rtp' && s.kind === 'audio') b += s.bytesReceived; }); return b; })()";
(async () => {
  const host = await open(url, shim);
  const cl = await open(url, "localStorage.setItem('tour_home','1'); localStorage.setItem('tour_sess','1');");
  await cl("document.getElementById('id').value='123456789'; document.getElementById('pw').value='secret123'; document.getElementById('go').click()");
  for (let i = 0; i < 100 && !(await host("!document.getElementById('hmic').classList.contains('hidden')")); i++) await sleep(200);
  console.log('mic_btn=' + await cl("!document.getElementById('mic').classList.contains('hidden')") + ' hmic_btn=' + await host("!document.getElementById('hmic').classList.contains('hidden')"));
  for (let i = 0; i < 50 && (await cl("au.pc?.connectionState")) !== 'connected'; i++) await sleep(200);
  console.log('state=' + await cl("au.pc?.connectionState") + '/' + await host("au.pc?.connectionState"));
  await sleep(2000);
  console.log('off: client=' + await cl(bytes) + ' host=' + await host(bytes));
  await cl("micToggle(document.getElementById('mic'))"); await host("micToggle(document.getElementById('hmic'))");
  await sleep(3000);
  console.log('on: client=' + await cl(bytes) + ' host=' + await host(bytes) + ' btn=' + await cl("document.getElementById('mic').classList.contains('on')") + '/' + await host("document.getElementById('hmic').classList.contains('on')"));
  await host("micToggle(document.getElementById('hmic'))"); await sleep(500);
  console.log('host_off=' + await host("document.getElementById('hmic').classList.contains('on')"));
  process.exit(0);
})();`

// TestBrowserAudio — звук (PLAN.md, REQ-F-21): кнопки 🎤 у клиента и в окне хоста, пока микрофоны выключены — звук
// не идёт (по умолчанию выключены, владелец 2026-11-10), после включения — идёт в обе стороны; окно хоста сообщает хосту
// о своём микрофоне (REQ-F-22).
func TestBrowserAudio(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	hubURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	a := newAgent(hubURL, "123456789", nil)
	a.FileDir = t.TempDir()
	a.Audio = true
	a.Capture = func(ctx context.Context, c Cap) (*exec.Cmd, error) {
		return exec.CommandContext(ctx, "ffmpeg", FFArgs("test", "libx264", c)...), nil
	}
	mic := make(chan bool, 4)
	mux.Handle("/ws", &hub.Hub{})
	mux.HandleFunc("/hubs", func(w http.ResponseWriter, _ *http.Request) { json.NewEncoder(w).Encode([]string{hubURL}) })
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { // мост окна хоста, как api() в app
		var args []json.RawMessage
		json.NewDecoder(r.Body).Decode(&args)
		str := func(i int) (s string) { json.Unmarshal(args[i], &s); return }
		var res any = true
		switch strings.TrimPrefix(r.URL.Path, "/api/") {
		case "hostInfo":
			m := map[string]any{"id": a.ID, "online": true, "session": "x"}
			if cid, sdp := a.AudioPending(); sdp != "" {
				m["audio"] = map[string]any{"cid": cid, "sdp": sdp, "ice": a.AudioICE()}
			}
			res = m
		case "audioAnswer":
			if err := a.AudioAnswer(str(0), str(1)); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
		case "audioMic":
			var on bool
			json.Unmarshal(args[0], &on)
			a.AudioMic(on)
			mic <- on
		}
		json.NewEncoder(w).Encode(res)
	})
	mux.Handle("/", http.FileServer(http.FS(ui.FS)))
	go a.Run(ctx)
	out := string(runCDP(t, ctx, chrome, cdpAudio, srv.URL+"/", "--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream", "--autoplay-policy=no-user-gesture-required"))
	for _, want := range []string{"mic_btn=true hmic_btn=true", "state=connected/connected", "off: client=0 host=0", "btn=true/true", "host_off=false"} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	var cb, hb int
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "on: ") {
			fmt.Sscanf(l, "on: client=%d host=%d", &cb, &hb)
		}
	}
	if cb < 1000 || hb < 1000 {
		t.Errorf("после включения микрофонов принято байт звука: клиент %d, хост %d — ждали > 1000 у обоих", cb, hb)
	}
	if len(mic) != 2 || !<-mic || <-mic {
		t.Error("окно хоста не сообщило хосту о своём микрофоне (вкл, затем выкл)")
	}
}
