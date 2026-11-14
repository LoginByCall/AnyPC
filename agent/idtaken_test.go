package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"anypc/hub"
	"anypc/ui"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// IDTaken: хаб ответил id_taken (живой случай владельца 2026-11-14: работала старая копия) — true; просто обрыв — false.
func TestIDTaken(t *testing.T) {
	for _, taken := range []bool{true, false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer c.CloseNow()
			nonce, _ := json.Marshal("n")
			wsjson.Write(r.Context(), c, hub.Msg{V: 1, Type: "challenge", Data: nonce})
			var reg hub.Msg
			wsjson.Read(r.Context(), c, &reg)
			if taken {
				wsjson.Write(r.Context(), c, hub.Msg{V: 1, Type: "error", Data: json.RawMessage(`"id_taken"`)})
				<-r.Context().Done()
			} // иначе — обрыв без ответа
		}))
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		a := newAgent("ws"+strings.TrimPrefix(srv.URL, "http"), "123456789", nil)
		states := make(chan bool, 16)
		a.OnState = func(on bool, _ string) { states <- a.IDTaken() }
		go a.Run(ctx)
		select {
		case got := <-states:
			if got != taken {
				t.Errorf("хаб id_taken=%v: IDTaken() = %v", taken, got)
			}
		case <-ctx.Done():
			t.Errorf("хаб id_taken=%v: состояние не пришло", taken)
		}
		cancel()
		srv.Close()
	}
}

// Окно хоста: idTaken — своё сообщение, а не «нет связи с сервером»; без него — прежнее.
func TestBrowserHostIDTaken(t *testing.T) {
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
	out := string(runCDP(t, ctx, chrome, cdpHostIDTaken, srv.URL+"/"))
	for _, want := range []string{
		"taken=This ID is already online: AnyPC is running on this PC a second time (perhaps an old version — close it) or this ID is in use on another PC\n",
		"drop=no connection to the server, retrying…\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if t.Failed() {
		t.Log(out)
	}
}

const cdpHostIDTaken = `
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
    window.S = { id: '123456789', confirm: true, otp: false, hasPass: true, users: [], online: false, idTaken: true };
    window.hostInfo = async () => JSON.parse(JSON.stringify(S));
  ` + "`" + ` });
  await call('Page.navigate', { url }); await sleep(1500);
  console.log('taken=' + await ev("onHostState(S); document.getElementById('mystate').textContent"));
  console.log('drop=' + await ev("S.idTaken = false; onHostState(S); document.getElementById('mystate').textContent"));
  process.exit(0);
})();`
