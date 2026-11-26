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

// fakeTakenHub — хаб: после challenge отвечает id_taken (taken) или рвёт связь без ответа.
func fakeTakenHub(taken bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		}
	}))
}

// firstTaken — Run до первого состояния: IDTaken() в нём; Run остановлен и завершён.
func firstTaken(t *testing.T, a *Agent, srv *httptest.Server) bool {
	t.Helper()
	a.Server = "ws" + strings.TrimPrefix(srv.URL, "http")
	states := make(chan bool, 16)
	a.OnState = func(bool, string) { states <- a.IDTaken() }
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	var got bool
	select {
	case got = <-states:
	case <-ctx.Done():
		t.Error("состояние не пришло")
	}
	cancel() // в паузе 5 с после отказа — как смена узла в окне (runner.start)
	<-done
	return got
}

// IDTaken: хаб ответил id_taken (живой случай владельца 2026-11-14: работала старая копия) — true; просто обрыв — false.
func TestIDTaken(t *testing.T) {
	taken, drop := fakeTakenHub(true), fakeTakenHub(false)
	defer taken.Close()
	defer drop.Close()
	if !firstTaken(t, newAgent("", "123456789", nil), taken) {
		t.Error("id_taken: IDTaken() = false")
	}
	if firstTaken(t, newAgent("", "123456789", nil), drop) {
		t.Error("обрыв: IDTaken() = true")
	}
	// регрессия (приёмка 2026-11-14): смена узла в паузе после id_taken — отказ старого хаба не остаётся навсегда
	a := newAgent("", "123456789", nil)
	firstTaken(t, a, taken)
	if firstTaken(t, a, drop) {
		t.Error("после смены узла окно всё ещё «ID уже в сети»: отказ прошлого хаба не сброшен")
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
    window.S = { id: '123456789', confirm: true, otp: false, hasPass: true, users: [], online: false, idTaken: true, give: true };
    window.hostInfo = async () => JSON.parse(JSON.stringify(S));
  ` + "`" + ` });
  await call('Page.navigate', { url }); await sleep(1500);
  console.log('taken=' + await ev("onHostState(S); document.getElementById('mystate').textContent"));
  console.log('drop=' + await ev("S.idTaken = false; onHostState(S); document.getElementById('mystate').textContent"));
  process.exit(0);
})();`
