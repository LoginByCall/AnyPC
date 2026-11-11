package agent

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"anypc/hub"
	"anypc/ui"

	"github.com/pion/webrtc/v4"
)

// modeHost — агент с окном «Разрешить управление?», которое отвечает из ans (и считает показы), и вошедшая сессия
// с управлением; byAsk — вход через «Разрешить».
func modeHost(byAsk bool) (*Agent, *session, chan bool, *atomic.Int32) {
	a := newAgent("", "", nil)
	ans, shown := make(chan bool), new(atomic.Int32)
	a.ConfirmControl = func(string, string) bool { shown.Add(1); return <-ans }
	s := &session{cid: "c1", salt: salt}
	s.authed.Store(true)
	s.byAsk.Store(byAsk)
	a.sess = s
	return a, s, ans, shown
}

func modeCall(ctx context.Context, a *Agent, s *session, view bool) chan modeMsg {
	ch := make(chan modeMsg, 1)
	a.setMode(ctx, s, view, func(m modeMsg) { ch <- m })
	return ch
}

func modeGot(t *testing.T, ch chan modeMsg, want modeMsg) {
	t.Helper()
	select {
	case m := <-ch:
		if m != want {
			t.Errorf("ответ %+v, ждали %+v", m, want)
		}
	case <-time.After(5 * time.Second):
		t.Errorf("нет ответа, ждали %+v", want)
	}
}

// TestMode — REQ-F-26: сессия «Спрашивать» уходит в просмотр сразу и без окна; управление — после «Разрешить».
func TestMode(t *testing.T) {
	ctx := context.Background()
	a, s, ans, shown := modeHost(true)
	modeGot(t, modeCall(ctx, a, s, true), modeMsg{T: "mode", View: true, OK: true})
	if s.control() || shown.Load() != 0 {
		t.Fatalf("в просмотр: управление %v, окон %d", s.control(), shown.Load())
	}
	ch := modeCall(ctx, a, s, false)
	ans <- true
	modeGot(t, ch, modeMsg{T: "mode", OK: true})
	if !s.control() || shown.Load() != 1 {
		t.Fatalf("«Разрешить»: управление %v, окон %d", s.control(), shown.Load())
	}
	modeGot(t, modeCall(ctx, a, s, false), modeMsg{T: "mode", OK: true}) // управление уже есть — без окна
	if shown.Load() != 1 {
		t.Fatal("окно при управлении")
	}
}

// TestModeDeny — «Отклонить» или нет ответа (AskControl → false): остаётся просмотр; второй запрос при открытом окне
// и в течение modeWait после отказа — отказ без окна; после modeWait — окно снова.
func TestModeDeny(t *testing.T) {
	defer func(w time.Duration) { modeWait = w }(modeWait)
	modeWait = 500 * time.Millisecond
	ctx := context.Background()
	a, s, ans, shown := modeHost(true)
	s.view.Store(true)
	ch := modeCall(ctx, a, s, false)
	modeGot(t, modeCall(ctx, a, s, false), modeMsg{T: "mode", View: true, Why: "busy"})
	ans <- false
	modeGot(t, ch, modeMsg{T: "mode", View: true, Why: "denied"})
	modeGot(t, modeCall(ctx, a, s, false), modeMsg{T: "mode", View: true, Why: "wait"})
	if s.control() || shown.Load() != 1 {
		t.Fatalf("после отказа: управление %v, окон %d", s.control(), shown.Load())
	}
	time.Sleep(modeWait)
	ch = modeCall(ctx, a, s, false)
	ans <- true
	modeGot(t, ch, modeMsg{T: "mode", OK: true})
	if !s.control() || shown.Load() != 2 {
		t.Fatalf("после modeWait: управление %v, окон %d", s.control(), shown.Load())
	}
}

// TestModeRefuse — режим навязан хостом: вход паролем, записью, TOTP (не через «Разрешить»), хост без окна смены,
// «Только показ экрана», права записи «просмотр» — отказ сразу, без окна; «Только показ экрана» включили, пока окно
// открыто, — «Разрешить» не повышает; сессия кончилась, пока окно открыто, — ответа нет.
func TestModeRefuse(t *testing.T) {
	defer func(w time.Duration) { modeWait = w }(modeWait)
	modeWait = 0
	ctx := context.Background()
	a, s, _, shown := modeHost(false)
	modeGot(t, modeCall(ctx, a, s, true), modeMsg{T: "mode", Why: "rights"})
	s.view.Store(true)
	modeGot(t, modeCall(ctx, a, s, false), modeMsg{T: "mode", View: true, Why: "rights"})
	a2, s2, _, _ := modeHost(true)
	a2.ConfirmControl = nil
	modeGot(t, modeCall(ctx, a2, s2, true), modeMsg{T: "mode", Why: "rights"})

	a, s, ans, shown2 := modeHost(true)
	s.view.Store(true)
	var on atomic.Bool
	on.Store(true)
	a.ViewOnly = on.Load
	modeGot(t, modeCall(ctx, a, s, false), modeMsg{T: "mode", View: true, Why: "viewonly"})
	on.Store(false)
	sec := a.Secret
	a.Secret = func(u string) ([]byte, []byte, bool) { st, h, _ := sec(u); return st, h, true }
	modeGot(t, modeCall(ctx, a, s, false), modeMsg{T: "mode", View: true, Why: "rights"})
	a.Secret = sec
	if shown.Load()+shown2.Load() != 0 {
		t.Fatal("окно при навязанном режиме")
	}

	ch := modeCall(ctx, a, s, false)
	on.Store(true)
	ans <- true
	modeGot(t, ch, modeMsg{T: "mode", View: true, Why: "viewonly"})
	on.Store(false)
	cctx, cancel := context.WithCancel(ctx)
	ch = modeCall(cctx, a, s, false)
	cancel()
	ans <- true
	select {
	case m := <-ch:
		t.Errorf("ответ кончившейся сессии: %+v", m)
	case <-time.After(300 * time.Millisecond):
	}
	if s.control() {
		t.Fatal("просмотр повышен")
	}
}

// TestModeE2E — по-настоящему: сессия «Спрашивать» (mode в "ok") уходит в просмотр — зажатая клавиша отпущена, ввод не
// доходит; «Отклонить» — не доходит; «Разрешить» — доходит. Вход без «Разрешить» (unattended) — mode нет, просьба
// просмотра не меняет управление.
func TestModeE2E(t *testing.T) {
	defer func(w time.Duration) { modeWait = w }(modeWait)
	modeWait = 0
	var ag *Agent
	var mode, allow atomic.Bool
	ask := func(a *Agent) {
		ag = a
		a.Unattended = func() bool { return false }
		a.Confirm = func(string, string) Answer { return Allow }
		a.ConfirmControl = func(string, string) bool { return allow.Load() }
	}
	e2eSeen = func(m authMsg) {
		if m.T == "ok" {
			mode.Store(m.Mode)
		}
	}
	held := func() int {
		ag.mu.Lock()
		s := ag.sess
		ag.mu.Unlock()
		s.keys.mu.Lock()
		defer s.keys.mu.Unlock()
		return len(s.keys.keys)
	}
	until := func(n int) bool {
		for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
			if held() == n {
				return true
			}
		}
		return false
	}
	set := func(t *testing.T, dc *webrtc.DataChannel, msgs chan ctlMsg, view bool) {
		dc.SendText(fmt.Sprintf(`{"t":"mode","view":%v}`, view))
		for end := time.After(5 * time.Second); ; {
			select {
			case m := <-msgs:
				if m.T == "mode" {
					return
				}
			case <-end:
				t.Fatal("нет ответа на mode")
			}
		}
	}
	key := func(c string) {
		e2eIn.SendText(`{"t":"k","c":"` + c + `","d":true}`)
		time.Sleep(300 * time.Millisecond)
	}
	e2eCtl = func(t *testing.T, dc *webrtc.DataChannel, msgs chan ctlMsg) {
		if !until(1) {
			t.Fatal("ввод до смены режима не дошёл")
		}
		set(t, dc, msgs, true)
		key("KeyA")
		if held() != 0 {
			t.Errorf("в просмотре зажато клавиш %d", held())
		}
		set(t, dc, msgs, false) // allow = false: «Отклонить»
		key("KeyB")
		if held() != 0 {
			t.Errorf("после «Отклонить» зажато клавиш %d", held())
		}
		allow.Store(true)
		set(t, dc, msgs, false)
		key("KeyC")
		if !until(1) {
			t.Errorf("после «Разрешить» ввод не дошёл: %d", held())
		}
	}
	defer func() { e2eCtl = nil; e2eReset() }()
	ff := FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000})
	e2eAgent = ask
	e2e(t, local(t), "123456789", false, ff, "secret123")
	if !mode.Load() {
		t.Error("сессия «Спрашивать» без mode в ok")
	}

	e2eAgent = func(a *Agent) { ag = a; a.ConfirmControl = func(string, string) bool { return true } } // Confirm nil — без «Разрешить»
	e2eCtl = func(t *testing.T, dc *webrtc.DataChannel, msgs chan ctlMsg) {
		if !until(1) {
			t.Fatal("ввод не дошёл")
		}
		set(t, dc, msgs, true)
		key("KeyA")
		if held() != 2 {
			t.Errorf("вход паролем: просьба просмотра изменила режим (зажато %d)", held())
		}
	}
	e2e(t, local(t), "123456789", false, ff, "secret123")
	if mode.Load() {
		t.Error("вход без «Разрешить» — mode в ok")
	}
}

// cdpMode — веб-клиент: кнопка смены режима (REQ-F-26). «Только просмотр» — сразу; «Управление» — ждёт ответа хоста,
// отказ — понятный текст, повтор сразу — «через 10 секунд»; после разрешения — управление. Хост без mode в ok
// (старый, вход паролем) — кнопки нет.
const cdpMode = `
const [, , port, url] = process.argv;
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const tab = await (await fetch('http://127.0.0.1:' + port + '/json/new?' + url, { method: 'PUT' })).json();
  const ws = new WebSocket(tab.webSocketDebuggerUrl); await new Promise(r => ws.onopen = r);
  let id = 0; const wait = {};
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && wait[m.id]) wait[m.id](m); };
  const ev = x => new Promise(r => { const i = ++id; wait[i] = m => r(m.result?.result?.value); ws.send(JSON.stringify({ id: i, method: 'Runtime.evaluate', params: { expression: x, awaitPromise: true, returnByValue: true } })); });
  const until = async (x, n = 75) => { for (let i = 0; i < n; i++) { if (await ev(x)) return true; await sleep(200); } return false; };
  const st = () => ev("[!document.getElementById('modebtn').classList.contains('hidden'), document.getElementById('modebtn').textContent, document.body.classList.contains('view'), document.getElementById('modebtn').disabled, document.getElementById('modemsg').textContent].join('|')");
  const sess = "!document.getElementById('sess').classList.contains('hidden')";
  const login = async h => { await ev("document.getElementById('id').value='" + h + "'; document.getElementById('pw').value='secret123'; document.getElementById('go').click()"); return until(sess); };
  const click = () => ev("document.getElementById('modebtn').click(); 1");
  await sleep(1000);
  console.log('session=' + await login('123456789'));
  await sleep(500);
  console.log('start=' + await st());
  await click(); await until("document.body.classList.contains('view')");
  console.log('view=' + await st());
  await click(); await sleep(100);
  console.log('asking=' + await st());
  await until("document.getElementById('modemsg').textContent.includes('not allowed')");
  console.log('denied=' + await st());
  await click(); await until("document.getElementById('modemsg').textContent.includes('10')");
  console.log('again=' + await st());
  await sleep(1600);
  await click(); await until("!document.body.classList.contains('view')");
  console.log('control=' + await st());
  await ev("document.getElementById('bye').click()"); await sleep(1500);
  console.log('old_session=' + await login('123456780'));
  await sleep(500);
  console.log('old=' + await st());
  process.exit(0);
})();`

// TestBrowserMode — веб-клиент и смена режима с живым хостом: кнопка, тексты ожидания и отказа; хост без смены режима
// (ConfirmControl nil — как старый хост) — кнопки нет.
func TestBrowserMode(t *testing.T) {
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
	defer func(w time.Duration) { modeWait = w }(modeWait)
	modeWait = 1500 * time.Millisecond
	mux := http.NewServeMux()
	mux.Handle("/ws", &hub.Hub{})
	mux.Handle("/", http.FileServer(http.FS(ui.FS)))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	capture := func(ctx context.Context, c Cap) (*exec.Cmd, error) {
		return exec.CommandContext(ctx, "ffmpeg", FFArgs("test", "libx264", c)...), nil
	}
	var asked atomic.Int32
	a := newAgent("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", "123456789", nil)
	a.Capture, a.Unattended = capture, func() bool { return false }
	a.Confirm = func(string, string) Answer { return Allow }
	a.ConfirmControl = func(string, string) bool { // первый раз — «Отклонить» через 1 с, дальше — «Разрешить»
		if asked.Add(1) == 1 {
			time.Sleep(time.Second)
			return false
		}
		return true
	}
	go a.Run(ctx)
	old := newAgent("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", "123456780", nil)
	old.Capture, old.Unattended = capture, func() bool { return false }
	old.Confirm = func(string, string) Answer { return Allow }
	go old.Run(ctx)
	out := string(runCDP(t, ctx, chrome, cdpMode, srv.URL+"/"))
	for _, want := range []string{
		"session=true",
		"start=true|View only|false|false|\n",
		"view=true|Control|true|false|\n",
		"asking=true|Control|true|true|Waiting for “Allow” on the remote PC…\n",
		"denied=true|Control|true|false|Control was not allowed\n",
		"again=true|Control|true|false|Control was just refused — try again in 10 seconds\n",
		"control=true|View only|false|false|\n",
		"old_session=true",
		"old=false|",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if asked.Load() != 2 {
		t.Errorf("окон «Разрешить управление?» %d, ждали 2", asked.Load())
	}
}
