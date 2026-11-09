package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"anypc/hub"
	"anypc/ui"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// TestFirefoxPaste — веб-клиент в настоящем Firefox (WebDriver через geckodriver).
// Firefox на каждый navigator.clipboard.readText() показывает у курсора свою кнопку «Вставить».
// Поэтому readText не должен вызываться сам: ни опросом, ни по возврату фокуса, ни по кликам в окне, ни по Ctrl+V.
// Ctrl+V — настоящие нажатия: текст из настоящего буфера Firefox уходит на хост раньше V.
func TestFirefoxPaste(t *testing.T) {
	gecko, err := exec.LookPath("geckodriver")
	if err != nil {
		t.Skip("нет geckodriver")
	}
	if _, err := exec.LookPath("firefox"); err != nil {
		t.Skip("нет firefox")
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
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var clipMu sync.Mutex
	var clips []string
	setClip = func(s string) error { clipMu.Lock(); clips = append(clips, s); clipMu.Unlock(); return nil }
	defer func() { setClip = SetClipText }()
	a := newAgent("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", "123456789", FFArgs("test", "libx264", Cap{FPS: 30, Kbps: 1000}))
	go a.Run(ctx)

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	gd := exec.CommandContext(ctx, gecko, "--port", fmt.Sprint(port))
	gd.Env = noProxy(os.Environ())
	if err := gd.Start(); err != nil {
		t.Fatal(err)
	}
	defer gd.Process.Kill()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 60 * time.Second}
	call := func(method, path string, body any) map[string]any {
		t.Helper()
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, base+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		for i := 0; ; i++ {
			resp, err := client.Do(req)
			if err != nil {
				if i < 30 { // geckodriver ещё не слушает
					time.Sleep(200 * time.Millisecond)
					req.Body = io.NopCloser(bytes.NewReader(b))
					continue
				}
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var r map[string]any
			json.NewDecoder(resp.Body).Decode(&r)
			if v, ok := r["value"].(map[string]any); ok && v["error"] != nil {
				t.Fatalf("WebDriver %s: %v", path, v["message"])
			}
			return r
		}
	}
	sess := call("POST", "/session", map[string]any{"capabilities": map[string]any{"alwaysMatch": map[string]any{
		"webSocketUrl": true, "moz:firefoxOptions": map[string]any{"args": []string{"-headless"}}}}})["value"].(map[string]any)
	sid := sess["sessionId"].(string)
	defer call("DELETE", "/session/"+sid, nil)
	s := "/session/" + sid
	// скрипты — через WebDriver BiDi в мире самой страницы: execute/sync Firefox выполняет в песочнице,
	// где не видно её let-переменных и не действуют подмены (а встроить <script> не даёт CSP)
	bidi, _, err := websocket.Dial(ctx, sess["capabilities"].(map[string]any)["webSocketUrl"].(string), &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	defer bidi.CloseNow()
	bidi.SetReadLimit(1 << 20)
	nextID := 0
	bidiCall := func(method string, params any) map[string]any {
		t.Helper()
		nextID++
		if err := wsjson.Write(ctx, bidi, map[string]any{"id": nextID, "method": method, "params": params}); err != nil {
			t.Fatal(err)
		}
		for {
			var r map[string]any
			if err := wsjson.Read(ctx, bidi, &r); err != nil {
				t.Fatal(err)
			}
			if id, _ := r["id"].(float64); int(id) == nextID {
				if r["error"] != nil {
					t.Fatalf("BiDi %s: %v %v", method, r["error"], r["message"])
				}
				return r["result"].(map[string]any)
			}
		}
	}
	bctx := bidiCall("browsingContext.getTree", map[string]any{})["contexts"].([]any)[0].(map[string]any)["context"]
	js := func(expr string) any {
		t.Helper()
		r := bidiCall("script.evaluate", map[string]any{"expression": expr, "target": map[string]any{"context": bctx}, "awaitPromise": true})
		if r["type"] == "exception" {
			t.Fatalf("скрипт %q: %v", expr, r["exceptionDetails"])
		}
		v, _ := r["result"].(map[string]any)["value"]
		return v
	}
	keys := func(acts ...map[string]any) {
		call("POST", s+"/actions", map[string]any{"actions": []any{map[string]any{"type": "key", "id": "kb", "actions": acts}}})
	}
	const ctrl = ""
	down := func(k string) map[string]any { return map[string]any{"type": "keyDown", "value": k} }
	up := func(k string) map[string]any { return map[string]any{"type": "keyUp", "value": k} }

	call("POST", s+"/url", map[string]any{"url": srv.URL + "/"})
	time.Sleep(time.Second)
	js("document.getElementById('id').value='123456789'; document.getElementById('pw').value='secret123'; document.getElementById('go').click()")
	for i := 0; js("authed && !document.getElementById('sess').classList.contains('hidden')") != true; i++ {
		if i > 200 {
			t.Fatalf("сеанс в Firefox не открылся: %v", js("document.getElementById('msg').textContent"))
		}
		time.Sleep(100 * time.Millisecond)
	}
	// счётчик readText (кнопка «Вставить» Firefox) и порядок отправок в каналы ctl и input
	js(`window.reads = 0; const rt = navigator.clipboard.readText.bind(navigator.clipboard);
		Object.defineProperty(navigator.clipboard, 'readText', { value: () => (reads++, rt()) });
		window.seq = []; const cs = ctl.send.bind(ctl), ds = dc.send.bind(dc);
		ctl.send = m => (seq.push('clip:' + JSON.parse(m).text), cs(m));
		dc.send = m => { const o = JSON.parse(m); if (o.t === 'k') seq.push(o.c + (o.d ? '↓' : '↑')); ds(m); };`)
	time.Sleep(2500 * time.Millisecond) // опрос раз в секунду — без разрешения его быть не должно
	js("window.dispatchEvent(new Event('focus')); document.getElementById('v').focus()")
	time.Sleep(500 * time.Millisecond)
	if st := js("[clipPerm, clipGranted, !document.getElementById('clipbtn').classList.contains('hidden'), reads].join()"); st != "false,false,true,0" {
		t.Errorf("Firefox: clipPerm,clipGranted,кнопка видна,readText = %v, ждали false,false,true,0", st)
	}
	// настоящий буфер Firefox: настоящий Ctrl+C в поле, затем настоящий Ctrl+V в окне сеанса
	// поле <input> сеанс не перехватывает (capturing) — Ctrl+C в нём копирует как обычно
	js(`const src = document.createElement('input'); src.id = 'src'; src.value = 'ff-text'; document.body.append(src); src.focus(); src.select()`)
	keys(down(ctrl), down("c"), up("c"), up(ctrl))
	js("document.getElementById('src').remove(); document.getElementById('v').focus(); seq.length = 0")
	keys(down(ctrl), down("v"), up("v"), up(ctrl))
	time.Sleep(800 * time.Millisecond)
	got := js("seq.join() + '|reads=' + reads")
	if got != "ControlLeft↓,clip:ff-text,KeyV↓,KeyV↑,ControlLeft↑|reads=0" {
		t.Errorf("Ctrl+V в Firefox: %v — ждали буфер раньше V и ни одного readText", got)
	}
	clipMu.Lock()
	host := strings.Join(clips, "|")
	clipMu.Unlock()
	if !strings.Contains(host, "ff-text") {
		t.Errorf("буфер Firefox не дошёл до хоста: %q", host)
	}
}

func noProxy(env []string) []string {
	var r []string
	for _, e := range env {
		if k, _, _ := strings.Cut(e, "="); !strings.EqualFold(k, "http_proxy") && !strings.EqualFold(k, "https_proxy") && !strings.EqualFold(k, "all_proxy") {
			r = append(r, e)
		}
	}
	return r
}
