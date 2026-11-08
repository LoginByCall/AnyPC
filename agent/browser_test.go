package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"anypc/hub"
	"anypc/pake"
	"anypc/ui"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/pion/webrtc/v4"
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
  // REQ-S-05: в памяти браузера «другой» ключ этого ID → предупреждение и кнопка доверия
  await ev("localStorage.setItem('known', JSON.stringify({'123456789': '0000 0000'})); document.getElementById('pw').value='secret123'; document.getElementById('go').click()");
  console.log('changed=' + await until(s => s.includes('changed')) + '|trust=' + await ev("!document.getElementById('trust').classList.contains('hidden')"));
  await ev("document.getElementById('trust').click()");
  console.log('right=' + await until(s => s.endsWith('|true')));
  console.log('stored=' + await ev("JSON.parse(localStorage.getItem('known'))['123456789']"));
  // регрессия: буфер браузера уходил на хост только по событию focus — скопированное в соседней вкладке терялось
  // Firefox: без постоянного разрешения опроса нет (каждое чтение — кнопка «Вставить» у курсора)
  await ev("window.reads = 0; clipGranted = false; Object.defineProperty(navigator, 'clipboard', { value: { readText: async () => (reads++, 'from-browser'), writeText: async () => {} } }); 1");
  await sleep(2500);
  console.log('reads=' + await ev("reads"));
  await ev("clipGranted = true; 1");
  await sleep(2500);
  // Ctrl+V в окне: буфер из события paste (без кнопки Firefox) уходит раньше V; Ctrl, отпущенный до paste, — после V
  await ev("clipGranted = false; clipBtn(); window.seq = []; const cs = ctl.send.bind(ctl), ds = dc.send.bind(dc);" +
    "ctl.send = m => (seq.push('clip:' + JSON.parse(m).text), cs(m)); dc.send = m => { const o = JSON.parse(m); if (o.t === 'k') seq.push(o.c + (o.d ? '↓' : '↑')); ds(m); }; 1");
  await ev("const k = (t, c) => document.dispatchEvent(new KeyboardEvent(t, { code: c, ctrlKey: true, bubbles: true }));" +
    "k('keydown', 'ControlLeft'); k('keydown', 'KeyV'); k('keyup', 'ControlLeft'); const dt = new DataTransfer(); dt.setData('text/plain', 'pasted-text');" +
    "document.activeElement.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true })); k('keyup', 'KeyV'); 1");
  await sleep(600);
  console.log('paste=' + await ev("seq.join(',')") + '|btn=' + await ev("!document.getElementById('clipbtn').classList.contains('hidden')"));
  await ev("seq = []; document.getElementById('clipbtn').click(); 1");
  await sleep(300);
  console.log('clipbtn=' + await ev("seq.join(',')"));
  await ev("sendFile(new File([new Uint8Array(300000).map((_, i) => i % 251)], 'browser.bin'))");
  let x = '';
  for (let i = 0; i < 75 && !/[✓✗]/.test(x); i++) { await sleep(200); x = await ev("document.getElementById('xfers').textContent"); }
  console.log('file=' + x);
  // регрессия: обрыв через relay завершал сессию насовсем → автопереподключение, хост не отвечает «занят»
  await ev("const p = pc; Object.defineProperty(p, 'connectionState', { get: () => 'failed' }); p.onconnectionstatechange(); 1");
  console.log('dropped=' + await state());
  console.log('redial=' + await until(s => s.endsWith('|true')));
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
	// Резервная сигнализация: страница открыта с хаба 1, где хоста нет (not_found), а /hubs подсказывает хаб 2,
	// где хост есть, — веб-клиент должен войти через хаб 2, и весь сценарий ниже идёт через него.
	other := httptest.NewServer(&hub.Hub{})
	defer other.Close()
	hub2 := "ws" + strings.TrimPrefix(other.URL, "http") + "/ws"
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.Handle("/ws", &hub.Hub{})
	mux.HandleFunc("/hubs", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]string{"ws" + strings.TrimPrefix(srv.URL, "http") + "/ws", hub2})
	})
	mux.Handle("/", http.FileServer(http.FS(ui.FS)))
	srv = httptest.NewServer(mux)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var clipMu sync.Mutex
	var clips []string
	setClip = func(s string) error { clipMu.Lock(); clips = append(clips, s); clipMu.Unlock(); return nil }
	defer func() { setClip = SetClipText }()
	a := newAgent(hub2, "123456789", nil)
	a.FileDir = t.TempDir() // не в настоящие «Загрузки»
	// адаптивный битрейт с GCC: Chrome обязан слать TWCC на наше расширение заголовка
	a.Bitrate = 1000
	a.Capture = func(ctx context.Context, _, kbps, fps int) (*exec.Cmd, error) {
		return exec.CommandContext(ctx, "ffmpeg", FFArgs("test", "libx264", fps, fmt.Sprintf("%dk", kbps))...), nil
	}
	var twcc, claimed atomic.Bool
	var enrolled atomic.Value // У3: ключ браузера, закреплённый после входа; при переподключении он приходит заявкой
	a.Trust = func(p []byte) { enrolled.Store(string(p)) }
	a.Trusted = func(p []byte) bool {
		k, _ := enrolled.Load().(string)
		claimed.Store(claimed.Load() || k == string(p))
		return k == string(p)
	}
	log.SetOutput(io.MultiWriter(os.Stderr, logSeen{"клиент шлёт TWCC", &twcc}))
	defer log.SetOutput(os.Stderr)
	go a.Run(ctx)

	out := runCDP(t, ctx, chrome, cdpScript, srv.URL+"/")
	if !strings.Contains(string(out), "wrong=Error: wrong password|false") {
		t.Error("неверный пароль: ждали «wrong password» и без сессии")
	}
	if !strings.Contains(string(out), "key has changed") || !strings.Contains(string(out), "|trust=true") {
		t.Error("смена ключа хоста: нет предупреждения или кнопки доверия")
	}
	if want := "stored=" + pake.KeyFingerprint(a.Key.Public().(ed25519.PublicKey)); !strings.Contains(string(out), want) {
		t.Errorf("после доверия запомнен не тот отпечаток, ждали %s", want)
	}
	if !strings.Contains(string(out), "|true") || !strings.Contains(string(out), "right=") {
		t.Error("верный пароль после неверного: сессия не открылась")
	}
	if !strings.Contains(string(out), "dropped=|false") || !strings.Contains(string(out), "redial=") || strings.Contains(string(out), "redial=Error") ||
		!regexp.MustCompile(`redial=[^\n]*\|true`).MatchString(string(out)) {
		t.Error("после обрыва сессия не восстановилась сама")
	}
	if !strings.Contains(string(out), "reads=0\n") {
		t.Error("без разрешения clipboard-read буфер опрашивается (Firefox: плашка «Вставить» каждую секунду)")
	}
	if enrolled.Load() == nil || !claimed.Load() {
		t.Errorf("ключ браузера: закреплён %v, заявлен при переподключении %v", enrolled.Load() != nil, claimed.Load())
	}
	if !twcc.Load() {
		t.Error("Chrome не прислал TWCC — оценка полосы GCC не работает")
	}
	clipMu.Lock()
	hostClips := strings.Join(clips, "|")
	clipMu.Unlock()
	if !strings.Contains(hostClips, "from-browser") || !strings.Contains(hostClips, "pasted-text") {
		t.Errorf("буфер браузера на хосте: %q — ждали и опрос (from-browser), и Ctrl+V (pasted-text)", hostClips)
	}
	if !strings.Contains(string(out), "paste=ControlLeft↓,clip:pasted-text,KeyV↓,ControlLeft↑,KeyV↑|btn=true") {
		t.Error("Ctrl+V: буфер должен уйти раньше V, а Ctrl отпуститься после V; кнопка «Передать буфер» видна без разрешения")
	}
	if !strings.Contains(string(out), "clipbtn=clip:from-browser") {
		t.Error("кнопка «Передать буфер» не отправила буфер")
	}
	got, err := os.ReadFile(filepath.Join(a.FileDir, "browser.bin")) // отправка файла из браузера (докачка-протокол)
	if err != nil || len(got) != 300000 || got[251] != 0 || got[252] != 1 {
		t.Errorf("файл из браузера: %d байт, %v", len(got), err)
	}
}

// runCDP — headless Chrome + node-скрипт по DevTools Protocol; вывод скрипта.
func runCDP(t *testing.T, ctx context.Context, chrome, script, url string) []byte {
	t.Helper()
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
	os.WriteFile(js, []byte(script), 0o600)
	out, err := exec.CommandContext(ctx, "node", js, port, url).CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// cdpFake — клиент вводит пароль; хост «входит» без CPace. Печатает: состояние, буфер клиента, запомненный ключ.
const cdpFake = `
const [, , port, url] = process.argv;
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const tab = await (await fetch('http://127.0.0.1:' + port + '/json/new?' + url, { method: 'PUT' })).json();
  const ws = new WebSocket(tab.webSocketDebuggerUrl); await new Promise(r => ws.onopen = r);
  let id = 0; const wait = {};
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && wait[m.id]) wait[m.id](m); };
  const ev = x => new Promise(r => { const i = ++id; wait[i] = m => r(m.result?.result?.value); ws.send(JSON.stringify({ id: i, method: 'Runtime.evaluate', params: { expression: x, awaitPromise: true, returnByValue: true } })); });
  await sleep(1000);
  await ev("document.getElementById('id').value='123456789'; document.getElementById('pw').value='secret123'; document.getElementById('go').click()");
  await sleep(6000);
  console.log('fake=' + await ev("document.getElementById('msg').textContent + '|' + !document.getElementById('sess').classList.contains('hidden')"));
  console.log('clip=' + await ev("lastClip") + '|known=' + await ev("localStorage.getItem('known')"));
  process.exit(0);
})();`

// TestBrowserFakeHost — Д-1, Д-2: поддельный хост (хаб или захвативший ID) присылает «ok» без обмена CPace,
// буфер обмена и файл. Клиент не должен открыть сессию, запомнить ключ, принять буфер или файл.
func TestBrowserFakeHost(t *testing.T) {
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
	mux := http.NewServeMux()
	mux.Handle("/ws", &hub.Hub{})
	mux.Handle("/", http.FileServer(http.FS(ui.FS)))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	go fakeHost(t, ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", "123456789", nil)
	out := string(runCDP(t, ctx, chrome, cdpFake, srv.URL+"/"))
	if !strings.Contains(out, "could not be verified") || !strings.Contains(out, "|false\n") {
		t.Error("«ok» без CPace принят: ждали ошибку проверки хоста и без сессии")
	}
	if !strings.Contains(out, "clip=|known=null") {
		t.Error("поддельный хост передал буфер или его ключ запомнен")
	}
}

// fakeHost — хост без пароля: регистрируется, на connect шлёт offer, в канале auth сразу «ok» со своей подписью.
// С guesses — вместо «ok» шлёт «a» на каждую догадку пароля и пишет в guesses, сколько «b» вернул клиент.
func fakeHost(t *testing.T, ctx context.Context, url, id string, guesses chan<- int) {
	_, key, _ := ed25519.GenerateKey(nil)
	pub := key.Public().(ed25519.PublicKey)
	c, _, err := websocket.Dial(ctx, url+"?host="+id+"&key="+base64.RawURLEncoding.EncodeToString(pub), nil)
	if err != nil {
		t.Error(err)
		return
	}
	defer c.CloseNow()
	var pc *webrtc.PeerConnection
	for {
		var m hub.Msg
		if wsjson.Read(ctx, c, &m) != nil {
			return
		}
		switch m.Type {
		case "challenge":
			var nonce string
			json.Unmarshal(m.Data, &nonce)
			d, _ := json.Marshal(map[string][]byte{"sig": ed25519.Sign(key, pake.RegisterMsg(id, nonce))})
			wsjson.Write(ctx, c, hub.Msg{Type: "register", Data: d})
		case "connect":
			pc, _ = webrtc.NewPeerConnection(webrtc.Configuration{})
			auth, _ := pc.CreateDataChannel("auth", nil)
			ctl, _ := pc.CreateDataChannel("ctl", nil)
			ctl.OnOpen(func() { ctl.SendText(`{"t":"clip","text":"evil"}`) })
			auth.OnOpen(func() {
				if guesses != nil {
					var n atomic.Int32
					auth.OnMessage(func(m webrtc.DataChannelMessage) {
						if strings.Contains(string(m.Data), `"t":"b"`) {
							n.Add(1)
						}
					})
					fpH, fpC := pake.Fingerprint(pc.LocalDescription().SDP), pake.Fingerprint(pc.RemoteDescription().SDP)
					for _, g := range []string{"guess1", "guess2", "guess3"} {
						salt := []byte("0123456789abcdef")
						msgA, _, _ := pake.HostStart(pake.KDF(g, salt), id, fpC, fpH)
						d, _ := json.Marshal(authMsg{T: "a", Salt: salt, Msg: msgA})
						auth.SendText(string(d))
					}
					time.AfterFunc(4*time.Second, func() { guesses <- int(n.Load()) })
					return
				}
				fpH, fpC := pake.Fingerprint(pc.LocalDescription().SDP), pake.Fingerprint(pc.RemoteDescription().SDP)
				sig := base64.StdEncoding.EncodeToString(pake.HostSign(key, id, fpC, fpH))
				auth.SendText(`{"t":"ok","conf":"","pub":"` + base64.StdEncoding.EncodeToString(pub) + `","sig":"` + sig + `"}`)
				time.AfterFunc(time.Second, func() {
					f, err := pc.CreateDataChannel("file", nil)
					if err != nil { // клиент уже закрыл соединение — тоже верно
						return
					}
					f.OnOpen(func() { f.SendText(`{"t":"meta","name":"evil.txt","size":4}`) })
				})
			})
			offer, _ := pc.CreateOffer(nil)
			done := webrtc.GatheringCompletePromise(pc)
			pc.SetLocalDescription(offer)
			<-done
			d, _ := json.Marshal(pc.LocalDescription())
			wsjson.Write(ctx, c, hub.Msg{Type: "offer", To: m.From, Data: d})
		case "answer":
			var sd webrtc.SessionDescription
			json.Unmarshal(m.Data, &sd)
			pc.SetRemoteDescription(sd)
		case "ice":
			var ci webrtc.ICECandidateInit
			json.Unmarshal(m.Data, &ci)
			pc.AddICECandidate(ci)
		}
	}
}

// TestBrowserGuessHost — поддельный хост (хаб) шлёт несколько «a» с разными догадками пароля:
// клиент отвечает только на первое, на повтор рвёт вход — иначе перебор пароля мимо блокировки хоста.
func TestBrowserGuessHost(t *testing.T) {
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
	mux := http.NewServeMux()
	mux.Handle("/ws", &hub.Hub{})
	mux.Handle("/", http.FileServer(http.FS(ui.FS)))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	guesses := make(chan int, 1)
	go fakeHost(t, ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", "123456789", guesses)
	out := string(runCDP(t, ctx, chrome, cdpFake, srv.URL+"/"))
	select {
	case n := <-guesses:
		if n > 1 {
			t.Errorf("клиент ответил на %d догадок пароля из 3 — перебор возможен", n)
		}
	case <-ctx.Done():
		t.Fatal("поддельный хост не дождался ответов")
	}
	if !strings.Contains(out, "could not be verified") || !strings.Contains(out, "|false\n") {
		t.Errorf("повторный обмен CPace не оборвал вход: %s", out)
	}
}

// cdpNode — «ID@узел»: без узла хост не найден, с узлом — сессия; в «Недавних» адрес запомнен с узлом.
const cdpNode = `
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
  await ev("document.getElementById('id').value='123456789'; document.getElementById('pw').value='secret123'; document.getElementById('go').click()");
  console.log('plain=' + await until(s => s.includes('rror')));
  await ev("document.getElementById('id').value='123 456 789@bad_node'; document.getElementById('go').click()");
  console.log('bad=' + await state());
  await ev("document.getElementById('id').value='123456789@NODE'; document.getElementById('go').click()");
  console.log('node=' + await until(s => s.endsWith('|true')));
  console.log('recent=' + await ev("localStorage.getItem('recent')"));
  process.exit(0);
})();`

// TestBrowserNode — Э-1: подключение «ID@узел» идёт только через указанный узел, без смены настроек.
func TestBrowserNode(t *testing.T) {
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
	own := httptest.NewServer(&hub.Hub{}) // «свой узел» с хостом; страница открыта с другого хаба, где хоста нет
	defer own.Close()
	mux := http.NewServeMux()
	mux.Handle("/ws", &hub.Hub{})
	mux.Handle("/", http.FileServer(http.FS(ui.FS)))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	go newAgent("ws"+strings.TrimPrefix(own.URL, "http")+"/ws", "123456789", FFArgs("test", "libx264", 30, "1M")).Run(ctx)
	node := strings.TrimPrefix(own.URL, "http://")
	out := string(runCDP(t, ctx, chrome, strings.Replace(cdpNode, "NODE", node, 1), srv.URL+"/"))
	if !strings.Contains(out, "plain=Error: ") || !strings.Contains(out, "|false\n") {
		t.Error("без узла хост найден — ждали ошибку")
	}
	if !strings.Contains(out, "bad=Invalid node address") {
		t.Error("неверный адрес узла не отклонён")
	}
	if !strings.Contains(out, "node=") || !regexp.MustCompile(`node=[^\n]*\|true`).MatchString(out) {
		t.Error("через ID@узел сессия не открылась")
	}
	if !strings.Contains(out, `recent=["123456789@`+node+`"]`) {
		t.Error("в «Недавних» нет адреса с узлом")
	}
}

// logSeen отмечает, что в журнал попала строка с текстом s.
type logSeen struct {
	s    string
	seen *atomic.Bool
}

func (l logSeen) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(l.s)) {
		l.seen.Store(true)
	}
	return len(p), nil
}
