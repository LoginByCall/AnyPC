package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"anypc/hub"
	"anypc/pake"
	"anypc/totp"
	"anypc/ui"
)

// cdpPause — «Мои ПК», фаза 2 (REQ-F-27): два ПК вкладками в одном окне, A умеет паузу (pause:true в "ok"), B — старый
// хост (поля нет). Уводим активную вкладку в фон и смотрим кадры на стороне хоста (счётчик /frames): у нового хоста в
// фоне видео останавливается и по возврату идёт снова; у старого хоста видео в фоне идёт как раньше (клиент "pause" ему
// не шлёт — /preq=0), переключение всё равно работает (соединения не рвутся).
const cdpPause = `
const [, , port, url] = process.argv;
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const tab = await (await fetch('http://127.0.0.1:' + port + '/json/new?' + url, { method: 'PUT' })).json();
  const ws = new WebSocket(tab.webSocketDebuggerUrl); await new Promise(r => ws.onopen = r);
  let id = 0; const wait = {};
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && wait[m.id]) wait[m.id](m); };
  const ev = x => new Promise(r => { const i = ++id; wait[i] = m => r(m.result?.result?.value); ws.send(JSON.stringify({ id: i, method: 'Runtime.evaluate', params: { expression: x, awaitPromise: true, returnByValue: true } })); });
  const ids = ['111111111', '222222222']; // A — с паузой, B — старый хост
  const tabState = () => ev("JSON.stringify(myPcStates())");
  const pcState = () => ev("JSON.stringify([...document.querySelectorAll('#frames iframe')].map(f => { try { return f.contentWindow.sessState(); } catch { return 'x'; } }))");
  const f = async id => +(await (await fetch(url + 'frames?id=' + id)).text()); // кадров отправлено хостом id
  const delta = async (id, ms) => { const a = await f(id); await sleep(ms); return await f(id) - a; };
  await sleep(800);
  for (let k = 0; k < 60; k++) { if (await ev("typeof myPcAdd === 'function' && typeof myPcStates === 'function'")) break; await sleep(100); } // дождаться загрузки страницы
  const ck = JSON.parse(await (await fetch(url + 'ckey')).text());
  const known = {}; for (const i of ids) known[i] = (await (await fetch(url + 'fp?id=' + i)).text());
  const ckeys = {}; for (const i of ids) ckeys[i] = { seed: ck.seed, pub: ck.pub, login: true, lu: '' };
  await ev("localStorage.setItem('ckeys', '" + JSON.stringify(ckeys) + "'); localStorage.setItem('known', '" + JSON.stringify(known) + "'); localStorage.setItem('mine', '[]'); 1");
  await sleep(500);
  await ev("myPcAdd('" + ids[0] + "'); myPcAdd('" + ids[1] + "'); 1");
  for (let k = 0; k < 200; k++) {
    const want = await ev("myPcCodeWanted()");
    if (want) { const c = await (await fetch(url + 'code?id=' + want)).text(); await ev("document.getElementById('mcot').value='" + c + "'; document.getElementById('mcgo').click()"); await sleep(300); continue; }
    const st = JSON.parse(await tabState());
    if (st.length === 2 && st.every(s => s === 'ok')) break;
    await sleep(300);
  }
  console.log('connected=' + await pcState());
  // A активна (вкладка 1), B — в фоне (старый хост). Оба хоста шлют видео: у A активна, у B — фон, но старый хост не паузит.
  await ev("myPcKey('Digit1'); 1"); await sleep(1200);
  console.log('active=' + await ev("myPcActive()"));
  const dA1 = await delta(ids[0], 2500), dB1 = await delta(ids[1], 2500);
  console.log('phase1=A' + dA1 + '|B' + dB1); // A активна — идёт; B старый в фоне — тоже идёт
  // Увести A в фон: вкладка 2 (B) активна. Новый хост A получает pause:true → его видео останавливается.
  await ev("myPcKey('Digit2'); 1"); await sleep(1500);
  const dA2 = await delta(ids[0], 2500), dB2 = await delta(ids[1], 2500);
  console.log('phase2=A' + dA2 + '|B' + dB2); // A в фоне — пауза (≈0); B активна — идёт
  // Вернуть A: вкладка 1. pause:false → видео A идёт снова (IDR).
  await ev("myPcKey('Digit1'); 1"); await sleep(1500);
  const dA3 = await delta(ids[0], 2500);
  console.log('phase3=A' + dA3); // A вернулась — идёт
  console.log('preq=A' + (await (await fetch(url + 'preq?id=' + ids[0])).text()) + '|B' + (await (await fetch(url + 'preq?id=' + ids[1])).text()));
  console.log('stillconnected=' + await pcState());
  process.exit(0);
})();`

// TestBrowserPause — «Мои ПК», фаза 2: пауза видео неактивной вкладки у хоста с поддержкой, обратная совместимость со
// старым хостом (без pause в "ok"). Кадры считаются на стороне хоста (крючок videoSent), "pause" — крючком pauseRecv.
func TestBrowserPause(t *testing.T) {
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

	ids := []string{"111111111", "222222222"}
	pause := map[string]bool{"111111111": true, "222222222": false} // A умеет паузу, B — старый хост
	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	seedB64 := base64.StdEncoding.EncodeToString(seed)
	ck, _ := pake.ClientSignB64(seedB64, "", "", "")
	clientPub, _ := base64.StdEncoding.DecodeString(ck["pub"])

	agents := map[string]*Agent{}
	otps := map[string]*otpHost{}
	frames := map[string]*atomic.Int64{} // отправленных видеокадров по ПК
	preqs := map[string]*atomic.Int64{}  // полученных "pause" по ПК
	byID := map[*Agent]string{}

	vs := func(a *Agent) {
		if id := byID[a]; id != "" {
			frames[id].Add(1)
		}
	}
	pr := func(a *Agent, _ bool) {
		if id := byID[a]; id != "" {
			preqs[id].Add(1)
		}
	}
	defer func() { videoSent.Store(nil); pauseRecv.Store(nil) }()

	mux := http.NewServeMux()
	mux.Handle("/ws", &hub.Hub{})
	mux.HandleFunc("/ckey", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"seed": seedB64, "pub": ck["pub"]})
	})
	mux.HandleFunc("/fp", func(w http.ResponseWriter, r *http.Request) {
		if a := agents[r.URL.Query().Get("id")]; a != nil {
			w.Write([]byte(pake.KeyFingerprint(a.Key.Public().(ed25519.PublicKey))))
		}
	})
	mux.HandleFunc("/code", func(w http.ResponseWriter, r *http.Request) {
		o := otps[r.URL.Query().Get("id")]
		if o == nil {
			http.Error(w, "no id", http.StatusNotFound)
			return
		}
		o.mu.Lock()
		o.last = 0
		o.mu.Unlock()
		w.Write([]byte(o.code()))
	})
	mux.HandleFunc("/frames", func(w http.ResponseWriter, r *http.Request) {
		if c := frames[r.URL.Query().Get("id")]; c != nil {
			fmt.Fprint(w, c.Load())
		}
	})
	mux.HandleFunc("/preq", func(w http.ResponseWriter, r *http.Request) {
		if c := preqs[r.URL.Query().Get("id")]; c != nil {
			fmt.Fprint(w, c.Load())
		}
	})
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
		http.FileServer(http.FS(ui.FS)).ServeHTTP(w, r)
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	for _, id := range ids {
		o := &otpHost{secret: totp.NewSecret()}
		ks := &keyStore{}
		ks.set("", clientPub)
		a := newAgent("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", id, nil)
		a.OTP = o.check
		a.KeyLogin = ks.login
		a.Pause = pause[id]
		a.Capture = func(ctx context.Context, c Cap) (*exec.Cmd, error) {
			return exec.CommandContext(ctx, "ffmpeg", FFArgs("test", "libx264", c)...), nil
		}
		agents[id], otps[id] = a, o
		frames[id], preqs[id] = &atomic.Int64{}, &atomic.Int64{}
		byID[a] = id
		go a.Run(ctx)
	}
	// Крючки — только теперь, когда карты (byID, frames, preqs) заполнены: иначе их читала бы из крючка
	// задержавшаяся горутина stream прошлого теста, пока этот пишет (DATA RACE); дальше карты только читаются.
	videoSent.Store(&vs)
	pauseRecv.Store(&pr)

	out := string(runCDP(t, ctx, chrome, cdpPause, srv.URL+"/"))
	// phaseN=A<dA>|B<dB>: новый хост A в фоне (phase2) останавливает видео, в остальных фазах — идёт; старый B идёт всегда.
	readPhase := func(tag string) (int, int) {
		for _, ln := range strings.Split(out, "\n") {
			if v, ok := strings.CutPrefix(ln, tag+"=A"); ok {
				a, b, _ := strings.Cut(v, "|B")
				ai, _ := strconv.Atoi(strings.TrimSpace(a))
				bi, _ := strconv.Atoi(strings.TrimSpace(b))
				return ai, bi
			}
		}
		t.Fatalf("нет строки %s в выводе", tag)
		return 0, 0
	}
	a1, b1 := readPhase("phase1")
	a2, b2 := readPhase("phase2")
	if a1 < 20 {
		t.Errorf("A активна: кадров %d, ждали поток (≥20)", a1)
	}
	if b1 < 20 {
		t.Errorf("старый хост B в фоне: кадров %d, ждали поток как раньше (≥20)", b1)
	}
	if a2 != 0 {
		t.Errorf("A в фоне: кадров %d, ждали 0 (REQ-F-27: у паузящего хоста 0 отправленных кадров)", a2)
	}
	if b2 < 20 {
		t.Errorf("B активна: кадров %d, ждали поток (≥20)", b2)
	}
	a3, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(readPhaseLine(out, "phase3"), "A"))) // phase3=A<n>
	if a3 < 20 {
		t.Errorf("A вернулась: кадров %d, ждали возобновление (≥20)", a3)
	}
	for _, want := range []string{
		`connected=["connected","connected"]`,
		`active=0`, // активна первая вкладка (A)
		`stillconnected=["connected","connected"]`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if pa := preqs[ids[0]].Load(); pa < 1 {
		t.Errorf("новый хост A получил \"pause\" %d раз, ждали ≥1", pa)
	}
	if pb := preqs[ids[1]].Load(); pb != 0 {
		t.Errorf("старый хост B получил \"pause\" %d раз, ждали 0 (клиент его не шлёт)", pb)
	}
	if t.Failed() {
		t.Log(out)
	}
}

// readPhaseLine — строка вывода CDP, начинающаяся с tag= (без парсинга значений).
func readPhaseLine(out, tag string) string {
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, tag+"=") {
			return strings.TrimPrefix(ln, tag+"=")
		}
	}
	return ""
}
