package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"anypc/hub"
	"anypc/pake"
	"anypc/totp"
	"anypc/ui"
)

// cdpMyPC — «Мои ПК» (С4, фаза 1): три ПК входят по ключу (REQ-S-24) вкладками в одном окне; код TOTP
// вводится в окне-родителе и уходит в ждущий фрейм по очереди. Проверяет: вход по ключу во фрейме и
// пополнение списка `mine` (на m.key); 20 переключений щелчком и Ctrl+Alt+2 (Input.dispatchKeyEvent, в т.ч.
// автоповтор) не рвут соединений (drops=0), не плодят входов (на хосте по 1) и не оставляют залипших клавиш;
// буфер/звук — только у активной вкладки (sessActive); обрыв ("bye") метит вкладку «разорвано» за ≤ 1 с через
// событие; переподключение оборванной; «nokey» (отзыв на хосте) и снятие «Доверять» убирают из `mine`; открытие
// ?embed=<ID> в ВЕРХНЕМ окне не входит само (защита). Пиксельная задержка картинки ≤ 1 с (MULTI-PC.md) — свойство
// реального браузера (headless приостанавливает декод скрытого видео), проверяется вживую (V2); тест гейтит то,
// что контролирует код: соединение не рвётся и входов на хосте по 1.
const cdpMyPC = `
const [, , port, url] = process.argv;
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const tab = await (await fetch('http://127.0.0.1:' + port + '/json/new?' + url, { method: 'PUT' })).json();
  const ws = new WebSocket(tab.webSocketDebuggerUrl); await new Promise(r => ws.onopen = r);
  let id = 0; const wait = {};
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && wait[m.id]) wait[m.id](m); };
  const cmd = (method, params) => new Promise(r => { const i = ++id; wait[i] = r; ws.send(JSON.stringify({ id: i, method, params })); });
  const ev = x => new Promise(r => { const i = ++id; wait[i] = m => r(m.result?.result?.value); ws.send(JSON.stringify({ id: i, method: 'Runtime.evaluate', params: { expression: x, awaitPromise: true, returnByValue: true } })); });
  const ids = ['111111111', '222222222', '333333333'];
  const pcState = () => ev("JSON.stringify([...document.querySelectorAll('#frames iframe')].map(f => { try { return f.contentWindow.sessState(); } catch { return 'x'; } }))");
  const tabState = () => ev("JSON.stringify(myPcStates())");
  const mine = async () => JSON.parse(await ev("JSON.stringify((JSON.parse(localStorage.getItem('mine')||'[]')).sort())"));
  await sleep(800);
  // ВЕРХНЕЕ окно: ?embed=<ID> не должно входить само (parent===window) даже с готовым ключом — пробуем до засева
  const top = await (await fetch('http://127.0.0.1:' + port + '/json/new?' + url + '?embed=111111111', { method: 'PUT' })).json();
  const tws = new WebSocket(top.webSocketDebuggerUrl); await new Promise(r => tws.onopen = r);
  let tid = 0; const tw = {}; tws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && tw[m.id]) tw[m.id](m); };
  const tev = x => new Promise(r => { const i = ++tid; tw[i] = m => r(m.result?.result?.value); tws.send(JSON.stringify({ id: i, method: 'Runtime.evaluate', params: { expression: x, awaitPromise: true, returnByValue: true } })); });
  // засев ключей и отпечатков хостов (localStorage того же источника, общий со всеми фреймами)
  const ck = JSON.parse(await (await fetch(url + 'ckey')).text());
  const known = {}; for (const i of ids) known[i] = (await (await fetch(url + 'fp?id=' + i)).text());
  const ckeys = {}; for (const i of ids) ckeys[i] = { seed: ck.seed, pub: ck.pub, login: true, lu: '' };
  await ev("localStorage.setItem('ckeys', '" + JSON.stringify(ckeys) + "'); localStorage.setItem('known', '" + JSON.stringify(known) + "'); localStorage.setItem('mine', '[]'); 1");
  await sleep(1500);
  console.log('toplink=' + await tev("(document.getElementById('sess').classList.contains('hidden') && !(window.sessState && window.sessState())) ? 'noenter' : 'entered'"));
  // открыть 3 ПК вкладками — вход по ключу
  await ev("myPcAdd('" + ids[0] + "'); myPcAdd('" + ids[1] + "'); myPcAdd('" + ids[2] + "'); 1");
  for (let k = 0; k < 200; k++) {
    const want = await ev("myPcCodeWanted()");
    if (want) { const c = await (await fetch(url + 'code?id=' + want)).text(); await ev("document.getElementById('mcot').value='" + c + "'; document.getElementById('mcgo').click()"); await sleep(300); continue; }
    const st = JSON.parse(await tabState());
    if (st.length === 3 && st.every(s => s === 'ok')) break;
    await sleep(300);
  }
  console.log('connected=' + await pcState());
  console.log('authed=' + await tabState());
  console.log('mine=' + JSON.stringify(await mine())); // вход по ключу пополнил «Мои ПК» (m.key)
  // 20 переключений подряд: соединения остаются connected (без переподключения — ключевой критерий MULTI-PC.md
  // «соединение не рвётся, без нового входа») и переключение мгновенно на уровне приложения. Пиксельная задержка
  // картинки ≤ 1 с — свойство реального браузера: headless приостанавливает декод скрытого видео (~2,4 с), поэтому
  // гейтим то, что контролирует наш код (тёплое соединение), а не артефакт headless (пиксель вживую — V2).
  let drops = 0, maxSw = 0;
  for (let n = 0; n < 20; n++) {
    const i = n % 3;
    const dt = await ev("(() => { const t0 = performance.now(); myPcKey('Digit" + (i + 1) + "'); return [performance.now() - t0, myPcActive()]; })()");
    maxSw = Math.max(maxSw, dt[0]);
    if (dt[1] !== i) drops++;
    if (JSON.parse(await pcState()).some(s => s !== 'connected')) drops++;
  }
  console.log('switch=' + (drops === 0 && maxSw <= 1000) + '|drops=' + drops + '|sw=' + Math.round(maxSw));
  // переключение щелчком по вкладке — на первую (у вкладок есть ещё ⌂ и ×, поэтому выбираем по id)
  await ev("[...document.querySelectorAll('#tabs .tab .nm')].find(n => n.textContent.replace(/\\D/g,'') === '" + ids[0] + "').parentNode.click(); 1"); await sleep(300);
  console.log('clickactive=' + await ev("myPcActive()"));
  // переключение с клавиатуры: Ctrl+Alt+2 через Input.dispatchKeyEvent (работает и когда фокус во фрейме)
  const key = (type, extra) => cmd('Input.dispatchKeyEvent', Object.assign({ type }, extra));
  await key('rawKeyDown', { modifiers: 2, code: 'ControlLeft', key: 'Control', windowsVirtualKeyCode: 17 });
  await key('rawKeyDown', { modifiers: 3, code: 'AltLeft', key: 'Alt', windowsVirtualKeyCode: 18 });
  await key('rawKeyDown', { modifiers: 3, code: 'Digit2', key: '2', windowsVirtualKeyCode: 50 });
  // автоповтор от удержания: должен глотаться целиком, иначе «2» уйдёт на удалённый ПК и залипнет (held[1]=1)
  await key('rawKeyDown', { modifiers: 3, code: 'Digit2', key: '2', windowsVirtualKeyCode: 50, autoRepeat: true });
  await key('rawKeyDown', { modifiers: 3, code: 'Digit2', key: '2', windowsVirtualKeyCode: 50, autoRepeat: true });
  await key('keyUp', { modifiers: 3, code: 'Digit2', key: '2', windowsVirtualKeyCode: 50 });
  await key('keyUp', { modifiers: 1, code: 'AltLeft', key: 'Alt', windowsVirtualKeyCode: 18 });
  await key('keyUp', { modifiers: 0, code: 'ControlLeft', key: 'Control', windowsVirtualKeyCode: 17 });
  await sleep(400);
  console.log('keyactive=' + await ev("myPcActive()"));
  console.log('stillconnected=' + await pcState());
  console.log('held=' + await ev("JSON.stringify([...document.querySelectorAll('#frames iframe')].map(f => { try { return f.contentWindow.sessHeld(); } catch { return -1; } }))"));
  // буфер/звук — только у активной вкладки (активна вторая: Ctrl+Alt+2)
  console.log('active=' + await ev("JSON.stringify([...document.querySelectorAll('#frames iframe')].map(f => { try { return f.contentWindow.sessActive(); } catch { return 'x'; } }))"));
  // обрыв ("bye" от хоста) метит вкладку «разорвано» за ≤ 1 с — ждём по событию (poll 20 мс), не sleep
  const t0 = Date.now(); await fetch(url + 'bye?id=' + ids[2]);
  let bms = -1; for (let k = 0; k < 60; k++) { const st = JSON.parse(await tabState()); if (st[2] === 'broken') { bms = Date.now() - t0; break; } await sleep(20); }
  console.log('brokenms=' + (bms >= 0 && bms <= 1000) + '|' + bms);
  // прочие ПК не тронуты (соединения живы), а вкладка третьего помечена «разорвано» (метка — по событию)
  const ps = JSON.parse(await pcState()), ts = JSON.parse(await tabState());
  console.log('afterbye=' + JSON.stringify([ps[0], ps[1], ts[2]]));
  // отзыв ключа на хосте → переподключение оборванной вкладки → "nokey" → из «Мои ПК» убран
  await fetch(url + 'revoke?id=' + ids[0]); await fetch(url + 'bye?id=' + ids[0]);
  for (let k = 0; k < 60 && JSON.parse(await tabState())[0] !== 'broken'; k++) await sleep(50);
  await ev("[...document.querySelectorAll('#tabs .tab .nm')].find(n => n.textContent.replace(/\\D/g,'') === '" + ids[0] + "').parentNode.click(); 1"); // клик по оборванной — переподключить
  for (let k = 0; k < 80 && (await mine()).includes(ids[0]); k++) await sleep(100);
  console.log('afternokey=' + JSON.stringify(await mine()));
  // снятие «Доверять» у второго ПК (его фрейм) — забыть ключ и убрать из «Мои ПК»
  await ev("const f = document.querySelectorAll('#frames iframe')[1]; const d = f.contentWindow.document; const c = d.getElementById('keylogin'); c.checked = false; c.dispatchEvent(new Event('change')); 1");
  for (let k = 0; k < 40 && (await mine()).includes(ids[1]); k++) await sleep(100);
  console.log('afteruntrust=' + JSON.stringify(await mine()));
  process.exit(0);
})();`

// TestBrowserMyPC — «Мои ПК», фаза 1: несколько тёплых соединений (вход по ключу) в одном окне.
func TestBrowserMyPC(t *testing.T) {
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
	ids := []string{"111111111", "222222222", "333333333"}
	// один клиентский ключ (У3) на все ПК: хосты принимают именно его, фрейм подписывает им вход (seed тот же)
	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	seedB64 := base64.StdEncoding.EncodeToString(seed)
	ck, _ := pake.ClientSignB64(seedB64, "", "", "")
	clientPub, _ := base64.StdEncoding.DecodeString(ck["pub"])

	agents := map[string]*Agent{}
	otps := map[string]*otpHost{}
	keys := map[string]*keyStore{}
	logins := map[string]*atomic.Int32{}

	mux := http.NewServeMux()
	mux.Handle("/ws", &hub.Hub{})
	mux.HandleFunc("/ckey", func(w http.ResponseWriter, _ *http.Request) { json.NewEncoder(w).Encode(map[string]string{"seed": seedB64, "pub": ck["pub"]}) })
	mux.HandleFunc("/fp", func(w http.ResponseWriter, r *http.Request) { // отпечаток ключа хоста (клиент пинит его как «Известный хост»)
		if a := agents[r.URL.Query().Get("id")]; a != nil {
			w.Write([]byte(pake.KeyFingerprint(a.Key.Public().(ed25519.PublicKey))))
		}
	})
	mux.HandleFunc("/code", func(w http.ResponseWriter, r *http.Request) { // свежий код TOTP указанного ПК
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
	mux.HandleFunc("/revoke", func(_ http.ResponseWriter, r *http.Request) { // отозвать ключ на хосте
		if k := keys[r.URL.Query().Get("id")]; k != nil {
			k.set("")
		}
	})
	mux.HandleFunc("/bye", func(_ http.ResponseWriter, r *http.Request) { // хост обрывает сессию ("bye")
		if a := agents[r.URL.Query().Get("id")]; a != nil {
			a.Disconnect()
		}
	})
	// Раздача клиентской страницы — как на проде (server/main.go): рамка только своему источнику. Голый ui.FS без
	// этих заголовков не поймал бы регресс frame-ancestors 'none' → фрейм не грузится.
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
		ks.set("", clientPub) // ключ клиента во входе без пароля записи по умолчанию
		a := newAgent("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", id, nil)
		a.OTP = o.check
		a.KeyLogin = ks.login
		cnt := &atomic.Int32{}
		var last atomic.Bool
		a.OnState = func(_ bool, s string) {
			now := s != ""
			if now && !last.Swap(true) {
				cnt.Add(1)
			} else if !now {
				last.Store(false)
			}
		}
		a.Capture = func(ctx context.Context, c Cap) (*exec.Cmd, error) {
			return exec.CommandContext(ctx, "ffmpeg", FFArgs("test", "libx264", c)...), nil
		}
		agents[id], otps[id], keys[id], logins[id] = a, o, ks, cnt
		go a.Run(ctx)
	}

	out := string(runCDP(t, ctx, chrome, cdpMyPC, srv.URL+"/"))
	for _, want := range []string{
		"toplink=noenter\n",                                   // ?embed в верхнем окне не вошёл (строка целиком)
		`connected=["connected","connected","connected"]`,
		`authed=["ok","ok","ok"]`,
		`mine=["111111111","222222222","333333333"]`,          // вход по ключу пополнил «Мои ПК» (m.key)
		`clickactive=0`,
		`keyactive=1`,                                         // Ctrl+Alt+2 переключил на вторую вкладку
		`switch=true|drops=0|`,                                // 20 переключений: 0 обрывов/переподключений, мгновенно
		`stillconnected=["connected","connected","connected"]`,
		`held=[0,0,0]`,                                        // залипших клавиш не осталось
		`active=[false,true,false]`,                           // буфер/звук — только у активной (второй) вкладки
		`brokenms=true|`,                                      // метка «разорвано» за ≤ 1 с через событие (не из тормозимого таймера)
		`afterbye=["connected","connected","broken"]`,         // обрыв третьего не тронул первые два; его вкладка «разорвано»
		`afternokey=["222222222","333333333"]`,                // "nokey" убрал первый из «Мои ПК»
		`afteruntrust=["333333333"]`,                          // снятие «Доверять» убрало второй
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	for _, id := range ids { // после первых трёх входов по ключу переключение/обрыв новых входов не создаёт
		if n := logins[id].Load(); n != 1 {
			t.Errorf("ПК %s: входов %d, ожидалось 1", id, n)
		}
	}
	if t.Failed() {
		t.Log(out)
	}
}
