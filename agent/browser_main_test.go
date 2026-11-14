package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"anypc/hub"
	"anypc/pake"
	"anypc/ui"
)

// mainStub — привязки окна app/spaceapi.go (Ч4) подменены; только в верхнем окне: фреймы «Моих ПК» берут их у
// родителя (ui/embed.js), иначе тест не поймал бы потерю имени в списке embed.js.
const mainStub = `(() => {
  if (window.parent !== window) return;
  localStorage.setItem('tour_home', '1');
  window.calls = []; window.op = null;
  const me = { id: '987654321', fp: 'SELF', pub: 'c2VsZg==', self: true, passUntil: 0 };
  window.st = { id: '987654321', confirm: false, otp: true, hasPass: true, users: [], keys: [],
    space: { in: true, damaged: false, compromised: false, over: false, pend: 0, wait: '', clock: [], ask: false, lock: true, gone: 0, members: [me], op: null } };
  window.hostInfo = async () => JSON.parse(JSON.stringify(st));
  window.spaceOp = async () => window.op && JSON.parse(JSON.stringify(window.op));
  window.knownGet = async id => JSON.parse(localStorage.getItem('known') || '{}')[id] || '';
  window.knownSet = async (id, fp) => { const k = JSON.parse(localStorage.getItem('known') || '{}'); k[id] = fp; localStorage.setItem('known', JSON.stringify(k)); };
  window.passOff = async () => { calls.push('off'); for (const m of st.space.members) m.passUntil = 0; await window.onOff?.(); };
  window.workHere = async (pw, code) => { calls.push('here:' + pw + ':' + code); window.here?.(pw, code); };
})();`

// cdpHead — общее начало сценариев: вкладка, CDP, подмена привязок (mainStub + extra), загрузка окна.
const cdpHead = `
const [, , port, url] = process.argv;
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const tab = await (await fetch('http://127.0.0.1:' + port + '/json/new?about:blank', { method: 'PUT' })).json();
  const ws = new WebSocket(tab.webSocketDebuggerUrl); await new Promise(r => ws.onopen = r);
  let id = 0; const wait = {};
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && wait[m.id]) wait[m.id](m); };
  const call = (method, params) => new Promise(r => { const i = ++id; wait[i] = r; ws.send(JSON.stringify({ id: i, method, params })); });
  const ev = async x => { const r = (await call("Runtime.evaluate", { expression: x, awaitPromise: true, returnByValue: true })).result; return r?.exceptionDetails ? "EXC " + JSON.stringify(r.exceptionDetails.exception?.description) : r?.result?.value; };
  const vis = i => "!document.getElementById('" + i + "').classList.contains('hidden')";
  const txt = i => "document.getElementById('" + i + "').textContent";
  const tile = (i, sel) => ev("document.querySelector('#sptiles .sptile[data-id=\"" + i + "\"] " + sel + "').click(); 1");
  await call('Page.enable', {});
  await call('Page.addScriptToEvaluateOnNewDocument', { source: ` + "`" + mainStub + "`" + ` });
  await call('Page.addScriptToEvaluateOnNewDocument', { source: '(() => { if (window.parent !== window) return; ' + await extra() + ' })()' });
  await call('Page.navigate', { url }); await sleep(1500);
`

// cdpMain — главный экран с подменёнными привязками: вкладки и плитки ПК пространства (имя из mine, иначе ID; пропуск
// или «нужен код»), «Передать управление этим ПК»; без детектора блокировки «Я тут» недоступно с объяснением; «Я тут» с
// неверным паролем и с итогом по ПК; «Открыть» — вкладка «Моих ПК»; код из плитки уходит во фрейм на его запрос (и только
// раз); «Снять».
const cdpMain = `
const extra = async () => ` + "`" + `
  st.space.members.push({ id: '444555666', fp: 'OF', pub: 'b2Y=', self: false, passUntil: Date.now() + 3 * 3600e3 },
    { id: '777888999', fp: 'HO', pub: 'aG8=', self: false, passUntil: 0 });
  localStorage.setItem('mine', JSON.stringify([{ id: '444555666', name: 'Office' }]));
  window.here = pw => { window.op = pw === 'owner-pass' ? { kind: 'workHere', state: 'done', result: [{ id: '444555666', state: 'ok' }, { id: '777888999', state: 'refused', err: 'auth' }] }
    : { kind: 'workHere', state: 'err', err: 'password', result: null }; st.space.op = { kind: op.kind, state: op.state }; };` + "`" + `;` + cdpHead + `
  const tabs = () => ev("[...document.querySelectorAll('#hometabs .tab')].map(b => b.textContent).join(';')");
  console.log('tabs=' + await tabs());
  console.log('tiles=' + await ev("[...document.querySelectorAll('#sptiles .sptile')].map(d => d.textContent + '|' + (d.querySelector('input')?.placeholder || '')).join(';')"));
  console.log('give=' + await ev("document.querySelector('#me h2').textContent + '|' + " + vis('accrow') + " + '|' + " + vis('spmain')));
  await ev("st.space.lock = false; 1"); await sleep(1300);
  console.log('nolock=' + await ev("[document.getElementById('shgo').disabled, " + vis('shlock') + ", " + txt('shlock') + "].join('|')"));
  await ev("st.space.lock = true; 1"); await sleep(1300);
  console.log('lock=' + await ev("[document.getElementById('shgo').disabled, " + vis('shlock') + "].join('|')"));
  await ev("document.getElementById('shpw').value = 'wrong'; document.getElementById('shcd').value = '123456'; document.getElementById('shgo').click(); 1"); await sleep(500);
  console.log('bad=' + await ev(txt('shres')));
  await ev("document.getElementById('shpw').value = 'owner-pass'; document.getElementById('shcd').value = '654321'; document.getElementById('shgo').click(); 1"); await sleep(500);
  console.log('here=' + await ev(txt('shres') + " + '|' + document.getElementById('shpw').value + document.getElementById('shcd').value"));
  await ev("window.op = { kind: 'sync', state: 'run', result: null }; st.space.op = { kind: 'sync', state: 'run' }; 1"); await sleep(1300);
  console.log('other=' + await ev(txt('shres'))); // итог другой операции (сверка) — не в строке «Я тут»
  await ev("window.op = null; st.space.op = null; 1");
  await tile('444555666', 'button'); await sleep(300);
  console.log('open=' + await ev("[...document.querySelectorAll('#frames iframe')].map(f => new URL(f.src).searchParams.get('embed')).join(',') + '|' + " + vis('home')));
  await ev("document.getElementById('tabhome').click(); 1"); await sleep(200);
  await ev("document.querySelector('#sptiles .sptile[data-id=\"777888999\"] input').value = '135790'; 1"); await tile('777888999', 'button');
  const f1 = "document.querySelectorAll('#frames iframe')[1].contentWindow";
  for (let k = 0; k < 50 && await ev("typeof " + f1 + ".embedCode") !== 'function'; k++) await sleep(100);
  await sleep(500);
  await ev("myPcState('777888999', 'code'); 1"); await sleep(300);
  const got = await ev(f1 + ".document.getElementById('otp').value") + '|' + await ev("myPcCodeWanted()");
  await ev("myPcState('777888999', 'code'); 1"); await sleep(100);
  console.log('code=' + got + '|' + await ev("myPcCodeWanted()"));
  await ev("document.getElementById('tabhome').click(); 1"); await sleep(200);
  const offv = await ev(vis('shoff'));
  await ev("document.getElementById('shoff').click(); 1"); await sleep(1300);
  console.log('off=' + offv + '|' + await ev("calls.join(',')") + '|' + await ev(txt('shres')) + '|' + await ev(vis('shoff')) + '|' + await tabs());
  process.exit(0);
})();`

func browserNeed(t *testing.T, tools ...string) string {
	chrome, err := exec.LookPath("google-chrome")
	if err != nil {
		t.Skip("нет google-chrome")
	}
	for _, x := range tools {
		if _, err := exec.LookPath(x); err != nil {
			t.Skip("нет " + x)
		}
	}
	return chrome
}

// TestBrowserMain — главный экран (Ч4) с подменёнными привязками.
func TestBrowserMain(t *testing.T) {
	chrome := browserNeed(t, "node")
	srv := httptest.NewServer(http.FileServer(http.FS(ui.FS)))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out := string(runCDP(t, ctx, chrome, cdpMain, srv.URL+"/"))
	for _, want := range []string{
		"tabs=This PCI'm here;Office;777 888 999code needed;+\n",
		"give=Hand over control of this PC|true|true\n",
		"nolock=true|true|Screen lock on this PC is not tracked — no pass is issued (password and code work as usual)\n",
		"lock=false|false\n",
		"bad=Wrong password\n",
		"here=Office · 444 555 666 — open777 888 999 — refused: Wrong password or code|\n", // итог по ПК; пароль и код из полей стёрты
		"other=Office · 444 555 666 — open777 888 999 — refused: Wrong password or code\n",
		"open=444555666|false\n",
		"code=135790||777888999\n", // код из плитки — во фрейм на первый запрос; второй запрос — в общую строку кода
		"off=true|here:wrong:123456,here:owner-pass:654321,off|Passes are taken off.|false|This PC;Officecode needed;777 888 999code needed;+\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if !regexp.MustCompile(`tiles=Officeno password until \d\d:\d\d[^;|]*444 555 666Open\|;777 888 999code needed777 888 999Sign in\|Code from the app\n`).MatchString(out) {
		t.Error("плитки не те")
	}
}

// cdpPassOpen — вход по пропуску из окна к настоящей цели: «Открыть» входит без пароля и кода; подпись прошлой
// сессии (повтор) в новой не проходит; после «Снять» вкладка разорвана, а вход по устаревшему passUntil — отказ.
const cdpPassOpen = `
const extra = async () => {
  const i = await (await fetch(url + 'tinfo')).json();
  return "st.space.members.push({ id: '123456789', fp: '" + i.fp + "', pub: '" + i.pub + "', self: false, passUntil: Date.now() + 3600e3 });" +
    "window.hostVerify = async (pub, sig, id, l, r) => { const x = await fetch('/hv', { method: 'POST', body: JSON.stringify({ pub, sig, id, l, r }) }); if (!x.ok) throw 'bad'; return x.text(); };" +
    "window.spaceSign = async (id, l, r) => { calls.push('sign:' + id); if (window.replay) return window.lastSig; const x = await fetch('/sign', { method: 'POST', body: JSON.stringify({ id, l, r }) }); if (!x.ok) throw 'space:nopass'; return window.lastSig = await x.json(); };" +
    "window.onOff = () => fetch('/off', { method: 'POST' });";
};` + cdpHead + `
  const st0 = async () => JSON.parse(await ev("JSON.stringify(myPcStates())"))[0];
  const waitSt = async (...want) => { for (let k = 0; k < 100 && !want.includes(await st0()); k++) await sleep(150); return st0(); };
  const msg = () => ev("document.querySelector('#frames iframe').contentWindow.document.getElementById('msg').textContent");
  const open = () => tile('123456789', 'button');
  const close = async () => { await ev("document.querySelector('#tabs .tab .tabx').click(); 1"); await sleep(1500); };
  await open();
  console.log('opened=' + await waitSt('ok') + '|' + await ev("document.querySelector('#frames iframe').contentWindow.sessState()"));
  await close();
  const mem = "st.space.members.find(m => m.id === '123456789')";
  await ev("window.fp0 = " + mem + ".fp; " + mem + ".fp = 'WRONG'; 1"); await open(); // ключ хоста не тот, что в M
  console.log('wrongkey=' + await waitSt('broken') + '|' + await msg());
  await close(); await ev(mem + ".fp = window.fp0; 1");
  await ev("window.replay = true; 1"); await open();
  console.log('replay=' + await waitSt('pw') + '|' + await msg());
  await close(); await ev("window.replay = false; 1"); await open();
  console.log('reopen=' + await waitSt('ok'));
  await ev("document.getElementById('tabhome').click(); document.getElementById('shoff').click(); 1");
  console.log('afteroff=' + await waitSt('broken'));
  await close();
  await ev("st.space.members.find(m => m.id === '123456789').passUntil = Date.now() + 3600e3; 1"); await sleep(1300); // устаревший passUntil
  await open();
  console.log('offopen=' + await waitSt('pw') + '|' + await msg());
  console.log('calls=' + await ev("calls.join(',')"));
  process.exit(0);
})();`

// TestBrowserPassOpen — e2e Ч4: окно входит по пропуску (spaceSign — как app/spaceapi.go: ключ этого хоста над
// отпечатками сессии окна) на настоящую цель; повтор подписи — отказ; «Снять» рвёт сессию и запрещает вход.
func TestBrowserPassOpen(t *testing.T) {
	chrome := browserNeed(t, "node", "ffmpeg")
	mux := http.NewServeMux()
	mux.Handle("/ws", &hub.Hub{})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	_, mkey, _ := ed25519.GenerateKey(nil)
	mpub := mkey.Public().(ed25519.PublicKey)
	p := passTarget(t, wsURL, nil, mpub, func(p *passRig) {
		p.a.Capture = func(ctx context.Context, c Cap) (*exec.Cmd, error) {
			return exec.CommandContext(ctx, "ffmpeg", FFArgs("test", "libx264", c)...), nil
		}
	})
	pid, err := PassOpenID(ctx, passDial(wsURL, p, mkey)) // «Я тут» мастера: пропуск выдан
	if err != nil {
		t.Fatal(err)
	}
	idle(t, p.a)
	tpub := p.a.Key.Public().(ed25519.PublicKey)
	body := func(r *http.Request) map[string]string {
		m := map[string]string{}
		json.NewDecoder(r.Body).Decode(&m)
		return m
	}
	mux.HandleFunc("/tinfo", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"fp": pake.KeyFingerprint(tpub), "pub": base64.StdEncoding.EncodeToString(tpub)})
	})
	mux.HandleFunc("/hv", func(w http.ResponseWriter, r *http.Request) {
		m := body(r)
		fp, err := pake.HostVerifyB64(m["pub"], m["sig"], m["id"], m["l"], m["r"])
		if err != nil {
			http.Error(w, "bad", http.StatusForbidden)
			return
		}
		w.Write([]byte(fp))
	})
	mux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) { // как spaceSign: seed окну не отдаётся
		m := body(r)
		k, err := pake.ClientSignB64(base64.StdEncoding.EncodeToString(mkey.Seed()), m["id"], m["l"], m["r"])
		if err != nil {
			http.Error(w, "bad", http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"pub": k["pub"], "sig": k["sig"]})
	})
	mux.HandleFunc("/off", func(w http.ResponseWriter, r *http.Request) {
		if err := PassOff(r.Context(), PassDial{Server: wsURL, ID: "123456789", HostPub: tpub, Key: mkey, PID: pid}); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
		}
	})
	mux.Handle("/", http.FileServer(http.FS(ui.FS)))
	out := string(runCDP(t, ctx, chrome, cdpPassOpen, srv.URL+"/"))
	for _, want := range []string{
		"opened=ok|connected\n",
		"wrongkey=broken|Error: the remote PC could not be verified — connection may be intercepted\n",
		"replay=pw|Error: no pass on that PC — sign in with password\n",
		"reopen=ok\n",
		"afteroff=broken\n",
		"offopen=pw|Error: no pass on that PC — sign in with password\n",
		"calls=sign:123456789,sign:123456789,sign:123456789,sign:123456789,off,sign:123456789\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if p.a.passValid(mpub, salt) {
		t.Error("после «Снять» пропуск на цели жив")
	}
}
