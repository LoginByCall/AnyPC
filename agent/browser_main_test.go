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
  st.space.members[0].passUntil = Date.now() + 3600e3; // свой ПК в M — вход по пропуску к себе не пробуется
  window.savedGet = async id => id === '777888999' ? 'frame-pass' : ''; window.savedSet = async () => {};
  window.spaceSign = async () => { calls.push('sign'); throw 'space:nopass'; }; window.hostVerify = async () => 'OF';
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
  const ho = "document.querySelector('#sptiles .sptile[data-id=\"777888999\"] input')";
  const nfr = () => ev("document.querySelectorAll('#frames iframe').length");
  await ev(ho + ".value = '123'; 1"); await tile('777888999', '.tact button'); // не 6 цифр — вкладка не открывается
  console.log('short=' + await nfr() + '|' + await ev("document.activeElement === " + ho));
  const f1 = "[...document.querySelectorAll('#frames iframe')].find(f => f.src.includes('embed=777888999')).contentWindow";
  const frame = async () => { for (let k = 0; k < 50 && await ev("typeof " + f1 + "?.embedCode") !== 'function'; k++) await sleep(100); await sleep(500); };
  const homeTab = async () => { await ev("document.getElementById('tabhome').click(); 1"); await sleep(200); };
  const closeHo = async () => { await ev("[...document.querySelectorAll('#tabs .tab')].find(b => b.querySelector('.nm')?.dataset.id === '777888999').querySelector('.tabx').click(); 1"); await sleep(300); };
  await ev(ho + ".value = '135790'; 1"); await tile('777888999', '.tact button'); await frame(); // фрейм с запомненным паролем ждёт хост
  await ev("myPcState('777888999', 'code'); 1"); await sleep(300);
  const got = await ev(f1 + ".document.getElementById('otp').value") + '|' + await ev("myPcCodeWanted()");
  await ev("myPcState('777888999', 'code'); 1"); await sleep(100);
  console.log('code=' + got + '|' + await ev("myPcCodeWanted()"));
  // код устарел: вход попросил пароль — код плитки стёрт; вкладку закрыли до запроса — тоже
  await closeHo(); await homeTab();
  await ev(ho + ".value = '246802'; 1"); await tile('777888999', '.tact button'); await frame();
  await ev("myPcState('777888999', 'pw'); myPcState('777888999', 'code'); 1"); await sleep(300);
  const st1 = await ev(f1 + ".document.getElementById('otp').value") + '|' + await ev("myPcCodeWanted()");
  await closeHo(); await homeTab();
  await ev(ho + ".value = '112233'; 1"); await tile('777888999', '.tact button'); await closeHo();
  await ev("myPcAdd('777888999'); 1"); await frame();
  await ev("myPcState('777888999', 'code'); 1"); await sleep(300);
  console.log('stale=' + st1 + '|' + await ev(f1 + ".document.getElementById('otp').value") + '|' + await ev("myPcCodeWanted()"));
  await closeHo();
  await ev("document.getElementById('tabhome')?.click(); 1"); await sleep(200);
  const offv = await ev(vis('shoff'));
  await ev("document.getElementById('shoff').click(); 1"); await sleep(1300);
  console.log('off=' + offv + '|' + await ev("calls.join(',')") + '|' + await ev(txt('shres')) + '|' + await ev(vis('shoff')) + '|' + await tabs() + '|' + await ev("document.querySelector('#sptiles .sptile[data-id=\"444555666\"] .tag').textContent"));
  // разметка в имени из mine и в итоге — только текстом
  await ev("localStorage.setItem('mine', JSON.stringify([{ id: '777888999', name: '<i id=xss1>X</i>' }])); window.op = { kind: 'workHere', state: 'done', result: [{ id: '777888999', state: 'refused', err: '<i id=xss2>' }] }; st.space.op = { kind: 'workHere', state: 'done' }; 1");
  await sleep(1300);
  console.log('xss=' + await ev("[!!document.getElementById('xss1'), !!document.getElementById('xss2'), document.querySelector('#sptiles .sptile[data-id=\"777888999\"] b').textContent, " + txt('shres') + "].join('|')"));
  // вход по пропуску (passOf): цель — не свой ПК, пропуск жив, запись без имени, не после отказа
  await ev("st.space.members[0].passUntil = st.space.members[1].passUntil = Date.now() + 3600e3; 1");
  const pof = () => ev("(async () => [!!await passOf('444555666'), !!await passOf('777888999'), !!await passOf('987654321')].join(','))()");
  const p1 = await pof();
  await ev("document.getElementById('user').value = 'anna'; 1"); const p2 = await pof(); await ev("document.getElementById('user').value = ''; 1");
  console.log('passof=' + p1 + '|' + p2);
  // ответы хоста при входе по пропуску: «a» без pass — подписи не просить; «otp» — код не показывать; отказ запоминается
  await ev("window.fch = { sent: [], send(x) { this.sent.push(x); } }; host = '444555666'; pc = { sp: { fp: 'OF' }, close() {} }; onAuth(fch, { data: JSON.stringify({ t: 'a', salt: '', msg: '' }) }, pc).then(() => 1)");
  console.log('nopassa=' + await ev("[fch.sent.length, calls.includes('sign'), " + txt('msg') + "].join('|')") + '|' + await pof());
  await ev("host = '777888999'; pc = { bypass: 'HO', close() {} }; onAuth(fch, { data: JSON.stringify({ t: 'otp' }) }, pc).then(() => 1)");
  console.log('otpbypass=' + await ev("[fch.sent.length, " + vis('otpbox') + ", " + txt('msg') + "].join('|')") + '|' + await pof());
  // «ok» без pass при входе по пропуску (ключ тот, что в M) — не вход
  await ev("host = '444555666'; pc = { bypass: 'OF', localDescription: { sdp: '' }, remoteDescription: { sdp: '' }, close() {} }; onAuth(fch, { data: JSON.stringify({ t: 'ok', pub: 'x', sig: 'y' }) }, pc).then(() => 1)");
  console.log('okpass=' + await ev("[authed, " + txt('msg') + "].join('|')"));
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
	hang := make(chan struct{}) // хаб, который не отвечает: вкладки ждут хост, не падая в «разорвано» и «нужен пароль»
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(http.ResponseWriter, *http.Request) { <-hang })
	mux.Handle("/", http.FileServer(http.FS(ui.FS)))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	defer close(hang)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out := string(runCDP(t, ctx, chrome, cdpMain, srv.URL+"/"))
	for _, want := range []string{

		"give=Hand over control of this PC|true|true\n",
		"nolock=true|true|Screen lock on this PC is not tracked — no pass is issued (password and code work as usual)\n",
		"lock=false|false\n",
		"bad=Wrong password\n",
		"here=Office · 444 555 666 — open777 888 999 — refused: Wrong password or code|\n", // итог по ПК; пароль и код из полей стёрты
		"other=Office · 444 555 666 — open777 888 999 — refused: Wrong password or code\n",
		"open=444555666|false\n",
		"short=1|true\n",           // код не из 6 цифр: вкладки нет, фокус в поле
		"code=135790||777888999\n", // код из плитки — во фрейм на первый запрос; второй запрос — в общую строку кода
		"stale=|777888999||777888999\n",
		"xss=false|false|<i id=xss1>X</i>|<i id=xss1>X</i> · 777 888 999 — refused: Error: space:<i id=xss2>\n",
		"passof=true,false,false|false,false,false\n",
		"nopassa=0|false|Error: no pass on that PC — sign in with password|false,false,false\n",
		"otpbypass=0|false|Error: no pass on that PC — sign in with password|false,false,false\n",
		"okpass=false|Error: the remote PC could not be verified — connection may be intercepted\n",
		// вкладка Office открыта (хаб молчит) — в полосе её состояние; пропуск снят — в плитке «нужен код»
		"off=true|here:wrong:123456,here:owner-pass:654321,off|Passes are taken off.|false|This PC;Officeconnecting…;777 888 999code needed;+|code needed\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if !regexp.MustCompile(`tiles=Officeuntil \d\d:\d\d[^;|]*sign-in without password · 444 555 666Open···Rename\|;777 888 999code needed···Renamesign-in without password · 777 888 999Sign in\|Code from the app\n`).MatchString(out) {
		t.Error("плитки не те")
	}
	if !regexp.MustCompile(`tabs=This PCI'm here;Officeno password until \d\d:\d\d[^;]*;777 888 999code needed;\+\n`).MatchString(out) {
		t.Error("полоса ПК не та")
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
    "window.onOff = () => fetch('/off', { method: 'POST' });" +
    "window.savedGet = async id => JSON.parse(localStorage.getItem('sv') || '{}')[id] || ''; window.savedSet = async (id, pw) => { const k = JSON.parse(localStorage.getItem('sv') || '{}'); if (pw) k[id] = pw; else delete k[id]; localStorage.setItem('sv', JSON.stringify(k)); };";
};` + cdpHead + `
  const st0 = async () => JSON.parse(await ev("JSON.stringify(myPcStates())"))[0];
  const waitSt = async (...want) => { for (let k = 0; k < 100 && !want.includes(await st0()); k++) await sleep(150); return st0(); };
  const msg = () => ev("document.querySelector('#frames iframe').contentWindow.document.getElementById('msg').textContent");
  const open = () => tile('123456789', 'button');
  const close = async () => { await ev("document.querySelector('#tabs .tab .tabx').click(); 1"); await sleep(1500); };
  await open();
  console.log('opened=' + await waitSt('ok') + '|' + await ev("document.querySelector('#frames iframe').contentWindow.sessState()"));
  await close();
  // с главной по ID с набранным (неверным) паролем и «Запомнить»: вход по пропуску пароль не проверял — не запоминать
  await ev("document.getElementById('id').value = '123456789'; document.getElementById('pw').value = 'WRONG-password'; document.getElementById('remember').checked = true; document.getElementById('go').click(); 1");
  for (let k = 0; k < 100 && await ev("sessState()") !== 'connected'; k++) await sleep(150);
  await sleep(500);
  console.log('mainpw=' + await ev("sessState()") + '|' + await ev("savedGet('123456789')") + '|' + await ev("again?.pw"));
  await ev("end(''); 1"); await sleep(1500);
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
		"mainpw=connected||\n",
		"calls=sign:123456789,sign:123456789,sign:123456789,sign:123456789,sign:123456789,off,sign:123456789\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if p.a.passValid(mpub, salt) {
		t.Error("после «Снять» пропуск на цели жив")
	}
}
