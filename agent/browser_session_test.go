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
	"testing"
	"time"

	"anypc/hub"
	"anypc/pake"
	"anypc/totp"
	"anypc/ui"
)

// cdpSession — экран 4 «Рабочее место (сессия)» по макету (Ч8): два ПК вкладками (вход по ключу, веб-клиент).
// Полоса ПК — та же, что на главном: подписи «на связи · напрямую» у активной, «в фоне · видео на паузе» у фоновой,
// «+» и подсказка Ctrl+Alt+← →. Панель: меню «Управляю / Файлы / Клавиши / Ещё» открываются и закрываются (щелчок,
// ↓ на кнопке, Esc, щелчок мимо), стрелки ходят по пунктам, клавиши в открытом меню на удалённый ПК не уходят; каждое
// прежнее действие панели доступно из нового места и делает то же (Win, Alt+Tab, Ctrl+Shift+Esc, раскладка, вставка,
// файлы и передачи, монитор, качество/скорость, сервер, статистика/CSV/сброс, переименовать, убрать). Ctrl+Alt+← →
// переключает вкладки (и из открытого меню) и на удалённый ПК не уходит. SHOTS=<папка> — снимки 1200×760 (ru, светлая/тёмная).
const cdpSession = `
const [, , port, url] = process.argv; const dir = process.env.SHOTS;
const fs = require('fs');
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const tab = await (await fetch('http://127.0.0.1:' + port + '/json/new?about:blank', { method: 'PUT' })).json();
  const ws = new WebSocket(tab.webSocketDebuggerUrl); await new Promise(r => ws.onopen = r);
  let id = 0; const wait = {};
  const ctxs = {}; // кадр → контекст выполнения его страницы (фрейм под CSP без eval — вычисляем по CDP в его контексте)
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && wait[m.id]) wait[m.id](m);
    if (m.method === 'Runtime.executionContextCreated' && m.params.context.auxData?.isDefault) ctxs[m.params.context.auxData.frameId] = m.params.context.id; };
  const cmd = (method, params) => new Promise(r => { const i = ++id; wait[i] = r; ws.send(JSON.stringify({ id: i, method, params })); });
  const ev = async x => { const r = (await cmd('Runtime.evaluate', { expression: x, awaitPromise: true, returnByValue: true })).result; return r?.exceptionDetails ? 'EXC ' + JSON.stringify(r.exceptionDetails.exception?.description) : r?.result?.value; };
  const until = async (x, n = 100) => { for (let i = 0; i < n; i++) { if (await ev(x)) return true; await sleep(200); } return false; };
  await cmd('Page.enable', {}); await cmd('Runtime.enable', {});
  if (dir) await cmd('Page.addScriptToEvaluateOnNewDocument', { source: "Object.defineProperty(navigator, 'languages', { get: () => ['ru'] });" });
  await cmd('Emulation.setDeviceMetricsOverride', { width: 1200, height: 760, deviceScaleFactor: 1, mobile: false });
  await cmd('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'light' }] });
  await cmd('Page.navigate', { url }); await sleep(1500);
  const ids = ['111111111', '222222222'];
  const ck = JSON.parse(await (await fetch(url + 'ckey')).text());
  const known = {}, ckeys = {}; for (const i of ids) { known[i] = await (await fetch(url + 'fp?id=' + i)).text(); ckeys[i] = { seed: ck.seed, pub: ck.pub, login: true, lu: '' }; }
  await ev("localStorage.setItem('ckeys', '" + JSON.stringify(ckeys) + "'); localStorage.setItem('known', '" + JSON.stringify(known) + "'); localStorage.setItem('mine', JSON.stringify([{ id: '111111111', name: 'Дом' }, { id: '222222222', name: 'Сервер' }])); localStorage.setItem('tour_home', '1'); localStorage.setItem('tour_sess', '1'); location.reload(); 1");
  await sleep(1500);
  await ev("myPcAdd('" + ids[1] + "'); myPcAdd('" + ids[0] + "'); 1"); // открыты в обратном порядке: порядок полосы — по списку, не по открытию
  for (let k = 0; k < 200; k++) {
    const want = await ev("myPcCodeWanted()");
    if (want) { const c = await (await fetch(url + 'code?id=' + want)).text(); await ev("document.getElementById('mcot').value='" + c + "'; document.getElementById('mcgo').click()"); await sleep(300); continue; }
    if ((await ev("JSON.stringify(myPcStates())")) === '["ok","ok"]') break;
    await sleep(300);
  }
  console.log('authed=' + await ev("JSON.stringify(myPcStates())"));
  // F(i) — документ фрейма ПК ids[i] (pcs: [222…, 111…])
  const F = i => "[...document.querySelectorAll('#frames iframe')].find(f => f.src.includes('embed=" + ids[i] + "')).contentWindow";
  const A = F(0); // активна — открыта последней
  // запись отправленного фреймами: клавиши (канал input) и сообщения ctl
  // fe(i, код) — выполнить в области фрейма (let/const окна фрейма: dc, ctl, samples, turns); монитор хосту не шлём (у ffmpeg-хоста он один)
  const fe = async (i, code) => {
    const t = (await cmd('Page.getFrameTree', {})).result.frameTree, f = (t.childFrames || []).find(c => c.frame.url.includes('embed=' + ids[i]));
    const r = (await cmd('Runtime.evaluate', { expression: code, contextId: ctxs[f.frame.id], awaitPromise: true, returnByValue: true })).result;
    return r?.exceptionDetails ? 'EXC ' + JSON.stringify(r.exceptionDetails.exception?.description) : r?.result?.value;
  };
  for (const i of [0, 1]) await fe(i, "window.rec = []; { const ds = dc.send.bind(dc), cs = ctl.send.bind(ctl); dc.send = m => { const o = JSON.parse(m); if (o.t === 'k') rec.push(o.c + (o.d ? 'v' : '^')); ds(m); }; ctl.send = m => { const o = JSON.parse(m); if (o.t !== 'pause') rec.push(o.t + ':' + (o.text ?? o.i ?? o.p ?? '')); if (o.t !== 'monitor') cs(m); }; } 1");
  const take = i => ev("(w => { const r = w.rec.join(','); w.rec.length = 0; return r; })(" + F(i) + ")");
  // полоса ПК: порядок по списку, активная — «на связи · напрямую», фоновая — «в фоне · видео на паузе», «+», подсказка
  await until("[...document.querySelectorAll('#tabs .tabg')].some(g => g.classList.contains('sel') && g.querySelector('small').textContent === t('st_live') + ' · ' + t('st_p2p'))");
  await until("[...document.querySelectorAll('#tabs .tabg')].some(g => g.querySelector('small').textContent === t('st_bg') + ' · ' + t('st_paused'))");
  console.log('strip=' + await ev("[...document.getElementById('tabs').children].map(e => e.id || (e.classList.contains('tabg') ? e.querySelector('.nm').textContent + (e.classList.contains('sel') ? '*' : '') + ':' + (e.querySelector('small').textContent === t('st_live') + ' · ' + t('st_p2p') ? 'live-p2p' : e.querySelector('small').textContent === t('st_bg') + ' · ' + t('st_paused') ? 'bg-paused' : e.querySelector('small').textContent) + ':' + !!e.querySelector('.tabx') : e.className)).join(',') + '|' + (document.getElementById('swhint').textContent === t('sw_hint'))"));
  // панель: кнопки по макету, ничего прежнего не пропало
  const vis = (w, i) => "(e => !!e && e.checkVisibility())(" + w + ".document.getElementById('" + i + "'))";
  console.log('bar=' + await ev("(w => [...w.document.getElementById('bar').children].filter(e => e.checkVisibility()).map(e => e.id || e.firstElementChild?.id || e.className).join(','))(" + A + ")"));
  console.log('ctl=' + await ev("(d => [d.getElementById('ctlm').textContent === t('ctl_on') + ' ▾', d.getElementById('ctlm').disabled].join())(" + A + ".document)"));
  // меню: щелчок открывает (фокус на первом пункте), Esc закрывает (фокус на кнопке), ↓ на кнопке открывает, End — последний
  const st = m => ev("(d => { const b = d.getElementById('" + m + "'), l = d.getElementById(b.getAttribute('aria-controls')); return [b.getAttribute('aria-expanded'), l.checkVisibility(), d.activeElement === b ? 'btn' : (d.activeElement?.dataset.keys || d.activeElement?.id || '-')].join(); })(" + A + ".document)");
  const key = (type, extra) => cmd('Input.dispatchKeyEvent', Object.assign({ type }, extra));
  const press = async (code, k, vk) => { await key('rawKeyDown', { code, key: k, windowsVirtualKeyCode: vk }); await key('keyUp', { code, key: k, windowsVirtualKeyCode: vk }); await sleep(60); };
  await ev(A + ".document.getElementById('keysm').click(); 1"); await sleep(100);
  const k1 = await st('keysm');
  await press('ArrowDown', 'ArrowDown', 40); await press('ArrowDown', 'ArrowDown', 40);
  const k2 = await st('keysm');
  await press('KeyA', 'a', 65);
  await press('ArrowUp', 'ArrowUp', 38); await press('ArrowUp', 'ArrowUp', 38); await press('ArrowUp', 'ArrowUp', 38);
  const k3 = await st('keysm');
  await press('Escape', 'Escape', 27);
  const k4 = await st('keysm');
  await press('ArrowDown', 'ArrowDown', 40); const k5 = await st('keysm');
  await press('End', 'End', 35); const k6 = await st('keysm');
  await press('Escape', 'Escape', 27);
  console.log('menukeys=' + [k1, k2, k3, k4, k5, k6].join('|') + '|sent=' + await take(0));
  // щелчок мимо меню закрывает его; два меню сразу не открыты
  await ev("(d => { d.getElementById('morem').click(); d.getElementById('filesm').click(); 1 })(" + A + ".document)"); await sleep(100);
  const two = await ev("(d => [d.getElementById('moremenu').checkVisibility(), d.getElementById('filesmenu').checkVisibility()].join())(" + A + ".document)");
  await ev("(d => { d.getElementById('v').click(); 1 })(" + A + ".document)"); await sleep(100);
  console.log('outside=' + two + '|' + await ev("(d => [d.getElementById('filesmenu').checkVisibility(), d.getElementById('filesm').getAttribute('aria-expanded')].join())(" + A + ".document)"));
  // пункт из меню: open(меню, селектор пункта) — меню открыто и пункт виден до щелчка; после — меню закрыто
  const item = async (m, sel) => { const r = await ev("(d => { d.getElementById('" + m + "').click(); const it = d.querySelector(\"" + sel + "\"); const on = d.getElementById(d.getElementById('" + m + "').getAttribute('aria-controls')).checkVisibility() && !!it && it.checkVisibility(); it?.click(); return on + ',' + d.getElementById(d.getElementById('" + m + "').getAttribute('aria-controls')).checkVisibility(); })(" + A + ".document)"); await sleep(300); return r; };
  const acts = [];
  for (const [n, sel] of [['win', "[data-keys='MetaLeft']"], ['alttab', "[data-keys='AltLeft Tab']"], ['taskmgr', "[data-keys='ControlLeft ShiftLeft Escape']"], ['layout', "[data-keys='MetaLeft Space']"]])
    acts.push(n + '=' + await item('keysm', sel) + ':' + await take(0));
  await ev("(w => { Object.defineProperty(w.navigator, 'clipboard', { value: { readText: async () => 'from-menu', writeText: async () => {} } }); 1 })(" + A + ")");
  acts.push('paste=' + await item('keysm', '#pastebtn') + ':' + await take(0));
  await ev("(w => { w.document.getElementById('fpick').click = () => w.rec.push('fpick'); 1 })(" + A + ")");
  acts.push('fsend=' + await item('filesm', '#fsend') + ':' + await take(0));
  acts.push('fget=' + await item('filesm', '#fget') + ':' + await take(0));
  const xf0 = await ev(A + ".document.getElementById('xfopen').classList.contains('hidden')");
  await ev(A + ".sendFile(new File([new Uint8Array(20000)], 'menu.bin')); 1");
  await until("(w => /[✓✗]/.test(w.document.getElementById('dlpop').textContent))(" + A + ")", 75);
  acts.push('xfers=' + xf0 + ',' + await item('filesm', '#xfopen') + ',' + await ev(vis(A, 'dlpop')) + ':' + await take(0));
  await ev(A + ".document.body.click(); 1");
  await ev(A + ".showMonitors({ list: [{ name: 'A', w: 1920, h: 1080, primary: true }, { name: 'B', w: 1280, h: 1024 }], cur: 0 }); 1");
  acts.push('mon=' + await item('morem', '#monm .mi button:nth-child(2)') + ':' + await take(0) + ':' + await ev(A + ".document.getElementById('mon').value"));
  acts.push('speed=' + await item('morem', "#qsel [data-q='1']") + ':' + await take(0) + ':' + await ev(A + ".document.querySelector(\"#qsel [data-q='1']\").getAttribute('aria-checked')"));
  acts.push('quality=' + await item('morem', "#qsel [data-q='0']") + ':' + await take(0));
  acts.push('stat=' + await item('morem', '#statbtn') + ':' + await ev("(d => [!d.body.classList.contains('nostat'), d.getElementById('statbtn').getAttribute('aria-checked')].join())(" + A + ".document)"));
  await ev("(w => { w.URL.createObjectURL = () => (w.rec.push('csv'), 'data:,'); 1 })(" + A + ")");
  acts.push('csv=' + await item('morem', '#csv') + ':' + await take(0));
  acts.push('reset=' + await item('morem', '#reset') + ':' + await fe(0, 'samples.length <= 1'));
  await item('morem', '#statbtn');
  console.log('acts=' + acts.join('|'));
  // переименовать и убрать — из «Ещё»; ☆ на панели — снова, когда ПК не свой
  const r1 = await item('morem', '#mren');
  await ev("(d => { const i = d.querySelector('#bar input.nmedit'); i.value = 'Дом 2'; i.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true })); 1 })(" + A + ".document)"); await sleep(300);
  console.log('rename=' + r1 + ':' + await ev("JSON.parse(localStorage.getItem('mine')).map(x => x.name).join('/')") + ':' + await ev("[...document.querySelectorAll('#tabs .nm')].map(n => n.textContent).join('/')") + ':' + await ev(vis(A, 'starbtn')));
  const d1 = await item('morem', '#mdel');
  console.log('remove=' + d1 + ':' + await ev("JSON.parse(localStorage.getItem('mine')).map(x => x.id).join('/')") + ':' + await ev(vis(A, 'starbtn')) + ':' + await ev("(d => [d.getElementById('mren').classList.contains('hidden'), d.getElementById('mdel').classList.contains('hidden')].join())(" + A + ".document)") + ':' + await ev("[...document.querySelectorAll('#tabs .tabg .nm')].map(n => n.dataset.id).join('/')"));
  await ev("localStorage.setItem('mine', JSON.stringify([{ id: '111111111', name: 'Дом' }, { id: '222222222', name: 'Сервер' }])); myPcRender(); 1"); await sleep(1500);
  if (dir) { // снимки: панель, открытые «Клавиши» и «Ещё», две вкладки — светлая и тёмная
    for (const th of ['light', 'dark']) {
      await cmd('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: th }] }); await sleep(500);
      const shot = async n => { const r = await cmd('Page.captureScreenshot', { format: 'png' }); fs.writeFileSync(dir + '/session-v031-' + n + '-' + th + '.png', Buffer.from(r.result.data, 'base64')); console.log('shot ' + n + '-' + th); };
      await shot('bar');
      await ev(A + ".document.getElementById('keysm').click(); 1"); await sleep(300); await shot('keys');
      await ev(A + ".document.getElementById('morem').click(); 1"); await sleep(300); await shot('more');
      await ev(A + ".document.body.click(); 1"); await sleep(200);
    }
    await cmd('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'light' }] });
  }
  // Ctrl+Alt+← → с фокусом на картинке активной вкладки: вкладка сменилась, на удалённые ПК ничего не ушло, залипших нет
  const order = JSON.parse(await ev("JSON.stringify(myPcOrder())")); // индексы pcs в порядке полосы: [111… (1), 222… (0)]
  const combo = async (code, k, vk, repeat) => {
    await key('rawKeyDown', { modifiers: 2, code: 'ControlLeft', key: 'Control', windowsVirtualKeyCode: 17 });
    await key('rawKeyDown', { modifiers: 3, code: 'AltLeft', key: 'Alt', windowsVirtualKeyCode: 18 });
    await key('rawKeyDown', { modifiers: 3, code, key: k, windowsVirtualKeyCode: vk });
    if (repeat) await key('rawKeyDown', { modifiers: 3, code, key: k, windowsVirtualKeyCode: vk, autoRepeat: true });
    await key('keyUp', { modifiers: 3, code, key: k, windowsVirtualKeyCode: vk });
    await key('keyUp', { modifiers: 1, code: 'AltLeft', key: 'Alt', windowsVirtualKeyCode: 18 });
    await key('keyUp', { modifiers: 0, code: 'ControlLeft', key: 'Control', windowsVirtualKeyCode: 17 }); await sleep(400);
  };
  const act = () => ev("myPcActive()");
  await ev("myPcAdd('" + ids[0] + "'); 1"); await sleep(400); // активна 111… — первая в полосе
  await take(0); await take(1);
  const a0 = await act();
  await combo('ArrowRight', 'ArrowRight', 39, true); const a1 = await act();
  await combo('ArrowRight', 'ArrowRight', 39); const a2 = await act();
  await combo('ArrowLeft', 'ArrowLeft', 37); const a3 = await act();
  const sent = (await take(0)) + '/' + (await take(1)); // Ctrl и Alt уходят (и отпускаются releaseAll), стрелки — нет
  console.log('switch=' + JSON.stringify(order) + '|' + [a0, a1, a2, a3].join(',') + '|arrows=' + /Arrow/.test(sent) + '|held=' + await ev("[" + F(0) + ".sessHeld(), " + F(1) + ".sessHeld()].join()"));
  // из открытого меню: Ctrl+Alt+→ переключает вкладку и закрывает меню
  const cur = await act(), W = "document.querySelectorAll('#frames iframe')[" + cur + "].contentWindow"; // фреймы в DOM — в порядке pcs
  await ev(W + ".document.getElementById('morem').click(); 1"); await sleep(100);
  await combo('ArrowRight', 'ArrowRight', 39);
  console.log('frommenu=' + (await act() !== cur) + '|' + await ev(W + ".document.getElementById('moremenu').checkVisibility()") + '|arrows=' + /Arrow/.test((await take(0)) + (await take(1))));
  // сервер-ретранслятор — из «Ещё» (последним: смена сервера переподключает сессию)
  await ev("myPcAdd('" + ids[0] + "'); 1"); await sleep(400);
  await fe(0, "turns = ['aa.test', 'bb.test']; renderTurn(); 1");
  console.log('turn=' + await item('morem', '#turnm .mi button:nth-child(3)') + ':' + await ev(A + ".document.getElementById('turn2').value") + ':' + await ev("JSON.parse(localStorage.getItem('turn'))"));
  process.exit(0);
})();`

// TestBrowserSession — экран сессии по макету (Ч8): полоса ПК, меню панели, прежние действия на новых местах, Ctrl+Alt+← →.
func TestBrowserSession(t *testing.T) {
	chrome := browserNeed(t, "node", "ffmpeg")
	if _, err := fs.Stat(ui.FS, "pake.wasm"); err != nil {
		t.Skip("нет ui/pake.wasm — собрать через build.sh")
	}
	ids := []string{"111111111", "222222222"}
	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	seedB64 := base64.StdEncoding.EncodeToString(seed)
	ck, _ := pake.ClientSignB64(seedB64, "", "", "")
	clientPub, _ := base64.StdEncoding.DecodeString(ck["pub"])
	agents := map[string]*Agent{}
	otps := map[string]*otpHost{}
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
	mux.Handle("/", http.FileServer(http.FS(ui.FS)))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	for _, id := range ids {
		o := &otpHost{secret: totp.NewSecret()}
		ks := &keyStore{}
		ks.set("", clientPub)
		a := newAgent("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", id, nil)
		a.OTP, a.KeyLogin, a.Pause = o.check, ks.login, true
		a.Capture = func(ctx context.Context, c Cap) (*exec.Cmd, error) {
			return exec.CommandContext(ctx, "ffmpeg", FFArgs("test", "libx264", c)...), nil
		}
		agents[id], otps[id] = a, o
		go a.Run(ctx)
	}
	out := string(runCDP(t, ctx, chrome, cdpSession, srv.URL+"/"))
	for _, want := range []string{
		`authed=["ok","ok"]`,
		// ⌂ (веб), «Дом» (активна, напрямую), «Сервер» (фон, на паузе) — у открытых ×; «+», подсказка клавиш
		`strip=tabhome,Дом*:live-p2p:true,Сервер:bg-paused:true,tabadd,grow,swhint|true`,
		`bar=ctlm,filesm,keysm,fsbtn,morem,grow,help2,pinbtn,bye` + "\n", // по макету; ☆ нет — ПК свой; микрофон — только с хостом со звуком; статистика скрыта
		`ctl=true,true`, // «Управляю ▾»; вход по ключу — режим не меняется, кнопка только показывает его
		// щелчок: открыто, фокус на Win; ↓↓ — Ctrl+Shift+Esc; «a» и пробел — не на удалённый; ↑↑↑ по кругу; Esc — закрыто,
		// фокус на кнопке; ↓ на кнопке — открыто с первым пунктом; End — последний видимый пункт («Передать буфер»: без разрешения clipboard-read)
		`menukeys=true,true,MetaLeft|true,true,ControlLeft ShiftLeft Escape|true,true,clipbtn|false,false,btn|true,true,MetaLeft|true,true,clipbtn|sent=` + "\n",
		`outside=false,true|false,false`, // второе меню закрыло первое (открыто «Файлы»); щелчок по картинке — закрыло
		`win=true,false:MetaLeftv,MetaLeft^|`,
		`alttab=true,false:AltLeftv,Tabv,Tab^,AltLeft^|`,
		`taskmgr=true,false:ControlLeftv,ShiftLeftv,Escapev,Escape^,ShiftLeft^,ControlLeft^|`,
		`layout=true,false:MetaLeftv,Spacev,Space^,MetaLeft^|`,
		`paste=true,false:clip:from-menu,ControlLeftv,KeyVv,KeyV^,ControlLeft^|`, // буфер раньше Ctrl+V
		`fsend=true,false:fpick|`,
		`fget=true,false:pick:|`,
		`xfers=true,true,false,true:|`, // «Передачи файлов» — только когда передачи есть; открывает тот же список
		`mon=true,false:monitor:1:1|`,
		`speed=true,false:quality:video:true|`,
		`quality=true,false:quality:text|`,
		`stat=true,false:true,true|`,
		`csv=true,false:csv|`,
		`reset=true,false:true`,
		`rename=true,false:Дом 2/Сервер:Дом 2/Сервер:false`,
		`remove=true,false:222222222:true:true,true:222222222/111111111`, // ушёл из списка, вкладка осталась (в конце полосы), ☆ — снова на панели
		// порядок полосы — по списку: 111… (pcs 1), 222… (pcs 0); → → ← по кругу; автоповтор проглочен; на удалённые ничего
		`switch=[1,0]|1,0,1,0|arrows=false|held=0,0`,
		`frommenu=true|false|arrows=false`,
		`turn=true,false:bb.test:bb.test`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if t.Failed() {
		t.Log(out)
	}
}
