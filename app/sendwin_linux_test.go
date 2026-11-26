package main

import (
	"context"
	"crypto/ed25519"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"anypc/agent"
	"anypc/pake"
	"anypc/totp"
	"anypc/ui"
)

// cdpSendJS — экран 7 «Отправить» в настоящей странице программы: шаги «что» → «кому» с подсказкой, что делать
// дальше; ход, итог, ошибка до первого байта (выбор сохранён); избранные — переименовать, убрать с отзывом;
// плашка нового закрепления и «Отозвать» в «Доступе»; курсор у края (H2): движение и уход за край — к краю,
// нажатие вне картинки — мимо. Снимки 1200×760, светлая и тёмная, — в каталог argv[4].
const cdpSendJS = `
const [, , port, base, shots] = process.argv;
const fs = require('fs');
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const tab = await (await fetch('http://127.0.0.1:' + port + '/json/new?about:blank', { method: 'PUT' })).json();
  const ws = new WebSocket(tab.webSocketDebuggerUrl); await new Promise(r => ws.onopen = r);
  let id = 0; const wait = {};
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && wait[m.id]) wait[m.id](m);
    if (m.method === 'Runtime.exceptionThrown') console.log('PAGEEXC ' + JSON.stringify(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text)); };
  const call = (method, params) => new Promise(r => { const i = ++id; wait[i] = r; ws.send(JSON.stringify({ id: i, method, params })); });
  const ev = async x => { const r = (await call("Runtime.evaluate", { expression: x, awaitPromise: true, returnByValue: true })).result; if (r?.exceptionDetails) console.log('EVALEXC ' + JSON.stringify(r.exceptionDetails.exception?.description)); return r?.exceptionDetails ? "EXC " + JSON.stringify(r.exceptionDetails.exception?.description) : r?.result?.value; };
  const vis = i => "document.getElementById('" + i + "').checkVisibility()";
  await call('Runtime.enable', {});
  const txt = i => "document.getElementById('" + i + "').textContent";
  const until = async (x, n = 50) => { for (let i = 0; i < n; i++) { if (await ev(x) === true) return true; await sleep(100); } return false; };
  const shot = async name => { const r = await call('Page.captureScreenshot', { format: 'png' }); fs.writeFileSync(shots + '/' + name + '.png', Buffer.from(r.result.data, 'base64')); };
  await call('Page.enable', {});
  await call('Emulation.setDeviceMetricsOverride', { width: 1200, height: 760, deviceScaleFactor: 1, mobile: false });
  await call('Page.addScriptToEvaluateOnNewDocument', { source: "localStorage.setItem('tour_home', '1'); localStorage.setItem('tour_connect', '1');" });
  await call('Page.navigate', { url: base + '/?t=tokui' });
  await until("typeof sendGo === 'function' && " + vis('sndgo'));
  await ev("document.getElementById('sndgo').click(); 1");
  await until(vis('send') + " && document.querySelectorAll('#sndown .sndt').length > 0");
  console.log('open=' + await ev("[" + vis('send') + ", " + vis('home') + ", document.getElementById('sndsend').disabled, " + txt('sndhint') + "].join('|')"));
  await ev("document.getElementById('sndpick').click(); 1");
  await until("document.querySelectorAll('#sndpicks .sndpk').length === 1");
  console.log('picked=' + await ev("[document.querySelector('#sndpicks .sndpk span').textContent, " + txt('sndpick') + ", " + txt('sndhint') + "].join('|')"));
  await ev("document.querySelector('#sndown .sndt').click(); 1"); await sleep(100);
  console.log('ready=' + await ev("[" + txt('sndsum') + ", " + txt('sndhint') + ", document.getElementById('sndsend').disabled, document.querySelector('#sndown .sndt').getAttribute('aria-pressed')].join('|')"));
  console.log('favs=' + await ev("[...document.querySelectorAll('#sndfavs .sndt')].map(b => b.textContent).join(',')"));
  await shot('send-light');
  await call('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'dark' }] }); await sleep(200);
  await shot('send-dark');
  await call('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'light' }] });
  // ход: отправка ждёт (sendRun в тесте), окно опрашивает hostInfo
  await ev("document.getElementById('sndsend').click(); 1");
  await until("/Отправляю/.test(" + txt('sndst') + ")");
  console.log('run=' + await ev("[" + txt('sndst') + ", " + txt('sndcancel') + ", document.getElementById('sndsend').disabled].join('|')"));
  await shot('send-run-light');
  // чужому — строка про «Принять?» (своему её нет — проверка run= выше); ход — нейтральная рамка, не ошибка
  console.log('runask=' + await ev("(() => { snd.last = ''; sndRender({ id: '555666777', kind: 'known', state: 'run', item: 1, items: 1, done: 1, total: 2 }); const b = document.querySelector('#sndst .banner'); const r = [b.className, /Принять/.test(b.textContent)].join('|'); snd.last = ''; sndRender(hostS.send); return r; })()"));
  await fetch(base + '/release');
  await until("/✓/.test(" + txt('sndst') + ")");
  console.log('done=' + await ev("[" + txt('sndst') + ", document.querySelectorAll('#sndpicks .sndpk').length].join('|')"));
  await shot('send-done-light');
  await ev("[...document.querySelectorAll('#sndst button')].find(b => /ещё/.test(b.textContent)).click(); 1");
  await until(txt('sndst') + " === ''");
  // неверный код чужому по ID: ни байта — выбор сохранён, окно говорит, что делать
  await ev("document.getElementById('sndpick').click(); 1");
  await until("document.querySelectorAll('#sndpicks .sndpk').length === 1");
  // отправка из трея (итог виден и в окне) выбор окна не стирает — ни итогом, ни «Отправить ещё»
  await fetch(base + '/tray');
  await until("/✓/.test(" + txt('sndst') + ")");
  const tr1 = await ev("document.querySelectorAll('#sndpicks .sndpk').length");
  await ev("[...document.querySelectorAll('#sndst button')].find(b => /ещё/.test(b.textContent)).click(); 1");
  await until(txt('sndst') + " === ''");
  console.log('tray=' + tr1 + '|' + await ev("document.querySelectorAll('#sndpicks .sndpk').length"));
  // устаревший выбор (send:pick до начала): выбор очищен, «Выбор сохранён» не пишется
  await fetch(base + '/expire');
  await ev("document.getElementById('sndsend').click(); 1");
  await until("/Выбор устарел/.test(" + txt('sndst') + ")");
  console.log('stale=' + await ev("[document.querySelectorAll('#sndpicks .sndpk').length, /сохранён/.test(" + txt('sndst') + ")].join('|')"));
  // итог с израсходованными метками: ни байта и ни файла — «устарел»; файл нулевого размера доставлен — «часть ушла»
  console.log('expired=' + await ev("(() => { const r = []; for (const x of [{ done: 0, files: 0 }, { done: 0, files: 1 }]) { snd.last = ''; sndRender({ id: '777888999', state: 'err', err: 'gone', kept: false, ...x }); r.push(/Выбор устарел \\(больше часа\\)/.test(" + txt('sndst') + ") + ',' + /Часть уже ушла/.test(" + txt('sndst') + ")); } snd.last = ''; sndRender(hostS.send); return r.join('|'); })()"));
  await ev("document.getElementById('sndpick').click(); 1");
  await until("document.querySelectorAll('#sndpicks .sndpk').length === 1");
  await ev("{ const i = document.getElementById('sndid'); i.value = '777 888 999'; i.dispatchEvent(new Event('input')); } 1");
  console.log('needcode=' + await ev("[" + txt('sndhint') + ", document.getElementById('sndsend').disabled, " + vis('sndaddfav') + "].join('|')"));
  await ev("{ const c = document.getElementById('sndcode'); c.value = '000000'; c.dispatchEvent(new Event('input')); } 1");
  await ev("document.getElementById('sndsend').click(); 1");
  await until("/Не отправлено/.test(" + txt('sndst') + ")");
  console.log('fail=' + await ev("[" + txt('sndst') + ", document.querySelectorAll('#sndpicks .sndpk').length].join('|')"));
  await shot('send-fail-light');
  await ev("{ const c = document.getElementById('sndcode'); c.value = '111111'; c.dispatchEvent(new Event('input')); } 1");
  await ev("document.getElementById('sndsend').click(); 1");
  await until("/Часть уже ушла/.test(" + txt('sndst') + ")");
  console.log('lost=' + await ev("[" + txt('sndst') + ", document.querySelectorAll('#sndpicks .sndpk').length, " + txt('sndpick') + "].join('|')"));
  await ev("[...document.querySelectorAll('#sndst button')].find(b => /Понятно/.test(b.textContent)).click(); 1");
  await until(txt('sndst') + " === ''");
  // избранные: «Изменить» → переименовать → «Убрать» с отзывом
  await ev("document.getElementById('sndfaved').click(); 1"); await sleep(100);
  await ev("{ const r = document.querySelector('#sndfavx .sndfe'); r.querySelector('input').value = 'Мама'; [...r.querySelectorAll('button')][0].click(); } 1");
  await until("/сохранено/.test(document.querySelector('#sndfavx [role=status]')?.textContent) && sndT.favs[0]?.name === 'Мама'");
  await ev("document.getElementById('sndfaved').click(); 1"); await sleep(100);
  console.log('renamed=' + await ev("[...document.querySelectorAll('#sndfavs .sndt b')].map(b => b.textContent).join(',')"));
  await ev("document.getElementById('sndfaved').click(); 1"); await sleep(100);
  await ev("{ const r = document.querySelector('#sndfavx .sndfe'); r.querySelector('input[type=checkbox]').checked = true; [...r.querySelectorAll('button')][1].click(); } 1");
  await until("/без кода он больше/.test(document.querySelector('#sndfavx [role=status]')?.textContent) && document.querySelectorAll('#sndfavx .sndfe').length === 1");
  console.log('removed=' + await ev("[...document.querySelectorAll('#sndfavx .sndfe')].length + '|' + document.querySelector('#sndfavx [role=status]').textContent"));
  // Новое закрепление: плашка на главном остаётся, отдельного блока управления отправителями больше нет
  await fetch(base + '/pin');
  await ev("document.getElementById('sndback').click(); 1");
  await until(vis('pinnew'));
  console.log('pinnew=' + await ev(txt('pinnewt')));
  console.log('pinremoved=' + await ev("[!document.getElementById('pincard'), !document.getElementById('pinnewgo')].join('|')"));
  await ev("document.getElementById('accback').click(); 1");
  const cur = await ev("(async () => { show(true); const c = document.createElement('canvas'); c.width = 160; c.height = 90; const g = c.getContext('2d'); g.fillRect(0, 0, 160, 90);" +
    " v.srcObject = c.captureStream(5); await v.play().catch(() => {}); for (let i = 0; i < 50 && !v.videoWidth; i++) { g.fillRect(0, 0, 1 + i, 1); await new Promise(r => setTimeout(r, 100)); }" +
    " const out = []; dc = { readyState: 'open', send: s => out.push(JSON.parse(s)) }; const r = v.getBoundingClientRect(), s = Math.min(r.width / 160, r.height / 90), w = 160 * s, x0 = r.left + (r.width - w) / 2;" +
    " const ev = (type, x, y, extra = {}) => v.dispatchEvent(new PointerEvent(type, { clientX: x, clientY: y, bubbles: true, pointerId: 1, ...extra }));" +
    " ev('pointermove', x0 + w + 40, r.top + r.height / 2); ev('pointerleave', x0 - 30, r.top - 30); ev('pointerdown', x0 - 5, r.top + r.height / 2, { button: 0 }); ev('pointermove', x0 + w / 2, r.top + r.height / 2);" +
    " return v.videoWidth + '|' + out.map(m => m.t + ':' + m.x + ',' + m.y).join(' '); })()");
  console.log('cursor=' + cur);
  process.exit(0);
})();`

// TestBrowserSend — экран 7 «Отправить» (Ч10.5) и курсор у края (H2) в настоящей странице программы (headless Chrome).
func TestBrowserSend(t *testing.T) {
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
	sec := totp.NewSecret()
	p := spaceCfg(t, spacePass, sec)
	ph := spaceMake(t, p)
	cfg := spaceCfg(t, "n-local-pass", totp.NewSecret())
	withSpaceNet(t, spaceNet(p, nil))
	if _, err := cfg.spaceEnter(context.Background(), p.id(), spacePass, spaceCode(p, sec), ph); err != nil {
		t.Fatal(err)
	}
	cfg.mu.Lock()
	cfg.UI = uiMap{"mine": `[{"id":"` + p.id() + `","name":"Офис"}]`, "tour_home": "1", "tour_connect": "1"}
	cfg.save()
	cfg.mu.Unlock()
	fpk := ed25519.PublicKey(make([]byte, 32))
	fpk[0] = 7
	cfg.favSet("555666777", "Ноутбук мамы", true)
	cfg.knownSet("555666777", pake.KeyFingerprint(fpk))
	cfg.recvPin(fpk, "555666777", "Мама")
	cfg.favSet("444555666", "", true)
	recvPinNew.Store(nil)

	dir := t.TempDir()
	doc := filepath.Join(dir, "Договор.pdf")
	os.WriteFile(doc, make([]byte, 2_500_000), 0o644)
	sendPickFile = func(context.Context) (string, bool) { return doc, true }
	release := make(chan struct{})
	sendRun = func(ctx context.Context, d agent.SendDial) (agent.SendResult, error) {
		if d.Code == "111111" { // часть ушла и обрыв: выбор израсходован
			d.Progress(agent.SendProgress{Item: 1, Items: 1, Done: 1000, Total: 2_500_000})
			return agent.SendResult{}, agent.ErrRecvGone
		}
		if d.Code != "" { // чужой по коду: неверный код до первого байта
			return agent.SendResult{}, agent.ErrRecvCode
		}
		d.Progress(agent.SendProgress{Item: 1, Items: 1, Done: 1_000_000, Total: 2_500_000})
		select {
		case <-release:
		case <-ctx.Done():
			return agent.SendResult{}, ctx.Err()
		}
		return agent.SendResult{HostPub: d.HostPub, Files: 1, Bytes: 2_500_000}, nil
	}
	defer func() { sendRun, sendPickFile, sendNotice = agent.SendTo, agent.PickFile, noticeOS; sendOps.clear() }()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	addr := l.Addr().String()
	page, _ := shimmed("ws://127.0.0.1:1/ws", "tokui") // хабов нет: страница не выходит в сеть
	info := func() map[string]any {
		return map[string]any{"id": cfg.id(), "users": []any{}, "keys": []any{}, "version": "test", "online": true,
			"space": spaceInfo(cfg), "send": sendOps.snap(), "recvNew": recvPinNewJSON(cfg)}
	}
	h := handler(addr, "tokui", page, cfg, &agent.Agent{}, nil, info, newFiles(t.TempDir()), nil)
	mux := http.NewServeMux()
	mux.Handle("/", h)
	mux.HandleFunc("/release", func(http.ResponseWriter, *http.Request) { close(release) })
	mux.HandleFunc("/tray", func(http.ResponseWriter, *http.Request) { sendOps.startTray(cfg, p.id()) })
	mux.HandleFunc("/expire", func(http.ResponseWriter, *http.Request) { // метки окна устарели (как через час)
		sendOps.mu.Lock()
		clear(sendOps.picks)
		sendOps.mu.Unlock()
	})
	sendNotice = func(string, string) {} // уведомления рабочего стола в тесте не показывать
	mux.HandleFunc("/pin", func(http.ResponseWriter, *http.Request) {
		k := ed25519.PublicKey(make([]byte, 32))
		k[0] = 9
		cfg.recvPin(k, "333444555", "Коллега")
	})
	go http.Serve(l, mux)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pl, _ := net.Listen("tcp", "127.0.0.1:0")
	port := strconv.Itoa(pl.Addr().(*net.TCPAddr).Port)
	pl.Close()
	prof, _ := os.MkdirTemp("", "anypc-chrome-")
	defer os.RemoveAll(prof)
	ch := exec.CommandContext(ctx, chrome, "--headless=new", "--disable-gpu", "--no-proxy-server", "--disable-background-networking", "--lang=ru",
		"--autoplay-policy=no-user-gesture-required", "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE localhost , EXCLUDE 127.0.0.1",
		"--remote-debugging-port="+port, "--user-data-dir="+prof, "about:blank")
	ch.Env = append(os.Environ(), "LANGUAGE=ru", "LANG=ru_RU.UTF-8")
	if err := ch.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { ch.Process.Kill(); ch.Wait() }()
	for end := time.Now().Add(15 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if r, err := http.Get("http://127.0.0.1:" + port + "/json/version"); err == nil {
			r.Body.Close()
			break
		}
		if time.Now().After(end) {
			t.Fatal("Chrome не открыл порт CDP")
		}
	}
	shots := os.Getenv("ANYPC_SHOTS") // снимки для сверки с макетом; без переменной — во временный каталог
	if shots == "" {
		shots = t.TempDir()
	}
	js := filepath.Join(t.TempDir(), "cdp.js")
	os.WriteFile(js, []byte(cdpSendJS), 0o600)
	b, err := exec.CommandContext(ctx, "node", js, port, "http://"+addr, shots).CombinedOutput()
	out := string(b)
	t.Logf("%s", out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"open=true|false|true|Шаг 1: нажмите «Выбрать файл…»", // сразу: что делать первым
		"picked=Договор.pdf · 2.4 MB|Добавить ещё…|Шаг 2: выберите, кому",
		"ready=Договор.pdf → Офис|Всё готово — нажмите «Отправить».|false|true\n",
		"favs=Ноутбук мамыспросит «Принять?»,444 555 666первый раз — нужен код\n",
		"run=Отправляю на «Офис»…Файл 1 из 1 · 977 KB из 2.4 MBОстановить можно кнопкой «Остановить»; уже принятое на том ПК останется.|Остановить|true\n", // своему — без строки про «Принять?»
		"runask=banner info|true\n", "tray=1|1\n", "stale=0|false\n", "expired=true,false|false,true\n",
		"done=✓ Отправлено на «Офис»файлов: 1 · 2.4 MBФайлы — в папке «Загрузки» того ПК", "|0\n",
		"needcode=Первый раз этому ПК: введите 6 цифр кода с его экрана.|true|true\n",
		"fail=Не отправлено на «777 888 999»Неверный код. Что делать: введите код", "Выбор сохранён: исправьте и нажмите «Отправить» снова.Понятно|1\n",
		"lost=Не отправлено на «777 888 999»Тот ПК прервал приём", "Часть уже ушла — выберите файлы снова и нажмите «Отправить».Понятно|0|Выбрать файл…\n",
		"renamed=Мама,444 555 666\n",
		"removed=1|Убран из избранных. Присылать сюда без кода он больше не может",
		"pinnew=Новый отправитель: Коллега · ID 333 444 555 теперь может присылать сюда без кода",
		"pinremoved=true|true\n",
		"cursor=160|m:65535,", " m:0,0 m:32768,", // за правый край — к краю; уход за левый верхний — в угол; нажатие вне картинки — мимо
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if strings.Contains(out, "PAGEEXC") || strings.Contains(out, "EVALEXC") {
		t.Error("исключение в странице")
	}
	if strings.Contains(out, " b:") {
		t.Error("нажатие вне картинки отправлено")
	}
	cfg.recvUnpin(fpk)
	if _, _, ok := cfg.recvPinned(fpk); ok {
		t.Error("backend не отозвал закрепление")
	}
}
