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
// событие; переподключение оборванной; открытие ?embed=<ID> в ВЕРХНЕМ окне не входит само (защита).
// Карточка канбана (имена и явное добавление): `mine` — [{id,name}], прежний формат (массив ID) мигрирует на чтении;
// переименование ✎ на месте (Enter — сохранить, Esc — отмена, пустое — ID, ≤ 40 символов) видно на вкладке;
// ★ на панели сессии убирает/добавляет ПК и сразу даёт поле имени; × в списке — явное удаление; «nokey» и снятие
// «Доверять» ПК из `mine` НЕ убирают (было в фазе 1): вкладка честно «нужен пароль», во фрейме — карточка входа
// с объяснением; отдельной карточки «Мои ПК» нет (v0.3.1): ПК из `mine` — плитки «Моё пространство», подсказка — только при пустом списке. Пиксельная задержка картинки ≤ 1 с (MULTI-PC.md) — свойство
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
  const mine = async () => JSON.parse(await ev("JSON.stringify((JSON.parse(localStorage.getItem('mine')||'[]')).map(x => x.id || x).sort())"));
  const names = () => ev("JSON.stringify(Object.fromEntries(JSON.parse(localStorage.getItem('mine')||'[]').map(x => [x.id, x.name])))");
  const tabClick = i => ev("[...document.querySelectorAll('#tabs .tab .nm')].find(n => n.dataset.id === '" + i + "').parentNode.click(); 1");
  // правка имени в поле .nmedit документа d (родитель или фрейм): значение и клавиша
  const nmKey = (d, val, key) => d + ".querySelector('input.nmedit').value = " + JSON.stringify(val) + "; " + d + ".querySelector('input.nmedit').dispatchEvent(new KeyboardEvent('keydown', { key: '" + key + "', bubbles: true })); 1";
  // плитка бывшего «Моего ПК» в «Моё пространство» (v0.3.1): «···» → «Переименовать» / «Убрать»
  const menu = (i, what) => ev("(() => { const d = document.querySelector('#sptiles .sptile[data-id=\"" + i + "\"]'); d.querySelector('.mpcmore').click(); const m = d.querySelector('.tmenu'); const on = !m.classList.contains('hidden'); d.querySelector('." + what + "').click(); return on; })()");
  const ren = async (i, val, key) => { await menu(i, 'mpcren'); await ev(nmKey('document', val, key)); };
  const tileNames = "JSON.stringify([...document.querySelectorAll('#sptiles .sptile')].map(d => d.querySelector('.nm').textContent + '|' + d.querySelector('.sub').textContent)";
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
    const dt = await ev("(() => { const t0 = performance.now(); myPcKey('Digit" + (i + 1) + "'); return [performance.now() - t0, myPcActive() === myPcOrder()[" + i + "] ? " + i + " : -1]; })()");
    maxSw = Math.max(maxSw, dt[0]);
    if (dt[1] !== i) drops++;
    if (JSON.parse(await pcState()).some(s => s !== 'connected')) drops++;
  }
  console.log('switch=' + (drops === 0 && maxSw <= 1000) + '|drops=' + drops + '|sw=' + Math.round(maxSw));
  // переключение щелчком по вкладке — на первую (у вкладок есть ещё ⌂ и ×, поэтому выбираем по id)
  await tabClick(ids[0]); await sleep(300);
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
  console.log('keyactive=' + await ev("myPcActive() === myPcOrder()[1]")); // вторая в полосе
  console.log('stillconnected=' + await pcState());
  console.log('held=' + await ev("JSON.stringify([...document.querySelectorAll('#frames iframe')].map(f => { try { return f.contentWindow.sessHeld(); } catch { return -1; } }))"));
  // буфер/звук — только у активной вкладки (активна вторая: Ctrl+Alt+2)
  console.log('active=' + await ev("(fr => JSON.stringify(myPcOrder().map(i => { try { return fr[i].contentWindow.sessActive(); } catch { return 'x'; } })))([...document.querySelectorAll('#frames iframe')])")); // в порядке полосы (Ч8)
  // 📌 во вкладке: закрепила — у соседних вкладок панель тоже закреплена (общий localStorage, событие storage), открепила — снова прячется
  console.log('pinsync=' + await ev("(async fr => { const p = i => fr[i].contentWindow.document, z = () => new Promise(r => setTimeout(r, 300)); p(1).getElementById('pinbtn').click(); await z(); const a = p(0).body.classList.contains('pinbar') + ',' + p(1).body.classList.contains('pinbar'); p(1).getElementById('pinbtn').click(); await z(); return a + ',' + p(0).body.classList.contains('pinbar'); })([...document.querySelectorAll('#frames iframe')])"));
  // переименование в списке «Мои ПК» (⌂): Enter сохраняет, Esc отменяет, пробелы — снова ID, длинное — до 40 символов
  await ev("document.getElementById('tabhome').click(); 1"); await sleep(200);
  await ren(ids[1], 'Офис', 'Enter');
  await ren(ids[1], 'Не то', 'Escape');
  await ren(ids[2], '   ', 'Enter');
  await ren(ids[0], 'A'.repeat(50), 'Enter');
  console.log('names=' + await names());
  // переименование в списке освежило имя на панели сессии открытой вкладки (родитель → embedStar)
  console.log('renstar=' + await ev("document.querySelectorAll('#frames iframe')[1].contentWindow.document.getElementById('starnm').textContent"));
  console.log('listnames=' + await ev(tileNames + ".sort())"));
  // ★ на панели сессии третьего ПК: снять — ушёл из списка; ☆ — вопрос шага 3 «Это ваш компьютер?» (вход ключом уже
  // есть: без галочки «Запомнить пароль» и без повторного входа), «Добавить» с именем — вернулся
  await tabClick(ids[2]); await sleep(200);
  const f2 = "document.querySelectorAll('#frames iframe')[2].contentWindow.document";
  const star = () => ev(f2 + ".getElementById('starbtn').getAttribute('aria-pressed')");
  const s0 = await star();
  await ev(f2 + ".getElementById('morem').click(); " + f2 + ".getElementById('mdel').click(); 1"); // Ч8: «Ещё ▾ → Убрать из моего пространства»
  const s1 = await star(), m1 = await mine();
  await ev(f2 + ".getElementById('starbtn').click(); 1");
  const edit = await ev(f2 + ".getElementById('mineq').checkVisibility() && !" + f2 + ".getElementById('mineqrl').checkVisibility() && !" + f2 + ".getElementById('starbtn').checkVisibility()");
  await ev(f2 + ".getElementById('mineqn').value = 'Дом'; " + f2 + ".getElementById('mineqn').dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true })); 1"); await sleep(300);
  console.log('star=' + [s0, s1, JSON.stringify(m1), await star(), edit].join('|'));
  console.log('starlabel=' + await ev(f2 + ".getElementById('starnm').textContent"));
  console.log('names2=' + await names());
  console.log('tabnames=' + await ev("JSON.stringify([...document.querySelectorAll('#tabs .tab .nm')].sort((a, b) => a.dataset.id.localeCompare(b.dataset.id)).map(n => n.textContent))")); // полоса — в порядке списка, сверяем по ID
  // обрыв ("bye" от хоста) метит вкладку «разорвано» за ≤ 1 с — ждём по событию (poll 20 мс), не sleep
  const t0 = Date.now(); await fetch(url + 'bye?id=' + ids[2]);
  let bms = -1; for (let k = 0; k < 60; k++) { const st = JSON.parse(await tabState()); if (st[2] === 'broken') { bms = Date.now() - t0; break; } await sleep(20); }
  console.log('brokenms=' + (bms >= 0 && bms <= 1000) + '|' + bms);
  // прочие ПК не тронуты (соединения живы), а вкладка третьего помечена «разорвано» (метка — по событию)
  const ps = JSON.parse(await pcState()), ts = JSON.parse(await tabState());
  console.log('afterbye=' + JSON.stringify([ps[0], ps[1], ts[2]]));
  // отзыв ключа на хосте → переподключение оборванной вкладки → "nokey" → ПК ОСТАЁТСЯ в «Моих ПК», вкладка — «нужен пароль»
  await fetch(url + 'revoke?id=' + ids[0]); await fetch(url + 'bye?id=' + ids[0]);
  for (let k = 0; k < 60 && JSON.parse(await tabState())[0] !== 'broken'; k++) await sleep(50);
  await tabClick(ids[0]); // клик по оборванной — переподключить
  for (let k = 0; k < 100 && JSON.parse(await tabState())[0] !== 'pw'; k++) await sleep(100);
  console.log('afternokey=' + JSON.stringify(await mine()) + '|' + JSON.parse(await tabState())[0]);
  console.log('pwlabel=' + await ev("[...document.querySelectorAll('#tabs .tab')].find(b => b.querySelector('.nm')?.dataset.id === '" + ids[0] + "').querySelector('.stt').textContent === t('st_pw')"));
  const f0 = "document.querySelectorAll('#frames iframe')[0].contentWindow";
  console.log('pwform=' + await ev("(() => { const w = " + f0 + ", d = w.document; return [d.body.classList.contains('needpw'), d.getElementById('connect').checkVisibility(), d.getElementById('pw').checkVisibility(), !d.getElementById('me').checkVisibility(), d.getElementById('msg').textContent.includes(t('e_nokey_why'))].join('|'); })()"));
  // вкладка-фрейм без пароля: только карточка входа — ни главного экрана, ни полосы ПК, ни «Назад», ни «Настроек»
  console.log('pwonly=' + await ev("(() => { const d = " + f0 + ".document; return ['home', 'hometabs', 'sptiles', 'connhead', 'settings', 'access', 'setgo'].map(i => d.getElementById(i).checkVisibility()).join(',') + '|' + d.getElementById('remote').checkVisibility(); })()"));
  // приёмка: вкладка — только к своему ID. «Недавние» во фрейме скрыты; подмена поля скриптом и щелчок по недавнему
  // чужому ID не подключают к нему (на чужом хосте новых входов нет — проверка logins ниже), вкладка не «на связи»
  const fd = f0 + ".document";
  console.log('recenthidden=' + await ev("!" + fd + ".getElementById('recentbox').checkVisibility() && " + fd + ".querySelectorAll('#recent button').length > 0"));
  await ev("(() => { const b = [..." + fd + ".querySelectorAll('#recent button')].find(b => b.textContent === '" + ids[2] + "'); b.click(); return 1; })()"); await sleep(300);
  await ev("(() => { const d = " + fd + "; d.getElementById('pw').value = 'secret123'; d.getElementById('go').click(); return 1; })()"); await sleep(1500);
  const hj1 = [JSON.parse(await tabState())[0], await ev(f0 + ".sessState()"), await ev(fd + ".getElementById('id').value"), await ev("myPcCodeWanted()")].join('|');
  await ev("(() => { const d = " + fd + "; d.getElementById('id').value = '" + ids[2] + "'; d.getElementById('pw').value = 'secret123'; d.getElementById('go').click(); return 1; })()"); await sleep(1500);
  const hj2 = [JSON.parse(await tabState())[0], await ev(f0 + ".sessState()"), await ev(fd + ".getElementById('id').value"), await ev("myPcCodeWanted()")].join('|');
  console.log('hijack=' + hj1 + '/' + hj2);
  // приёмка: печать пароля во фрейме + запрос кода от другой вкладки — фокус не уходит в #mcot
  await ev("(() => { const w = " + f0 + "; w.focus(); const i = w.document.getElementById('pw'); i.value = ''; i.focus(); return 1; })()");
  await cmd('Input.insertText', { text: 'Se' });
  await ev("myPcState('" + ids[2] + "', 'code'); 1"); await sleep(100);
  await cmd('Input.insertText', { text: 'cr3' });
  console.log('typefocus=' + await ev(fd + ".getElementById('pw').value + '|' + document.getElementById('mcot').value"));
  await ev("myPcState('" + ids[2] + "', 'broken'); " + fd + ".getElementById('pw').value = ''; 1");
  // вход паролем в карточке фрейма: неверный — метка остаётся «нужен пароль» (не «разорвано»); верный + код — на связи
  const pwGo = pw => ev("(() => { const d = " + f0 + ".document; d.getElementById('pw').value = '" + pw + "'; d.getElementById('go').click(); return 1; })()");
  await pwGo('wrong-pass');
  for (let k = 0; k < 100 && !(await ev(f0 + ".document.getElementById('msg').textContent.includes(t('e_auth'))")); k++) await sleep(100);
  console.log('wrongpw=' + JSON.parse(await tabState())[0] + '|' + await ev(f0 + ".document.body.classList.contains('needpw')"));
  await pwGo('secret123');
  for (let k = 0; k < 150; k++) {
    if (await ev("myPcCodeWanted()") === ids[0]) { const c = await (await fetch(url + 'code?id=' + ids[0])).text(); await ev("document.getElementById('mcot').value='" + c + "'; document.getElementById('mcgo').click()"); await sleep(300); continue; }
    if (JSON.parse(await tabState())[0] === 'ok') break;
    await sleep(100);
  }
  console.log('pwlogin=' + JSON.parse(await tabState())[0] + '|' + await ev(f0 + ".document.body.classList.contains('needpw')") + '|' + await ev(f0 + ".sessState()"));
  // «Забыть» вход ключом у второго ПК (его фрейм, «Параметры») — забыть ключ, но из «Моих ПК» не убирать
  await ev("document.querySelectorAll('#frames iframe')[1].contentWindow.document.getElementById('keyforget').click(); 1");
  for (let k = 0; k < 40 && await ev("!!JSON.parse(localStorage.getItem('ckeys'))['" + ids[1] + "']"); k++) await sleep(100);
  console.log('afteruntrust=' + JSON.stringify(await mine()) + '|key=' + await ev("!!JSON.parse(localStorage.getItem('ckeys'))['" + ids[1] + "']"));
  // явное удаление: × в списке «Мои ПК»
  await ev("document.getElementById('tabhome').click(); 1"); await sleep(200);
  const menuOn = await menu(ids[0], 'mpcdel');
  console.log('afterdel=' + JSON.stringify(await mine()) + '|' + menuOn + '|' + await ev("!!document.querySelector('#sptiles .sptile[data-id=\"" + ids[0] + "\"]')"));
  console.log('delstar=' + await ev(fd + ".getElementById('starbtn').getAttribute('aria-pressed')")); // × в списке освежил ★ открытой вкладки
  // v0.3.1 (по макету): отдельной карточки «Мои ПК» нет — одна строка подсказки только при пустом списке
  const hint = () => ev("[!document.getElementById('mine'), !document.getElementById('minelist'), document.getElementById('mineempty').checkVisibility(), document.getElementById('sptiles').childElementCount].join(',')");
  const h1 = await hint();
  await ev("localStorage.setItem('mine', '[]'); myPcRender(); 1");
  console.log('hint=' + h1 + '|' + await hint());
  // миграция прежнего формата (массив ID) при загрузке окна: мусор и повторы отброшены, имена — ID
  await ev("localStorage.setItem('mine', JSON.stringify(['111111111', 5, { id: 'x' }, null, '222222222', '111111111', { id: '333333333', name: 'Склад' }])); 1");
  await tev("location.reload(); 1"); await sleep(1500);
  console.log('migrated=' + await tev("localStorage.getItem('mine')"));
  console.log('miglist=' + await tev(tileNames + ")"));
  await ev("localStorage.setItem('mine', '{\"bad\":1}'); 1");
  console.log('garbage=' + await ev("JSON.stringify(myPcs.get())"));
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
	mux.HandleFunc("/ckey", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"seed": seedB64, "pub": ck["pub"]})
	})
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
		"toplink=noenter\n", // ?embed в верхнем окне не вошёл (строка целиком)
		`connected=["connected","connected","connected"]`,
		`authed=["ok","ok","ok"]`,
		`mine=["111111111","222222222","333333333"]`, // вход по ключу пополнил «Мои ПК» (m.key)
		`clickactive=0`,
		`keyactive=true`,       // Ctrl+Alt+2 переключил на вторую вкладку полосы
		`switch=true|drops=0|`, // 20 переключений: 0 обрывов/переподключений, мгновенно
		`stillconnected=["connected","connected","connected"]`,
		`held=[0,0,0]`,                                // залипших клавиш не осталось
		`active=[false,true,false]`,                   // буфер/звук — только у активной (второй) вкладки
		`pinsync=true,true,false`,                     // булавка во вкладке — у всех вкладок «Моих ПК»
		`brokenms=true|`,                              // метка «разорвано» за ≤ 1 с через событие (не из тормозимого таймера)
		`afterbye=["connected","connected","broken"]`, // обрыв третьего не тронул первые два; его вкладка «разорвано»
		// имена: Enter сохранил, Esc отменил, пробелы → ID, длинное обрезано до 40
		`names={"111111111":"` + strings.Repeat("A", 40) + `","222222222":"Офис","333333333":"333333333"}`,
		// плитка: имя (без имени — ID) и «по паролю · ID» (сортировка: порядок входов не задан)
		`listnames=["333 333 333|by password · 333 333 333","` + strings.Repeat("A", 40) + `|by password · 111 111 111","Офис|by password · 222 222 222"]`,
		`star=true|false|["111111111","222222222"]|true|true`, // ★ снял — ушёл; ☆ — вопрос шага 3, «Добавить» — вернулся с именем
		`starlabel=Дом ✎`,
		`names2={"111111111":"` + strings.Repeat("A", 40) + `","222222222":"Офис","333333333":"Дом"}`,
		`tabnames=["` + strings.Repeat("A", 40) + `","Офис","Дом"]`, // на вкладках — имена
		// карточка канбана: БЫЛО (фаза 1) — "nokey" и снятие «Доверять» убирали ПК из `mine`
		// (afternokey=["222222222","333333333"], afteruntrust=["333333333"]); СТАЛО — удаление только явное
		`afternokey=["111111111","222222222","333333333"]|pw`, // "nokey": ПК остался, вкладка «нужен пароль»
		`pwlabel=true`,
		`pwform=true|true|true|true|true`, // во фрейме — карточка входа (без «Это рабочее место») и объяснение
		`pwonly=false,false,false,false,false,false,false|true`, // и больше ничего: ни главного, ни полосы ПК, ни «Назад», ни ⚙
		`wrongpw=pw|true`,            // неверный пароль во фрейме: метка «нужен пароль», карточка входа осталась
		`pwlogin=ok|false|connected`, // верный пароль + код TOTP из окна-родителя: вкладка на связи
		`afteruntrust=["111111111","222222222","333333333"]|key=false`, // ключ забыт, ПК в списке остался
		`afterdel=["222222222","333333333"]|true|false`,                // «···» открыл меню, «Убрать» — ПК ушёл из `mine` и плитки
		`delstar=false`,                           // × в списке — ★ во вкладке снята
		`renstar=Офис ✎`,                          // ✎ в списке — имя на панели вкладки обновилось
		`recenthidden=true`,                       // «Недавние» во фрейме скрыты (кнопки есть)
		`hijack=pw||111111111|/pw||111111111|`,    // ни недавний, ни подмена поля не подключили вкладку к чужому ID
		`typefocus=Secr3|`,                        // символы остались в пароле, #mcot пуст                           // × — явное удаление
		`hint=true,true,false,2|true,true,true,0`, // карточки «Мои ПК» нет; подсказка — одна строка и только при пустом списке
		`migrated=[{"id":"111111111","name":"111111111"},{"id":"222222222","name":"222222222"},{"id":"333333333","name":"Склад"}]`,
		`miglist=["111 111 111|by password · 111 111 111","222 222 222|by password · 222 222 222","Склад|by password · 333 333 333"]`,
		`garbage=[]`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	for _, id := range ids { // после первых трёх входов по ключу переключение/обрыв новых входов не создаёт;
		want := int32(1) // у первого — ещё один: вход паролем во фрейме после "nokey"
		if id == ids[0] {
			want = 2
		}
		if n := logins[id].Load(); n != want {
			t.Errorf("ПК %s: входов %d, ожидалось %d", id, n, want)
		}
	}
	if t.Failed() {
		t.Log(out)
	}
}
