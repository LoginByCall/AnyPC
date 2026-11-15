package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"anypc/ui"
)

// cdpSpace — экран «Доступ к этому ПК», блок «Вы (владелец)» (этап «окна пространства», Ч3, ASK-1 A) с подменёнными привязками
// app/spaceapi.go: без привязок блока нет; «Спрашивать» — подсказка login; создание (неверный пароль, фраза один раз,
// отмена, чужая фраза, OK); пять плашек и их действия; «Отозвать» с итогом по ПК и новым QR; правка фразой с ошибкой
// phrase_word; выход паролем и кодом (код — всегда); вступление в два шага (превью, отказ, подтверждение); «Назад».
const cdpSpace = `
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
  const val = (i, v) => "document.getElementById('" + i + "').value = " + JSON.stringify(v) + ";";
  const click = async i => { await ev("document.getElementById('" + i + "').click(); 1"); await sleep(250); };
  const calls = () => ev("calls.splice(0).join(',')");
  const shot = async (name, el) => { if (!process.env.SHOTS) return; // Ч12: снимки мастера (SHOTS=<каталог>)
    if (el) await ev("document.getElementById('" + el + "').scrollIntoView({ block: 'center' }); 1"); await sleep(200);
    const r = await call('Page.captureScreenshot', { format: 'png' }); require('fs').writeFileSync(process.env.SHOTS + '/space-ux-' + name + '.png', Buffer.from(r.result.data, 'base64')); };
  await call('Page.enable', {});
  if (process.env.SHOTS) await call('Emulation.setDeviceMetricsOverride', { width: 1200, height: 760, deviceScaleFactor: 1, mobile: false });
  await call('Page.navigate', { url }); await sleep(1200); // веб-клиент с сервера: привязок нет
  console.log('web=' + await ev("[" + vis('spcard') + ", " + vis('me') + ", " + vis('access') + "].join('|')"));
  await call('Page.addScriptToEvaluateOnNewDocument', { source: ` + "`" + `(() => { // в IIFE: имена не сталкиваются с const страницы
    localStorage.setItem('mine', JSON.stringify([{ id: '444555666', name: 'Office' }])); localStorage.setItem('tour_home', '1');
    const PH = 'able baker cable delta eagle fable gable habit ideal jewel';
    const me = { id: '123456789', fp: 'SELF-FP', pub: 'c2VsZg==', self: true, passUntil: 0 };
    const office = { id: '444555666', fp: 'OFFICE-FP', pub: 'b2ZmaWNl', self: false, passUntil: 0 };
    const empty = () => ({ in: false, damaged: false, compromised: false, over: false, pend: 0, wait: '', clock: [], ask: false, lock: true, gone: 0, members: [], op: null });
    window.st = { id: '123456789', confirm: true, otp: true, hasPass: true, users: [{ name: 'anna', view: true, otp: true }], keys: [], space: empty() };
    window.empty = empty; window.calls = []; window.op = null; window.confirm = () => true;
    const setOp = window.setOp = o => { window.op = o; st.space.op = o && { kind: o.kind, state: o.state }; };
    window.hostInfo = async () => JSON.parse(JSON.stringify(st));
    window.opSlow = 0; window.failConfirm = 0; // каждый ответ spaceOp медленнее опроса; сбой транспорта spaceConfirm
    window.opDelay = 0; // мс: следующий ответ spaceOp придёт позже (снимок — на момент вызова)
    window.spaceOp = async () => { const o = window.op && JSON.parse(JSON.stringify(window.op)), d = window.opDelay || window.opSlow; window.opDelay = 0; if (d) await new Promise(r => setTimeout(r, d)); return o; };
    window.spaceCreate = async pw => { calls.push('create:' + pw); if (pw !== 'owner-pass') throw 'space:password'; return { phrase: PH }; };
    window.spaceCreateOK = async ph => { calls.push('createok:' + ph); if (ph !== PH) throw 'space:phrase'; st.space.in = true; st.space.members = [me]; };
    window.spaceCreateNo = async () => { calls.push('createno'); };
    window.enterRun = false; // Ч12: вступление идёт (шаг 2), а не сразу превью
    window.spaceCancel = async () => { calls.push('cancel'); setOp({ kind: 'enter', state: 'err', err: 'cancel', result: null }); };
    window.spaceEnter = async (id, pw, code, ph) => {
      calls.push('enter:' + [id, pw, code, ph].join(':'));
      if (window.enterRun) return void setOp({ kind: 'enter', state: 'run', stage: 'link', result: null });
      if (window.enterErr) return void setOp({ kind: 'enter', state: 'err', err: window.enterErr, result: null }); // быстрая ошибка до сети
      setOp({ kind: 'enter', state: 'confirm', result: null, preview: { members: [{ id: '444555666', fp: 'OFFICE-FP' }, { id: '123456789', fp: 'SELF-FP' }], password: true, code: true, trusted: 2, keyLogin: 1, ask: true, already: false, gone: ['GONE-FP1', 'GONE-FP2'] } });
      return null;
    };
    window.spaceConfirm = async yes => {
      calls.push('confirm:' + yes);
      if (window.failConfirm) { window.failConfirm--; throw new TypeError('Failed to fetch'); }
      if (!yes) return setOp({ kind: 'enter', state: 'err', err: 'no', result: null });
      setOp({ kind: 'enter', state: 'done', result: { password: true, code: true, trusted: 2, keyLogin: 1, ask: true, already: false, fresh: false } });
      st.space.in = true; st.space.wait = '444555666'; st.space.members = [me, office];
    };
    window.spaceExclude = async (ph, pub, pw) => {
      calls.push('exclude:' + ph + ':' + pub + ':' + pw);
      setOp({ kind: 'exclude', state: 'done', result: { results: [{ id: '444555666', state: 'ok' }, { id: '777888999', state: 'offline', err: 'offline' }],
        qr: { uri: 'otpauth://totp/AnyPC?secret=ABCDEFGHIJKLMNOP&issuer=AnyPC', svg: '<svg xmlns="http://www.w3.org/2000/svg"/>' } } });
      return null;
    };
    window.spaceLogin = async (ph, pw, code) => { calls.push('login:' + ph + ':' + pw + ':' + code); setOp({ kind: 'login', state: 'err', err: 'phrase_word:3', result: null }); return null; };
    window.spaceLeave = async (pw, code) => { calls.push('leave:' + pw + ':' + code); if (code !== '123456') throw 'space:code'; if (st.space.wait) { st.hasPass = false; st.confirm = true; } st.space = empty(); };
    window.setPassword = async pw => { calls.push('setpw:' + pw); st.hasPass = true; };
    window.spaceOpClear = async () => { calls.push('clear'); setOp(null); };
    window.setConfirm = async on => { calls.push('setconfirm:' + on); st.confirm = on; };
    window.spaceSync = async () => { calls.push('sync'); setOp({ kind: 'sync', state: 'run', result: null }); return null; };
  })();` + "`" + ` });
  await call('Page.navigate', { url }); await sleep(1500);
  await click('accgo');
  console.log('nav=' + await ev("[" + vis('access') + ", " + vis('home') + ", " + txt('acccode') + ", " + vis('spcard') + ", " + vis('spout') + ", " + vis('spin') + "].join('|')"));
  await click('spnew'); // «Спрашивать» включено — создать нельзя
  console.log('hint=' + await ev(txt('spmsg') + " + '|' + " + vis('spcreate')));
  await ev("st.confirm = false; 1"); await sleep(1200);
  console.log('old=' + await ev("[" + vis('pwrow') + ", " + vis('users') + ", document.getElementById('confirm').checked].join('|')"));
  await click('spnew'); await ev(val('spcpw', 'wrong-pass')); await click('spcgo');
  console.log('badpw=' + await ev("[" + txt('spmsg') + ", " + vis('spc2') + "].join('|')"));
  await ev(val('spcpw', 'owner-pass')); await click('spcgo');
  console.log('phrase=' + await ev("[" + txt('spphr') + ", " + vis('spc1') + ", " + vis('spc2') + ", document.getElementById('spcpw').value].join('|')"));
  await ev("document.querySelector('#spc2 .spcno').click(); 1"); await sleep(250);
  console.log('cancel=' + await ev("[" + txt('spphr') + ", " + vis('spcreate') + "].join('|')") + '|' + await calls());
  await click('spnew'); await ev(val('spcpw', 'owner-pass')); await click('spcgo');
  await click('spnew'); // повторное «Создать» на шаге фразы
  console.log('renew=' + await ev("[" + txt('spphr') + ", " + vis('spc1') + ", " + vis('spc2') + "].join('|')") + '|' + await calls());
  await ev(val('spcpw', 'owner-pass')); await click('spcgo'); await click('accback');
  console.log('backphrase=' + await ev(txt('spphr') + " + '|' + " + vis('spcreate')) + '|' + await calls());
  await click('accgo'); await click('spnew'); await ev(val('spcpw', 'owner-pass')); await click('spcgo');
  await ev(val('spcph', 'able baker')); await click('spcok');
  console.log('foreign=' + await ev(txt('spmsg')));
  // Ч12: мастер создания — шаги 2 (фраза) и 3 (проверка), «← Показать фразу»
  console.log('steps=' + await ev("[...document.querySelectorAll('#spcreate [data-n]')].map(e => e.textContent).join(';') + '|' + " + vis('spc2')));
  await click('spc2go'); console.log('step3=' + await ev([vis('spc2'), vis('spc3'), "document.activeElement.id"].join(" + '|' + ")));
  await click('spc3back'); console.log('step3back=' + await ev(vis('spc2') + " + '|' + " + txt('spphr')).then(x => x.length)); await click('spc2go');
  await ev(val('spcph', ' able baker cable delta eagle fable gable habit ideal jewel ')); await click('spcok'); await sleep(300);
  console.log('created=' + await ev("[" + txt('spphr') + ", " + vis('spcreate') + ", " + vis('spout') + ", " + vis('spin') + ", " + vis('pwrow') + ", " + txt('splist') + "].join('|')") + '|' + await calls().then(c => c.replace(/^(create:owner-pass,createno,)+/, '')));
  // Ч12: «Что дальше» после создания — что ввести на другом ПК; код — из записи AnyPC с ID этого ПК
  console.log('next=' + await ev([vis('spnext'), vis('sphow'), txt('spnext')].join(" + '|' + ")));
  await shot('created', 'spnext');
  await ev("[...document.querySelectorAll('#spnext button')].find(b => b.textContent === 'Got it').click(); 1"); await sleep(300);
  console.log('gotit=' + await ev([vis('spnext'), vis('sphow')].join(" + '|' + ")));
  await shot('list1', 'splist');
  await click('sphow'); console.log('how=' + await ev([vis('spnext'), vis('sphow'), "document.getElementById('spnext').textContent.startsWith('Next: add')"].join(" + '|' + ")));
  await ev("[...document.querySelectorAll('#spnext button')].find(b => b.textContent === 'Got it').click(); 1"); await sleep(300);
  // «Спрашивать» в пространстве: включить нельзя; выключить (вступил с «Спрашивать») — сразу, без настройки TOTP
  console.log('askin=' + await ev("document.getElementById('confirm').disabled"));
  await ev("st.confirm = true; 1"); await sleep(1200);
  await ev("document.getElementById('confirm').click(); 1"); await sleep(400);
  console.log('askoff=' + await calls() + '|' + await ev("[document.getElementById('confirm').checked, document.getElementById('confirm').disabled, " + vis('otpset') + "].join('|')"));
  // пять плашек
  await ev("Object.assign(st.space, { damaged: true, compromised: true, over: false, pend: 2, wait: '444555666', clock: ['777888999'], members: [{ id: '123456789', fp: 'SELF-FP', pub: 'c2VsZg==', self: true, passUntil: 0 }, { id: '444555666', fp: 'OFFICE-FP', pub: 'b2ZmaWNl', self: false, passUntil: 0 }] }); 1"); await sleep(1200);
  console.log('bars=' + await ev("[...document.querySelectorAll('#spbars .banner')].map(b => b.textContent).join(';')"));
  console.log('list=' + await ev("[...document.querySelectorAll('#splist .row')].map(r => r.textContent).join(';')"));
  const bar = async (n, k) => { await ev("document.querySelectorAll('#spbars .banner')[" + n + "].querySelector('button').click(); 1"); await sleep(250); };
  await bar(0); console.log('leaveform=' + await ev("[" + txt('spfh') + ", " + vis('spfph') + ", " + vis('spfpw') + ", " + vis('spfcd') + ", document.getElementById('spfpw').placeholder].join('|')"));
  await bar(1); console.log('codeform=' + await ev("[" + txt('spfh') + ", " + vis('spfph') + ", " + vis('spfpw') + ", " + vis('spfcd') + "].join('|')"));
  await bar(3); await sleep(300); console.log('sync=' + await calls() + '|' + await ev(txt('spop')));
  await ev("op = null; st.space.op = null; Object.assign(st.space, { damaged: false, compromised: false, pend: 0, wait: '', clock: [] }); 1"); await sleep(1200);
  console.log('nobars=' + await ev("document.querySelectorAll('#spbars .banner').length + '|' + " + txt('spop')));
  await click('sppw'); await ev(val('spfph', 'able baker cable') + val('spfpw', 'NEW-password-1')); await click('spleave');
  console.log('switch=' + await ev("JSON.stringify([document.getElementById('spfph').value, document.getElementById('spfpw').value])")); await click('spfx');
  // «Отозвать» = исключить: фраза + новый пароль → итог по ПК и новый QR
  await ev("[...document.querySelectorAll('#splist .row')].find(r => r.textContent.includes('Office')).querySelector('button').click(); 1"); await sleep(250);
  console.log('delform=' + await ev("[" + txt('spfh') + ", " + vis('spform') + ", " + vis('spfph') + ", " + vis('spfpw') + ", " + vis('spfcd') + "].join('|')"));
  await ev(val('spfph', 'able baker cable delta eagle fable gable habit ideal jewel') + val('spfpw', 'new-pass1')); await click('spfgo'); await sleep(300);
  console.log('excluded=' + await calls() + '|' + await ev("[" + txt('spop') + ", !!document.querySelector('#spop img[src^=\"data:image/svg+xml\"]'), " + vis('spform') + ", document.getElementById('spfph').value].join('|')"));
  await ev("[...document.querySelectorAll('#spop button')].find(b => b.textContent === 'Done').click(); 1"); await sleep(300);
  console.log('cleared=' + await calls() + '|' + await ev(txt('spop') + " + '|' + !!document.querySelector('#spop img')"));
  // смена пароля и кода фразой
  await click('sppw'); await ev(val('spfph', 'x') + val('spfpw', 'short')); await click('spfgo');
  console.log('pwshort=' + await ev(txt('spmsg')) + '|' + await calls());
  await click('spcode'); await ev(val('spfph', 'able baker zzz')); await click('spfgo'); await sleep(300);
  console.log('login=' + await calls() + '|' + await ev(txt('spop') + " + '|' + " + vis('spform')));
  // выход: пароль и код этого ПК
  await ev("st.otp = false; st.space.wait = '444555666'; 1"); await sleep(1200); // выход — с кодом и без TOTP (владелец 2026-11-14); до сверки
  await click('spleave'); await ev(val('spfpw', 'owner-pass') + val('spfcd', '000000')); await click('spfgo');
  console.log('leavewarn=' + await ev(txt('spfh')));
  console.log('leavebad=' + await ev(txt('spmsg') + " + '|' + " + vis('spfcd')) + '|' + await calls());
  await ev(val('spfcd', '123456')); await click('spfgo'); await sleep(300);
  console.log('left=' + await calls() + '|' + await ev("[" + vis('spform') + ", " + vis('spout') + ", " + vis('spin') + ", " + vis('pwrow') + ", " + vis('spleft') + "].join('|')"));
  await click('spleftb'); await sleep(1200); // поле пароля открыто и после опроса hostInfo, хотя «Спрашивать» включено
  console.log('setpw=' + await ev("[" + vis('pwrow') + ", " + vis('spleft') + ", document.activeElement.id].join('|')"));
  await ev(val('newpw', 'new-pass1')); await click('setpw'); await sleep(300);
  console.log('pwset=' + await calls() + '|' + await ev(vis('pwrow')));
  // Ч12: мастер вступления — подписи полей, ход по стадиям, ошибка соединения (поля, кроме пароля и кода, на месте), отмена
  await click('spjoin');
  console.log('labels=' + await ev("[...document.querySelectorAll('#spenter label > span')].map(e => e.textContent).join(';') + '|' + document.querySelector('#spenter [data-n]').textContent"));
  await ev(val('speid', '444 555 666') + val('spepw', 'owner-pass') + val('specd', '654321') + val('speph', 'able baker cable delta eagle fable gable habit ideal jewel'));
  await shot('form', 'spenter');
  await ev("enterRun = true; 1"); await click('spego'); await sleep(1300);
  const stp = () => ev("[...document.getElementById('spop').children].map(e => e.textContent).join(';') + '|' + [document.getElementById('spnew').disabled, document.getElementById('spjoin').disabled, " + vis('spenter') + "].join('|')");
  console.log('st1=' + await calls() + '|' + await stp());
  console.log('pwgone=' + await ev("document.getElementById('spepw').value + '|' + document.getElementById('specd').value")); // не держать после отправки
  await ev("setOp({ kind: 'enter', state: 'run', stage: 'auth', result: null }); 1"); await sleep(1300);
  console.log('st2=' + await stp());
  await shot('progress', 'spop');
  await ev("spJoinID = ''; setOp({ kind: 'enter', state: 'run', stage: 'link', result: null }); 1"); await sleep(1300); // окно перезагрузили
  console.log('st0=' + await stp());
  await ev("spJoinID = '444555666'; setOp({ kind: 'enter', state: 'run', stage: 'save', result: null }); 1"); await sleep(1300);
  console.log('stsave=' + await stp()); // на сохранении «Отмены» нет
  await ev("setOp({ kind: 'enter', state: 'err', err: 'nolink', result: null }); 1"); await sleep(1300);
  console.log('nolink=' + await ev("[" + txt('speerr') + ", " + vis('spenter') + ", " + vis('speerr') + ", document.getElementById('speid').value, document.getElementById('spepw').value, document.getElementById('specd').value, document.getElementById('speph').value.length, document.getElementById('spjoin').disabled, " + txt('spop') + "].join('|')"));
  await shot('nolink', 'speerr');
  await ev("setOp({ kind: 'enter', state: 'err', err: 'noudp', result: null }); 1"); await sleep(1300);
  console.log('noudp=' + await ev(txt('speerr')));
  await ev(val('spepw', 'owner-pass') + val('specd', '654321')); await click('spego'); await sleep(1300); await calls();
  await ev("[...document.querySelectorAll('#spop button')].find(b => b.textContent === 'Cancel').click(); 1"); await sleep(1300);
  console.log('cancelled=' + await calls() + '|' + await ev(txt('speerr') + " + '|' + " + vis('spenter')));
  // приёмка B1: та же быстрая ошибка второй раз подряд — рамка снова видна, пароль и код стёрты
  await ev("enterRun = false; enterErr = 'phrase'; 1");
  for (let i = 0; i < 2; i++) { await ev(val('spepw', 'owner-pass') + val('specd', '654321')); await click('spego'); await sleep(1300); }
  console.log('err2=' + await calls() + '|' + await ev([vis('speerr'), "document.getElementById('spepw').value", "document.getElementById('specd').value", txt('speerr')].join(" + '|' + ")));
  await ev("enterErr = ''; setOp(null); 1"); await sleep(1300); await click('spex');
  // вступление в два шага: превью → отказ → снова → подтверждение
  await click('spjoin');
  await ev(val('speid', '444 555 666') + val('spepw', 'owner-pass') + val('specd', '654321') + val('speph', 'able baker cable delta eagle fable gable habit ideal jewel')); await click('spego'); await sleep(300);
  console.log('preview=' + await calls() + '|' + await ev("[...document.getElementById('spop').children].map(e => e.textContent).join(';')"));
  await click('spex'); await sleep(200);
  console.log('enterx=' + await calls() + '|' + await ev(vis('spenter') + " + '|' + document.getElementById('speph').value"));
  await click('spjoin');
  await ev(val('speid', '444555666') + val('spepw', 'owner-pass') + val('specd', '654321') + val('speph', 'able baker cable delta eagle fable gable habit ideal jewel')); await click('spego'); await sleep(300);
  console.log('answer=' + await ev("[...document.querySelectorAll('#spop button')].find(b => b.textContent === 'Refuse').click(), document.querySelectorAll('#spop button').length"));
  await sleep(400);
  console.log('refused=' + await calls() + '|' + await ev(txt('spop') + " + '|' + " + vis('spenter') + " + '|' + " + txt('speerr')));
  await ev(val('spepw', 'owner-pass') + val('specd', '654321')); await click('spego'); await sleep(300);
  await ev("[...document.querySelectorAll('#spop button')].find(b => b.textContent === 'Confirm').click(); 1"); await sleep(1300);
  console.log('joined=' + await calls() + '|' + await ev("[" + txt('spop') + ", " + vis('spenter') + ", document.getElementById('speph').value, " + vis('spin') + ", [...document.querySelectorAll('#spbars .banner')].map(b => b.textContent).join(';')].join('|')"));
  console.log('how2=' + await ev(vis('sphow'))); // «Как добавить ПК» — и при двух ПК (добавлять можно через любой член)
  // M4: запоздавший ответ spaceOp с confirm не рисует кнопки, если операция уже кончилась
  await ev("setOp({ kind: 'enter', state: 'confirm', result: null, preview: { members: [], gone: [] } }); 1"); await sleep(1300);
  const nb = () => ev("document.querySelectorAll('#spop button').length");
  // ответ, запрошенный до конца операции, приходит через 3 с — после того как hostInfo уже без op (≤ 1 с)
  const shown = await nb(); await ev("opDelay = 3000; 1"); await sleep(1100); await ev("setOp(null); 1"); await sleep(1100);
  let most = 0; for (let i = 0; i < 16; i++) { most = Math.max(most, await nb()); await sleep(200); }
  console.log('stale=' + shown + '|' + most);
  // spaceOp всегда медленнее опроса (1,5 с при опросе 1 с) — превью всё равно рисуется
  await ev("opSlow = 1500; setOp({ kind: 'enter', state: 'confirm', result: null, preview: { members: [], gone: [] } }); 1"); await sleep(4500);
  console.log('slow=' + await nb());
  // spaceConfirm упал по транспорту, операция ещё ждёт — кнопки возвращаются
  await ev("opSlow = 0; failConfirm = 1; [...document.querySelectorAll('#spop button')].find(b => b.textContent === 'Confirm').click(); 1"); await sleep(1500);
  console.log('cfail=' + await nb() + '|' + await ev(txt('spmsg')));
  await ev("setOp(null); 1"); await sleep(1300);
  // M6: подсказка при «Спрашивать» в пространстве; плашка входящего сеанса на экране доступа
  await ev("st.space.ask = true; 1"); await sleep(1300);
  console.log('askbar=' + await ev("[...document.querySelectorAll('#spbars .banner')].map(b => b.textContent).filter(x => x.includes('Sign-in from the space')).length"));
  await ev("st.session = '987654321'; 1"); await sleep(1300);
  console.log('incoming=' + await ev("[" + vis('incoming') + ", document.getElementById('access').contains(document.getElementById('incoming'))].join('|')"));
  // M5: ПК вышел из пространства (другое окно), пока открыта форма правки — форма закрыта, пароль стёрт
  await click('sppw'); await ev(val('spfpw', 'typed-pass')); await ev("st.space = empty(); 1"); await sleep(1300);
  console.log('outform=' + await ev(vis('spform') + " + '|' + document.getElementById('spfpw').value"));
  // сессия показана и закрыта, пока открыт экран доступа: плашка входящей — снова на главной, черновик создания стёрт
  await ev("st.confirm = false; st.otp = true; st.hasPass = true; 1"); await sleep(1300);
  await click('spnew'); await ev(val('spcpw', 'owner-pass')); await click('spcgo'); await calls();
  await ev("show(true); show(false); 1"); await sleep(300);
  console.log('showback=' + await ev("[" + vis('home') + ", " + vis('access') + ", document.getElementById('home').contains(document.getElementById('incoming')), " + txt('spphr') + ", " + vis('spcreate') + "].join('|')") + '|' + await calls());
  await click('accback');
  console.log('back=' + await ev(vis('access') + " + '|' + " + vis('home') + " + '|' + document.getElementById('home').contains(document.getElementById('incoming'))"));
  process.exit(0);
})();`

// TestBrowserSpace — экран «Доступ к этому ПК»: блок «Вы (владелец)» на подменённых привязках пространства.
func TestBrowserSpace(t *testing.T) {
	chrome, err := exec.LookPath("google-chrome")
	if err != nil {
		t.Skip("нет google-chrome")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("нет node")
	}
	srv := httptest.NewServer(http.FileServer(http.FS(ui.FS)))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second) // сценарий идёт ~70 с
	defer cancel()
	out := string(runCDP(t, ctx, chrome, cdpSpace, srv.URL+"/"))
	const ph = "able baker cable delta eagle fable gable habit ideal jewel"
	for _, want := range []string{
		"web=false|false|false\n", // веб-клиент без привязок: ни карточки хоста, ни экрана доступа, ни блока пространства
		"nav=true|false|off|true|true|false\n",
		"hint=First prepare this PC (below on this screen): untick “Ask before each connection”, set up the authenticator app code and set this PC’s password. Then press “Create a space” again.|false\n",
		"steps=Step 1 of 3;Step 2 of 3;Step 3 of 3|true\n", "step3=false|true|spcph\n", "step3back=" + strconv.Itoa(len("true|"+ph)) + "\n",
		"old=true|true|false\n", // прежние элементы на месте: пароль, гости, «Спрашивать»
		"badpw=Wrong password|false\n",
		"phrase=" + ph + "|false|true|\n",
		"cancel=|false|create:wrong-pass,create:owner-pass,createno\n",
		"renew=|true|false|create:owner-pass,createno\n", // повторное «Создать»: фраза стёрта, черновик отменён
		"backphrase=|false|create:owner-pass,createno\n", // «Назад»: то же
		"foreign=Wrong space phrase\n",
		"created=|false|false|true|false|This PCID 123 456 789key: SELF-FP|create:owner-pass,createok:able baker,createok:" + ph + "\n",
		"next=true|false|✓ The space is created. This PC is the first one in it.Next: add another PC of yours" +
			"On the other PC open AnyPC → “Access to this PC” → “Join” and enter:This PC’s ID123 456 789📋Space passwordthe same password you use to sign in to the PCs of the space" +
			"Authenticator app code6 digits from the app entry you use to sign in to the PCs of the space: “AnyPC” with the ID of the PC where the space was created, or “AnyPC пространство” if the code was changed" +
			"Space phrasethe 10 words you wrote downWhile the other PC joins, this one must be on and online.Got it\n",
		"gotit=false|true\n", "how=true|false|true\n",
		"askin=true\n",
		"askoff=setconfirm:false|false|true|false\n", // выключено, и снова включить нельзя
		"bars=The space records on this PC are damaged.Leave and join again;" +
			"Passes and “I'm here” are off: a revoked PC saw the code secret.Set a new code;" +
			"Too many parallel edits.Set a new code;" +
			"Password sign-in and “I'm here” are closed until a check with your PC other than Office · 444 555 666.Check now;" +
			"The clock differs from 777 888 999 — check the time.\n",
		"list=This PCID 123 456 789key: SELF-FP;OfficeID 444 555 666key: OFFICE-FPRevoke\n", // ID и ключ — раздельно, с подписями
		"leaveform=Before the check with your other PC: leaving erases the password and code of this PC — only the one-time code from the screen will work.|false|true|true|Password of this PC\n",
		"switch=[\"\",\"\"]\n", // смена режима формы стирает фразу и пароль
		"codeform=New authenticator code on all your PCs: the space phrase.|true|false|false\n",
		"sync=sync|In progress…\n",
		"nobars=0|\n",
		"delform=Revoke Office · 444 555 666: the space phrase and a new password (recommended — that PC knew the old one). The code changes right away.|true|true|true|false\n",
		"excluded=exclude:" + ph + ":b2ZmaWNl:new-pass1|Done.Office · 444 555 666 — up to date777 888 999 — offline: That PC is offline" +
			"New code: scan the QR with the authenticator app — the old code no longer works.ABCD EFGH IJKL MNOPDone|true|false|\n",
		"cleared=clear||false\n",
		"pwshort=Password must be at least 8 characters.|\n",
		"login=login:able baker zzz::true|Word 3 of the phrase is not in the dictionary|true\n",
		"leavewarn=Before the check with your other PC: leaving erases the password and code of this PC — only the one-time code from the screen will work.\n",
		"leavebad=Wrong code|true|leave:owner-pass:000000\n",
		"left=leave:owner-pass:123456|false|true|false|false|true\n", // до сверки: пароль и TOTP стёрты — подсказка
		"setpw=true|false|newpw\n",
		"pwset=setpw:new-pass1|false\n", // задан — снова «как прежде»: под «Спрашивать» поле скрыто
		"labels=ID of your PC that is already in the space;9 digits from that PC’s main screen (“This computer’s ID”);Space password;" +
			"the same password you use to sign in to the PCs of the space;Authenticator app code (6 digits);" +
			"from the space entry in the app — the one you use to sign in to the PCs of the space: “AnyPC” with the ID of the PC where the space was created, or “AnyPC пространство” if the code was changed. Not this PC’s entry; the code changes every 30 seconds;Space phrase (10 words in Latin letters);" +
			"the 10 words you wrote down when creating the space|Step 1 of 3\n",
		"st1=enter:444555666:owner-pass:654321:" + ph + "|Step 2 of 3;Connecting and checking;Usually up to 30 seconds. Nothing to press.;" +
			"…Connecting to 444 555 666…;·Checking the password and code…;·Getting the list of PCs in the space…;Cancel|true|true|false\n",
		"st2=Step 2 of 3;Connecting and checking;Usually up to 30 seconds. Nothing to press.;" +
			"✓Connecting to 444 555 666…;…Checking the password and code…;·Getting the list of PCs in the space…;Cancel|true|true|false\n",
		"nolink=Could not joinCould not connect to that PC: is AnyPC running and online there? A firewall or VPN may block the direct connection" +
			"What to do: make sure AnyPC is running on that PC and its main screen says “online”. While joining, turn off VPN and allow AnyPC in the firewall on both PCs, then press “Join” again." +
			"The password and code were cleared — enter them again; everything else is kept.|true|true|444 555 666|||" + strconv.Itoa(len(ph)) + "|false|\n",
		"noudp=Could not joinThe connection was not established: this PC or its network does not let AnyPC through (firewall, VPN or closed port UDP/TCP 3478)" +
			"What to do: allow outgoing connections for AnyPC in this PC’s firewall (on a Mac — LuLu, Little Snitch: a rule for AnyPC to any address, not only to the server), turn off VPN while joining, and on a foreign network (office, hotel) try another one. Then press “Join” again." +
			"The password and code were cleared — enter them again; everything else is kept.\n",
		"pwgone=|\n", // пароль и код не держатся в поле после отправки
		"st0=Step 2 of 3;Connecting and checking;Usually up to 30 seconds. Nothing to press.;…Connecting to your PC…;·Checking the password and code…;·Getting the list of PCs in the space…;Cancel|true|true|false\n",
		"stsave=Step 3 of 3;Saving the join…|true|true|false\n",
		"err2=enter:444555666:owner-pass:654321:" + ph + ",enter:444555666:owner-pass:654321:" + ph + "|true|||Could not joinWrong space phrase" +
			"What to do: compare the phrase with your note — 10 words in Latin letters separated by spaces, then “Join”.The password and code were cleared — enter them again; everything else is kept.\n",
		"cancelled=cancel|Joining stoppedCancelledWhat to do: to join, press “Join” again.The password and code were cleared — enter them again; everything else is kept.|true\n",
		"preview=enter:444555666:owner-pass:654321:" + ph + "|Step 3 of 3;Are these all your PCs?;Check the list. All yours — “Confirm”. A PC that is not yours — “Refuse”.;" +
			"OfficeID 444 555 666key: OFFICE-FP;This PCID 123 456 789key: SELF-FP;" +
			"The password of this PC will be replaced with the space password.;The authenticator code of this PC will be replaced with the space code.;" +
			"Will be reset: trusted keys — 2, sign-in by key — 1.;" +
			"“Ask before each connection” stays on: sign-in with password and code works once you turn it off.;Revoked: 2;key: GONE-FP1;key: GONE-FP2;ConfirmRefuse\n",
		"enterx=confirm:false|true|\n", // «Отмена» при ждущем превью — отказ: снова шаг 1 с итогом
		"answer=0\n",
		"refused=enter:444555666:owner-pass:654321:" + ph + ",confirm:false||true|Joining stoppedJoining cancelledWhat to do: to join, press “Join” again." +
			"The password and code were cleared — enter them again; everything else is kept.\n",
		"how2=true\n",
		"joined=enter:444555666:owner-pass:654321:" + ph + ",confirm:true|✓ This PC has joined the space." +
			"Password sign-in and “I'm here” open after a check with another PC of yours: it runs by itself when that PC is online, or press “Check now”." + // сначала сверка, потом «Я тут»
			"Next: on the main screen, in the “My space” block, enter the space password and code and press “I'm here” — your PCs open from here without a password." +
			"The app code for this PC is now shared by the space — from the same entry you used to sign in to 444 555 666. This PC’s old entry no longer works." +
			"“Ask before each connection” is on for this PC: your PCs get in only with confirmation. Untick it below to sign in with the password and code.Got it|false||true|" +
			"Password sign-in and “I'm here” are closed until a check with your PC other than Office · 444 555 666.Check now\n",
		"stale=2|0\n",
		"askbar=1\n",
		"slow=2\n",
		"cfail=2|Error: TypeError: Failed to fetch\n",
		"incoming=true|true\n",
		"outform=false|\n",
		"showback=true|false|true||false|createno\n",
		"back=false|true|true\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
}

// TestSpaceCodesUI — у каждого кода ошибки пространства (app/spaceapi.go spaceCodes) есть строка sp_e_<код> в окне.
func TestSpaceCodesUI(t *testing.T) {
	src, err := os.ReadFile("../app/spaceapi.go")
	if err != nil {
		t.Fatal(err)
	}
	html, _ := ui.FS.ReadFile("index.html")
	codes := regexp.MustCompile(`, "([a-z_]+)"\}`).FindAllStringSubmatch(string(src), -1)
	if len(codes) < 30 {
		t.Fatalf("кодов в spaceCodes: %d — разбор устарел", len(codes))
	}
	for _, c := range append(codes, []string{"", "other"}, []string{"", "phrase_word"}) {
		if n := strings.Count(string(html), " sp_e_"+c[1]+": "); n != 7 {
			t.Errorf("sp_e_%s: в словарях %d раз из 7", c[1], n)
		}
	}
	// Ч12, приёмка M2: у каждой ошибки вступления — свой «что делать» (sw_a_<код>; синонимы — SP_ADV в окне)
	for _, c := range []string{"noudp", "nolink", "offline", "closed", "auth", "ask", "old", "phrase", "id", "busythere", "lockedthere", "nopassthere",
		"hostkey", "badid", "clock", "change", "other", "busy", "in", "compromised", "over", "damaged", "again", "retry"} {
		if n := strings.Count(string(html), " sw_a_"+c+": "); n != 7 {
			t.Errorf("sw_a_%s: в словарях %d раз из 7", c, n)
		}
	}
}
