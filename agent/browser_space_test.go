package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"anypc/ui"
)

// cdpSpace — экран «Доступ к этому ПК», блок «Вы (владелец)» на подменённых привязках модели «Инициатор по ID»:
// без привязок блока нет (веб-клиент); создание — одно действие (spaceCreate без аргументов), файл/фразу и QR хоста
// UI не показывает (моки возвращают их как «отраву» — показ пошёл бы в asserts); вступление — шаги ID → логин →
// пароль+TOTP, spaceEnter(id, user, password, code) ровно четырьмя аргументами (лишний виден как ∅); превью
// «Это все ваши ПК?», spaceConfirm и стадия admit отсутствуют; ход — стадии link/auth/list/save; успешный done
// с итогом; ошибка auth (клиентская и от хоста) возвращает к полям, стирая пароль и код, но сохраняя ID и логин;
// отмена мастера и операции (spaceCancel); «Отозвать» — spaceExclude(pub), «Изменить»/«Заново» — spaceLogin(bool,bool),
// «Покинуть» — spaceLeave() — формы без полей: фразы, пароля и кода хост не вводит. settingsEnter не мокается
// (SETAUTH=false): «Доступ» открывается без системной авторизации.
const cdpSpace = `
const [, , port, url] = process.argv;
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const tab = await (await fetch('http://127.0.0.1:' + port + '/json/new?about:blank', { method: 'PUT' })).json();
  const ws = new WebSocket(tab.webSocketDebuggerUrl); await new Promise(r => ws.onopen = r);
  let id = 0; const wait = {};
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && wait[m.id]) wait[m.id](m); if (m.method === 'Runtime.exceptionThrown' || m.method === 'Log.entryAdded') console.log('PAGEEXC ' + JSON.stringify(m.params)); };
  const call = (method, params) => new Promise(r => { const i = ++id; wait[i] = r; ws.send(JSON.stringify({ id: i, method, params })); });
  const ev = async x => { const r = (await call("Runtime.evaluate", { expression: x, awaitPromise: true, returnByValue: true })).result; return r?.exceptionDetails ? "EXC " + JSON.stringify(r.exceptionDetails.exception?.description) : r?.result?.value; };
  const vis = i => "!document.getElementById('" + i + "').classList.contains('hidden')";
  const txt = i => "document.getElementById('" + i + "').textContent";
  const val = (i, v) => "document.getElementById('" + i + "').value = " + JSON.stringify(v) + ";";
  const click = async i => { await ev("document.getElementById('" + i + "').click(); 1"); await sleep(250); };
  const calls = () => ev("calls.splice(0).join(',')");
  const opkids = () => "[...document.getElementById('spop').children].map(e => e.textContent).join(';')";
  const inputs = sel => "[...document.querySelectorAll('" + sel + "')].filter(i => !i.closest('.hidden')).length";
  const step = () => ev("['spj1','spj2','spj3','speerr'].map(i => !document.getElementById(i).classList.contains('hidden')).join(',') + '|' + (document.querySelector('#spj1:not(.hidden) b, #spj2:not(.hidden) b, #spj3:not(.hidden) b') || {}).textContent + '|' + document.activeElement.id + '|' + (document.querySelector('#spj1:not(.hidden) [data-n], #spj2:not(.hidden) [data-n], #spj3:not(.hidden) [data-n]') || {}).getAttribute('data-n')");
  await call('Page.enable', {}); await call('Runtime.enable', {}); await call('Log.enable', {});
  await call('Page.navigate', { url }); await sleep(1200); // веб-клиент с сервера: привязок нет — блока пространства нет
  console.log('web=' + await ev("[" + vis('spcard') + ", " + vis('me') + ", " + vis('access') + "].join('|')"));
  await call('Page.addScriptToEvaluateOnNewDocument', { source: ` + "`" + `(() => { // в IIFE: имена не сталкиваются с const страницы
    localStorage.setItem('mine', JSON.stringify([{ id: '444555666', name: 'Office' }])); localStorage.setItem('tour_home', '1');
    const me = { id: '123456789', fp: 'SELF-FP', pub: 'c2VsZg==', self: true, passUntil: 0 };
    const office = { id: '444555666', fp: 'OFFICE-FP', pub: 'b2ZmaWNl', self: false, passUntil: 0 };
    const PH = 'able baker cable delta eagle fable gable habit ideal jewel'; // фраза и файл — хост их вернёт, UI показать не должен
    const QR = { uri: 'otpauth://totp/AnyPC?secret=ABCDEFGHIJKLMNOP&issuer=AnyPC', svg: '<svg xmlns="http://www.w3.org/2000/svg"/>' };
    const empty = () => ({ in: false, damaged: false, compromised: false, over: false, pend: 0, wait: '', clock: [], ask: false, lock: true, gone: 0, members: [], op: null });
    window.st = { id: '123456789', confirm: true, otp: true, hasPass: true, users: [{ name: 'anna', view: true, otp: true }], keys: [], space: empty() };
    window.empty = empty; window.calls = []; window.op = null;
    const setOp = window.setOp = o => { window.op = o; st.space.op = o && { kind: o.kind, state: o.state }; };
    window.hostInfo = async () => JSON.parse(JSON.stringify(st));
    window.spaceOp = async () => window.op && JSON.parse(JSON.stringify(window.op));
    let gate = Promise.resolve(); // создание «идёт», пока тест не разрешит: ловим промежуточное состояние
    window.createGate = () => { gate = new Promise(r => { window.createGo = r; }); };
    window.spaceCreate = async function () { calls.push('create:' + arguments.length + ':' + [...arguments].join(',')); await gate; st.space.in = true; st.space.members = [me]; return { path: '/home/user/Downloads/AnyPC-space-123456789.txt', phrase: PH }; };
    window.spaceEnter = async function () { // ровно (id, user, password, code); лишний аргумент виден как ∅
      calls.push('enter:' + [...arguments].map(a => a === undefined ? '∅' : a).join(':'));
      if (window.enterRun) return void setOp({ kind: 'enter', state: 'run', stage: window.enterStage || 'link', result: null, preview: { members: [{ id: '444555666', fp: 'OFFICE-FP' }], password: true, code: true, trusted: 2, keyLogin: 1, ask: true, already: false, gone: [] } });
      if (window.enterErr) return void setOp({ kind: 'enter', state: 'err', err: window.enterErr, result: null });
      return null;
    };
    window.spaceCancel = async () => { calls.push('cancel'); setOp({ kind: 'enter', state: 'err', err: 'cancel', result: null }); };
    window.spaceExclude = async function (pub, legacy) { calls.push('exclude:' + arguments.length + ':' + pub + ':' + legacy); setOp({ kind: 'exclude', state: 'done', result: { results: [{ id: '444555666', state: 'ok' }, { id: '777888999', state: 'offline', err: 'offline' }], qr: QR } }); return null; };
    window.spaceLogin = async function (pwNew, codeNew) { calls.push('login:' + arguments.length + ':' + [...arguments].map(a => typeof a + '=' + a).join(',')); if (window.loginOpErr) { setOp({ kind: 'login', state: 'err', err: window.loginOpErr, result: null }); return null; } if (window.loginErr) throw 'space:' + window.loginErr; setOp({ kind: 'login', state: 'done', result: { results: [{ id: '123456789', state: 'ok' }], qr: QR } }); return null; };
    window.spaceLeave = async function () { calls.push('leave:' + arguments.length + ':' + [...arguments].join(',')); st.space = empty(); return null; };
    window.spaceOpClear = async () => { calls.push('clear'); setOp(null); return null; };
    window.spaceSync = async () => { calls.push('sync'); return null; };
    window.spaceConfirm = async () => { calls.push('CONFIRM:' + [...arguments].join(',')); return null; }; // UI не должен вызывать
  })();` + "`" + ` });
  await call('Page.navigate', { url }); await sleep(1500);
  await click('setgo'); await click('setacc'); // без мока settingsEnter «Доступ» открывается без пароля ОС (SETAUTH=false)
  console.log('nav=' + await ev("[" + vis('access') + ", " + vis('home') + ", " + vis('spcard') + ", " + vis('spout') + ", " + vis('spin') + "].join('|')"));
  console.log('gone=' + await ev("['speph','spfph','spfpw','spfcd'].every(i => !document.getElementById(i)) + '|' + " + inputs('#spcard input')));
  // создание — одно действие; хост отвечает файлом и фразой — UI показывает только «Создаётся…» и «Что дальше»
  await ev('createGate(); 1'); await click('spnew');
  console.log('creating=' + await ev("[" + vis('spcreate') + ", " + vis('spin') + ", " + vis('spnext') + ", document.getElementById('spnew').disabled, document.getElementById('spcreatemsg').textContent, !/Downloads|phrase is saved/.test(" + txt('spcard') + ")].join('|')"));
  await ev('createGo(); 1'); await sleep(500);
  console.log('created=' + await calls() + '|' + await ev("[" + vis('spcreate') + ", " + vis('spin') + ", " + vis('spnext') + ", document.getElementById('spnew').disabled].join('|')"));
  console.log('next=' + await ev(txt('spnext') + " + '|' + !/phrase/i.test(" + txt('spnext') + ")"));
  const gotit = "[...document.querySelectorAll('#spnext button')].find(b => b.textContent === 'Got it').click(); 1";
  await ev(gotit); await sleep(300);
  console.log('gotit=' + await ev("[" + vis('spnext') + ", " + vis('sphow') + ", " + txt('sphow') + "].join('|')"));
  await click('sphow'); // «Как добавить ПК» — тот же экран, без плашки создания
  console.log('how=' + await ev("[" + vis('spnext') + ", !document.getElementById('spnext').textContent.includes('The space is created')].join('|')"));
  await ev(gotit); await sleep(300);
  console.log('list=' + await ev("[...document.querySelectorAll('#splist .row')].map(r => r.textContent).join(';')"));
  // мастер вступления доступен только ПК вне пространства: после проверки создания возвращаем состояние «вне Space»
  await ev("st.space.in = false; st.space.members = []; 1"); await sleep(1300);
  // мастер вступления: шаг 1 — ID
  await click('spjoin');
  console.log('j1=' + await step());
  await ev(val('speid', '123 456 789')); await click('spj1go'); // свой ID
  console.log('j1self=' + await step() + '|' + await ev(txt('speerr')));
  await ev(val('speid', '444555')); await click('spj1go'); // не 9 цифр
  console.log('j1short=' + await step() + '|' + await ev("document.getElementById('speerr').textContent.includes('Wrong PC ID')"));
  await ev(val('speid', '444 555 666')); await click('spj1go');
  console.log('j2=' + await step());
  await click('spj2go'); // пустой логин — остаёмся на шаге 2
  console.log('j2empty=' + await step() + '|' + await ev(vis('speerr')));
  await ev(val('speuser', 'anna')); await click('spj2go');
  console.log('j3=' + await step() + '|' + await ev(txt('spj3b')));
  await ev("document.querySelector('#spj3 .spjback').click(); 1"); await sleep(250);
  console.log('j3back=' + await step());
  await ev("document.querySelector('#spj2 .spjback').click(); 1"); await sleep(250);
  console.log('j2back=' + await step());
  await ev(val('speid', '444 555 666')); await click('spj1go'); await ev(val('speuser', 'anna')); await click('spj2go');
  await ev("document.querySelector('#spj3 .spex').click(); 1"); await sleep(250); // отмена мастера
  console.log('jx=' + await ev("[" + vis('spenter') + ", document.getElementById('speid').value, document.getElementById('speuser').value, document.getElementById('spepw').value, document.getElementById('specd').value].join('|')"));
  await click('spjoin');
  await ev(val('speid', '444555666')); await click('spj1go'); await ev(val('speuser', 'anna')); await click('spj2go');
  await click('spego'); // клиентская проверка: пустой пароль — space:auth, spaceEnter не звался
  console.log('j3auth=' + await step() + '|' + await ev(txt('speerr')) + '|' + await calls());
  await ev(val('spepw', 'Str0ng-pass-1') + val('specd', '12')); await click('spego'); // короткий код — снова space:auth
  console.log('j3code=' + await ev(vis('speerr') + " + '|' + document.getElementById('specd').value") + '|' + await calls());
  // точные аргументы spaceEnter(id, user, password, code); ход — стадии link/auth/list
  await ev('enterRun = true; 1'); await ev(val('spepw', 'Str0ng-pass-1') + val('specd', '654321')); await click('spego'); await sleep(400);
  console.log('st1=' + await calls() + '|' + await ev(opkids() + " + '|' + [document.getElementById('spnew').disabled, document.getElementById('spjoin').disabled, " + vis('spenter') + "].join('|')"));
  console.log('pwgone=' + await ev("document.getElementById('spepw').value + '|' + document.getElementById('specd').value"));
  await ev("setOp({ kind: 'enter', state: 'run', stage: 'auth', result: null }); 1"); await sleep(1300);
  console.log('st2=' + await ev(opkids()));
  await ev("setOp({ kind: 'enter', state: 'run', stage: 'list', result: null }); 1"); await sleep(1300);
  console.log('st3=' + await ev(opkids()));
  await ev("setOp({ kind: 'enter', state: 'run', stage: 'admit', result: null }); 1"); await sleep(1300); // стадии admit нет: текст «Разрешить» не появляется
  console.log('admit=' + await ev(opkids() + ".includes('Allow') + '|' + document.getElementById('spop').textContent.includes('your PCs?') + '|' + document.querySelectorAll('#spop button').length"));
  await ev("setOp({ kind: 'enter', state: 'confirm', result: null, preview: { members: [{ id: '444555666', fp: 'OFFICE-FP' }, { id: '123456789', fp: 'SELF-FP' }], gone: [] } }); 1"); await sleep(1300); // состояния confirm нет: ничего не рисуется
  console.log('noconfirm=' + await ev("document.getElementById('spop').textContent.length + '|' + document.querySelectorAll('#spop button').length"));
  await ev("setOp({ kind: 'enter', state: 'run', stage: 'save', result: null }); 1"); await sleep(1300);
  console.log('stsave=' + await ev(opkids() + " + '|' + document.querySelectorAll('#spop button').length"));
  // успешный done: итог без превью и кнопок Confirm/Refuse, поля стёрты
  await ev("st.space.in = true; st.space.wait = '444555666'; st.space.members = [{ id: '123456789', fp: 'SELF-FP', pub: 'c2VsZg==', self: true, passUntil: 0 }, { id: '444555666', fp: 'OFFICE-FP', pub: 'b2ZmaWNl', self: false, passUntil: 0 }]; setOp({ kind: 'enter', state: 'done', result: { code: true, ask: true, preview: { members: [{ id: '444555666', fp: 'OFFICE-FP' }], password: true, code: true, trusted: 2, keyLogin: 1, ask: false, already: false, gone: [] } } }); 1"); await sleep(1300);
  console.log('joined=' + await ev(opkids() + " + '|' + document.querySelectorAll('#spop button').length"));
  console.log('joined2=' + await ev("[" + vis('spenter') + ", " + vis('spin') + ", document.getElementById('speid').value, document.getElementById('speuser').value, document.getElementById('spepw').value, document.getElementById('specd').value].join('|')"));
  await ev("[...document.querySelectorAll('#spop button')][0].click(); 1"); await sleep(300);
  console.log('cleared=' + await calls() + '|' + await ev(txt('spop') + " + '|' + " + vis('spin')));
  console.log('list2=' + await ev("[...document.querySelectorAll('#splist .row')].map(r => r.textContent).join(';')"));
  // отмена идущей операции: снова шаг 2, логин сохранён, пароль и код стёрты
  await ev("st.space.in = false; st.space.members = []; 1"); await sleep(1300);
  await click('spjoin');
  await ev(val('speid', '444555666') + val('speuser', 'anna')); await click('spj1go'); await click('spj2go');
  await ev(val('spepw', 'Str0ng-pass-1') + val('specd', '654321')); await click('spego'); await sleep(300);
  await ev("[...document.querySelectorAll('#spop button')].find(b => b.textContent === 'Cancel').click(); 1"); await sleep(1300);
  console.log('cancelled=' + await calls() + '|' + await step() + '|' + await ev(txt('speerr') + " + '|' + document.getElementById('spepw').value + '|' + document.getElementById('speuser').value"));
  // ошибка auth от хоста: возврат к шагу 3, пароль и код стёрты, логин и ID на месте
  await ev("setOp(null); enterRun = false; enterErr = 'auth'; 1"); await sleep(1300); await calls();
  await click('spj2go'); await ev(val('spepw', 'Str0ng-pass-1') + val('specd', '654321')); await click('spego'); await sleep(1300);
  console.log('errauth=' + await step() + '|' + await ev(txt('speerr') + " + '|' + [document.getElementById('speid').value, document.getElementById('speuser').value, document.getElementById('spepw').value, document.getElementById('specd').value].join('|')"));
  // «Отозвать» — spaceExclude(pub) без полей; QR из ответа хоста не показывается
  await ev("enterErr = ''; st.space.in = true; st.space.members = [{ id: '123456789', fp: 'SELF-FP', pub: 'c2VsZg==', self: true, passUntil: 0 }, { id: '444555666', fp: 'OFFICE-FP', pub: 'b2ZmaWNl', self: false, passUntil: 0 }]; setOp(null); 1"); await sleep(1300); await calls();
  await ev("[...document.querySelectorAll('#splist .row')].find(r => r.textContent.includes('Office')).querySelector('button').click(); 1"); await sleep(250);
  console.log('delform=' + await ev("[" + vis('spform') + ", document.getElementById('spfh').textContent.includes('Office · 444 555 666'), " + inputs('#spform input') + ", document.activeElement.id].join('|')"));
  await click('spfgo'); await sleep(1300);
  console.log('excluded=' + await calls() + '|' + await ev(opkids() + " + '|' + document.querySelectorAll('#spop img').length + '|' + !/otpauth|scan the QR/i.test(document.getElementById('spop').textContent) + '|' + " + vis('spform')));
  await ev("[...document.querySelectorAll('#spop button')].find(b => b.textContent === 'Done').click(); 1"); await sleep(300);
  console.log('exclear=' + await calls() + '|' + await ev(txt('spop')));
  // «Изменить» и «Заново» — spaceLogin(bool, bool) ровно двумя булевыми
  await click('sppw');
  console.log('pwform=' + await ev("[" + vis('spform') + ", " + inputs('#spform input') + "].join('|')"));
  await click('spfgo'); await sleep(1300);
  console.log('loginpw=' + await calls() + '|' + await ev(opkids() + " + '|' + document.querySelectorAll('#spop img').length + '|' + " + vis('spform')));
  await click('spcode'); await click('spfx'); // отмена формы — без вызова
  console.log('codecancel=' + await calls() + '|' + await ev(vis('spform')));
  await click('spcode'); await click('spfgo'); await sleep(1300);
  console.log('logincode=' + await calls());
  await ev("loginErr = 'password'; setOp(null); 1"); await sleep(1300);
  await click('sppw'); await click('spfgo'); await sleep(300);
  console.log('loginerr=' + await calls() + '|' + await ev(txt('spmsg') + " + '|' + " + vis('spform')));
  await ev("loginErr = ''; loginOpErr = 'phrasefile'; 1"); await click('spfx'); await calls();
  await click('sppw'); await click('spfgo'); await sleep(1300);
  console.log('migration=' + await ev("[" + vis('spflrow') + ", document.activeElement.id, document.getElementById('spop').textContent.includes('predates automatic')].join('|')"));
  await calls();
  await ev(val('spfl', 'able baker cable delta eagle fable gable habit ideal jewel') + "loginOpErr = ''; 1"); await click('spfgo'); await sleep(1300);
  console.log('migrated=' + await calls() + '|' + await ev(vis('spflrow')));
  // выход — spaceLeave() без аргументов и полей
  await ev("st.space.wait = '444555666'; 1"); await sleep(1200);
  await click('spleave');
  console.log('leavewarn=' + await ev("document.getElementById('spfh').textContent.startsWith('Before the check with your other PC') + '|' + " + inputs('#spform input')));
  await click('spfgo'); await sleep(1300);
  console.log('left=' + await calls() + '|' + await ev("[" + vis('spform') + ", " + vis('spin') + ", " + vis('spout') + ", " + vis('spleft') + "].join('|')") + '|' + await ev("document.getElementById('spleft').textContent.includes('Leaving before the check erased')"));
  await click('accback');
  console.log('back=' + await ev("[" + vis('access') + ", " + vis('home') + "].join('|')"));
  process.exit(0);
})();`

// TestBrowserSpace — новая модель «Инициатор по ID»: создание одним действием, вступление ID → логин → пароль+TOTP,
// точные аргументы привязок, отсутствие превью/подтверждения/admit и QR, правки и выход без ввода секретов.
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
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	out := string(runCDP(t, ctx, chrome, cdpSpace, srv.URL+"/"))
	const enterArgs = "enter:444555666:anna:Str0ng-pass-1:654321:" // (id, user, password, code, legacyPhrase="")
	for _, want := range []string{
		"web=false|false|false\n", // веб-клиент без привязок: ни карточки пространства, ни блока владельца, ни экрана доступа
		"nav=true|false|true|true|false\n",
		"gone=true|0\n", // старых полей фразы/пароля/кода нет; вне мастера полей нет вовсе
		"creating=true|false|false|true|Creating the space after system authorization…|true\n",
		"created=create:0:|false|true|true|false\n", // spaceCreate без аргументов; файл и фраза из ответа не показаны
		"next=✓ The space is created. This PC is the first one in it.Next: add another PC of yoursOn the other PC open AnyPC → “My space” → “Set up” → “Join” and enter:This PC’s ID123 456 789📋Add userSpace accountEnter the permanent login created for you on that PC.While the other PC joins, this one must be on and online.Got it|true\n",
		"gotit=false|true|How to add a PC\n",
		"how=true|true\n",
		"list=This PCID 123 456 789key: SELF-FP\n",
		"j1=true,false,false,false|Details of your PC that is already in the space|speid|1/3\n",
		"j1self=true,false,false,true|Details of your PC that is already in the space|speid|1/3|Could not joinWrong PC IDWhat to do: enter the 9-digit ID of your other PC (not this one).The password and code were cleared — enter them again; everything else is kept.\n",
		"j1short=true,false,false,true|Details of your PC that is already in the space|speid|1/3|true\n",
		"j2=false,true,false,false|Space account|speuser|2/3\n",
		"j2empty=false,true,false,false|Space account|speuser|2/3|false\n",
		"j3=false,false,true,false|Password and code|spepw|3/3|Enter the permanent password and the code from your authenticator, both created for you on that PC.\n",
		"j3back=false,true,false,false|Space account|speuser|2/3\n",
		"j2back=true,false,false,false|Details of your PC that is already in the space|speid|1/3\n",
		"jx=false||||\n", // отмена мастера: мастер скрыт, все поля стёрты
		"j3auth=false,false,true,true|Password and code|spepw|3/3|Could not joinWrong password or codeWhat to do: check the space password and enter a fresh code from the space entry in the app (“AnyPC” with the ID of the PC where the space was created, or “AnyPC пространство”) — not this PC’s entry, then “Join”.The password and code were cleared — enter them again; everything else is kept.|\n",
		"j3code=true||\n", // и короткий код — ошибка без вызова spaceEnter; поле стёрто
		"st1=" + enterArgs + "|Step 3 of 3;Connecting and checking;Usually up to 30 seconds. Nothing to press.;…Connecting to Office · 444 555 666…;·Checking the password and code…;·Getting the list of PCs in the space…;Cancel|true|true|false\n",
		"pwgone=|\n", // пароль и код не держатся в полях после отправки
		"st2=Step 3 of 3;Connecting and checking;Usually up to 30 seconds. Nothing to press.;✓Connecting to Office · 444 555 666…;…Checking the password and code…;·Getting the list of PCs in the space…;Cancel\n",
		"st3=Step 3 of 3;Connecting and checking;Usually up to 30 seconds. Nothing to press.;✓Connecting to Office · 444 555 666…;✓Checking the password and code…;…Getting the list of PCs in the space…;Cancel\n",
		"admit=false|false|1\n", // стадия admit отсутствует: ни «Разрешить», ни превью, только «Отмена»
		"noconfirm=0|0\n",       // состояние confirm не рисуется: ни текста, ни кнопок Confirm/Refuse
		"stsave=Step 3 of 3;Saving the join…|0\n",
		"joined=✓ This PC has joined the space.Password sign-in and “I'm here” open after a check with another PC of yours: it runs by itself when that PC is online, or press “Check now”.Next: on the main screen, in the “My space” block, enter the space password and code and press “I'm here” — your PCs open from here without a password.The app code for this PC is now shared by the space — from the same entry you used to sign in to 444 555 666. This PC’s old entry no longer works.“Ask before each connection” is on for this PC: your PCs get in only with confirmation. Untick it below to sign in with the password and code.Got it|1\n",
		"joined2=false|true||||\n", // после итога мастер скрыт и поля стёрты
		"cleared=clear||true\n",
		"list2=This PCID 123 456 789key: SELF-FP;OfficeID 444 555 666key: OFFICE-FPRevoke\n",
		"cancelled=" + enterArgs + ",cancel|false,true,false,true|Space account|speuser|2/3|Joining stoppedCancelledWhat to do: to join, press “Join” again.The password and code were cleared — enter them again; everything else is kept.||anna\n",
		"errauth=false,false,true,true|Password and code|spepw|3/3|Could not joinWrong password or codeWhat to do: check the space password and enter a fresh code from the space entry in the app (“AnyPC” with the ID of the PC where the space was created, or “AnyPC пространство”) — not this PC’s entry, then “Join”.The password and code were cleared — enter them again; everything else is kept.|444555666|anna||\n",
		"delform=true|true|0|spfgo\n", // форма отзыва без полей
		"excluded=exclude:2:b2ZmaWNl:|Done.;Office · 444 555 666 — up to date;777 888 999 — offline: That PC is offline;Done|0|true|false\n",
		"exclear=clear|\n",
		"pwform=true|0\n",
		"loginpw=login:3:boolean=true,boolean=false,string=|Done.;123 456 789 — up to date;Done|0|false\n",
		"codecancel=|false\n",
		"logincode=login:3:boolean=false,boolean=true,string=",
		"loginerr=login:3:boolean=true,boolean=false,string=|Wrong password|true",
		"migration=true|spfl|true\n",
		"migrated=login:3:boolean=true,boolean=false,string=able baker cable delta eagle fable gable habit ideal jewel|false\n",
		"leavewarn=true|0\n",
		"left=leave:0:|false|false|true|true|true\n",
		"back=false|true\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if strings.Contains(out, "CONFIRM") { // spaceConfirm удалён: UI не вызывает его даже при ждущем превью
		t.Errorf("UI вызвал spaceConfirm:\n%s", out)
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
	for _, c := range []string{"needpw", "badcode", "badphrase", "declined", "noanswer", "nowin", "later", "nospace", "waitthere", "joinlocked", "late", "viewonly", "noudp", "nolink", "offline", "closed", "auth", "ask", "old", "phrase", "id", "busythere", "lockedthere", "nopassthere",
		"hostkey", "badid", "clock", "change", "other", "busy", "in", "compromised", "over", "damaged", "again", "retry"} {
		if n := strings.Count(string(html), " sw_a_"+c+": "); n != 7 {
			t.Errorf("sw_a_%s: в словарях %d раз из 7", c, n)
		}
	}
}
