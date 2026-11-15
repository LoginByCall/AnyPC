package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"anypc/ui"
)

// cdpGive — «Передать управление этим ПК» (требование владельца 2026-11-15): ID, ниже переключатель «Разрешить
// управление»; выкл (по умолчанию) — строки кода нет; вкл — строка кода и «Новый код»; режим пароля — переключатель
// недоступен с пояснением. «Настроить» — в заголовке «Моё пространство» во всех состояниях блока и строкой в ⚙.
// ANYPC_SHOT=<папка> — снимки 1200×760 в светлой теме: give-off.png, give-on.png.
const cdpGive = `
const extra = async () => ` + "`" + `
  Object.defineProperty(navigator, 'languages', { get: () => ['ru'] });
  Object.assign(st, { confirm: true, otp: false, give: false, code: '', online: true, version: '0.3.1' });
  st.space = { in: false, damaged: false, compromised: false, over: false, pend: 0, wait: '', clock: [], ask: false, lock: true, gone: 0, members: [], op: null };
  window.setGive = async on => { calls.push('give:' + on); st.give = on; st.code = on ? '741902' : ''; return st.code; };
  window.newCode = async () => { calls.push('new'); if (!st.give) throw 'give_off'; st.code = '333444'; return st.code; };` + "`" + `;` + cdpHead + `
  const fs = require('fs'), path = require('path');
  const shown = i => "(e => !!e && e.checkVisibility())(document.getElementById('" + i + "'))";
  const hgt = i => "Math.round(document.getElementById('" + i + "').getBoundingClientRect().height)";
  const meTxt = "document.getElementById('me').innerText";
  await call('Emulation.setDeviceMetricsOverride', { width: 1200, height: 760, deviceScaleFactor: 1, mobile: false });
  await call('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'light' }] });
  await sleep(1300);
  const shot = async n => { const d = process.env.ANYPC_SHOT; if (!d) return; const r = await call('Page.captureScreenshot', { format: 'png' }); fs.writeFileSync(path.join(d, n + '.png'), Buffer.from(r.result.data, 'base64')); console.log('shot ' + n); };
  const state = () => ev("[document.getElementById('giveon').checked, " + vis('codebox') + ", " + txt('mycode') + ", " + shown('giveoff') + ", " + meTxt + ".includes('Код на одно подключение'), calls.join(',')].join('|')");
  // по умолчанию — выкл: строки кода нет, подсказка что делать; настоящий checkbox role="switch", цель ≥ 44 px
  console.log('off=' + await state());
  console.log('sw=' + await ev("[document.getElementById('giveon').type, document.getElementById('giveon').getAttribute('role'), document.querySelector('#giverow span').textContent, " + txt('giveoff') + ", " + hgt('giverow') + " >= 44, " + hgt('giveon') + " >= 44, !document.getElementById('accrow'), " + meTxt + ".includes('Настроить')].join('|')"));
  await ev("st.code = '999888'; 1"); await sleep(1300); // хост прислал код при выкл (старый хост) — всё равно не показывать
  console.log('leak=' + await ev("[" + vis('codebox') + ", " + meTxt + ".includes('999')].join('|')"));
  await ev("st.code = ''; 1"); await sleep(1100);
  await shot('give-off');
  // вкл — строка кода, «Новый код», пояснение; подсказка «включите» скрыта
  await ev("document.getElementById('giveon').click(); 1"); await sleep(400);
  console.log('on=' + await state() + '|' + await ev("[" + txt('newcode') + ", " + meTxt + ".includes('Продиктуйте ID и код')].join('|')"));
  await shot('give-on');
  await ev("document.getElementById('newcode').click(); 1"); await sleep(400);
  console.log('new=' + await ev(txt('mycode') + " + '|' + calls.join(',')"));
  // экран «Доступ»: блок «По коду» — состояние переключателя
  await ev("document.getElementById('accgo').click(); 1"); await sleep(200);
  const accOn = await ev(txt('acccode'));
  await ev("document.getElementById('accback').click(); 1"); await sleep(200);
  // выкл — строки кода нет, код из разметки ушёл
  await ev("document.getElementById('giveon').click(); 1"); await sleep(400);
  console.log('off2=' + await state() + '|' + await ev("['333 444', '333444', '741 902', '741902'].some(c => document.documentElement.outerHTML.includes(c))")); // M7: и из разметки, не только из текста
  // M7: «Новый код» при выкл — отказ хоста словами, не «give_off»
  await ev("document.getElementById('newcode').click(); 1"); await sleep(300);
  console.log('err=' + await ev(txt('codemsg')));
  // M2: выкл во время сессии — своя строка: новые по коду закрыты, идущая сессия живёт
  await ev("st.session = 'c123456789012'; 1"); await sleep(1300);
  console.log('sess=' + await ev("[" + shown('givesess') + ", " + shown('giveoff') + ", " + txt('givesess') + ", " + shown('incoming') + ", document.getElementById('giveon').getAttribute('aria-describedby')].join('|')"));
  await ev("st.session = ''; 1"); await sleep(1300);
  await ev("document.getElementById('accgo').click(); 1"); await sleep(200);
  console.log('acc=' + accOn + '|' + await ev(txt('acccode')));
  await ev("document.getElementById('accback').click(); 1"); await sleep(200);
  // режим пароля (без вопросов, TOTP): кода нет вовсе — переключатель недоступен, сказано почему
  await ev("st.confirm = false; st.otp = true; 1"); await sleep(1300);
  console.log('pw=' + await ev("[document.getElementById('giveon').disabled, document.getElementById('giveon').checked, " + shown('givena') + ", " + shown('giveoff') + ", " + vis('codebox') + "].join('|')"));
  // M4: тур в режиме пароля — шаг «код» пропущен
  console.log('tour=' + await ev("TOURS.home.filter(x => tEls(x).length).map(x => x[1]).join(',')"));
  // M3: ПК пространства — честный текст без ссылки на неактивное «Спрашивать», и в блоке «По коду»
  await ev("st.space.in = true; 1"); await sleep(1300);
  console.log('na=' + await ev(txt('givena') + " + '|' + " + txt('acccodeb')));
  // M5: одна «Настроить» вне пространства
  await ev("st.space.in = false; 1"); await sleep(1300);
  console.log('one=' + await ev("[!document.getElementById('mnoneb'), [...document.querySelectorAll('#spmain button')].filter(b => b.checkVisibility() && b.textContent === 'Настроить').length].join('|')"));
  // «Настроить» в заголовке «Моё пространство» — во всех состояниях блока; открывает «Доступ к этому ПК»
  const states = { out: {}, in: { in: true }, wait: { in: true, wait: '444555666' }, damaged: { in: true, damaged: true }, comp: { in: true, compromised: true } };
  const res = [];
  for (const [k, v] of Object.entries(states)) {
    await ev("Object.assign(st.space, { in: false, wait: '', damaged: false, compromised: false }, " + JSON.stringify(v) + "); 1"); await sleep(1300);
    const vis1 = await ev("[" + shown('accgo') + ", " + hgt('accgo') + " >= 44, document.getElementById('accgo').closest('#mhead') !== null].join(',')");
    await ev("document.getElementById('accgo').click(); 1"); await sleep(200);
    res.push(k + ':' + vis1 + ',' + await ev(shown('access') + " + ',' + document.querySelector('#acchead h2').textContent"));
    await ev("document.getElementById('accback').click(); 1"); await sleep(200);
  }
  console.log('setup=' + res.join(';'));
  // второй путь — ⚙ «Настройки» → «Доступ к этому ПК»
  await ev("document.getElementById('setgo').click(); 1"); await sleep(200);
  await ev("document.getElementById('setacc').click(); 1"); await sleep(200);
  console.log('gear=' + await ev("[" + shown('access') + ", " + shown('settings') + ", " + txt('setacc') + "].join('|')"));
  process.exit(0);
})();`

// TestBrowserGive — переключатель «Разрешить управление» и «Настроить» в «Моё пространство».
func TestBrowserGive(t *testing.T) {
	chrome := browserNeed(t, "node")
	hang := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(http.ResponseWriter, *http.Request) { <-hang })
	mux.Handle("/", http.FileServer(http.FS(ui.FS)))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	defer close(hang)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out := string(runCDP(t, ctx, chrome, cdpGive, srv.URL+"/"))
	for _, want := range []string{
		"off=false|false||true|false|\n",
		"sw=checkbox|switch|Разрешить управление|Включите, чтобы вам помогли: появится код, который нужно продиктовать.|true|true|true|false\n",
		"leak=false|false\n",
		"on=true|true|741 902|false|true|give:true|Новый код|true\n",
		"new=333 444|give:true,new\n",
		"off2=false|false||true|false|give:true,new,give:false|false\n",
		"err=Код не выдан: включите «Разрешить управление». Если переключатель неактивен, этот ПК сейчас не принимает вход по коду.\n",
		"sess=true|false|Новые подключения по коду выключены. Идущий сеанс продолжается — завершить: «Разорвать».|true|givesess\n",
		"tour=tour_id,tour_pw,tour_add,tour_talk,tour_help\n",
		"na=На ПК вашего пространства разовая помощь по коду пока недоступна. Можно самому подключиться к помощнику через «+» сверху или получить помощь на ПК вне пространства.|На ПК вашего пространства разовая помощь по коду пока недоступна: вход сюда — паролем и кодом из приложения.\n",
		"one=true|1\n",
		"acc=включено|выключено\n",
		"pw=true|false|true|false|false\n",
		"setup=out:true,true,true,true,Доступ к этому ПК;in:true,true,true,true,Доступ к этому ПК;wait:true,true,true,true,Доступ к этому ПК;damaged:true,true,true,true,Доступ к этому ПК;comp:true,true,true,true,Доступ к этому ПК\n",
		"gear=true|false|Настроить\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if t.Failed() {
		t.Log(out)
	}
}
