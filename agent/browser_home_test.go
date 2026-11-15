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

// cdpHome — главный экран по макету (Main.dc.html, v0.3.1) с подменёнными привязками, окно по-русски: один список своих
// ПК (члены пространства с пропуском и без, бывший «Мой ПК» — плитка «по паролю» с «Открыть» и «···»); отдельной
// карточки «Мои ПК» нет; справа «Передать управление» без узла, отпечатка и «Выйти» — они в «Настройках» (⚙);
// «+» — экран «Другой ПК» с формой входа, «Назад» — обратно; плашка входящей сессии — на видимом экране.
// ANYPC_SHOT=<файл.png> — снимок главного экрана 1200×760 в светлой теме (сверка с макетом).
const cdpHome = `
const extra = async () => ` + "`" + `
  Object.defineProperty(navigator, 'languages', { get: () => ['ru'] });
  Object.assign(st, { confirm: true, code: '741902', online: true, version: '0.3.1', fp: 'ab12 cd34', users: [{ name: 'anna', view: true, otp: true }] });
  st.space.members.push({ id: '482113907', fp: 'OF', pub: 'b2Y=', self: false, passUntil: Date.now() + 3 * 3600e3 },
    { id: '730554218', fp: 'HO', pub: 'aG8=', self: false, passUntil: 0 });
  st.space.members[0].passUntil = Date.now() + 3600e3;
  localStorage.setItem('mine', JSON.stringify([{ id: '482113907', name: 'Офис' }, { id: '730554218', name: 'Дом' }, { id: '915020664', name: 'Ноутбук мамы' }]));
  window.quit = () => calls.push('quit'); localStorage.setItem('tour_connect', '1');
  window.savedGet = async id => id === '111222333' ? 'pw1' : ''; window.savedSet = async () => {};
  localStorage.setItem('users', JSON.stringify({ '111222333': 'anna' }));` + "`" + `;` + cdpHead + `
  const fs = require('fs');
  const shown = i => "(e => !!e && e.checkVisibility())(document.getElementById('" + i + "'))";
  await call('Emulation.setDeviceMetricsOverride', { width: 1200, height: 760, deviceScaleFactor: 1, mobile: false });
  await call('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'light' }] });
  await sleep(1300);
  console.log('strip=' + await ev("[...document.querySelectorAll('#hometabs .tab')].map(b => b.textContent).join(';') + '|' + document.getElementById('hadd').getAttribute('aria-label')"));
  console.log('nomine=' + await ev("[!document.getElementById('mine'), !document.getElementById('minelist'), !document.body.innerText.includes('Мои ПК'), document.querySelectorAll('#sptiles .sptile').length].join(',')"));
  const own = "document.querySelector('#sptiles .sptile[data-id=\"915020664\"]')";
  console.log('own=' + await ev("[" + own + ".querySelector('.nm').textContent, " + own + ".querySelector('.sub').textContent, " + own + ".querySelector('.mpcopen').textContent, " + own + ".querySelector('.mpcmore').textContent, " + own + ".querySelector('.mpcmore').getAttribute('aria-label')].join('|')"));
  console.log('members=' + await ev("['482113907', '730554218'].map(i => { const d = document.querySelector('#sptiles .sptile[data-id=\"' + i + '\"]'); return d.querySelector('.sub').textContent + '/' + (d.querySelector('input')?.placeholder || d.querySelector('button').textContent); }).join('|')"));
  // три плитки в ряд на ширине макета; правая колонка узкая (~340 px); цели не меньше 44 px
  // плитки ряда одной высоты, ряды действий — по одной нижней линии (плитка «нужен код» не выше соседних)
  console.log('align=' + await ev("(() => { const t = [...document.querySelectorAll('#sptiles .sptile')]; return [new Set(t.map(d => Math.round(d.getBoundingClientRect().height))).size, new Set(t.map(d => Math.round(d.querySelector('.tact').getBoundingClientRect().bottom))).size].join(','); })()"));
  console.log('grid=' + await ev("(() => { const t = [...document.querySelectorAll('#sptiles .sptile')].map(d => d.getBoundingClientRect().top); return new Set(t).size + ',' + Math.round(document.getElementById('side').getBoundingClientRect().width); })()"));
  console.log('small=' + await ev("[...document.querySelectorAll('#home button, #home input')].filter(e => e.checkVisibility() && e.getBoundingClientRect().height < 44).map(e => e.id || e.className || e.textContent).join(',')"));
  // на главном — ID, код, «Доступ», «в сети»; узла, отпечатка, версии и «Выйти» нет — они в «Настройках»
  console.log('give=' + await ev("['myid', 'mycode', 'accgo', 'mystate', 'setgo'].map(i => document.getElementById(i).checkVisibility()).join(',') + '|' + ['myfp', 'myver', 'node', 'nodepub', 'quit', 'id', 'go'].map(i => document.getElementById(i).checkVisibility()).join(',')"));
  const shot = async n => { const f = process.env.ANYPC_SHOT; if (!f) return; const r = await call('Page.captureScreenshot', { format: 'png' }); fs.writeFileSync(n ? f.replace(/\.png$/, '-' + n + '.png') : f, Buffer.from(r.result.data, 'base64')); console.log('shot ' + (n || 'main')); };
  await shot('');
  // «+» — экран «Другой ПК»: форма, фокус в ID, прочие галочки свёрнуты в «Параметры»; «Назад» — на главный
  await ev("document.getElementById('hadd').click(); 1"); await sleep(200);
  console.log('connect=' + await ev("[" + shown('connect') + ", " + shown('home') + ", document.activeElement.id, " + shown('go') + ", " + shown('pw') + ", document.getElementById('copts').open, " + shown('turbo') + ", document.querySelector('#connhead h2').textContent].join('|')"));
  await shot('connect');
  await ev("document.getElementById('connback').click(); 1"); await sleep(200);
  console.log('connback=' + await ev("[" + shown('connect') + ", " + shown('home') + "].join('|')"));
  // ⚙ — «Настройки»: узел, отпечаток, версия, «Выйти»; «Назад» — на главный
  await ev("document.getElementById('setgo').click(); 1"); await sleep(200);
  console.log('settings=' + await ev("[" + shown('settings') + ", " + shown('home') + ", " + shown('node') + ", " + shown('nodepub') + ", " + shown('myfp') + ", " + txt('myfp') + ", " + txt('myver') + ", " + shown('quit') + ", document.querySelector('#sethead h2').textContent].join('|')"));
  await shot('settings');
  await ev("document.getElementById('setgo').click(); 1"); await sleep(200);
  // входящая сессия: плашка на видимом экране («Настройки»), после «Назад» — в «Передать управление»
  await ev("st.session = '111222333'; 1"); await sleep(1300);
  const inc = () => ev("[" + shown('incoming') + ", ['me', 'settings'].find(i => document.getElementById(i).contains(document.getElementById('incoming')))].join('|')");
  const inc1 = await inc(); await ev("document.getElementById('setback').click(); 1"); await sleep(200);
  console.log('incoming=' + inc1 + '/' + await inc());
  await ev("st.session = ''; 1");
  // «···» бывшего «Моего ПК»: меню, «Переименовать» на месте — имя в плитке и в полосе
  await ev(own + ".querySelector('.mpcmore').click(); 1");
  const menu = await ev("[!" + own + ".querySelector('.tmenu').classList.contains('hidden'), " + own + ".querySelector('.mpcmore').getAttribute('aria-expanded'), [..." + own + ".querySelectorAll('.tmenu button')].map(b => b.textContent).join('/')].join('|')");
  await ev(own + ".querySelector('.mpcren').click(); const i = document.querySelector('#sptiles input.nmedit'); i.value = 'Мамин'; i.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true })); 1"); await sleep(300);
  console.log('menu=' + menu + '|' + await ev("JSON.parse(localStorage.getItem('mine'))[2].name + '|' + " + own + ".querySelector('.nm').textContent + '|' + [...document.querySelectorAll('#hometabs .tab')].some(b => b.textContent.startsWith('Мамин'))"));
  // «Открыть» на плитке бывшего «Моего ПК» — вкладка «Моих ПК» к нему
  await ev(own + ".querySelector('.mpcopen').click(); 1"); await sleep(300);
  console.log('open=' + await ev("[...document.querySelectorAll('#frames iframe')].map(f => new URL(f.src).searchParams.get('embed')).join(',') + '|' + " + shown('home')));
  // вкладка к ПК «по паролю» без запомненного пароля и ключа: во фрейме карточка входа — пароль есть куда ввести
  const fr = "document.querySelector('#frames iframe').contentWindow.document";
  for (let k = 0; k < 50 && await ev(fr + "?.body?.classList.contains('needpw')") !== true; k++) await sleep(100);
  console.log('framepw=' + await ev("(() => { const d = " + fr + "; return [d.body.classList.contains('needpw'), ...['connect', 'remote', 'pw', 'go'].map(i => d.getElementById(i).checkVisibility()), ...['home', 'connhead'].map(i => d.getElementById(i).checkVisibility()), [...document.querySelectorAll('#tabs .tabg .stt')].map(e => e.textContent).join(',')] /* Ч8: в полосе и закрытые ПК — метка открытой вкладки */.join('|'); })()"));
  await shot('frame-nopw');
  // myPcHome (трей): из вкладки ПК — на главный, вкладка жива
  console.log('pchome=' + await ev("[myPcHome(), " + shown('home') + ", " + shown('mypc') + ", document.querySelectorAll('#frames iframe').length].join('|')"));
  await ev("myPcAdd('915020664'); 1"); await sleep(200);
  // узкое окно: плиток в ряд меньше трёх, колонка «Передать управление» под ними
  await ev("document.getElementById('tabhome').click(); 1");
  // N1: в плитке «нужен код» 6 цифр видны целиком при 1100 и 900 px; «···» — в строке имени, в ряду — поле и «Войти»
  const fit = async w => { await call('Emulation.setDeviceMetricsOverride', { width: w, height: 760, deviceScaleFactor: 1, mobile: false }); await sleep(300);
    return ev("(d => { const i = d.querySelector('input'); i.value = '123456'; const r = [i.scrollWidth <= i.clientWidth, [...d.querySelectorAll('.tact > *')].map(e => e.tagName + (e.className ? '.' + e.className : '')).join('+'), !!d.querySelector('.hd .mpcmore')].join(','); i.value = ''; return r; })(document.querySelector('#sptiles .sptile[data-id=\"730554218\"]'))"); };
  const f1100 = await fit(1100); await shot('1100');
  console.log('codefit=' + f1100 + '|' + await fit(900));
  // «···» в строке имени: меню открывается вниз от неё и помещается в плитке по ширине
  await ev("document.querySelector('#sptiles .sptile[data-id=\"730554218\"] .hd .mpcmore').click(); 1");
  console.log('hdmenu=' + await ev("(d => { const b = d.querySelector('.hd .mpcmore').getBoundingClientRect(), m = d.querySelector('.tmenu').getBoundingClientRect(); return [m.top >= b.bottom, m.right <= d.getBoundingClientRect().right + 1].join(','); })(document.querySelector('#sptiles .sptile[data-id=\"730554218\"]'))"));
  await ev("document.body.click(); 1");
  await call('Emulation.setDeviceMetricsOverride', { width: 640, height: 900, deviceScaleFactor: 1, mobile: false }); await sleep(300);
  console.log('narrow=' + await ev("(() => { const t = [...document.querySelectorAll('#sptiles .sptile')].map(d => d.getBoundingClientRect().top); const s = document.getElementById('side').getBoundingClientRect(), m = document.getElementById('spmain').getBoundingClientRect(); return (new Set(t).size > 1) + ',' + (s.top >= m.bottom) + ',' + (document.documentElement.scrollWidth <= 640); })()"));
  await call('Emulation.setDeviceMetricsOverride', { width: 1200, height: 760, deviceScaleFactor: 1, mobile: false }); await sleep(300);
  // «···» у членов пространства — только «Переименовать» («Убрать» члена — исключение на «Доступе»); член без записи в mine получает имя
  const mt = i => "document.querySelector('#sptiles .sptile[data-id=\"" + i + "\"]')";
  const memMenu = await ev("[" + mt('482113907') + ".querySelector('.mpcmore').getAttribute('aria-label'), [..." + mt('482113907') + ".querySelectorAll('.tmenu button')].map(b => b.textContent).join('/'), " + mt('482113907') + ".querySelector('button').className].join('|')");
  await ev("localStorage.setItem('mine', JSON.stringify(JSON.parse(localStorage.getItem('mine')).filter(p => p.id !== '730554218'))); myPcRender(); 1"); await sleep(200);
  await ev(mt('730554218') + ".querySelector('.mpcmore').click(); " + mt('730554218') + ".querySelector('.mpcren').click(); { const n = document.querySelector('#sptiles input.nmedit'); n.value = 'Дача'; n.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true })); } 1"); await sleep(300);
  console.log('memmenu=' + memMenu + '|' + await ev("JSON.stringify(JSON.parse(localStorage.getItem('mine')).find(p => p.id === '730554218')) + '|' + " + mt('730554218') + ".querySelector('.nm').textContent"));
  // ★ в сессии: член пространства — уже свой (★, снять нельзя); ПК из mine — ★ (переключатель); чужой — ☆
  console.log('star=' + await ev("['482113907', '915020664', '123123123'].map(h => { host = h; starShow(); const b = document.getElementById('starbtn'); return b.textContent + ':' + b.disabled; }).join('|')"));
  await ev("host = ''; 1");
  // набранный код в плитке без фокуса переживает перерисовку; с фокусом плитка не перерисовывается до ухода фокуса
  const ci = mt('730554218') + ".querySelector('input')";
  await ev("window.t0 = " + mt('730554218') + "; " + ci + ".value = '135'; localStorage.setItem('mine', JSON.stringify([...JSON.parse(localStorage.getItem('mine')), { id: '555666777', name: 'X' }])); myPcRender(); 1"); await sleep(100);
  const kept = await ev("[t0 !== " + mt('730554218') + ", " + ci + ".value].join('|')");
  await ev("window.t1 = " + mt('730554218') + "; " + ci + ".focus(); " + ci + ".value = '2468'; localStorage.setItem('mine', JSON.stringify(JSON.parse(localStorage.getItem('mine')).filter(p => p.id !== '555666777'))); myPcRender(); 1"); await sleep(1300);
  const foc = await ev("[t1 === " + mt('730554218') + ", document.activeElement === " + ci + ", " + ci + ".value, !!" + mt('555666777') + "].join('|')");
  await ev("document.activeElement.blur(); 1"); await sleep(1000);
  console.log('typed=' + kept + '/' + foc + '/' + await ev("[t1 !== " + mt('730554218') + ", " + ci + ".value, !!" + mt('555666777') + "].join('|')"));
  // начатое переименование не сбрасывается опросом (пропуск Офиса истёк — плиткам нужна перерисовка)
  await ev(own + ".querySelector('.mpcmore').click(); " + own + ".querySelector('.mpcren').click(); document.querySelector('#sptiles input.nmedit').value = 'Набор'; st.space.members[1].passUntil = 0; 1"); await sleep(1300);
  const rn = await ev("(i => [!!i && i.isConnected, document.activeElement === i, i?.value].join('|'))(document.querySelector('#sptiles input.nmedit'))");
  await ev("document.querySelector('#sptiles input.nmedit').dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })); 1"); await sleep(1300);
  console.log('renpoll=' + rn + '|' + await ev(mt('482113907') + ".querySelector('.tag').textContent + '|' + " + own + ".querySelector('.nm').textContent"));
  // «Разорвать» — красный (--bad), не синий акцент; «Подключиться» — синий
  console.log('colors=' + await ev("['bye', 'hostbye', 'go'].map(i => getComputedStyle(document.getElementById(i)).backgroundColor).join('|') + '|' + getComputedStyle(document.getElementById('msg')).color"));
  // тур не ссылается на скрытые/несуществующие элементы: главный — без формы (она на «Другом ПК»), «Другой ПК» — форма и «Параметры»
  const tl = k => ev("TOURS." + k + ".filter(s => tEls(s).length).map(s => s[1]).join(',')");
  const tHome = await tl('home'), tAll = await ev("Object.values(TOURS).flat().flatMap(s => s[0]).filter(i => !document.getElementById(i)).join(',')");
  await ev("startTour('home', true); 1"); await sleep(200);
  const tOn = await ev(shown('tour') + " + ':' + tour?.kind");
  await ev("document.getElementById('hadd').click(); 1"); await sleep(500);
  const tConn = await tl('connect'), tOff = await ev(shown('tour'));
  // конец сессии, начатой с «Другого ПК», — снова «Другой ПК» (там причина разрыва), не главный
  await ev("show(true); show(false); document.getElementById('msg').textContent = 'reason'; 1");
  console.log('tour=' + tHome + '|' + tAll + '|' + tOn + '|' + tConn + '|' + tOff + '|end=' + await ev("[" + shown('connect') + ", " + shown('home') + ", " + shown('msg') + "].join(',')"));
  // рамка шага «Параметры» — по строке summary, не по всему <details>; «Показать подсказки снова» сбрасывает и тур «Другого ПК»
  const tOpt = await ev("tEls(TOURS.connect[1]).map(e => e.tagName + '#' + e.id).join(',')");
  await ev("document.getElementById('helpbtn').click(); 1"); await sleep(200);
  await ev("[...document.querySelectorAll('#helpbody button')].find(b => b.textContent === t('help_tour')).click(); 1"); await sleep(300);
  console.log('tour2=' + tOpt + '|' + await ev("[localStorage.getItem('tour_connect'), localStorage.getItem('tour_home'), tour?.kind].join('|')"));
  await ev("tourEnd(); 1");
  // имя записи из запомненного входа не прячется в свёрнутых «Параметрах»
  await ev("{ const d = document.getElementById('id'); d.value = '111222333'; d.dispatchEvent(new Event('input')); } 1"); await sleep(400);
  console.log('user=' + await ev("[document.getElementById('copts').open, " + shown('user') + ", document.getElementById('user').value].join('|')"));
  // myPcHome: с «Другого ПК» и из «Настроек» — на главный
  const h1 = await ev("myPcHome() + ':' + " + shown('home') + " + ':' + " + shown('connect'));
  await ev("document.getElementById('setgo').click(); 1");
  console.log('myPcHome=' + h1 + '|' + await ev("myPcHome() + ':' + " + shown('home') + " + ':' + " + shown('settings')) + '|' + await ev("typeof myPcAdd + ',' + !!document.getElementById('shpw')"));
  // «Показать подсказки снова» с главного: сброшен и тур «Другого ПК» (начнётся при входе на него), идёт тур главного
  await ev("localStorage.setItem('tour_connect', '1'); document.getElementById('helpbtn').click(); 1"); await sleep(200);
  await ev("[...document.querySelectorAll('#helpbody button')].find(b => b.textContent === t('help_tour')).click(); 1"); await sleep(300);
  const again = await ev("[localStorage.getItem('tour_connect'), localStorage.getItem('tour_home'), tour?.kind].join('|')");
  await ev("tourEnd(); document.getElementById('hadd').click(); 1"); await sleep(600);
  console.log('tour3=' + again + '|' + await ev("[tour?.kind, localStorage.getItem('tour_connect')].join('|')"));
  await ev("tourEnd(); document.getElementById('connback').click(); 1");
  await ev("document.getElementById('quit').click(); 1");
  console.log('quit=' + await ev("calls.join(',')"));
  process.exit(0);
})();`

// TestBrowserHome — главный экран v0.3.1 по макету: один список своих ПК, «+» → «Другой ПК», ⚙ → «Настройки».
func TestBrowserHome(t *testing.T) {
	chrome := browserNeed(t, "node")
	hang := make(chan struct{}) // хаб не отвечает: вкладка «Открыть» ждёт хост, не падая в «разорвано»
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(http.ResponseWriter, *http.Request) { <-hang })
	mux.Handle("/", http.FileServer(http.FS(ui.FS)))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	defer close(hang)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out := string(runCDP(t, ctx, chrome, cdpHome, srv.URL+"/"))
	for _, want := range []string{
		"|Подключиться к другому ПК\n",
		"nomine=true,true,true,3\n", // карточки «Мои ПК» нет, все три своих ПК — плитки одного списка
		"own=Ноутбук мамы|по паролю · 915 020 664|Открыть|···|Переименовать или убрать: Ноутбук мамы\n",
		"members=вход без пароля · 482 113 907/Открыть|вход без пароля · 730 554 218/Код из приложения\n",
		"grid=1,340\n",
		"small=\n",
		"give=true,true,true,true,true|false,false,false,false,false,false,false\n",
		"connect=true|false|id|true|true|false|false|Другой ПК\n",
		"connback=false|true\n",
		"settings=true|false|true|true|true|ab12 cd34|AnyPC 0.3.1|true|Настройки\n",
		"quit=quit\n",
		"framepw=true|true|true|true|true|false|false|нужен пароль\n", // B1: во фрейме без пароля — карточка входа, без главного и «Назад»
		"pchome=true|true|false|1\n",
		"memmenu=Переименовать: Офис|Переименовать|main|{\"id\":\"730554218\",\"name\":\"Дача\"}|Дача\n",
		"star=★ В моём пространстве:true|★ В моём пространстве:false|☆ В моё пространство:false\n",
		"typed=true|135/true|true|2468|true/true|2468|false\n",
		"renpoll=true|true|Набор|нужен код|Мамин\n",
		"colors=rgb(180, 35, 24)|rgb(180, 35, 24)|rgb(29, 78, 216)|rgb(180, 35, 24)\n",
		"tour=tour_id,tour_code,tour_pw,tour_add,tour_talk,tour_help||true:home|tour_go,tour_opts|false|end=true,false,true\n",
		"user=true|true|anna\n",
		"codefit=true,INPUT+BUTTON.main,true|true,INPUT+BUTTON.main,true\n", // N1
		"hdmenu=true,true\n",
		"align=1,1\n",
		"tour3=0|1|home|connect|1\n",          // сброс с главного: tour_connect=0; вход на «Другой ПК» начал его тур
		"tour2=SUMMARY#coptsum|1|0|connect\n", // на «Другом ПК»: сброшены все, начат тур «Другого ПК»
		"myPcHome=true:true:false|true:true:false|function,true\n",
		"incoming=true|settings/true|me\n",
		"menu=true|true|Переименовать/Убрать из «Моего пространства»|Мамин|Мамин|true\n",
		"open=915020664|false\n",
		"narrow=true,true,true\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
	if !strings.Contains(out, "strip=Этот ПКя тут;Офисбез пароля до ") || !strings.Contains(out, ";Домнужен код;Ноутбук мамыпо паролю;+|") {
		t.Error("полоса ПК не та")
	}
}
