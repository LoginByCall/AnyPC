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
  window.quit = () => calls.push('quit');` + "`" + `;` + cdpHead + `
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
  // узкое окно: плиток в ряд меньше трёх, колонка «Передать управление» под ними
  await ev("document.getElementById('tabhome').click(); 1");
  await call('Emulation.setDeviceMetricsOverride', { width: 640, height: 900, deviceScaleFactor: 1, mobile: false }); await sleep(300);
  console.log('narrow=' + await ev("(() => { const t = [...document.querySelectorAll('#sptiles .sptile')].map(d => d.getBoundingClientRect().top); const s = document.getElementById('side').getBoundingClientRect(), m = document.getElementById('spmain').getBoundingClientRect(); return (new Set(t).size > 1) + ',' + (s.top >= m.bottom) + ',' + (document.documentElement.scrollWidth <= 640); })()"));
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
