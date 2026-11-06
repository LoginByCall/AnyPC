// Проверка словарей: синтаксис, одинаковые ключи во всех языках, все data-t определены.
const fs = require('fs');
for (const [file, start, end] of [['site/index.html', 'const T = {', '};\nconst MB'], ['ui/index.html', 'const L = {', '};\nconst lang']]) {
  const html = fs.readFileSync(file, 'utf8');
  const js = html.slice(html.indexOf('<script>') + 8, html.lastIndexOf('</script>'));
  new Function(js); // синтаксис
  const D = eval('(' + html.slice(html.indexOf(start) + start.length - 1, html.indexOf(end) + 1) + ')');
  const en = Object.keys(D.en);
  for (const k in D) { const miss = en.filter(x => !(x in D[k])); if (miss.length) throw new Error(`${file} ${k}: нет ${miss}`); }
  const used = [...html.matchAll(/data-t[pt]?="(\w+)"/g)].map(m => m[1]).filter(k => !en.includes(k));
  if (used.length) throw new Error(`${file}: не определены ${used}`);
  console.log(`${file}: ${Object.keys(D).join(',')} — ${en.length} ключей OK`);
}
