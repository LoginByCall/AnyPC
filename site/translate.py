#!/usr/bin/env python3
"""texts.ru.md → texts.<lang>.md через DeepL (ключ в DEEPL_KEY; ключ API Free кончается на ":fx").
Надписи программы и Windows в «ёлочках» машина не переводит: подставляются точные строки из
ui/index.html, agent/input.go и локализации Windows, иначе на сайте будет не то, что человек видит на экране.
Запуск: DEEPL_KEY=... python3 site/translate.py [en zh ...]   затем   python3 site/texts.py
Проверка без ключа: python3 site/translate.py --dry  (подстановка надписей, без перевода)"""
import html, json, os, pathlib, re, sys, urllib.parse, urllib.request

D = pathlib.Path(__file__).parent
R = D.parent
LANGS = {'en': 'EN-US', 'zh': 'ZH-HANS', 'es': 'ES', 'de': 'DE', 'fr': 'FR', 'it': 'IT'}
FORMAL = {'de': 'prefer_more', 'fr': 'prefer_more', 'es': 'prefer_less', 'it': 'prefer_less'}  # как в программе: Sie/vous, tú/tu
QUOTE = {'en': '“{}”', 'zh': '“{}”', 'es': '«{}»', 'de': '„{}“', 'fr': '« {} »', 'it': '«{}»'}
# SmartScreen — официальные строки Windows по памяти; сверить на экране локализованной Windows.
WIN = {
    'Система Windows защитила ваш компьютер': {'en': 'Windows protected your PC', 'zh': 'Windows 已保护你的电脑', 'es': 'Windows protegió su PC',
                                              'de': 'Der Computer wurde durch Windows geschützt', 'fr': 'Windows a protégé votre ordinateur', 'it': 'PC protetto da Windows'},
    'Подробнее': {'en': 'More info', 'zh': '更多信息', 'es': 'Más información', 'de': 'Weitere Informationen', 'fr': 'Informations complémentaires', 'it': 'Ulteriori informazioni'},
    'Выполнить в любом случае': {'en': 'Run anyway', 'zh': '仍要运行', 'es': 'Ejecutar de todas formas', 'de': 'Trotzdem ausführen', 'fr': 'Exécuter quand même', 'it': 'Esegui comunque'},
}

UI = (R / 'ui/index.html').read_text()
GO = (R / 'agent/input.go').read_text()

def ui(lang, key):  # строка окна программы
    block = re.search(rf'^  {lang}: \{{(.*?)(?=^  \w\w: \{{|^\}};)', UI, re.M | re.S).group(1)
    return re.search(rf"\b{key}: '([^']*)'", block).group(1)

def ask(lang):  # «Разрешить», «Отклонить» окна подтверждения на хосте
    return re.search(rf'"{lang}": \{{"[^"]*", "[^"]*", "[^"]*", "([^"]*)", "([^"]*)"\}}', GO).groups()

def terms(lang):
    t = {ui('ru', k): ui(lang, k) for k in ('go', 'me_h', 'quit')}
    (ra, rd), (a, d) = ask('ru'), ask(lang)
    t[ra], t[f'{ra} / {rd}'] = a, f'{a} / {d}'
    t.update({ru: v[lang] for ru, v in WIN.items()})
    return t

def deepl(texts, lang):
    key = os.environ['DEEPL_KEY']
    host = 'api-free.deepl.com' if key.endswith(':fx') else 'api.deepl.com'
    out = []
    for i in range(0, len(texts), 50):  # предел DeepL — 50 текстов на запрос
        data = [('text', x) for x in texts[i:i + 50]] + [('source_lang', 'RU'), ('target_lang', LANGS[lang]),
                ('tag_handling', 'xml'), ('ignore_tags', 'x'), ('preserve_formatting', '1')]
        if lang in FORMAL:
            data.append(('formality', FORMAL[lang]))
        req = urllib.request.Request(f'https://{host}/v2/translate', urllib.parse.urlencode(data).encode(),
                                     {'Authorization': 'DeepL-Auth-Key ' + key})
        out += [x['text'] for x in json.load(urllib.request.urlopen(req, timeout=60))['translations']]
    return out

dry = '--dry' in sys.argv
langs = [a for a in sys.argv[1:] if a in LANGS] or list(LANGS)
src = dict(re.findall(r'^- `(\w+)`: (.+)$', (D / 'texts.ru.md').read_text(), re.M))
for lang in langs:
    T, unknown = terms(lang), set()
    def mask(m):
        if m.group(1) in T:
            return f'<x>{html.escape(T[m.group(1)])}</x>'
        unknown.add(m.group(1))
        return m.group(0)
    masked = [re.sub(r'«([^»]+)»', mask, html.escape(v, quote=False)) for v in src.values()]
    res = masked if dry else deepl(masked, lang)
    res = [html.unescape(re.sub(r'<x>(.*?)</x>', lambda m: QUOTE[lang].format(m.group(1)), r)) for r in res]
    bad = [k for k, r in zip(src, res) if not r.strip() or '<x' in r]
    if bad:
        sys.exit(f'{lang}: пустые или с метками: {bad}')
    if unknown:
        print(f'{lang}: переведены машиной (не надписи программы): {sorted(unknown)}')
    if dry:
        print(lang, '|', res[list(src).index('s3')])
        continue
    body = '\n'.join(f'- `{k}`: {r}' for k, r in zip(src, res))
    (D / f'texts.{lang}.md').write_text(f'# Тексты лендинга — {lang}: DeepL из texts.ru.md; правьте texts.ru.md и перегенерируйте\n\n{body}\n')
    print(lang, len(res), 'текстов')
