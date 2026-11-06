#!/usr/bin/env python3
"""texts.<lang>.md → словарь T в index.html (строки вида - `ключ`: текст).
Языки без md-файла остаются как есть; недостающий ключ на странице берётся из en.
Проверка: каждый data-t страницы есть в texts.ru.md (оригинал) — иначе ошибка.
Запуск: python3 site/texts.py"""
import json, pathlib, re, sys

D = pathlib.Path(__file__).parent
NAMES = {'en': 'English', 'ru': 'Русский', 'zh': '中文', 'es': 'Español', 'de': 'Deutsch', 'fr': 'Français', 'it': 'Italiano'}
page = (D / 'index.html').read_text()

def load(lang):
    t = dict(re.findall(r'^- `(\w+)`: (.+)$', (D / f'texts.{lang}.md').read_text(), re.M))
    return {'_': NAMES[lang], **t}

ru = load('ru')
missing = set(re.findall(r'data-t="(\w+)"', page)) - ru.keys()
if missing:
    sys.exit(f'нет в texts.ru.md: {sorted(missing)}')

for f in sorted(D.glob('texts.*.md')):
    lang = f.name.split('.')[1]
    line = f'  {lang}: {json.dumps(load(lang), ensure_ascii=False)},\n'
    page, n = re.subn(rf'^  {lang}: \{{.*?\n(?=  \w\w: \{{|\}};)', lambda _: line, page, count=1, flags=re.M | re.S)
    if n != 1:
        sys.exit(f'{lang}: нет блока в const T')
    print(lang, len(load(lang)) - 1, 'текстов')
(D / 'index.html').write_text(page)
