#!/usr/bin/env python3
"""PRIVACY.md → site/privacy.html (страница /privacy.html на лендинге). Один источник текста — PRIVACY.md.
Разметка: # ## заголовки, абзацы, списки «- », **жирный**, `код`, ---, ссылки https://… Запуск: python3 site/privacy.py"""
import html, pathlib, re

D = pathlib.Path(__file__).parent
md = (D.parent / 'PRIVACY.md').read_text()

def inline(s):
    s = html.escape(s, quote=False)
    s = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', s)
    s = re.sub(r'`(.+?)`', r'<code>\1</code>', s)
    return re.sub(r'(https://[^\s<),]+[^\s<),.])', r'<a href="\1">\1</a>', s)

out, lst = [], False
for line in md.split('\n'):
    if lst and not line.startswith('- '):
        out.append('</ul>'); lst = False
    if line.startswith('## '): out.append(f'<h2>{inline(line[3:])}</h2>')
    elif line.startswith('# '): out.append(f'<h1>{inline(line[2:])}</h1>')
    elif line.startswith('- '):
        if not lst: out.append('<ul>'); lst = True
        out.append(f'<li>{inline(line[2:])}</li>')
    elif line.strip() == '---': out.append('<hr>')
    elif line.strip(): out.append(f'<p>{inline(line)}</p>')
if lst: out.append('</ul>')

page = '''<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>AnyPC — Privacy</title>
<!-- создано site/privacy.py из PRIVACY.md — правьте PRIVACY.md -->
<style>
  :root { --bg: #fbfaf8; --fg: #1a1a1a; --mut: #666; --line: #e5e2dc; --acc: #c0392b; }
  @media (prefers-color-scheme: dark) { :root { --bg: #141414; --fg: #eee; --mut: #9a9a9a; --line: #2c2c2c; --acc: #e57368; } }
  body { margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.6 system-ui, sans-serif; }
  main { max-width: 760px; margin: 0 auto; padding: 24px 16px 64px; }
  h1 { font-size: 28px; line-height: 1.2; margin: 32px 0 8px; } h2 { font-size: 20px; margin: 28px 0 8px; }
  a { color: var(--acc); overflow-wrap: anywhere; } code { font: 14px ui-monospace, monospace; overflow-wrap: anywhere; }
  hr { border: 0; border-top: 1px solid var(--line); margin: 48px 0; } ul { padding-left: 22px; }
  .home { color: var(--mut); text-decoration: none; font-weight: 600; }
</style>
</head>
<body><main>
<a class="home" href="/">← AnyPC</a>
''' + '\n'.join(out) + '\n</main></body>\n</html>\n'
(D / 'privacy.html').write_text(page)
print('site/privacy.html:', len(out), 'блоков')
