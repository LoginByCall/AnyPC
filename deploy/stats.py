#!/usr/bin/env python3
"""Суточная статистика хабов (MONITORING.md): stats.jsonl + stats-today.json с каждого хаба по ssh (только чтение).
   deploy/stats.py [дней=14]        хабы — ANYPC_HUBS (по умолчанию HK и RU)
Хосты держат соединение со всеми хабами сразу: «хостов» у HK и RU — одни и те же компьютеры, не складывать."""
import json, os, subprocess, sys

HUBS = os.environ.get('ANYPC_HUBS', 'hk=root@170.168.24.45 ru=root@170.168.5.86').split()
DAYS = int(sys.argv[1]) if len(sys.argv) > 1 else 14
COLS = [('хостов', lambda d: d['hosts']), ('макс', lambda d: d['hosts_max']), ('новых', lambda d: n(d, 'new_id')),
        ('connect', lambda d: n(d, 'connect')), ('offer', lambda d: n(d, 'offer')), ('answer', lambda d: n(d, 'answer')),
        ('прил.', lambda d: n(d, 'client_app')), ('брауз.', lambda d: n(d, 'client_web')),
        ('лендинг', lambda d: n(d, 'page_www')), ('загрузок', lambda d: sum(v for k, v in d['n'].items() if k.startswith('dl/AnyPC'))),
        ('отказов', lambda d: n(d, 'refused'))]


def n(d, k):
    return d['n'].get(k, 0)


def days(target):
    out = subprocess.run(['ssh', '-o', 'BatchMode=yes', target,
                          'cat /var/lib/anypc/stats.jsonl; echo; cat /var/lib/anypc/stats-today.json'],
                         capture_output=True, text=True, timeout=60).stdout
    return [json.loads(l) for l in out.splitlines() if l.strip()]


for hub in HUBS:
    name, target = hub.split('=', 1)
    ds = days(target)[-DAYS:]
    print(f'\n== {name} ({len(ds)} сут., последние — текущие; ≈ — узел перезапускался, «хостов» завышено)')
    print('сутки       ' + ' '.join(f'{c:>8}' for c, _ in COLS))
    for d in ds:
        print(d['day'] + ('≈' if d.get('restarted') else ' ') + ' ' + ' '.join(f'{f(d):>8}' for _, f in COLS))
    if ds:
        last = ds[-2] if len(ds) > 1 else ds[-1]  # последние полные сутки
        print('ОС и версии за', last['day'] + ':', ', '.join(f'{k} — {v}' for k, v in sorted(last['os'].items(), key=lambda x: -x[1])) or '—')
        dl = {k[3:]: v for k, v in last['n'].items() if k.startswith('dl/')}
        print('загрузки:', ', '.join(f'{k} — {v}' for k, v in sorted(dl.items(), key=lambda x: -x[1])) or '—')
