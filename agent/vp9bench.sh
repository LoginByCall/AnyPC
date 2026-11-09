#!/bin/bash
# Стенд кодера VP9 (FINDINGS.md «Видео: кодеки», LOGBOOK 2026-11-10): кодирует тестовую последовательность 1080p30
# (2 с текста → смена → 10 с другого текста) тем же кодом, что программа (TestVP9Bench), и печатает: ключевой и
# наибольший кадр, PSNR через 0,5/1/2/4/9 с после смены, время до 35/40 дБ, трафик статики за последние 3 с.
# Нужны: libvpx из deploy/libvpx.sh (linux-amd64), ffmpeg, python3, ~1,2 ГБ во временном каталоге.
# Запуск: agent/vp9bench.sh "kbps fps aq keyms cq cbr drop interms minq" … ; без аргументов — текущие настройки на 300/5, 1000/30, 4000/30.
set -eu
cd "$(dirname "$0")/.."
W=${VP9BENCH_DIR:-${TMPDIR:-/tmp}/anypc-vp9bench}; mkdir -p "$W"
L=$PWD/third_party/libvpx/linux-amd64
CGO_ENABLED=1 CGO_CFLAGS=-I$L/include CGO_LDFLAGS=-L$L/lib go test -c -tags vp9 -o "$W/vp9bench.test" ./agent
F=/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf
[ -f "$W/seq.y4m" ] || ffmpeg -y -hide_banner -loglevel error \
  -f lavfi -i "color=c=white:s=1920x1080:r=30:d=2,drawtext=fontfile=${F}:textfile=/etc/services:fontsize=13:fontcolor=black:x=10:y=50:line_spacing=2" \
  -f lavfi -i "color=c=0xf4f4f4:s=1920x1080:r=30:d=10,drawtext=fontfile=${F}:textfile=/etc/protocols:fontsize=15:fontcolor=0x202040:x=300:y=80:line_spacing=3" \
  -filter_complex "[0:v][1:v]concat=n=2:v=1,format=yuv420p" -f yuv4mpegpipe "$W/seq.y4m"
cd "$W"
run() { # kbps fps aq keyms cq cbr drop interms minq (пусто — значение из vp9Opt)
  local K=$1 FPS=$2 STEP=$((30 / $2)) N="r_$(echo "$*" | tr ' ' _)"
  ANYPC_VP9_Y4M=seq.y4m ANYPC_VP9_OUT=$N.ivf ANYPC_VP9_RUN="$(echo "$*" | tr ' ' ,)" ./vp9bench.test -test.run '^TestVP9Bench$' -test.count=1 >/dev/null
  ffmpeg -y -hide_banner -loglevel error -i $N.ivf -f rawvideo -pix_fmt yuv420p dec.yuv
  python3 -I - "$N" <<'PY'
import sys
n = sys.argv[1]; fs = 1920 * 1080 * 3 // 2
sizes = [int(x) for x in open(n + ".ivf.sizes") if x.strip()]
with open("dec.yuv", "rb") as d, open("exp.yuv", "wb") as o:  # пропущенный кодером кадр = повтор предыдущего
    last = None
    for s in sizes:
        if s > 0: last = d.read(fs)
        o.write(last)
PY
  ffmpeg -hide_banner -loglevel error -f rawvideo -pix_fmt yuv420p -s 1920x1080 -r $FPS -i exp.yuv -i seq.y4m \
    -lavfi "[1:v]select='eq(mod(n+1\,$STEP)\,0)',setpts=N/($FPS*TB)[ref];[0:v]setpts=N/($FPS*TB)[d];[d][ref]psnr=stats_file=$N.psnr" -f null -
  python3 -I - "$N" "$STEP" "$K" "$FPS" <<'PY'
import sys, re
n, step, kbps, fps = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
sizes = [int(x) for x in open(n + ".ivf.sizes") if x.strip()]
ps = [float(re.search(r"psnr_y:(\S+)", l).group(1).replace("inf", "99")) for l in open(n + ".psnr")]
t = lambda k: (k + 1) * step / 30.0
after = [(t(k) - 2.0, p) for k, p in enumerate(ps) if t(k) > 2.0]
at = lambda dt: next((p for d, p in after if d >= dt), after[-1][1])
reach = lambda th: next((round(d, 1) for d, p in after if p >= th), "нет")
avg = kbps * 1000 / 8 / fps
print(f"{n:34} ключ {sizes[0]//1000:3} КБ, макс {max(sizes[1:])//1000:3} КБ = {max(sizes[1:])/avg:4.1f} ср., пропусков {sizes.count(0):2} | "
      f"PSNR +0.5с {at(0.5):4.1f} +1с {at(1):4.1f} +2с {at(2):4.1f} +4с {at(4):4.1f} +9с {at(9):4.1f} | 40 дБ за {reach(40)} с | "
      f"статика {sum(sizes[-3*fps:])*8//3000} кбит/с")
PY
}
if [ $# -eq 0 ]; then set -- "300 5" "1000 30" "4000 30"; fi
for c in "$@"; do run $c; done
