#!/bin/sh
# compat.sh TAG [hub|client|host] [ключи go test] (RUN=… — выбор тестов client/host) — совместимость с выпущенной версией TAG (Э5) на настоящем коде TAG:
#   hub    — тесты ./agent и ./app этого коммита через хаб TAG (боевые хабы обновляются только с владельцем);
#   client — браузерные тесты ./agent: хост этого коммита, клиент (ui/index.html, embed.js) из TAG;
#   host   — браузерные тесты ./agent из TAG: хост TAG, клиент этого коммита.
# Падения тестов новых функций (булавка, id_taken, «снять» через хаб) в чужой паре ожидаемы — разбирать по журналу.
# Деревья — во временном каталоге (git archive), рабочее дерево не меняется. Нужны ffmpeg, google-chrome, node.
set -eu
tag=$1 mode=${2:-hub}
if [ $# -ge 2 ]; then shift 2; else shift $#; fi
cd "$(dirname "$0")"
t=$(mktemp -d) && trap 'rm -rf "$t"' EXIT
mkdir "$t/new" "$t/old"
git archive HEAD | tar -x -C "$t/new"
git archive "$tag" | tar -x -C "$t/old"
for d in new old; do
  (cd "$t/$d" && GOOS=js GOARCH=wasm go build -ldflags='-s -w' -o ui/pake.wasm ./wasm && cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" ui/)
done
export DBUS_SESSION_BUS_ADDRESS=
unset ANYPC_LIVE # TestLive идёт на боевые хабы — здесь только локальные
case $mode in
hub) rm -r "$t/new/hub" && cp -r "$t/old/hub" "$t/new/hub" && cd "$t/new" && timeout 1800 go test -count=1 -timeout 25m "$@" ./agent ./app ;;
client) cp "$t/old/ui/index.html" "$t/old/ui/embed.js" "$t/new/ui/" && cd "$t/new" && timeout 900 go test -count=1 -timeout 14m -run "${RUN:-TestBrowser}" "$@" ./agent ;;
host) cp "$t/new/ui/index.html" "$t/new/ui/embed.js" "$t/old/ui/" && cd "$t/old" && timeout 900 go test -count=1 -timeout 14m -run "${RUN:-TestBrowser}" "$@" ./agent ;;
*) echo "режим: hub | client | host" >&2; exit 2 ;;
esac
