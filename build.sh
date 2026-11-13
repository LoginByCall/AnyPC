#!/bin/sh
# Сборка: bin/anypc-server (Linux), bin/AnyPC.exe (Windows), bin/AnyPC-linux-amd64.
# FFmpeg не вшивается: Windows-версия скачивает его с gyan.dev при первом запуске (app/ffmpeg.go, SHA-256 закреплён),
# Linux берёт системный. Так AnyPC сам не распространяет GPL-код (ASK #11 → A, 2026-11-07).
set -eu
cd "$(dirname "$0")"
export GOTOOLCHAIN=auto GOFLAGS="-trimpath -buildvcs=false" # без путей каталога и меток git: из одного тега — одни и те же байты

# CPace для веб-клиента: тот же Go-код в WebAssembly (встраивается в ui)
V=$(git describe --tags --always --dirty 2>/dev/null || echo dev) # v0.1.0, v0.1.0-3-gabc123, …-dirty
echo "версия $V"
GOOS=js GOARCH=wasm go build -ldflags='-s -w' -o ui/pake.wasm ./wasm
install -m 644 "$(go env GOROOT)/lib/wasm/wasm_exec.js" ui/wasm_exec.js
go vet ./...
if command -v node >/dev/null; then node ui/i18n_check.js; fi
go test ./...
mkdir -p bin
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=$V" -o bin/anypc-server ./server
# Кодер VP9 в процессе (agent/vp9.go): если deploy/libvpx.sh собрал статическую libvpx для цели — cgo и -tags vp9,
# бинарник остаётся статическим (netgo/osusergo, -extldflags -static); нет библиотеки — как раньше, H.264 через ffmpeg.
VPX=$PWD/third_party/libvpx
vpx() { [ -f "$VPX/$1/lib/libvpx.a" ] && echo "CGO_ENABLED=1 CGO_CFLAGS=-I$VPX/$1/include CGO_LDFLAGS=-L$VPX/$1/lib"; }
if [ "$(vpx linux-amd64)" ]; then
  env $(vpx linux-amd64) go vet -tags vp9 ./agent
  env $(vpx linux-amd64) go test -count=1 -tags vp9 -run '^(TestVP9|TestE2EVP9|TestPause|TestPauseIDR|TestBrowserPause)$' ./agent
  env $(vpx linux-amd64) GOOS=linux GOARCH=amd64 go build -tags vp9,netgo,osusergo -ldflags="-s -w -X main.version=$V -linkmode external -extldflags -static" -o bin/AnyPC-linux-amd64 ./app
else
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=$V" -o bin/AnyPC-linux-amd64 ./app
fi
GOOS=windows GOARCH=amd64 go vet ./app ./agent
if [ "$(vpx windows-amd64)" ] && command -v x86_64-w64-mingw32-gcc >/dev/null; then
  env $(vpx windows-amd64) CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 go build -tags vp9 -ldflags="-s -w -H windowsgui -X main.version=$V -extldflags -static" -o bin/AnyPC.exe ./app
else
  GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H windowsgui -X main.version=$V" -o bin/AnyPC.exe ./app
fi
rm -f bin/AnyPC-macos
if [ "${ANYPC_MAC:-}" ]; then # macOS: сборка на самом Маке по ssh (Go в ~/.local/go) — deploy/mac.sh
  git ls-files -co --exclude-standard | grep -vE '^(bin|\.claude)/' | { cat; printf 'ui/pake.wasm\nui/wasm_exec.js\n'; } | rsync -a --files-from=- ./ "$ANYPC_MAC:anypc-src/"
  ssh "$ANYPC_MAC" "anypc-src/deploy/mac.sh $V"
  scp "$ANYPC_MAC:anypc-src/AnyPC-macos" bin/
fi
cp deploy/setup.sh bin/install.sh # свой узел одной командой: скачивает anypc-server и сверяет с SHA256SUMS
echo "$V" > bin/VERSION # проверка обновлений в программе (app/update.go): выпуском считается только чистый тег
# VERSION — в подписанном списке: install.sh отвергает подписанный, но старый выпуск (откат версии)
(cd bin && sha256sum AnyPC.exe AnyPC-linux-amd64 $(ls AnyPC-macos 2>/dev/null) anypc-server install.sh VERSION > SHA256SUMS)
ls -la bin
