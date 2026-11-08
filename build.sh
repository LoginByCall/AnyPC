#!/bin/sh
# Сборка: bin/anypc-server (Linux), bin/AnyPC.exe (Windows), bin/AnyPC-linux-amd64.
# FFmpeg не вшивается: Windows-версия скачивает его с gyan.dev при первом запуске (app/ffmpeg.go, SHA-256 закреплён),
# Linux берёт системный. Так AnyPC сам не распространяет GPL-код (ASK #11 → A, 2026-11-07).
set -eu
cd "$(dirname "$0")"
export GOTOOLCHAIN=auto

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
GOOS=windows GOARCH=amd64 go vet ./app ./agent
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H windowsgui -X main.version=$V" -o bin/AnyPC.exe ./app
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=$V" -o bin/AnyPC-linux-amd64 ./app
rm -f bin/AnyPC-macos
if [ "${ANYPC_MAC:-}" ]; then # macOS: ввод через CoreGraphics (cgo) — сборка на самом Маке по ssh (Go в ~/.local/go), Intel + Apple Silicon в одном файле
  git ls-files -co --exclude-standard | grep -vE '^(bin|\.claude)/' | { cat; printf 'ui/pake.wasm\nui/wasm_exec.js\n'; } | rsync -a --files-from=- ./ "$ANYPC_MAC:anypc-src/"
  ssh "$ANYPC_MAC" "set -e; cd anypc-src; export PATH=\$HOME/.local/go/bin:/usr/local/bin:/opt/homebrew/bin:\$PATH GOTOOLCHAIN=local CGO_ENABLED=1
    # ponytail: e2e через en0 на Маке плавает и на v0.1.5 (ICE pion зависает в WriteTo) — пропуск до разбора; на Linux идут все
    go vet ./app ./agent; go test -count=1 -skip '^(TestE2E|TestWrongPassword|TestCaptureRestart)\$' ./agent ./app
    for a in amd64 arm64; do GOARCH=\$a go build -ldflags='-s -w -X main.version=$V' -o AnyPC-macos-\$a ./app; done
    lipo -create -output AnyPC-macos AnyPC-macos-amd64 AnyPC-macos-arm64; codesign -s - -f AnyPC-macos; lipo -info AnyPC-macos"
  scp "$ANYPC_MAC:anypc-src/AnyPC-macos" bin/
fi
cp deploy/setup.sh bin/install.sh # свой узел одной командой: скачивает anypc-server и сверяет с SHA256SUMS
echo "$V" > bin/VERSION # проверка обновлений в программе (app/update.go): выпуском считается только чистый тег
# VERSION — в подписанном списке: install.sh отвергает подписанный, но старый выпуск (откат версии)
(cd bin && sha256sum AnyPC.exe AnyPC-linux-amd64 $(ls AnyPC-macos 2>/dev/null) anypc-server install.sh VERSION > SHA256SUMS)
ls -la bin
