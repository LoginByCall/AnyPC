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
(cd bin && sha256sum AnyPC.exe AnyPC-linux-amd64 > SHA256SUMS)
echo "$V" > bin/VERSION # проверка обновлений в программе (app/update.go): выпуском считается только чистый тег
ls -la bin
