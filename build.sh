#!/bin/sh
# Сборка: bin/anypc-server (Linux) и bin/AnyPC.exe (Windows, ffmpeg вшит).
# ffmpeg: gyan.dev essentials (GPLv3) — допустимо для своих ПК; раздача третьим лицам → ASK #11.
set -eu
cd "$(dirname "$0")"
export GOTOOLCHAIN=auto

FF=app/ffmpeg.exe.gz
if [ ! -s "$FF" ]; then
  URL=https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip
  tmp=$(mktemp -d)
  curl -fL -o "$tmp/ff.zip" "$URL"
  want=$(curl -fsL "$URL.sha256" | cut -c1-64)
  got=$(sha256sum "$tmp/ff.zip" | cut -c1-64)
  [ "$want" = "$got" ] || { echo "ffmpeg: SHA-256 не совпал ($got != $want)"; exit 1; }
  unzip -q -j "$tmp/ff.zip" '*/bin/ffmpeg.exe' -d "$tmp"
  gzip -9c "$tmp/ffmpeg.exe" > "$FF"
  rm -rf "$tmp"
fi

# CPace для веб-клиента: тот же Go-код в WebAssembly (встраивается в ui)
GOOS=js GOARCH=wasm go build -ldflags='-s -w' -o ui/pake.wasm ./wasm
install -m 644 "$(go env GOROOT)/lib/wasm/wasm_exec.js" ui/wasm_exec.js
go vet ./...
if command -v node >/dev/null; then node ui/i18n_check.js; fi
go test ./...
mkdir -p bin
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags='-s -w' -o bin/anypc-server ./server
GOOS=windows GOARCH=amd64 go vet ./app ./agent
GOOS=windows GOARCH=amd64 go build -ldflags='-s -w -H windowsgui' -o bin/AnyPC.exe ./app
(cd bin && sha256sum AnyPC.exe > SHA256SUMS)
ls -la bin
