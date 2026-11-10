#!/bin/sh
# AnyPC-macos (Intel + Apple Silicon в одном файле, ad-hoc подпись) — на самом Маке: build.sh по ssh или CI.
# Ввод через CoreGraphics — cgo, кросс-сборки с Linux нет. Аргумент — версия. ui/pake.wasm должен уже лежать в ui/.
# libvpx: deploy/libvpx.sh darwin-amd64 darwin-arm64; в lib/ только libvpx.a — иначе ld возьмёт dylib.
set -eu
cd "$(dirname "$0")/.."
V=$1
export PATH=$HOME/.local/go/bin:$PATH:/usr/local/bin:/opt/homebrew/bin GOTOOLCHAIN=local CGO_ENABLED=1 GOFLAGS="-trimpath -buildvcs=false"
vpx() { L=$PWD/third_party/libvpx/darwin-$1; if [ -f $L/lib/libvpx.a ]; then export CGO_CFLAGS=-I$L/include CGO_LDFLAGS=-L$L/lib; T=-tags=vp9; else unset CGO_CFLAGS CGO_LDFLAGS; T=; fi; }
vpx $(uname -m | sed s/x86_64/amd64/)
go vet $T ./app ./agent
go test -count=1 $T ./agent ./app # сетевые e2e на Маке вернулись 2026-11-10: 4 прогона подряд и 3 полных — зелёные при включённом LuLu
for a in amd64 arm64; do vpx $a; GOARCH=$a go build $T -ldflags="-s -w -X main.version=$V" -o AnyPC-macos-$a ./app; done
for a in amd64 arm64; do otool -L AnyPC-macos-$a | grep -q libvpx && { echo "AnyPC-macos-$a: libvpx слинкована динамически"; exit 1; }; done
lipo -create -output AnyPC-macos AnyPC-macos-amd64 AnyPC-macos-arm64
codesign -s - -f AnyPC-macos
lipo -info AnyPC-macos
