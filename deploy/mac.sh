#!/bin/sh
# AnyPC-macos (Intel + Apple Silicon в одном файле; подпись — свой сертификат или ad-hoc, см. ниже) — на самом Маке: build.sh по ssh или CI.
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
# Info.plist в бинарнике (решение владельца 2026-11-14): без NSMicrophoneUsageDescription WebKit не даёт окну getUserMedia;
# CFBundleIdentifier = идентификатор подписи ниже (-i org.anypc.host), чтобы требование подписи и разрешения не менялись.
P="-extldflags '-Wl,-sectcreate,__TEXT,__info_plist,$PWD/deploy/Info.plist'"
for a in amd64 arm64; do vpx $a; GOARCH=$a go build $T -ldflags="-s -w -X main.version=$V $P" -o AnyPC-macos-$a ./app; done
for a in amd64 arm64; do otool -s __TEXT __info_plist AnyPC-macos-$a | grep -q . || { echo "AnyPC-macos-$a: нет Info.plist"; exit 1; }; done
for a in amd64 arm64; do otool -L AnyPC-macos-$a | grep -q libvpx && { echo "AnyPC-macos-$a: libvpx слинкована динамически"; exit 1; }; done
lipo -create -output AnyPC-macos AnyPC-macos-amd64 AnyPC-macos-arm64
# Подпись: свой сертификат «AnyPC Code Signing» (связка anypc-sign, решение владельца 2026-11-11) — требование подписи
# одинаково у всех сборок, и macOS не сбрасывает выданные AnyPC разрешения («Запись экрана», «Универсальный доступ») при
# обновлении; нет связки (CI, чужой Мак) — ad-hoc, как раньше. Пароль связки — в ~/.config/anypc/sign-keychain.pass (не пароль Мака).
K=$HOME/Library/Keychains/anypc-sign.keychain-db
if [ -f "$K" ]; then # связка есть — только своей подписью: молчаливый откат на ad-hoc сбросил бы разрешения у пользователей
  trap 'security lock-keychain "$K" 2>/dev/null' EXIT # и при ошибке codesign связка не остаётся открытой
  security unlock-keychain -p "$(cat "$HOME/.config/anypc/sign-keychain.pass")" "$K" || { echo "связка anypc-sign не открылась" >&2; exit 1; }
  codesign -s "AnyPC Code Signing" --keychain "$K" -i org.anypc.host -f AnyPC-macos
else
  codesign -s - -f AnyPC-macos
fi
codesign -dr - AnyPC-macos 2>&1 | grep designated
lipo -info AnyPC-macos
