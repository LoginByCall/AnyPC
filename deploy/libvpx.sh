#!/bin/sh
# Статическая libvpx (кодер VP9 в процессе, agent/vp9.go) → third_party/libvpx/<ос-арх>/{include,lib}; build.sh
# собирает с -tags vp9, когда каталог цели есть. Нужны: git, make, perl, nasm или yasm; для windows-amd64 — mingw
# (Debian/Ubuntu: sudo apt install nasm gcc-mingw-w64-x86-64); на Маке — Command Line Tools (arm64 без nasm).
# Запуск: deploy/libvpx.sh [linux-amd64 windows-amd64 darwin-amd64 darwin-arm64]; без аргументов — linux-amd64 windows-amd64.
set -eu
cd "$(dirname "$0")/.."
VER=v1.15.2 # 2025-07; при смене — прогнать TestVP9 и TestE2EVP9
SRC=$PWD/third_party/libvpx/src
[ -d "$SRC" ] || git clone -q --depth 1 -b $VER https://chromium.googlesource.com/webm/libvpx "$SRC"
for T in ${@:-linux-amd64 windows-amd64}; do
  case $T in
    linux-amd64)   TGT=x86_64-linux-gcc;  CROSS= ;;
    windows-amd64) TGT=x86_64-win64-gcc;  CROSS=x86_64-w64-mingw32- ;;
    darwin-amd64)  TGT=x86_64-darwin20-gcc; CROSS= ;;
    darwin-arm64)  TGT=arm64-darwin20-gcc;  CROSS= ;;
    *) echo "неизвестная цель $T" >&2; exit 1 ;;
  esac
  OUT=$PWD/third_party/libvpx/$T; B=$PWD/third_party/libvpx/build-$T
  rm -rf "$B" "$OUT"; mkdir -p "$B"
  (cd "$B" && "$SRC/configure" --target=$TGT ${CROSS:+--cross=$CROSS} --prefix="$OUT" \
     --enable-vp9 --disable-vp8 --disable-vp9-decoder --enable-static --disable-shared --enable-pic \
     --disable-examples --disable-tools --disable-docs --disable-unit-tests --disable-install-bins --disable-install-docs >/dev/null \
   && make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" >/dev/null && make install >/dev/null)
  rm -rf "$B"
  echo "$T: $(ls "$OUT"/lib/libvpx.a)"
done
