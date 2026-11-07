#!/bin/sh
# Сборка и выкладка на VPS — только если build.sh (vet, тесты, сборка) прошёл целиком.
# macOS: ANYPC_MAC=пользователь@мак — сборка AnyPC-macos на Маке (build.sh); без неё файла для Мака в выкладке нет.
# Серверы: ANYPC_VPS — один или несколько через пробел (по умолчанию root@hk.anypc.org); вход по ключу.
set -eu
cd "$(dirname "$0")/.."
./build.sh
for H in ${ANYPC_VPS:-root@hk.anypc.org}; do
  echo "== $H"
  ssh "$H" 'mkdir -p /root/anypc-deploy /srv/anypc/dl'
  scp bin/anypc-server "$H:/root/anypc-deploy/"
  scp bin/AnyPC.exe bin/AnyPC-linux-amd64 $(ls bin/AnyPC-macos 2>/dev/null) bin/anypc-server bin/install.sh bin/SHA256SUMS bin/VERSION "$H:/srv/anypc/dl/"
  ssh "$H" 'chmod 644 /srv/anypc/dl/*
install -m 755 /root/anypc-deploy/anypc-server /usr/local/bin/
systemctl restart anypc-server && sleep 1 && systemctl is-active anypc-server
cd /srv/anypc/dl && sha256sum -c SHA256SUMS'
done
