#!/bin/sh
# Сборка и выкладка на VPS — только если build.sh (vet, тесты, сборка) прошёл целиком.
# Сервер: ANYPC_VPS (по умолчанию root@any.turboseller.xyz); вход — ключ или SSH_ASKPASS.
set -eu
cd "$(dirname "$0")/.."
./build.sh
H=${ANYPC_VPS:-root@any.turboseller.xyz}
scp bin/anypc-server "$H:/root/anypc-deploy/"
scp bin/AnyPC.exe bin/AnyPC-linux-amd64 bin/SHA256SUMS "$H:/srv/anypc/dl/"
ssh "$H" 'chmod 644 /srv/anypc/dl/*
install -m 755 /root/anypc-deploy/anypc-server /usr/local/bin/
systemctl restart anypc-server && sleep 1 && systemctl is-active anypc-server
cd /srv/anypc/dl && sha256sum -c SHA256SUMS'
