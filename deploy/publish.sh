#!/bin/sh
# Сборка и выкладка на VPS — только если build.sh (vet, тесты, сборка) прошёл целиком.
# Docker: ANYPC_DOCKER=1 — собрать и опубликовать образ узла (нужен доступ к Docker и право write:packages у gh).
# macOS: ANYPC_MAC=пользователь@мак — сборка AnyPC-macos на Маке (build.sh); без неё файла для Мака в выкладке нет.
# Серверы: ANYPC_VPS — один или несколько через пробел (по умолчанию root@hk.anypc.org); вход по ключу.
set -eu
cd "$(dirname "$0")/.."
./build.sh
V=$(cat bin/VERSION)
if echo "$V" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' && ! grep -qx "MIN_VERSION=$V" deploy/setup.sh; then
  echo "выпуск $V: поднимите MIN_VERSION в deploy/setup.sh до $V (иначе install.sh примет старый выпуск)" >&2; exit 1
fi
# П1: подпись SHA256SUMS ключом выпуска (Ed25519); install.sh проверяет её ключом, вшитым в deploy/setup.sh.
# Ключ — только на машине владельца; без него выпуск не выкладывается. Самопроверка — тем же путём, что у install.sh.
K=${ANYPC_SIGN_KEY:-$HOME/.config/anypc/release-ed25519.pem}
openssl pkeyutl -sign -rawin -inkey "$K" -in bin/SHA256SUMS -out bin/SHA256SUMS.sig
P=$(mktemp) # открытый ключ на зеркало не кладём: проверять им файлы того же зеркала бессмысленно (ключ — в README)
sed -n '/^-----BEGIN PUBLIC KEY-----$/,/^-----END PUBLIC KEY-----$/p' deploy/setup.sh > "$P"
openssl pkeyutl -verify -pubin -inkey "$P" -rawin -in bin/SHA256SUMS -sigfile bin/SHA256SUMS.sig; rm -f "$P"
# Образ свой-узла ghcr.io/loginbycall/anypc-server (amd64 + arm64) — только из чистого тега выпуска.
# Один раз: docker buildx create --use --name anypc; gh auth refresh -s write:packages.
if [ "${ANYPC_DOCKER:-}" ]; then
  echo "$V" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || { echo "образ — только из чистого тега, а сборка $V" >&2; exit 1; }
  gh auth token | docker login ghcr.io -u LoginByCall --password-stdin
  docker buildx build --platform linux/amd64,linux/arm64 -f deploy/docker/Dockerfile --build-arg VERSION="$V" \
    -t "ghcr.io/loginbycall/anypc-server:$V" -t ghcr.io/loginbycall/anypc-server:latest --push .
fi
for H in ${ANYPC_VPS:-root@hk.anypc.org}; do
  echo "== $H"
  ssh "$H" 'mkdir -p /root/anypc-deploy /srv/anypc/dl'
  scp bin/anypc-server "$H:/root/anypc-deploy/"
  scp bin/AnyPC.exe bin/AnyPC-linux-amd64 $(ls bin/AnyPC-macos 2>/dev/null) bin/anypc-server bin/install.sh bin/SHA256SUMS bin/SHA256SUMS.sig bin/VERSION "$H:/srv/anypc/dl/"
  ssh "$H" 'chmod 644 /srv/anypc/dl/*
install -m 755 /root/anypc-deploy/anypc-server /usr/local/bin/
systemctl restart anypc-server && sleep 1 && systemctl is-active anypc-server
cd /srv/anypc/dl && sha256sum -c SHA256SUMS'
done
