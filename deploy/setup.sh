#!/bin/sh
# Развёртывание сервера AnyPC на Ubuntu (root). Повторный запуск безопасен.
# Использование: [TURN=a,b HUBS=wss://a/ws,wss://b/ws] sh setup.sh <домен клиента> [домен лендинга]   (рядом — бинарник anypc-server)
# Второй TURN без сигнализации: TURN_ONLY=1 [TURN_MIN=50000 TURN_MAX=50999] sh setup.sh <домен TURN> — нужен /etc/anypc/turn-secret,
# скопированный с основного сервера (учётки TURN выдаёт его хаб).
# Файлы для скачивания с лендинга кладутся в /srv/anypc/dl (AnyPC.exe, SHA256SUMS).
# Свой узел одной командой (бинарника рядом нет — скачивается и сверяется с SHA256SUMS; обновление — та же команда):
#   curl -fsSL https://raw.githubusercontent.com/LoginByCall/AnyPC/main/deploy/setup.sh | sudo sh -s my.example.com
# Скрипт — с GitHub, файлы — с зеркал: подменённое зеркало не подменит и проверку (П1).
set -eu
DOMAIN=${1:?"использование: install.sh <домен узла>   (запись A домена → IP этого сервера)"}
SITE=${2:-}
cd "$(dirname "$0")"
if [ ! "${TURN_ONLY:-}" ] && [ ! -f anypc-server ]; then
  # П1: SHA256SUMS подписан ключом выпуска (deploy/publish.sh); сумма с того же зеркала без подписи защищала бы
  # только от порчи, не от подмены. Открытый ключ — здесь; закрытый — у владельца (~/.config/anypc/release-ed25519.pem).
  cd "$(mktemp -d)"
  cat > release.pub <<'KEY'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAEtMc223pBHlegIQtFumvKY0PBHohIXYMzwMw8bR9bJs=
-----END PUBLIC KEY-----
KEY
  for u in ${ANYPC_DL:-https://hk.anypc.org/download https://ru.anypc.org/download https://github.com/LoginByCall/AnyPC/releases/latest/download}; do
    curl -fsSL -o anypc-server "$u/anypc-server" && curl -fsSL -o SHA256SUMS "$u/SHA256SUMS" && curl -fsSL -o SHA256SUMS.sig "$u/SHA256SUMS.sig" &&
      openssl pkeyutl -verify -pubin -inkey release.pub -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig >/dev/null &&
      grep ' anypc-server$' SHA256SUMS | sha256sum -c - && break
    echo "зеркало $u: файл или подпись не прошли проверку" >&2
    rm -f anypc-server SHA256SUMS SHA256SUMS.sig
  done
  [ -f anypc-server ] || { echo "не удалось скачать anypc-server ни с одного зеркала" >&2; exit 1; }
fi
[ "${ANYPC_DL_ONLY:-}" ] && exit 0 # тест проверки скачивания (server/install_test.go)
mkdir -p /srv/anypc/dl

apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -yq coturn

mkdir -p /etc/anypc
if [ "${TURN_ONLY:-}" ] && [ ! -s /etc/anypc/turn-secret ]; then
  echo "TURN_ONLY: сначала скопируйте /etc/anypc/turn-secret с основного сервера" >&2; exit 1
fi
[ -s /etc/anypc/turn-secret ] || head -c 32 /dev/urandom | base64 > /etc/anypc/turn-secret
chmod 600 /etc/anypc/turn-secret
SECRET=$(cat /etc/anypc/turn-secret)
printf 'ANYPC_TURN_SECRET=%s\n' "$SECRET" > /etc/anypc/env
chmod 600 /etc/anypc/env

# TURN: временные учётки (use-auth-secret), запрет ретрансляции во внутренние сети VPS и на собственные адреса машины:
# учётку выдаёт хаб любому клиенту, а relay на свой IP достал бы до соседних служб сервера (почта и т.п.) «изнутри».
# no-tcp-relay: WebRTC берёт только UDP-аллокации, TCP-relay (RFC 6062) нужен лишь прокси-злоупотреблению;
# max-bps — байт/с на сеанс (10 Мбит/с при видео до 4 Мбит/с); ::ffff:… — обход запретов IPv4 через IPv4-mapped IPv6.
cat > /etc/turnserver.conf <<EOF
listening-port=3478
fingerprint
use-auth-secret
static-auth-secret=$SECRET
realm=$DOMAIN
min-port=${TURN_MIN:-49152}
max-port=${TURN_MAX:-65535}
no-tls
no-dtls
no-cli
no-multicast-peers
user-quota=4
total-quota=40
no-tcp-relay
max-bps=1250000
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=100.64.0.0-100.127.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
denied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff
denied-peer-ip=::1
denied-peer-ip=::ffff:0.0.0.0-::ffff:255.255.255.255
denied-peer-ip=64:ff9b::-64:ff9b::ffff:ffff
denied-peer-ip=198.18.0.0-198.19.255.255
denied-peer-ip=240.0.0.0-255.255.255.255
$(for ip in $(hostname -I); do echo "denied-peer-ip=$ip"; done)
EOF
chmod 640 /etc/turnserver.conf
chgrp turnserver /etc/turnserver.conf 2>/dev/null || true
systemctl enable coturn
systemctl restart coturn
[ "${TURN_ONLY:-}" ] && { systemctl --no-pager --lines=5 status coturn; exit 0; }

install -m 755 anypc-server /usr/local/bin/anypc-server
cat > /etc/systemd/system/anypc-server.service <<EOF
[Unit]
Description=AnyPC signaling server
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/anypc/env
ExecStart=/usr/local/bin/anypc-server -domain $DOMAIN -turn ${TURN:-$DOMAIN} -hubs "${HUBS:-}" -site "$SITE" -dl /srv/anypc/dl -certs /var/lib/anypc/certs
DynamicUser=yes
StateDirectory=anypc
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable anypc-server
systemctl restart anypc-server
# ufw включён — открыть порты узла (иначе межсетевой экран — у хостера, см. README)
if command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; then
  ufw allow 80,443/tcp; ufw allow 3478; ufw allow 49152:65535/udp
fi
sleep 2
systemctl --no-pager --lines=5 status coturn anypc-server
echo "Узел готов: https://$DOMAIN/ (веб-клиент). В программе AnyPC: «Свой сервер» = $DOMAIN"
