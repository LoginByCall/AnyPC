#!/bin/sh
# Развёртывание сервера AnyPC на Ubuntu (root). Повторный запуск безопасен.
# Использование: [TURN=a,b HUBS=wss://a/ws,wss://b/ws] sh setup.sh <домен клиента> [домен лендинга]   (рядом — бинарник anypc-server)
# Второй TURN без сигнализации: TURN_ONLY=1 [TURN_MIN=50000 TURN_MAX=50999] sh setup.sh <домен TURN> — нужен /etc/anypc/turn-secret,
# скопированный с основного сервера (учётки TURN выдаёт его хаб).
# Файлы для скачивания с лендинга кладутся в /srv/anypc/dl (AnyPC.exe, SHA256SUMS).
set -eu
DOMAIN=$1
SITE=${2:-}
mkdir -p /srv/anypc/dl
cd "$(dirname "$0")"

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
sleep 2
systemctl --no-pager --lines=5 status coturn anypc-server
