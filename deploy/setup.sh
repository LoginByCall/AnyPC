#!/bin/sh
# Развёртывание сервера AnyPC на Ubuntu (root). Повторный запуск безопасен.
# Использование: sh setup.sh <домен клиента> [домен лендинга]   (рядом — бинарник anypc-server)
# Файлы для скачивания с лендинга кладутся в /srv/anypc/dl (AnyPC.exe, SHA256SUMS).
set -eu
DOMAIN=$1
SITE=${2:-}
mkdir -p /srv/anypc/dl
cd "$(dirname "$0")"

apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -yq coturn

mkdir -p /etc/anypc
[ -s /etc/anypc/turn-secret ] || head -c 32 /dev/urandom | base64 > /etc/anypc/turn-secret
chmod 600 /etc/anypc/turn-secret
SECRET=$(cat /etc/anypc/turn-secret)
printf 'ANYPC_TURN_SECRET=%s\n' "$SECRET" > /etc/anypc/env
chmod 600 /etc/anypc/env

# TURN: временные учётки (use-auth-secret), запрет ретрансляции во внутренние сети VPS
cat > /etc/turnserver.conf <<EOF
listening-port=3478
fingerprint
use-auth-secret
static-auth-secret=$SECRET
realm=$DOMAIN
min-port=49152
max-port=65535
no-tls
no-dtls
no-cli
no-multicast-peers
user-quota=4
total-quota=40
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=100.64.0.0-100.127.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
EOF
chmod 640 /etc/turnserver.conf
chgrp turnserver /etc/turnserver.conf 2>/dev/null || true
systemctl enable coturn
systemctl restart coturn

install -m 755 anypc-server /usr/local/bin/anypc-server
cat > /etc/systemd/system/anypc-server.service <<EOF
[Unit]
Description=AnyPC signaling server
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/anypc/env
ExecStart=/usr/local/bin/anypc-server -domain $DOMAIN -turn $DOMAIN -site "$SITE" -dl /srv/anypc/dl -certs /var/lib/anypc/certs
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
