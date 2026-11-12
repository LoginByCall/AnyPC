#!/bin/sh
# Установка/обновление anypc-probe на US (MONITORING.md). Запускает владелец: ! deploy/probe-install.sh
# Токен и chat_id бота — из vault VPN-solution (telegram.alerting_bot) прямо в /etc/anypc-probe.env (600):
# не печатаются и не попадают в argv. Повторный запуск безопасен.
set -eu
D=$(cd "$(dirname "$0")/.." && pwd)
V=${VAULT:-$D/../VPN-solution/secrets/secrets.sops.yaml}
ssh_us() { ssh -o BatchMode=yes -J root@176.125.243.168:1917 -p 1917 root@159.195.14.69 "$@"; }
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o "$D/bin/anypc-probe" "$D/probe"
T=$(sops -d --extract '["telegram"]["alerting_bot"]["token"]' "$V")
C=$(sops -d --extract '["telegram"]["alerting_bot"]["chat_id"]' "$V")
printf 'TG_TOKEN=%s\nTG_CHAT=%s\n' "$T" "$C" | ssh_us 'umask 077; cat > /etc/anypc-probe.env'
ssh_us 'cat > /usr/local/bin/anypc-probe.new && chmod 755 /usr/local/bin/anypc-probe.new && mv /usr/local/bin/anypc-probe.new /usr/local/bin/anypc-probe' < "$D/bin/anypc-probe"
ssh_us 'cat > /etc/systemd/system/anypc-probe.service' < "$D/deploy/anypc-probe.service"
ssh_us 'cat > /etc/systemd/system/anypc-probe.timer' < "$D/deploy/anypc-probe.timer"
ssh_us 'install -d -m 700 /var/lib/anypc-probe && systemctl daemon-reload && systemctl enable --now anypc-probe.timer && systemctl start anypc-probe.service; journalctl -u anypc-probe -n 3 --no-pager -o cat'
