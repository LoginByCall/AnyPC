#!/bin/sh
# Аудит настроек сервера AnyPC — ТОЛЬКО ЧТЕНИЕ, ничего не меняет. Секреты маскируются на сервере до отправки.
# Запуск: ssh root@<хаб> 'sh -s' < deploy/audit.sh
R() { sed -E -e 's/((static-auth-secret|secret|password|passwd|token|cli-password|private-key)[[:space:]]*[=:][[:space:]]*).*/\1<СКРЫТО>/I' -e 's/^(user[[:space:]]*=[[:space:]]*[^:]*:).*/\1<СКРЫТО>/'; }
s() { echo; echo "##### $*"; }
s ОС; . /etc/os-release; echo "$PRETTY_NAME"; uname -r; uptime
s Слушающие порты; ss -tulpnH | awk '{print $1,$5,$7}' | sort -u
s nftables; nft list ruleset 2>&1 | head -150
s ufw; ufw status verbose 2>&1 | head -30
s iptables; iptables -S 2>&1 | head -40; ip6tables -S 2>&1 | head -20
s coturn версия; turnserver --version 2>&1 | head -2; dpkg -l coturn 2>/dev/null | tail -1
s turnserver.conf; for f in /etc/turnserver.conf /etc/coturn/turnserver.conf; do [ -f $f ] && { echo "== $f"; grep -vE '^\s*(#|$)' $f | R; }; done
s coturn unit; systemctl cat coturn 2>/dev/null | grep -vE '^\s*#' | R
s anypc-server unit; systemctl cat anypc-server 2>/dev/null | grep -vE '^\s*#' | R
systemctl show anypc-server -p User,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp,CapabilityBoundingSet,AmbientCapabilities,RestrictAddressFamilies,MemoryMax,TasksMax,LimitNOFILE 2>/dev/null
s Процессы; ps -eo user,pid,args | grep -E 'anypc|turnserver' | grep -v grep | R
s Права; ls -la /srv/anypc /srv/anypc/dl /usr/local/bin/anypc-server /root/anypc-deploy 2>&1
find /srv/anypc /var/lib/anypc /etc/anypc -maxdepth 2 -printf '%M %u:%g %p\n' 2>/dev/null | head -40
s Сертификаты; ls -la /etc/letsencrypt/live 2>&1 | head
s sshd эффективно; sshd -T 2>/dev/null | grep -E '^(port|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|x11forwarding|allowtcpforwarding|gatewayports|permittunnel|maxauthtries|allowusers|allowgroups|loglevel) '
s Ключи root; awk '{print $1, $NF}' /root/.ssh/authorized_keys 2>/dev/null
s Пользователи с оболочкой; awk -F: '$7!~/(nologin|false|sync)$/{print $1,$3,$7}' /etc/passwd
s Обновления; systemctl is-enabled unattended-upgrades 2>&1; apt list --upgradable 2>/dev/null | grep -c upgradable; ls /var/run/reboot-required 2>&1
s fail2ban; systemctl is-active fail2ban 2>&1
s sysctl; sysctl net.ipv4.ip_forward net.ipv4.tcp_syncookies net.ipv4.conf.all.rp_filter 2>&1
s cron; ls /etc/cron.d; crontab -l 2>&1 | grep -v '^#'
s Докер; command -v docker && docker ps --format '{{.Image}} {{.Ports}}' 2>&1
