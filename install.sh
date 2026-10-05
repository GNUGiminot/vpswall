#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
if [ "$(id -u)" -ne 0 ]; then echo 'Run: sudo sh ./install.sh' >&2; exit 1; fi
if [ "$(uname -s)" != Linux ] || [ ! -d /run/systemd/system ]; then echo 'Linux with systemd is required.' >&2; exit 1; fi
for file in /var/lib/vpswall/pending.json /var/lib/vpswall/change.json; do
    if [ -e "$file" ]; then echo 'Confirm or roll back the pending change before updating.' >&2; exit 1; fi
done
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo 'Supported architectures: amd64, arm64' >&2; exit 1 ;;
esac
binary="$script_dir/dist/vpswall-linux-$arch"
if [ ! -f "$binary" ]; then echo "Missing binary: $binary" >&2; exit 1; fi
for cmd in systemctl systemd-run; do
    if [ ! -x "/usr/bin/$cmd" ]; then echo "Missing /usr/bin/$cmd" >&2; exit 1; fi
done
install -d -m 0700 /var/lib/vpswall /var/lib/vpswall/backups
# Package installation and firewall activation happen explicitly in the panel.
systemctl stop vpswall-worker.timer vpswall-worker.service 2>/dev/null || true
install -m 0755 "$binary" /usr/local/bin/.vpswall-new
mv -f /usr/local/bin/.vpswall-new /usr/local/bin/vpswall
cat > /etc/systemd/system/vpswall-recover.service <<'EOF'
[Unit]
Description=Recover VPSWall changes and restore managed firewall state at boot
After=ufw.service firewalld.service nftables.service netfilter-persistent.service
Before=network-pre.target
Wants=network-pre.target
StartLimitIntervalSec=0
[Service]
Type=oneshot
ExecStart=/usr/local/bin/vpswall recover
Restart=on-failure
RestartSec=15s
UMask=0077
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/vpswall-worker.service <<'EOF'
[Unit]
Description=VPSWall timed port windows
After=vpswall-recover.service
StartLimitIntervalSec=0
[Service]
Type=oneshot
ExecStart=/usr/local/bin/vpswall worker
Restart=on-failure
RestartSec=15s
UMask=0077
EOF
cat > /etc/systemd/system/vpswall-worker.timer <<'EOF'
[Unit]
Description=VPSWall port scheduler, every 15 seconds
[Timer]
OnBootSec=15s
OnUnitActiveSec=15s
AccuracySec=1s
Unit=vpswall-worker.service
[Install]
WantedBy=timers.target
EOF
chmod 0644 /etc/systemd/system/vpswall-recover.service /etc/systemd/system/vpswall-worker.service /etc/systemd/system/vpswall-worker.timer
systemctl daemon-reload
systemctl enable vpswall-recover.service
systemctl enable --now vpswall-worker.timer
# Restart an existing web panel after atomic binary update; never enable it here.
systemctl try-restart vpswall-web.service 2>/dev/null || true
echo 'VPSWall installed. Start: sudo --preserve-env=SSH_CONNECTION vpswall'
