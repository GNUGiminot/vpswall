#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

if [ "$(id -u)" -ne 0 ]; then
    echo 'Run: sudo sh ./install.sh' >&2
    exit 1
fi
if [ "$(uname -s)" != Linux ] || [ ! -d /run/systemd/system ]; then
    echo 'Linux with systemd is required.' >&2
    exit 1
fi
if [ ! -x /usr/sbin/ufw ]; then
    echo 'Install UFW first: sudo apt install ufw' >&2
    exit 1
fi
if [ -e /var/lib/vpswall/pending.json ]; then
    echo 'A change is pending. Confirm or roll back before updating.' >&2
    exit 1
fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo 'Supported architectures: amd64, arm64' >&2; exit 1 ;;
esac
binary="$script_dir/dist/vpswall-linux-$arch"
if [ ! -f "$binary" ]; then
    echo "Missing binary: $binary" >&2
    exit 1
fi
for cmd in systemctl systemd-run cp; do
    if [ ! -x "/usr/bin/$cmd" ]; then
        echo "Missing /usr/bin/$cmd" >&2
        exit 1
    fi
done
install -d -m 0700 /var/lib/vpswall /var/lib/vpswall/backups
install -m 0755 "$binary" /usr/local/bin/vpswall
cat > /etc/systemd/system/vpswall-recover.service <<'EOF'
[Unit]
Description=Recover an unconfirmed VPSWall firewall change after reboot
After=ufw.service
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vpswall rollback
Restart=on-failure
RestartSec=15s
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 /etc/systemd/system/vpswall-recover.service
systemctl daemon-reload
systemctl enable vpswall-recover.service
echo 'Installed. UFW rules have not been changed.'
echo 'Start: sudo --preserve-env=SSH_CONNECTION vpswall'
