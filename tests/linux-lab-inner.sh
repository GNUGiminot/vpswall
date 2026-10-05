#!/bin/sh
set -eu
task_root=$1
source_dir=$2
test_pattern=$3
mount --make-rprivate /
mount -t overlay overlay -o "lowerdir=/,upperdir=$task_root/upper,workdir=$task_root/work" "$task_root/rootfs"
mount -t proc proc "$task_root/rootfs/proc"
mount -t tmpfs tmpfs "$task_root/rootfs/run"
mount --rbind /dev "$task_root/rootfs/dev"
mount --make-rslave "$task_root/rootfs/dev"
mount --bind /sys "$task_root/rootfs/sys"
mount -o remount,bind,ro "$task_root/rootfs/sys"
rm -f "$task_root/rootfs/etc/resolv.conf"
cp "$task_root/resolv.conf" "$task_root/rootfs/etc/resolv.conf"
mkdir -p "$task_root/rootfs/opt/vpswall"
mount --bind "$source_dir" "$task_root/rootfs/opt/vpswall"
printf '#!/bin/sh\nexit 101\n' > "$task_root/rootfs/usr/sbin/policy-rc.d"
chmod 0755 "$task_root/rootfs/usr/sbin/policy-rc.d"
touch "$task_root/rootfs/VPSWALL_ISOLATED_ROOT"
chroot "$task_root/rootfs" /usr/bin/apt-get update -qq > "$source_dir/tests/linux-lab-packages.log" 2>&1
if ! chroot "$task_root/rootfs" /usr/bin/env DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get install -y -qq ufw nftables iptables firewalld openssh-server >> "$source_dir/tests/linux-lab-packages.log" 2>&1; then
    tail -n 30 "$source_dir/tests/linux-lab-packages.log"
    exit 1
fi
# WSL 6.6 lacks CONFIG_NFT_FIB_IPV6. Disable rpfilter only inside the disposable root.
sed -i 's/^IPv6_rpfilter=.*/IPv6_rpfilter=no/' "$task_root/rootfs/etc/firewalld/firewalld.conf"
if ! grep -q '^IPv6_rpfilter=no' "$task_root/rootfs/etc/firewalld/firewalld.conf"; then
    printf '\nIPv6_rpfilter=no\n' >> "$task_root/rootfs/etc/firewalld/firewalld.conf"
fi
cp "$source_dir/dist/vpswall-linux.test" "$task_root/rootfs/tmp/vpswall-linux.test"
chmod 0755 "$task_root/rootfs/tmp/vpswall-linux.test"
mkdir -p "$task_root/rootfs/run/systemd/system"
# Stub control commands only in the private root; verify generated units offline below.
printf '#!/bin/sh\nexit 0\n' > "$task_root/rootfs/usr/bin/systemctl"
chmod 0755 "$task_root/rootfs/usr/bin/systemctl"
chroot "$task_root/rootfs" /bin/sh /opt/vpswall/install.sh
chroot "$task_root/rootfs" /usr/bin/systemd-analyze verify /etc/systemd/system/vpswall-recover.service /etc/systemd/system/vpswall-worker.service /etc/systemd/system/vpswall-worker.timer
unshare --net chroot "$task_root/rootfs" /usr/bin/env VPSWALL_LAB=1 /tmp/vpswall-linux.test -test.v -test.run "$test_pattern" -test.timeout 5m
