#!/bin/sh
# Disposable overlay root: never install packages in the host and never change its firewall.
set -eu
if [ "$(id -u)" -ne 0 ]; then echo 'Run as root on Linux.' >&2; exit 1; fi
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_pattern=${1:-TestIntegration}
task_root=$(mktemp -d /tmp/vpswall-lab.XXXXXX)
cp -L /etc/resolv.conf "$task_root/resolv.conf"
mkdir "$task_root/upper" "$task_root/work" "$task_root/rootfs"
cleanup() {
    case "$task_root" in /tmp/vpswall-lab.*) rm -rf -- "$task_root" ;; *) exit 1 ;; esac
}
trap cleanup EXIT HUP INT TERM
unshare --mount --pid --fork sh "$source_dir/tests/linux-lab-inner.sh" "$task_root" "$source_dir" "$test_pattern"
