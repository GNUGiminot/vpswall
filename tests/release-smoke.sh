#!/bin/sh
# Run in a private network namespace, from the shipped archive, without Go or internet.
set -eu
archive=${1:?Usage: release-smoke.sh /absolute/path/vpswall-VERSION.zip}
if [ "${VPSWALL_SMOKE_NETNS:-}" != 1 ]; then
    exec unshare --net env VPSWALL_SMOKE_NETNS=1 sh "$0" "$archive"
fi
ip link set lo up

task_dir=$(mktemp -d /tmp/vpswall-release-smoke.XXXXXX)
task_pid=
cleanup() {
    if [ -n "$task_pid" ]; then kill "$task_pid" 2>/dev/null || true; wait "$task_pid" 2>/dev/null || true; fi
    case "$task_dir" in /tmp/vpswall-release-smoke.*) rm -rf -- "$task_dir" ;; *) exit 1 ;; esac
}
trap cleanup EXIT HUP INT TERM
python3 -m zipfile -e "$archive" "$task_dir"
cd "$task_dir"
(cd dist && sha256sum -c SHA256SUMS)
chmod 0755 dist/vpswall-linux-amd64
test "$(./dist/vpswall-linux-amd64 --version)" = 'vpswall 0.5.0'
./dist/vpswall-linux-amd64 web --demo > "$task_dir/demo.log" 2>&1 &
task_pid=$!
curl --fail --silent --show-error --retry 15 --retry-connrefused --retry-delay 1 --max-time 5 -H 'Authorization: Bearer vpswall-demo' http://127.0.0.1:8091/api/state > "$task_dir/state.json"
python3 - "$task_dir/state.json" <<'PY'
import json,sys
state=json.load(open(sys.argv[1],encoding='utf-8'))
assert state['version']=='0.5.0'
assert any(p['port']=='443' and p['address']=='::' for p in state['inventory']['listeners'])
assert any(r['destination']=='8080/tcp' and r['comment']=='Console service' for f in state['inventory']['firewalls'] for r in f.get('rules',[]))
assert all(r['port']!='8080' for r in state['config']['rules'])
print('RELEASE_SMOKE_OK: offline extracted Linux binary; console rule and listeners visible')
PY
