#!/bin/sh
# Start the localhost web panel; the firewall worker is managed independently.
set -eu
if [ "$(id -u)" -ne 0 ]; then echo 'Run: sudo sh ./start.sh' >&2; exit 1; fi
/usr/local/bin/vpswall web enable
echo 'Web panel: 127.0.0.1:8090. Get a token from SSH:'
echo 'sudo --preserve-env=SSH_CONNECTION vpswall web token'
