#!/bin/sh
# Stop the web panel and revoke its token; retain firewall protection and scheduling.
set -eu
if [ "$(id -u)" -ne 0 ]; then echo 'Run: sudo sh ./stop.sh' >&2; exit 1; fi
/usr/local/bin/vpswall web disable
