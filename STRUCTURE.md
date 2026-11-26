# VPSWall project structure

VPSWall manages its own Linux firewall rules, scheduled access windows and SSH
migration with rollback, and observes existing administrator rules without adoption.

- `main.go`, `cli.go`: shared helpers, compatibility code and CLI entry point.
- `manager.go`: configuration, ownership journal, transactions, rollback and worker.
- `backends.go`: UFW/firewalld/nftables/iptables adapters and command allowlist.
- `inventory.go`: read-only native firewall and listening-port snapshots, UFW parsing.
- `ssh.go`, `certbot.go`, `forward.go`: SSH listener, Certbot and IPv4 forwarding.
- `ui.go`: terminal interface; `web.go` and `web/`: authenticated localhost web panel.
- `*_test.go`, `tests/`: unit tests, isolated real-firewall lab and release smoke test.
- `vendor/`, `go.mod`, `go.sum`: pinned offline module dependencies and licenses.
- `install.sh`: checksum-verified Linux installation.
- `start.sh`, `stop.sh`: web service start/stop; firewall worker remains independent.
- `build.ps1`: patched Go 1.26.11 build, packaging and SHA-256 generation.
- `dist/`, `vpswall-*.zip`, `SHA256SUMS.txt`: ignored generated release artifacts.
- `README.md`, `CHANGELOG.md`, `THIRD_PARTY_NOTICES.txt`: usage, changes and licenses.
- `conversations/`: private local conversation snapshots; excluded from Git and releases.
