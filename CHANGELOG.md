# Changelog

## 0.2.2 — 2026-09-26

- Update installer downloads, documentation, badges and creator links to `itsalirezaw/wg-bridge` following the GitHub account rename.
- Retain Ubuntu 26.04 support and the branded menus from 0.2.1; published tags remain unchanged.

## 0.2.1 — 2026-09-26

- Accept Ubuntu 26.04 LTS, including 26.04.1. Ubuntu point releases retain `VERSION_ID=26.04` in `/etc/os-release`.
- Add Ubuntu 26.04 to real network and installer lifecycle CI.
- Refresh installation and management menus with terminal-aware colors, clearer role descriptions and alirezaw's GitHub/YouTube links.
- Use `bash <(curl -fsSL ...)` for installation and upgrades in both language guides. The bootstrap downloads a version-pinned, checksum-verified manager.

## 0.2.0 — 2026-09-26

- Deployment roles: **Server (Iran / entry)** and **Client (Outside / exit)**. WireGuard initiation and the traffic path are preserved.
- Internal `entry`/`exit` roles with backward-compatible loading of v0.1 state and pairing codes.
- `install.sh --upgrade` validates existing state and atomically replaces the manager without regenerating keys or restarting the tunnel.
- Complete removal of owned tunnel configuration, keys, services, firewall/routing rules, manager and launcher. Available from the menu, `wg-bridge uninstall` and `install.sh --uninstall`.
- Concise English and Persian documentation with separate Requirements and Install commands.
- Lifecycle coverage for upgrade, legacy role mapping, cancelled removal and complete uninstall.

## 0.1.0 — 2026-09-26

- Initial two-server WireGuard deployment with automatic dependencies and systemd startup.
- IPv4/IPv6 forwarding, NAT, incoming connection reply routing and traffic blocking while the tunnel is down.
- Pairing code exchange, status, diagnostics, restart, stop/start and tunnel removal.
- Real network namespace tests and Ubuntu installer lifecycle CI.
