# Changelog

## 0.4.0 — 2026-09-26

- Add panel egress through source/interface-selected kernel WireGuard without installing SOCKS or editing panels.
- New WGB3 installs provide Outside NAT and Iran policy routing with terminal failure routes; keep host defaults unchanged and block tunnel-bound IPv6.
- Convert existing v0.3 pairs with key/port preservation, backups and rollback. Keep WGB2 legacy management available.
- Add panel instructions, DNS/routing examples, expanded doctor checks and English/Persian recording documentation.
- Test TCP/UDP/DNS, both socket binding methods, strict rp_filter, failures, cleanup and lifecycle conversions. Reset owned systemd start-limit state for intentional restarts.

## 0.3.1 — 2026-09-26

- Default new WireGuard transport listeners to UDP 9999; keep both peer ports editable and service ports independent.
- Configure Outside with Iran's public endpoint and enable 25-second keepalives on both peers so either side can initiate.
- Carry Iran's planned endpoint in WGB2 pairing; reject mismatched Iran setup before network changes. Continue accepting older WGB2 codes.
- Add Outside menu/CLI peer editing with key preservation, refreshed pairing codes and rollback on restart failure. Upgrades retain existing ports and configs.
- Test Outside-initiated handshakes, default/custom ports, peer edits and rollback on Ubuntu 22.04, 24.04 and 26.04.

## 0.3.0 — 2026-09-26

- Replace full-host routing with one configurable IPv4 port mapping from Iran to Outside. Suggest random available service/transport ports; select TCP, UDP or both.
- Keep host default routes, policy rules and IPv6 unchanged; confine failure to the selected mapping.
- Add WGB2 pairing with visible input, target service diagnostics and Iran port editing from the menu/CLI.
- Explain every setup step and highlight Enter-to-accept defaults; open the grouped menu directly with `wg-bridge`.
- Reject legacy full-routing upgrades before mutation; document stop, uninstall and re-pair migration.
- Verify direct IPv4/IPv6 access, existing services, LAN forwarding, custom/protocol-specific ports and unavailable peers alongside installer lifecycle tests.

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
