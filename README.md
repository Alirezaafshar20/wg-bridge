# WG Bridge

**English** | [فارسی](README.fa.md)

[![Tests](https://github.com/itsalirezaw/wg-bridge/actions/workflows/test.yml/badge.svg)](https://github.com/itsalirezaw/wg-bridge/actions/workflows/test.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Forward one IPv4 service port from an Iran server to an outside server through WireGuard. Choose TCP, UDP or both. The installer suggests random available ports and lets you enter your own; `8443` below is an example. Host Internet routes, other service ports and IPv6 configuration are unchanged.

```text
User → Iran:8443 → WireGuard → Outside service:8443
```

The destination application runs on the outside server. This forwards connections; it does not select the Internet traffic of a proxy application running on Iran by its incoming port. Existing v0.1/v0.2 deployments must follow [migration](#migration-from-v01v02).

## Requirements

Ubuntu 22.04/24.04/26.04 LTS (26.04.1 included) or Debian 12/13; root; systemd; a WireGuard-capable kernel; public IPv4 on both hosts. Allow the selected service port in the Iran provider firewall and the WireGuard UDP transport port selected on Outside. The installer provisions the remaining distribution packages.

```bash
apt-get update && apt-get install -y curl ca-certificates
```

## Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/itsalirezaw/wg-bridge/main/install.sh)
```

## Configuration

1. Run the installer on **Outside**, choose **2 — Client**, confirm its public IP and WireGuard UDP port, and select the destination service port and protocol (`both`). Each suggested value is highlighted with “Press Enter to use …”; type your own value to override it.
2. Run the destination application on `0.0.0.0:8443` or `10.204.0.1:8443`, substituting your chosen port. A service bound only to `127.0.0.1` or the public IP is not reachable through the private tunnel address. This installer does not deploy the application itself.
3. Copy the complete **WGB2** pairing code. On **Iran**, choose **1 — Server**, paste the code, confirm Iran's IP and local WireGuard UDP port, and choose the public forwarding port. It defaults to the destination port when available; otherwise a free port is suggested. You can enter a different value. The pasted pairing code is visible.
4. Connect from another device to `IRAN_IP:PORT`. The full pairing code, including `WGB2.`, is required; it contains private keys and must remain secret.

The service port and WireGuard transport port have different purposes. Changing the service port does not resolve a blocked WireGuard UDP path. Iran initiates the encrypted connection to Outside. One installation supports one server pair and one port mapping.

## Management

```bash
wg-bridge
wg-bridge status
wg-bridge doctor
```

Run `wg-bridge` from any directory to open the installed menu; there is no need to run the installer again.

The menu provides status, diagnostics, restart, pairing, stop/start, port editing on Iran and complete removal. To change only Iran's public port:

```bash
wg-bridge port 9443
```

Keys and the outside service port are retained. Existing forwarded connections can be interrupted by a port change. To change the outside service port or protocol, reinstall and pair both hosts with the new selection.

Services start at boot. Stopping WireGuard leaves only the selected mapping unavailable; direct Internet and unrelated services retain their routes. Test the forwarded port from another host: connections initiated locally on Iran are not redirected.

## Upgrade

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/itsalirezaw/wg-bridge/main/install.sh) --upgrade
```

Updates compatible v0.3 installations while retaining keys and configuration. Full-routing v0.1/v0.2 installations are rejected before replacing the manager or changing the network.

## Migration from v0.1/v0.2

On **Iran**, restore direct Internet before downloading the new installer:

```bash
systemctl stop wg-quick@wgb-exit.service wg-bridge-network.service
```

On **each host**, use the installed manager to remove the old tunnel:

```bash
wg-bridge uninstall
```

Confirm `REMOVE`. This deletes the old WG Bridge tunnel and keys. Install v0.3 on Outside first, then Iran, using a **new WGB2 code**. Old WGB1 codes are incompatible. Plan for the selected service to run on Outside; a panel remaining on Iran needs a separate application-level outbound configuration.

## Uninstall

```bash
wg-bridge uninstall
```

Confirm `REMOVE`. Removal is also available in the menu or through the installer's `--uninstall` option. Owned rules, keys, interface, services and manager are removed; shared distribution packages are retained. Iran's recorded IPv4 forwarding setting is restored if its value is still owned by the tool.

## Operations

```bash
journalctl -u wg-bridge-network -u wg-quick@wgb-exit --no-pager -n 60
```

MTU: `1380`. Forwarding uses IPv4; existing host IPv6 remains independent. The outside application sees `10.204.0.2` as the client address because the mapping uses source NAT. Listen-port conflicts and overlapping tunnel subnets are rejected. Custom policy routing, nftables base chains, Docker-published ports and firewall reloads require integration review. The installer does not configure provider firewalls or protocol obfuscation.

[Network design](docs/network.md) · [Development and validation](CONTRIBUTING.md) · [Changelog](CHANGELOG.md) · [Persian video outline](docs/video-fa.md)

Created by **alirezaw** · [GitHub](https://github.com/itsalirezaw) · [YouTube @ialirezaw](https://www.youtube.com/@ialirezaw)

[MIT License](LICENSE)
