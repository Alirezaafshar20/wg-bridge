# WG Bridge

**English** | [فارسی](README.fa.md)

[![Tests](https://github.com/itsalirezaw/wg-bridge/actions/workflows/test.yml/badge.svg)](https://github.com/itsalirezaw/wg-bridge/actions/workflows/test.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Routed WireGuard transport between an Iran ingress server and an external egress client. A single peer pair carries the outgoing traffic of services and proxy panels running on the Iran host.

```text
Users → Server (Iran / ingress) ⇄ WireGuard ⇄ Client (Outside / egress) → Internet
```

## Requirements

Ubuntu 22.04/24.04/26.04 LTS (26.04.1 included) or Debian 12/13; root access; systemd; a WireGuard-capable kernel with IPv6 enabled; public IPv4 on both hosts. Permit outbound UDP from Iran to the outside endpoint and inbound UDP on the outside tunnel port (default `51830`). The installer provisions the remaining distribution packages.

```bash
apt-get update && apt-get install -y curl ca-certificates
```

## Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/itsalirezaw/wg-bridge/main/install.sh)
```

## Configuration

- **1 — Server (Iran):** ingress host, existing panel and user management.
- **2 — Client (Outside):** Internet egress host.

Initialize **Client (Outside)** first, then supply its pairing code to **Server (Iran)**. These labels identify deployment roles; the Iran peer initiates the WireGuard transport toward the outside endpoint. The pairing code contains private key material and is valid for one server pair.

## Management

```bash
wg-bridge
wg-bridge status
wg-bridge doctor
```

The menu provides status, diagnostics, restart, pairing, stop, start and complete removal. Services start at boot. Stopping the tunnel keeps affected Internet traffic blocked; incoming management replies and documented routing exceptions remain available.

## Upgrade

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/itsalirezaw/wg-bridge/main/install.sh) --upgrade
```

Updates the manager while retaining keys, WireGuard configuration and running connections. Legacy v0.1 role names are mapped to their existing ingress/egress function.

## Uninstall

```bash
wg-bridge uninstall
```

Confirm with `REMOVE`. Removal is also available in the menu or through the installer’s `--uninstall` option. It removes the tunnel, keys, owned firewall/routing rules, systemd configuration, manager and launcher; recorded network settings are restored where still owned. Shared distribution packages remain installed.

## Operations

```bash
journalctl -u wg-bridge-network -u wg-quick@wgb-exit --no-pager -n 60
```

Default MTU: `1380`. IPv6 egress uses NAT66 when available; otherwise affected IPv6 Internet traffic is blocked. Existing policy-routing VPNs and active firewalld are rejected. Custom nftables, TProxy, multi-WAN and inbound DNAT require separate integration. WireGuard requires a working UDP path and does not provide protocol obfuscation.

[Network design and routing exceptions](docs/network.md) · [Development and validation](CONTRIBUTING.md) · [Changelog](CHANGELOG.md) · [Persian video outline](docs/video-fa.md)

Created by **alirezaw** · [GitHub](https://github.com/itsalirezaw) · [YouTube @ialirezaw](https://www.youtube.com/@ialirezaw)

[MIT License](LICENSE)
