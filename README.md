# WG Bridge

**English** | [فارسی](README.fa.md)

[![Tests](https://github.com/itsalirezaw/wg-bridge/actions/workflows/test.yml/badge.svg)](https://github.com/itsalirezaw/wg-bridge/actions/workflows/test.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Route selected panel outbounds from an Iran server to an outside Internet exit through kernel WireGuard. Keep users, inbound ports and accounting in your existing panel. Host default routes stay in place, so SSH and unrelated services keep their normal Internet connection.

WG Bridge configures the link, selective routing, outside NAT and tunnel failure guards. Configure your panel manually to use source **10.204.0.2** and interface **wgb-exit**. No SOCKS listener, extra proxy protocol or panel is installed. Multiple panel inbounds can share this one outbound.

WireGuard transport defaults to **9999/UDP** on both servers; choose another free UDP port during installation if needed. Panel inbound ports are independent of this transport port.

## Video tutorial (Persian)

[Watch the WG Bridge tutorial on YouTube](https://www.youtube.com/watch?v=UAeH-ErkCGc)

## Requirements

Ubuntu 22.04/24.04/26.04 LTS (including 26.04.1) or Debian 12/13; root; systemd; a WireGuard-capable kernel; public IPv4 on both hosts. Allow the selected WireGuard UDP port on both provider firewalls. Allow your own panel inbound ports on Iran. Remaining dependencies are installed automatically.

```bash
apt-get update && apt-get install -y curl ca-certificates
```

## Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/itsalirezaw/wg-bridge/main/install.sh)
```

## Connect the servers

1. On **Outside**, choose **2 — Client**. Confirm its public IPv4 and WireGuard UDP port. Enter the **Iran public IPv4** and its planned WireGuard UDP port. Press Enter to accept a highlighted default.
2. Copy the complete **WGB3** pairing code, including `WGB3.`. It contains private keys: keep it private and hide it in recordings. Use it on one Iran server only.
3. On **Iran**, run the same installer and choose **1 — Server**. Paste the code visibly, then confirm Iran's IP and UDP port. They must match the values entered on Outside.
4. Run `wg-bridge doctor` on Iran. It checks the handshake, source route, HTTPS through Outside and UDP DNS through the tunnel. A handshake alone does not prove Internet access.
5. Configure the panel below. WG Bridge does not edit panel databases, configs or user accounts.

Both peers use an explicit endpoint and a 25-second keepalive. One installation manages one pair. Port selection cannot overcome every provider or network restriction; a reachable UDP path is required.

## Connect your panel

For **3x-ui and other Xray panels**, create an outbound with:

- Protocol: `freedom`
- Tag: `wg-out`
- Send Through: `10.204.0.2`
- Sockopts / Interface: `wgb-exit`
- IPv4 resolution strategy: `ForceIPv4`
- Redirect and Dialer Proxy: empty; Mark: `0`

Route the chosen **user inbound tags** to `wg-out`. Preserve the panel API and blocking rules. Configure DNS to use this outbound as well. Adding an outbound alone does not select users or change DNS routing.

**[Panel setup, DNS and JSON examples](docs/panels.md)** · **[راهنمای فارسی پنل و DNS](docs/panels.fa.md)**

Other engines can use the tunnel if they support binding an outbound to a source IP or network interface. The guide includes sing-box field names; panel UI support varies. Host services and Docker panels using host networking can access the interface. A panel inside a separate Docker bridge namespace needs additional network integration and is not covered by automatic setup.

This release provides **IPv4 egress**. IPv6 destinations are not forwarded; interface-bound IPv6 is blocked. Existing host IPv6 remains available to unrelated services. There is no direct fallback for traffic correctly bound to the tunnel. Panel rules selecting other outbounds remain the administrator's choice.

## Management

```bash
wg-bridge
wg-bridge status
wg-bridge doctor
wg-bridge panel
```

Run `wg-bridge` from any directory. The menu includes status, diagnostics, restart, stop/start, pairing, panel settings and uninstall. Services start at boot. Stopping WireGuard leaves the routing guards installed; only tunnel-selected traffic becomes unavailable.

To correct Iran's endpoint, run on **Outside**:

```bash
wg-bridge peer IRAN_PUBLIC_IPV4 IRAN_WIREGUARD_UDP_PORT
```

This preserves keys and Outside's UDP port, updates the pairing code and restarts an active tunnel. It does not remotely change Iran's listening port.

## Upgrade and convert v0.3

Run on **Outside first, then Iran**:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/itsalirezaw/wg-bridge/main/install.sh) --upgrade
wg-bridge routing
```

`--upgrade` replaces only the manager. `wg-bridge routing` converts the old public-port mapping to panel egress, backs up the old state/configuration under `/etc/wg-bridge/before-panel-*`, and restarts the tunnel. Keys, private link addresses and existing WireGuard ports are retained. The old public forwarding rule is removed on Iran. Both sides must be converted before panel egress works; existing peers need no new pairing code. Do not convert an installation that still needs its old public mapping.

On panel-routing installations, repeating `wg-bridge routing` is a no-op. The `9999` default never changes an existing port automatically. Older WGB2 pairs remain manageable in legacy port-forward mode until explicitly converted.

Full-routing v0.1/v0.2 cannot be upgraded in place. On Iran, stop `wg-quick@wgb-exit` and `wg-bridge-network` to restore direct access; then use the old manager's `wg-bridge uninstall` on each host and install the current release Outside first, with a new WGB3 code. WGB1 codes are incompatible.

## Uninstall

```bash
wg-bridge uninstall
```

Confirm `REMOVE`. Owned firewall rules, policy rules, private table entries, interface, services, keys and manager are removed. The saved IPv4 forwarding value is restored if it still has the value WG Bridge set. Shared distribution packages remain. Remove or disable the tunnel outbound in your panel separately.

## Operations

```bash
journalctl -u wg-bridge-network -u wg-quick@wgb-exit --no-pager -n 60
```

MTU is `1380`. Table `51888` and priorities `18880/18881` are reserved for the selected source/interface. Conflicts are rejected before installation or conversion. Existing custom routing and independent nftables/firewall managers need manual integration. Do not flush firewall rules while the tunnel is in use; rerun restart and doctor after firewall changes. WG Bridge does not configure provider firewalls or protocol obfuscation.

[Network design](docs/network.md) · [Release validation](docs/validation.md) · [Development](CONTRIBUTING.md) · [Changelog](CHANGELOG.md) · [Persian recording guide](docs/video-fa.md)

Created by **alirezaw** · [GitHub](https://github.com/itsalirezaw) · [YouTube @ialirezaw](https://www.youtube.com/@ialirezaw)

[MIT License](LICENSE)
