# WG Bridge

**English** | [فارسی](README.fa.md)

A small WireGuard **server-to-server** tunnel. Run the same installer on an outside exit (1: Server) and an Iran entry (2: Client). Existing proxy-panel users connect to the entry as before; new Internet connections from the entry leave through the exit. No end-user profiles, panel, account database or subscription management.

[Network details](docs/network.md) · [Video guide (Persian)](docs/video-fa.md)

```text
Users <-> Panel / Xray on Iran entry <-> WireGuard <-> Outside exit <-> Internet
```

## Install

Root access, a systemd VPS, a WireGuard-capable kernel, enabled kernel IPv6, and public IPv4 on both hosts are required. Installer targets Ubuntu 22.04/24.04 and Debian 12/13. Permit UDP 51830 (or your chosen port) in the outside provider's firewall. IPv6 Internet on the outside is optional.

Run on **outside first**, then **Iran**, as root:

```bash
apt-get update && apt-get install -y curl ca-certificates && curl --proto '=https' --tlsv1.2 -fSL https://raw.githubusercontent.com/Alirezaafshar20/wg-bridge/v0.1.0/install.sh -o /root/wg-bridge-install.sh && bash /root/wg-bridge-install.sh
```

Dependencies come from official distribution repositories. The manager download is version-pinned and SHA-256 checked; this verifies consistency, not a detached publisher signature.

### 1. Outside server first

1. Run the installer and select **`1) Server`**.
2. Confirm the detected public IPv4 address.
3. Choose the tunnel UDP port; the default is `51830`. Open that UDP port in your provider's firewall too.
4. Copy the **secret pairing code** printed at the end.

### 2. Iran server second

1. Run the same installer and select **`2) Client`**.
2. Paste the outside server's pairing code. Input is hidden; seeing no characters while pasting is normal.
3. Confirm the Iran server's public IPv4 and local WireGuard UDP port (default `51831`).
4. Check the handshake and outgoing-IP results, then test a real user through your existing panel.
5. Open a new SSH session to the Iran server before closing the original one.

The pairing code contains the entry private key and PSK. It is **not encrypted**. Keep it private, hide it in recordings, and use it for exactly one entry server. No SSH password is requested or exchanged. Use a fresh pair on two fresh hosts for a separate deployment.

Keep your initial SSH session open and test a **new** SSH connection and real proxy-panel traffic before closing it. Provider console access is useful for any routing change.

## Operate

`sudo wg-bridge` opens status, diagnose, restart, pairing, stop, start and uninstall. The same installer opens the existing menu without regenerating keys or upgrading. Units start at boot.

`sudo wg-bridge doctor` tests active services, a recent client handshake and outgoing IP. `sudo wg-bridge uninstall` asks for `REMOVE`, removes owned settings and restores ordinary entry Internet access. Shared packages remain installed.

Stopping the tunnel retains a default route to a local discard interface in its routing table: affected Internet traffic cannot fall back to the entry WAN. Incoming management replies and documented exclusions still work. Start restores the tunnel. Uninstall removes the policy and this block deliberately.

## Scope and limits

One peer carries many simultaneous IP flows. User count alone cannot establish capacity: bandwidth, CPU, packet rate, conntrack limits, MTU, loss and congestion matter. The project does not promise a user limit or throughput figure. Tests include 300 HTTP requests using 40 workers; these are correctness tests, not a production capacity benchmark.

Plain WireGuard uses UDP and does not hide its protocol. If UDP/WireGuard is filtered, the installer cannot make that route reachable. The simple Server/Client experience is inspired by [paqet](https://github.com/LivingG0D/paqet), with independent code and a different transport.

This is routed Layer 3 IP connectivity with encryption, not Ethernet bridging. Standard locally running proxy services are the intended entry use case. Existing policy-routing VPNs and active firewalld are rejected. Custom nftables, TProxy, explicit application marks/routes, multi-WAN and inbound DNAT to other machines require separate integration. Cloud firewalls cannot be changed by this script. See [all exclusions and persistence behavior](docs/network.md).

The first release should be evaluated with your own panel and traffic before broad deployment. Ubuntu/Debian support in the installer is distinct from performance validation on every provider.

## Diagnostics and development

```bash
sudo journalctl -u wg-bridge-network -u wg-quick@wgb-exit --no-pager -n 60
python3 -m unittest discover -s tests -v
sudo python3 tests/integration.py
bash install.sh --check
```

Integration tests create isolated network namespaces, run real WireGuard and test TCP/UDP, IPv4/IPv6, forwarding, existing/new inbound TCP connections, tunnel failure, restart and cleanup. They do not alter host routes/firewall rules. Root and the installer dependencies are needed; systemd is not needed for the namespace test itself.

Private state: `/etc/wg-bridge/state.json` and `/etc/wireguard/wgb-exit.conf`, mode 0600. IP detection/diagnostics contact `api.ipify.org` / `api64.ipify.org`. Do not attach private state or pairing codes to issues.

[MIT license](LICENSE).
