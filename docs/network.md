# Network design

WG Bridge v0.3 forwards one IPv4 TCP/UDP port from Iran to a service running on Outside. It does not route the Iran host's general Internet traffic or infer proxy outbounds from an inbound port. Pairing input is visible. Each pair has one service mapping; TCP, UDP or both may share that port.

## Transport and addressing

The Iran host is **Server (entry)**; the outside host is **Client (exit)**. These are deployment labels. Both peers have an explicit UDP endpoint and a 25-second keepalive, allowing either to initiate. The default transport port is **9999/UDP** on both sides. Outside setup asks for Iran's public IPv4 and planned UDP port; Iran setup checks these against the pairing code before changing the network. All transport ports remain configurable. The separate service port gets a free random suggestion between 20000 and 59999; Iran reuses that destination service port if locally available. Neither a default nor randomization guarantees network reachability.

Interface `wgb-exit` has MTU 1380. Iran uses `10.204.0.2/30`; Outside uses `10.204.0.1/30`. Each peer permits only the other's private `/32`. Both configs use `Table = off`; assigning the interface address supplies the connected private route. No default routes, policy rules, packet marks or dummy interfaces are installed. Host IPv6 is untouched.

The WGB2 pairing payload carries the target service port/protocol and keys. v0.3.1 adds the paired Iran IPv4 and UDP port together as optional fields; new managers accept v0.3.0 codes, while new codes require v0.3.1 on Iran. It is encoded, not encrypted. One code provisions one pair. WGB1 belongs to the old full-routing architecture and is rejected explicitly.

## Packet path

On Iran, a `nat/PREROUTING` rule matches the chosen protocol and destination port, ingress WAN interface, and a destination local to the host. DNAT sends that connection to `10.204.0.1:TARGET_PORT`. A matching forwarding rule permits only that mapping toward `wgb-exit`. SNAT to `10.204.0.2` guarantees a symmetric reply through Iran. The outside application therefore sees the private Iran address, not the original client IP. Payload and TLS are passed through unchanged.

Outside accepts the target port from its private peer, plus tunnel ICMP diagnostics. Other incoming traffic from the WireGuard interface and forwarding through it are rejected. The target application must bind the private address or `0.0.0.0`; a public-IP-only or loopback-only listener is not reachable through this mapping. Outside's public service access remains governed by its existing firewall.

There is no `OUTPUT` redirect: Iran-local requests and downloads retain their normal route. Existing IPv4/IPv6 default routes, unrelated forwarded LAN traffic and inbound services keep their paths. Only Iran's `net.ipv4.ip_forward` is enabled; its previous value is recorded and restored on removal if still equal to the managed value.

## Failure and lifecycle

When the peer is unreachable, only the selected mapping times out. If the local WG interface disappears, a mapping-specific reject rule prevents DNAT packets from escaping through the WAN default route. Stopping WireGuard leaves these rules active. Other traffic does not depend on tunnel availability.

The network service precedes `wg-quick@wgb-exit`. Rules use scoped `WGB_IN`, `WGB_FWD`, `WGB_DNAT`, `WGB_NAT`, `WGB_MSS` chains. DNAT is attached after forwarding guards and removed first during cleanup. Before removing the fallback guard, cleanup deletes only conntrack entries matching the old protocol/public port and private reply tuple; it never flushes the shared connection table. No existing global chain is flushed. Uninstall removes owned files, rules, interface, units and keys, retaining shared packages. Interrupted setup rolls back owned network changes.

Changing Iran's public port validates availability before changing rules, preserves keys and the target port, and restores the old mapping on failure. Active forwarded connections can be interrupted. The protocol and outside target remain fixed for the pair; changing them requires reinstalling/re-pairing both hosts.

Outside's `peer IRAN_IP IRAN_WG_PORT` command updates its saved peer endpoint and pairing code without rotating keys or changing service ports. An active interface is restarted; an inactive one remains inactive. On failure, the original configuration and state are restored. Upgrading the manager alone preserves old port defaults and configurations; run this command to opt an existing Outside installation into bidirectional initiation. It never edits the Iran host remotely.

## Integration boundaries

Forwarding applies to public IPv4 ingress through the selected WAN interface. There is no IPv6 port forwarding, local hairpin redirect, transparent proxy selection, user accounting or end-user VPN provisioning. Provider firewalls must permit Iran's chosen service port and the WireGuard UDP ports on both hosts.

Active firewalld, overlapping private subnets and existing IPv4 policy routing are refused. An occupied local socket is detected, but a Docker-published port or custom NAT redirect can exist without a host listener; these configurations need explicit review. Separate nftables base chains may drop packets even after iptables accepts them. Firewall reloads can remove the rules; restart the manager's tunnel after reviewing such changes. WireGuard requires a working UDP path and does not obfuscate its protocol.

## Migration and verification

v0.1/v0.2 used default-route policy and different pairing semantics. An in-place upgrade is refused before replacing the old manager. Stop both WG Bridge services on Iran to restore direct Internet, uninstall the old deployment on both hosts, then install Outside followed by Iran with a fresh WGB2 code. See the README for commands.

CI on Ubuntu 22.04, 24.04 and 26.04 exercises real WireGuard forwarding, TCP/UDP selection, unequal and changed ports, peer failure, stopped interfaces, restart and cleanup. Assertions preserve ordinary IPv4/IPv6 routes, outbound access, unrelated forwarded LAN traffic and inbound sessions. A 300-request/40-worker correctness exercise is not a throughput or user-capacity guarantee.

## References

- [WireGuard routing and namespaces](https://www.wireguard.com/netns/)
- [wg-quick manual](https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8)
- [iptables extensions: DNAT, SNAT and conntrack](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html)
