# Network design

The outside host is `Server`; the Iran host is `Client`. These names describe tunnel establishment, not the roles of panel users. The client initiates UDP, and the server learns its endpoint. One pairing code provisions exactly one pair.

## Resources owned by WG Bridge

- Interface `wgb-exit`, MTU 1380. Outside `10.204.0.1/30`, entry `10.204.0.2/30`; IPv6 `fd42:204::1/64` and `::2/64`.
- Entry-only dummy interface `wgb-block`, a local discard destination used while the tunnel is down.
- Entry route table and WireGuard fwmark `52031`; policy priorities `12127`–`12131`.
- Connection mark bit `0x40000000` records incoming WAN connections. Restoring that bit does not overwrite WireGuard's transport mark.
- Dedicated `WGB_*` chains in iptables/ip6tables filter, nat and mangle, with explicit jumps at the top of relevant chains. Existing global chains are never flushed. FORWARD allowances override the host default forwarding policy only for this tunnel.
- `wg-bridge-network.service`, the standard `wg-quick@wgb-exit` unit and its owned dependency drop-in.
- `/etc/wg-bridge`, `/etc/wireguard/wgb-exit.conf`, `/usr/local/lib/wg-bridge/wg_bridge.py` and `/usr/local/sbin/wg-bridge`.

IPv4/IPv6 forwarding is enabled. Loose IPv4 reverse-path checking accommodates the asymmetric encrypted/cleartext interfaces. WAN IPv6 `accept_ra=2` preserves SLAAC/default router advertisements with forwarding enabled. Previous sysctl values are recorded and restored on uninstall only if still equal to the values this tool set. Installing other routing services afterward requires reviewing these shared settings before uninstalling.

## Routing and NAT

New ordinary Internet connections from the entry, and forwarded flows from networks behind it, select table 52031. Source NAT on the entry makes the outside peer's AllowedIPs a single entry address per family. Outside masquerading supplies public egress; no provider static routes are needed. TCP MSS is clamped toward the tunnel. UDP and other IP traffic use the same tunnel.

Incoming WAN connections get a connection mark; their replies consult the main table. This preserves SSH and the response path of locally running panel/proxy listeners. Existing inbound conntrack entries are marked at installation as well. A separate proxy connection to a destination website is a fresh connection without that bypass mark.

Exceptions consult the existing main route table:

- local destinations (Linux's existing priority-zero local table);
- marked responses to incoming WAN connections;
- the administrator's SSH source address captured during installation;
- the outside tunnel endpoint IPv4;
- non-default routes already present in the main table, including connected/provider/private networks;
- WireGuard UDP transport carrying its fwmark.

The SSH source exception remains until uninstall, including new egress to that same IP. These exceptions mean “all traffic” is not literal. Applications that intentionally bind special devices or use custom routing/marks need separate validation. Inbound WAN forwarding/DNAT and TProxy are outside the first release's automatic configuration scope.

A persistent default to the dummy discard interface `wgb-block`, metric 32767, remains in table 52031 when the WG interface disappears. Active WireGuard defaults have a lower metric. Filter rules reject output/forwarding to the dummy; the interface itself cannot transmit externally. This supplies an initial route so the OUTPUT connection-mark restoration can still reroute incoming SSH replies onto WAN. An unreachable route would fail before OUTPUT and break these replies. Stopping or losing the interface cannot fall through to the main default for traffic assigned to the tunnel. The fallback does not detect peer failure: packets then stay assigned to the unresponsive tunnel and time out. Stopping only wg-quick retains the block; uninstalling the network service deliberately removes the policy.

Outside IPv6 support is inferred from a default route and checked during client diagnosis. If absent, entry output/forwarding toward the IPv6 Internet is rejected. Internal link IPv6 and the main-table exceptions still exist. Disabled kernel IPv6 is not supported. NAT66 is used when exit IPv6 is available.

## Persistence and integration boundaries

The network unit runs before wg-quick and after network-online, UFW/firewalld and Docker at boot. An active firewalld is refused. Rules are idempotent, but external firewall reloads can remove/reorder custom chains. Run Restart from the manager after such a change. Rules from unrelated nftables base chains can still drop packets even after iptables ACCEPT; a custom firewall requires explicit integration.

Existing alternate routing policies, overlapping link subnets, owned names/files or a busy UDP port cause installation to stop rather than overwrite them. One WAN interface is selected from the lowest-metric IPv4 default route. Multi-WAN and nonstandard routing environments are not automatically handled.

No quotas, per-user accounting, panels, multiple exit selection, obfuscation or end-user VPN configuration are included. The tunnel's aggregate transfer counters are not per-panel-user billing.

## Capacity

Each peer handles many concurrent flows; each user does not need a peer here. For example, 300 users averaging 2 Mbps at the same time require roughly 600 Mbps payload before tunnel overhead. Idle accounts consume very little compared with simultaneous downloads. Measure sustained throughput, packet loss, CPU, conntrack utilization and latency on the actual two-server route. Namespace correctness tests do not measure a provider's network or demonstrate 300-user capacity.

## References

- [Official WireGuard routing and namespaces](https://www.wireguard.com/netns/)
- [wg-quick manual](https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8)
- [WireGuard quick start](https://www.wireguard.com/quickstart/)
