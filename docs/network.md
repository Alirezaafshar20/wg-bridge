# Network design

v0.4 defaults to selective **panel-routing-v1**. The panel stays on Iran; selected local application sockets use a WireGuard interface to reach the Internet through Outside. There is no public DNAT mapping, local SOCKS daemon, userspace inter-server proxy or panel configuration mutation.

## Link

Deployment roles remain Server (Iran/entry) and Client (Outside/exit). Both have explicit endpoints and keepalive 25. UDP defaults to 9999, is configurable on each peer and stays separate from panel inbound ports. The link is `wgb-exit`, MTU 1380, Iran `10.204.0.2/30`, Outside `10.204.0.1/30`. WGB3 identifies panel-mode pairing; private material is protected by filesystem permissions but the pairing code itself is not encrypted.

Both configurations use `Table = off`. Iran's peer allows `0.0.0.0/0`; Outside permits only Iran's `10.204.0.2/32`. The permitted destinations do not install a host-wide default route.

## Selective routing and failure behavior

Iran owns table 51888. Priority 18880 selects source `10.204.0.2/32`; priority 18881 selects sockets bound to `wgb-exit`. An unreachable IPv4 default at metric 32767 remains while the manager is installed. A wg-quick PostUp adds a metric-10 default through WireGuard to that table. Interface removal automatically removes the usable route; the terminal unreachable route prevents fall-through to the host WAN default.

An IPv6 interface-selection rule points to an unreachable default in the same private table. This release does not provide tunnel IPv6 egress. Main IPv4/IPv6 default routes and host resolver settings remain unchanged. A panel must use IPv4 DNS resolution and route its DNS explicitly; WG Bridge cannot intercept DNS issued by an unbound system resolver on a panel's behalf.

Only the Iran tunnel interface gets `rp_filter=2` after it starts, so Internet replies are accepted even if the main-table reverse route points to WAN. Global/default reverse-path settings are preserved. MSS clamping covers local Iran OUTPUT and forwarded replies on Outside.

## Firewall and exit

Owned IPv4 chains are WGB_IN, WGB_OUT, WGB_FWD, WGB_NAT, WGB_MSS and WGB_OMSS. Existing global chains are never flushed. Iran OUTPUT rejects packets sourced from the tunnel IP that would leave a different interface, and rejects unrelated sources using the tunnel. Iran accepts only tunnel ping and related/established replies. Forwarding through Iran's tunnel interface is blocked; this mode handles local panel sockets.

Outside enables IPv4 forwarding, accepts only authenticated Iran private-source traffic from WireGuard to WAN, permits corresponding replies, and masquerades that source on WAN. Other tunnel input/forwarding is rejected. No inbound application needs to listen on Outside. Only the WireGuard UDP transport must be accessible there. The recorded forwarding value is restored on uninstall if it still equals the value set by WG Bridge.

The network oneshot unit starts before WireGuard and stays active when only WireGuard is stopped. Stopping or flushing the network guard service directly is not the supported stop operation; use the menu's Stop. External firewall flushes, custom policy rules and independent nftables chains require integration and revalidation.

## Lifecycle

Fresh setup refuses address overlaps, occupied UDP sockets, active firewalld, conflicting routing resources and unsupported custom IPv4 policy routing. Panel and WireGuard must share the host network namespace. Bridged Docker panels are not automatically integrated.

Upgrading replaces only the manager. `wg-bridge routing` explicitly converts v0.3: Outside first, then Iran. Each side backs up old state/config, stops its owned services, removes old rules, writes the new mode and restarts. Errors restore old state/config and forwarding settings. Existing keys, private addresses and transport ports are retained. Repeated conversion is a no-op. The public port mapping is removed. v0.1/v0.2 full-routing deployments require the documented uninstall/reinstall path.

The manager continues to handle WGB2 public-port pairs for compatibility; new Outside installations issue WGB3. Menu peer editing preserves keys and restarts only an active link. Rapid intentional lifecycle operations reset systemd's start-limit state for the two owned units.

## Verification

CI uses real WireGuard in isolated network namespaces for legacy forwarding and panel source/interface routing. It checks TCP, UDP, DNS, fragmented UDP payloads, strict reverse-path filtering, tunnel loss, interface removal, restart and cleanup. Existing SSH-like TCP sessions, ordinary IPv4/IPv6 egress, inbound HTTP and unrelated LAN forwarding must remain usable. Concurrent HTTP requests test correctness, not a promised production capacity.

Installer tests run only on disposable CI VMs: both roles, retained configuration on upgrade, conversion and injected rollback failures, stop/start guards, cancelled uninstall and complete removal. Supported Ubuntu CI versions are 22.04, 24.04 and 26.04. Debian is accepted but does not have a full lifecycle matrix.

[WireGuard routing](https://www.wireguard.com/netns/) · [wg-quick manual](https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8) · [Panel integration](panels.md)
