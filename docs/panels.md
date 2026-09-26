# Panel integration

[فارسی](panels.fa.md)

First establish a **panel-routing-v1** pair on v0.4 or newer and run `wg-bridge doctor` on Iran. A legacy v0.3 port-forward pair must be converted on Outside and Iran with `wg-bridge routing`. No SOCKS server is installed; `127.0.0.1:1080` is not a WireGuard endpoint.

## 3x-ui / Xray

In Outbounds, add the following **single outbound object** using the JSON tab. Do not replace the whole Xray configuration with it. The source address belongs to Iran, not Outside. Keep the built-in `direct` and `blocked` entries.

```json
{
  "tag": "wg-out",
  "protocol": "freedom",
  "sendThrough": "10.204.0.2",
  "settings": {"domainStrategy": "ForceIPv4"},
  "streamSettings": {
    "sockopt": {
      "interface": "wgb-exit",
      "domainStrategy": "ForceIPv4"
    }
  }
}
```

`settings.domainStrategy` serves older cores; current Xray places the resolution strategy in `sockopt.domainStrategy`. The JSON includes both for panel/core compatibility. In the form, use Protocol `freedom`, Tag `wg-out`, Send Through `10.204.0.2`, enable Sockopts and set Interface `wgb-exit`. Leave Redirect and Dialer Proxy empty, Mark `0`, TProxy off. A WireGuard-protocol outbound would create a separate userspace WireGuard peer; it is not how this kernel tunnel is selected.

### DNS

In the panel's Xray DNS configuration, use an IP-address resolver that follows routing, tag its requests, and request IPv4 answers. Merge this **DNS object** into the panel's DNS section:

```json
{
  "servers": ["1.1.1.1", "8.8.8.8"],
  "queryStrategy": "UseIPv4",
  "tag": "wg-dns"
}
```

Route `wg-dns` to `wg-out` using the rule below. Avoid `localhost` and local-mode DNS transports in this setup: they bypass the intended DNS routing. This example routes the Xray instance's built-in DNS through Outside; specialized split-DNS configurations need their own review. It does not change the host's resolver. Client applications making their own DNS requests use the selected user outbound like other traffic.

### Routing

Keep the panel API routing first and retain your existing blocking rules. Before general direct rules, add these **rule objects** to the existing rules list:

```json
{
  "type": "field",
  "inboundTag": ["wg-dns"],
  "outboundTag": "wg-out"
}
```

```json
{
  "type": "field",
  "inboundTag": ["YOUR_USER_INBOUND_TAG_1", "YOUR_USER_INBOUND_TAG_2"],
  "outboundTag": "wg-out"
}
```

Replace the placeholder tags with the actual tags of your enabled user inbounds. Do not include `api`. Select all desired inbounds in the panel's Routing UI, regardless of their port numbers. The routing `port` field means the **destination port**, not the incoming listener port; do not use it to select users. Remove unused placeholder tags. Save and apply/restart Xray using the panel controls. An earlier matching direct rule will take precedence, so review ordering.

## Other panels / engines

Xray panels that accept custom outbounds and routing can use the same objects. The engine must run in the host network namespace with permission to bind the interface. Docker `network_mode: host` exposes the host interface; a bridged container needs separate integration. Do not point a bridged container at the host's loopback address.

For sing-box, the corresponding direct outbound fields are:

```json
{
  "type": "direct",
  "tag": "wg-out",
  "bind_interface": "wgb-exit",
  "inet4_bind_address": "10.204.0.2"
}
```

This is an outbound fragment, not a full sing-box configuration. Route selected inbounds to it and configure the installed version's DNS server to dial through `wg-out`, with IPv4 resolution. DNS syntax differs between sing-box releases. UI support is panel-dependent; this example is based on upstream field definitions and is not a claim that every panel/version has been tested.

## Verify before recording or serving users

1. `wg-bridge doctor` on Iran should report handshake, HTTPS and UDP DNS success. The observed public exit should be Outside's IP.
2. Connect a real client to a user inbound. Check its observed public IP and browse by domain name; test a UDP-capable application as well.
3. Briefly stop the tunnel using `wg-bridge`. The selected client should lose Internet access, while the server's direct SSH/Internet stays available. Start the tunnel again.

Tunnel egress is IPv4 only. IPv6 literal destinations fail rather than fall back through the Iran WAN; ordinary host IPv6 stays independent. Leave the direct outbound available for API/internal use, but do not configure a direct fallback or an earlier direct rule for users who must stay on the tunnel.

References: [Xray source address](https://xtls.github.io/en/config/outbound.html), [Xray interface binding](https://xtls.github.io/en/config/transports/sockopt.html), [Xray DNS](https://xtls.github.io/en/config/dns.html), [Xray routing](https://xtls.github.io/en/config/routing.html), [sing-box dial fields](https://sing-box.sagernet.org/configuration/shared/dial/).
