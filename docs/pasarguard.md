# PasarGuard panel setup

**English** | [فارسی](pasarguard.fa.md) · [All panel guides](panels.md)

Use the existing WG Bridge tunnel as an outbound for selected PasarGuard Xray inbounds. Users still connect to Iran; their traffic exits through Outside. No SOCKS service or additional WireGuard core is needed in the panel.

This guide is based on PasarGuard's documentation and core-editor source. UI labels vary by release; it has not been validated on every PasarGuard version.

## 1. Check the tunnel and the node

Use WG Bridge v0.4 or newer in **panel-routing-v1** mode on both servers. On the **Iran node that actually runs the user-facing Xray process**, run:

```bash
wg-bridge doctor
```

The handshake, HTTPS egress and UDP DNS checks must pass. A handshake alone is not enough. A legacy public-port-forwarding installation must first be converted as described in the [upgrade guide](../README.md#upgrade-and-convert-v03).

The Iran Xray process must be able to use source address `10.204.0.2` and interface `wgb-exit`. Installing WG Bridge on the management-panel host alone does not help a separate node. PasarGuard's official panel Compose file uses `network_mode: host`; check the actual deployment of your Xray node. A custom bridged container needs separate network integration.

## 2. Open the configuration assigned to Iran

1. Open **Nodes**, edit the Iran node and note its **Core Config** selection.
2. Open **Cores** and edit that configuration. Keep its type **Xray**.
3. In recent releases, open **Advanced → All** to edit the full JSON. Older releases may expose a JSON editor directly in the core-config dialog.
4. Copy the current JSON to a backup before editing. If other nodes share this core configuration, create a separate copy and assign it only to the intended Iran node before applying these changes.

Do not create a WireGuard-type core or a WireGuard-protocol outbound for this setup. WG Bridge already owns the kernel tunnel; the panel selects it through a `freedom` outbound.

## 3. Merge the outbound, DNS and routing settings

**The following is an integration fragment, not a complete replacement core configuration.** Keep your existing `inbounds`, users, API, policy, statistics and other settings. Merge the sections below into the existing root object; do not add duplicate `outbounds`, `dns` or `routing` keys.

- Add `wg-out` to the existing `outbounds` array. Keep existing outbounds and their exact tag names. `DIRECT` and `BLOCK` below are example names used by PasarGuard's default template.
- Keep `DIRECT` first for this selective-routing setup. Xray uses the first outbound when no routing rule matches; putting `BLOCK` first would block unmatched traffic. Selected users still go to `wg-out` through the explicit rule.
- Configure the existing `dns` object as below. Put `tag: "wg-dns"` on the **whole DNS object**, not only on one server. Plain IP resolvers use UDP port 53 by default. Review existing split-DNS, server-specific tags and hosts overrides before merging; local-mode resolvers bypass this DNS routing.
- Add the two rule objects to the existing `routing.rules` array. Keep internal API and blocking rules ahead of them, and place them before general `DIRECT` rules. Preserve any other routing settings.
- Replace `YOUR_INBOUND_TAG` with the exact `tag` from your user-facing `inbounds` array. This is not a username, UUID or port number. Tags are case-sensitive; do not select the panel API inbound.

```json
{
  "outbounds": [
    {
      "tag": "DIRECT",
      "protocol": "freedom"
    },
    {
      "tag": "wg-out",
      "protocol": "freedom",
      "sendThrough": "10.204.0.2",
      "settings": {
        "domainStrategy": "ForceIPv4"
      },
      "streamSettings": {
        "sockopt": {
          "interface": "wgb-exit",
          "domainStrategy": "ForceIPv4"
        }
      }
    },
    {
      "tag": "BLOCK",
      "protocol": "blackhole"
    }
  ],
  "dns": {
    "servers": ["8.8.8.8", "1.1.1.1"],
    "queryStrategy": "UseIPv4",
    "tag": "wg-dns"
  },
  "routing": {
    "rules": [
      {
        "type": "field",
        "inboundTag": ["wg-dns"],
        "outboundTag": "wg-out"
      },
      {
        "type": "field",
        "inboundTag": ["YOUR_INBOUND_TAG"],
        "outboundTag": "wg-out"
      }
    ]
  }
}
```

For several user inbounds, replace the second rule's list with their real tags, for example:

```json
["VLESS-IN", "TROJAN-IN", "SS-IN"]
```

The two IPv4 strategy fields cover older and newer Xray versions. Panel editors may normalize their representation. After saving, check that the outbound still has `sendThrough`, `sockopt.interface` and an IPv4 resolution strategy.

This setup sends the Xray instance's built-in DNS and selected user inbounds through Outside. Unmatched traffic keeps the first outbound, `DIRECT`; it is not a fallback for a failed `wg-out` connection. When adding another inbound later, add its tag to the user rule if it should use the tunnel. Do not put `9999` or the user's inbound port in the routing `port` field: that field matches destination ports.

## 4. Save, apply and test

1. Save the core configuration and apply it to the Iran node. Use **Restart Nodes** when saving if available, or restart the affected core/node through the panel. A shared configuration can affect several nodes.
2. Confirm that the node is connected and its core logs show no configuration or interface-binding errors.
3. Reconnect a real client, check its public IP and open sites by domain name. The exit IP should be Outside's public IPv4; also test a UDP-capable application.

Keep the client subscription/Host address pointing at Iran and its normal inbound port. Do not change it to Outside, `10.204.0.2` or the WireGuard transport port. This guide does not change the host's default Internet route. Tunnel egress is IPv4 only.

## If it still does not work

- **Handshake succeeds but doctor fails:** resolve tunnel routing/NAT or Outside connectivity before changing the panel further.
- **Doctor succeeds but the client still exits through Iran:** check the selected node's Core Config, the exact inbound tag and earlier direct rules. Confirm that changes were applied.
- **Outside IP is visible but domains fail:** check the global `wg-dns` tag, its routing rule and any old local-mode DNS servers or hosts overrides.
- **Interface not found / cannot assign address:** Xray is running on a different host or in a network namespace without `wgb-exit` / `10.204.0.2`.

Sources: [PasarGuard core configuration](https://docs.pasarguard.org/en/panel/core/), [node core selection](https://github.com/PasarGuard/panel/blob/main/dashboard/src/features/nodes/dialogs/node-modal.tsx), [advanced editor](https://github.com/PasarGuard/panel/blob/main/dashboard/src/features/core-editor/components/xray/xray-advanced-section.tsx), [official Compose file](https://github.com/PasarGuard/panel/blob/main/docker-compose.yml), [Xray DNS](https://xtls.github.io/en/config/dns.html), [Xray routing](https://xtls.github.io/en/config/routing.html).
