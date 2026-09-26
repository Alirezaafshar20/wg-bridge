# Development

WG Bridge uses Bash, Python's standard library, distribution WireGuard tools and systemd. There are no pip dependencies.

## Validation

On a supported Linux host with the runtime dependencies installed:

```bash
shellcheck install.sh
bash -n install.sh
python3 -m unittest discover -s tests -v
sudo python3 tests/integration.py
bash install.sh --check
```

The integration suite creates isolated network namespaces and exercises real WireGuard, IPv4/IPv6, NAT, TCP/UDP, forwarded traffic, incoming connections, tunnel loss, restart and cleanup. It does not modify host routing or firewall rules. Its 300 HTTP requests with 40 workers check correctness, not production capacity.

`tests/lifecycle.py` modifies its host and is restricted to explicitly opted-in disposable GitHub Actions VMs. CI runs the installer, systemd units, upgrade, rollback and uninstall on Ubuntu 22.04 and 24.04. Debian 12/13 are accepted by the installer; a complete Debian systemd lifecycle is not covered by this CI matrix.

## Releases

Keep `wg_bridge.py`'s `VERSION`, the installer's `REF`, README download URLs, changelog and release notes aligned. Refresh the installer's `CORE_SHA256` from the final LF-encoded `wg_bridge.py`. Validate the checksum, network suite and lifecycle suite before tagging; published tags are immutable.

Manager upgrades must preserve keys and the active WireGuard configuration. Changes to persistent state require backward-compatible loading or an explicit migration. New firewall/routing resources require scoped removal and rollback coverage.

## Reports

Include the OS, kernel, WireGuard version, deployment role and the failing operation. Provide redacted diagnostic output and reproduction steps. Exclude pairing codes, private keys, `state.json` and WireGuard configuration files.
