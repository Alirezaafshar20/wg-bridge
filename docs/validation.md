# v0.4 validation record

Validated on 2026-09-26. The core release candidate is commit `473bc5b433535834d31046e31b2c2b1aaeac7c3e`.

## Automated Linux validation

[Successful CI run](https://github.com/itsalirezaw/wg-bridge/actions/runs/36258022327): Ubuntu 22.04, 24.04 and 26.04 passed syntax/checksum, 15 unit tests, real WireGuard network tests and installer lifecycle tests.

Network fixtures checked both legacy public forwarding and new panel routing: source-address binding, interface binding, TCP, 4096-byte UDP payloads, DNS, strict reverse-path filtering, unavailable peer, removed interface, restart and cleanup. Each mode exercised 300 HTTP requests using 40 workers. Unrelated host IPv4/IPv6 access, LAN forwarding, incoming services and an existing inbound TCP session remained usable.

Lifecycle fixtures checked fresh setup on both roles, preserved state on upgrade, legacy conversion, injected rollback failures on both sides, retained routing guards during stop, service restart, cancelled removal and complete uninstall. A rapid-start limit encountered on Ubuntu 26.04 was addressed by resetting the owned units' failure state before intentional restart/conversion; the final matrix passed.

## Live pair and Xray validation

An existing v0.3.1 pair on Ubuntu 22.04 (Iran) and Ubuntu 26.04.1 (Outside) was converted to panel mode. Existing keys and UDP 9999 were retained. Main IPv4/IPv6 routes were compared against pre-conversion snapshots; dynamic IPv6 RA expiry timestamps were excluded from that comparison.

`wg-bridge doctor` confirmed a fresh link, correct source route, HTTPS with Outside's public exit address and UDP DNS through WireGuard.

The already installed Xray **26.9.9** was tested with the documented Freedom outbound, DNS tag and inbound-routing rules in a separate temporary process. A local test input existed only for the test and was removed afterward; no proxy daemon is shipped or installed by WG Bridge. The production panel service and database were not modified.

- The real Xray binary accepted the JSON configuration.
- HTTPS requested by domain exited with Outside's address.
- A UDP DNS request through Xray succeeded.
- Packet capture observed DNS inside WireGuard and no plaintext DNS to the test resolver on Iran's WAN during the bounded test.
- Stopping Iran's WireGuard blocked that Xray outbound while a direct host HTTPS request remained reachable through Iran. The control request used a previously resolved address to avoid unrelated intermittent host-DNS timeouts.
- Restarting WireGuard restored Xray TCP and UDP access. Temporary processes, listeners, captures and files were removed.

This verifies the tunnel and the documented Xray integration. Each deployment still needs its own panel's user-inbound selection and DNS configuration, followed by a real client test. sing-box field examples reference upstream documentation; a complete sing-box/panel matrix was not run. Debian lifecycle, bridged Docker integration, IPv6 egress, production throughput and arbitrary network filtering are outside this validation claim.
