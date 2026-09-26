#!/usr/bin/env bash
# WG Bridge installer: no root password, API token or pip packages required.
set -Eeuo pipefail
REPO="Alirezaafshar20/wg-bridge"
REF="v0.1.0"
CORE_SHA256="f6a07c11ff91b81f70f4d91ce951b7f1ddb43d14873a85380811766725dbd0ae"
APP_DIR="/usr/local/lib/wg-bridge"

if [[ "${1:-}" == "--help" ]]; then
  echo "Usage: sudo bash install.sh [--check]"
  echo "Run on outside first: 1) Server. Then Iran: 2) Client."
  echo "--check downloads/verifies the manager without installing it. Requires curl + sha256sum."
  exit 0
fi
if [[ "${1:-}" != "--check" && "$EUID" -ne 0 ]]; then
  echo "Run this installer with sudo or as root." >&2
  exit 1
fi
if [[ -n "${1:-}" && "${1:-}" != "--check" ]]; then
  echo "Unknown argument. Use --help." >&2; exit 1
fi
TMP_INSTALL=$(mktemp -d /tmp/wg-bridge-install.XXXXXX)
trap 'rm -rf -- "$TMP_INSTALL"' EXIT
trap 'echo "Installation failed. No success has been claimed. Inspect the error above." >&2' ERR

if [[ "${1:-}" != "--check" ]]; then
  [[ -f /etc/os-release ]] || { echo "Missing os-release." >&2; exit 1; }
  # Trusted operating-system file, not downloaded input.
  # shellcheck source=/dev/null
  . /etc/os-release
  case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:22.04|ubuntu:24.04|debian:12|debian:13) ;;
    *) echo "Supported: Ubuntu 22.04/24.04 or Debian 12/13 with systemd." >&2; exit 1 ;;
  esac
  [[ -d /run/systemd/system ]] || { echo "A systemd VPS/VM is required." >&2; exit 1; }
  [[ -t 0 || -r /dev/tty ]] || { echo "An interactive SSH terminal is required." >&2; exit 1; }
  if [[ -f /etc/wg-bridge/state.json && -f "$APP_DIR/wg_bridge.py" ]]; then
    echo "Existing installation: opening its menu; keys and routing are preserved."
    python3 "$APP_DIR/wg_bridge.py" </dev/tty
    exit 0
  fi
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
  echo "Installing official distribution packages (no system upgrade or reboot)..."
  apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update
  apt-get -o DPkg::Lock::Timeout=120 install -y --no-install-recommends \
    ca-certificates curl python3 wireguard-tools iproute2 iptables conntrack iputils-ping kmod procps
fi

# A version pin and embedded checksum prevent partial/mismatched manager downloads.
SCRIPT_DIR=""
if [[ -f "${BASH_SOURCE[0]:-}" ]]; then
  SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fi
if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/wg_bridge.py" ]]; then
  cp -- "$SCRIPT_DIR/wg_bridge.py" "$TMP_INSTALL/wg_bridge.py"
else
  curl --proto '=https' --tlsv1.2 -fsSL --retry 2 --connect-timeout 10 --max-time 90 \
    "https://raw.githubusercontent.com/$REPO/$REF/wg_bridge.py" -o "$TMP_INSTALL/wg_bridge.py"
fi
printf '%s  %s\n' "$CORE_SHA256" "$TMP_INSTALL/wg_bridge.py" | sha256sum -c -
if [[ "${1:-}" == "--check" ]]; then
  echo "Verified $REF. Nothing installed."; exit 0
fi
python3 -m py_compile "$TMP_INSTALL/wg_bridge.py"
install -d -m 755 "$APP_DIR"
install -m 755 "$TMP_INSTALL/wg_bridge.py" "$APP_DIR/wg_bridge.py"
printf '#!/bin/sh\nexec /usr/bin/python3 /usr/local/lib/wg-bridge/wg_bridge.py "$@"\n' > "$TMP_INSTALL/wg-bridge"
install -m 755 "$TMP_INSTALL/wg-bridge" /usr/local/sbin/wg-bridge
SSH_SOURCE="${SSH_CLIENT:-${SSH_CONNECTION:-}}"
export WGB_SSH_PEER="${SSH_SOURCE%% *}"
python3 "$APP_DIR/wg_bridge.py" install </dev/tty
