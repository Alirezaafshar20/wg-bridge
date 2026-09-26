#!/usr/bin/env bash
# WG Bridge bootstrap and lifecycle entry point.
set -Eeuo pipefail
REPO="Alirezaafshar20/wg-bridge"
REF="v0.2.1"
CORE_SHA256="0de4b71b19b5a33b8cb1fb13a83127848ac2ce03b6690011458c4a0a507fcc33"
APP_DIR="/usr/local/lib/wg-bridge"
MODE="${1:-install}"

if [[ "$MODE" == "--help" ]]; then
  echo "Usage: sudo bash install.sh [--upgrade | --uninstall | --check]"
  echo "Roles: 1) Server (Iran / entry), 2) Client (Outside / exit)."
  echo "Initialize Client (Outside) first, then pair Server (Iran)."
  echo "--upgrade replaces the manager while retaining tunnel keys and configuration."
  echo "--uninstall removes the installed tunnel and manager after confirmation."
  echo "--check verifies the manager download without installation (curl + sha256sum required)."
  exit 0
fi
case "$MODE" in
  install|--upgrade|--uninstall|--check) ;;
  *) echo "Unknown argument. Use --help." >&2; exit 1 ;;
esac
if [[ "$MODE" != "--check" && "$EUID" -ne 0 ]]; then
  echo "Run as root or with sudo." >&2; exit 1
fi
if [[ $# -gt 1 ]]; then
  echo "Use one operation at a time. See --help." >&2; exit 1
fi
# Removal is available without downloads or package repository access.
if [[ "$MODE" == "--uninstall" ]]; then
  [[ -f "$APP_DIR/wg_bridge.py" ]] || { echo "Installed manager not found." >&2; exit 1; }
  python3 "$APP_DIR/wg_bridge.py" uninstall </dev/tty
  # Also remove executable files when the installed manager predates full removal.
  if [[ ! -e /etc/wg-bridge && ! -L "$APP_DIR" ]]; then
    rm -f -- "$APP_DIR/wg_bridge.py" /usr/local/sbin/wg-bridge
    rmdir -- "$APP_DIR" 2>/dev/null || true
  fi
  exit 0
fi
TMP_INSTALL=$(mktemp -d /tmp/wg-bridge-install.XXXXXX)
trap 'rm -rf -- "$TMP_INSTALL"' EXIT
trap 'echo "WG Bridge operation failed. Inspect the error above." >&2' ERR

if [[ "$MODE" != "--check" ]]; then
  [[ -f /etc/os-release ]] || { echo "Missing os-release." >&2; exit 1; }
  # shellcheck source=/dev/null
  . /etc/os-release
  case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:22.04|ubuntu:24.04|ubuntu:26.04|debian:12|debian:13) ;;
    *) echo "Supported: Ubuntu 22.04/24.04/26.04 LTS (including point releases) or Debian 12/13 with systemd." >&2; exit 1 ;;
  esac
  [[ -d /run/systemd/system ]] || { echo "A systemd VPS/VM is required." >&2; exit 1; }
  if [[ "$MODE" == "install" && -f /etc/wg-bridge/state.json && -f "$APP_DIR/wg_bridge.py" ]]; then
    echo "Opening installed manager. Use --upgrade to install $REF without replacing keys."
    python3 "$APP_DIR/wg_bridge.py" </dev/tty
    exit 0
  fi
  if [[ "$MODE" == "--upgrade" ]]; then
    [[ -f /etc/wg-bridge/state.json && -f "$APP_DIR/wg_bridge.py" ]] || { echo "No complete installation to upgrade." >&2; exit 1; }
  fi
  printf '\n  WG BRIDGE %s | Preparing %s\n\n' "$REF" "$MODE"
  echo '  [1/3] Installing system dependencies'
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
  apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update
  apt-get -o DPkg::Lock::Timeout=120 install -y --no-install-recommends \
    ca-certificates curl python3 wireguard-tools iproute2 iptables conntrack iputils-ping kmod procps util-linux
fi

if [[ "$MODE" != "--check" ]]; then
  printf '\n  [2/3] Downloading and verifying WG Bridge\n'
fi
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
if [[ "$MODE" == "--check" ]]; then
  echo "Verified $REF. Nothing installed."; exit 0
fi
python3 -m py_compile "$TMP_INSTALL/wg_bridge.py"
if [[ "$MODE" == "--upgrade" ]]; then
  exec 9>/run/lock/wg-bridge.lock
  flock -n 9 || { echo "Another WG Bridge operation is running." >&2; exit 1; }
  # Validate persisted state with the new manager before replacing any executable.
  python3 -c 'import runpy,sys; runpy.run_path(sys.argv[1])["load"]()' "$TMP_INSTALL/wg_bridge.py"
fi
[[ ! -L "$APP_DIR" ]] || { echo "Refusing a symlinked application directory." >&2; exit 1; }
install -d -m 755 "$APP_DIR"
install -m 755 "$TMP_INSTALL/wg_bridge.py" "$APP_DIR/.wg_bridge.py.new"
mv -f -- "$APP_DIR/.wg_bridge.py.new" "$APP_DIR/wg_bridge.py"
printf '#!/bin/sh\nexec /usr/bin/python3 /usr/local/lib/wg-bridge/wg_bridge.py "$@"\n' > "$TMP_INSTALL/wg-bridge"
install -m 755 "$TMP_INSTALL/wg-bridge" /usr/local/sbin/wg-bridge
if [[ "$MODE" == "--upgrade" ]]; then
  printf '\n  [3/3] Manager upgraded to %s. Tunnel keys and configuration retained.\n' "$REF"
  echo '  Open the menu: sudo wg-bridge'
  exit 0
fi
printf '\n  [3/3] Opening installation menu\n'
SSH_SOURCE="${SSH_CLIENT:-${SSH_CONNECTION:-}}"
export WGB_SSH_PEER="${SSH_SOURCE%% *}"
python3 "$APP_DIR/wg_bridge.py" install </dev/tty
