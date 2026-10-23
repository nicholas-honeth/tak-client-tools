#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Nicholas Honeth
# Install tak-lan-bridge as a systemd service (Raspberry Pi OS Bookworm / Debian / Ubuntu).
# Idempotent: re-run after a git pull to update the code; config and certs are left alone.
#
# Usage: sudo tools/install-bridge.sh [--no-meshtastic]
#
# Layout: code + venv in /opt/tak-lan-bridge, config + certs in /etc/tak-lan-bridge
# (dir 750, group tak-bridge), service user tak-bridge (in dialout for a USB Meshtastic node).
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
src=$(cd "$(dirname "$0")/../tak-lan-bridge" && pwd)
pkgs=(takproto meshtastic)
[[ ${1:-} == --no-meshtastic ]] && pkgs=(takproto)

python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' || { echo "need Python >= 3.11" >&2; exit 1; }
python3 -m venv --help >/dev/null 2>&1 || apt-get install -y python3-venv

id tak-bridge >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -G dialout tak-bridge

install -d -m 755 /opt/tak-lan-bridge
install -m 644 "$src/tak_lan_bridge.py" /opt/tak-lan-bridge/
[[ -x /opt/tak-lan-bridge/venv/bin/python ]] || python3 -m venv /opt/tak-lan-bridge/venv
/opt/tak-lan-bridge/venv/bin/pip install -q --upgrade "${pkgs[@]}"

install -d -m 750 -g tak-bridge /etc/tak-lan-bridge
if [[ ! -e /etc/tak-lan-bridge/config.toml ]]; then
  install -m 640 -g tak-bridge "$src/config.example.toml" /etc/tak-lan-bridge/config.toml
  echo "Created /etc/tak-lan-bridge/config.toml: edit name/lat/lon/interface and the server section"
fi

install -m 644 "$src/tak-lan-bridge.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable tak-lan-bridge >/dev/null

missing=()
for f in client.pem client.key ca.pem; do [[ -e /etc/tak-lan-bridge/$f ]] || missing+=("$f"); done
if (( ${#missing[@]} )); then
  echo "Missing in /etc/tak-lan-bridge: ${missing[*]} (see tools/ots-client-cert.sh), then:"
  echo "  sudo chgrp tak-bridge /etc/tak-lan-bridge/*; sudo chmod 640 /etc/tak-lan-bridge/*"
  echo "  sudo systemctl restart tak-lan-bridge"
else
  systemctl restart tak-lan-bridge
  echo "Started. Logs: journalctl -u tak-lan-bridge -f"
fi
