#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Nicholas Honeth
# Run tak-lan-bridge in the background from a runtime directory (laptop / non-systemd use).
# The directory holds config.toml, the certs it points to, bridge.log and loopback.log.
#
# Usage: tools/run-gateway.sh start|stop|restart|status|log [RUNDIR]
#   RUNDIR defaults to ~/tak-client/meshbridge
# The venv is <repo>/.venv (created on first start, with takproto + meshtastic).
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
script=$repo/tak-lan-bridge/tak_lan_bridge.py
venv=$repo/.venv
cmd=${1:?usage: $0 start|stop|restart|status|log [RUNDIR]}
rundir=$(cd "${2:-$HOME/tak-client/meshbridge}" && pwd)

# Bridges running from RUNDIR, however they were started (matched by working directory)
pids() {
  local p
  for p in $(pgrep -f tak_lan_bridge.py || true); do
    [[ $(readlink "/proc/$p/cwd" 2>/dev/null) == "$rundir" ]] && echo "$p"
  done
  return 0
}

start() {
  if [[ -n $(pids) ]]; then echo "already running: $(pids | xargs)"; return; fi
  if [[ ! -x $venv/bin/python ]]; then
    python3 -m venv "$venv"
    "$venv/bin/pip" install -q -r "$repo/tak-lan-bridge/requirements.txt"
  fi
  cd "$rundir"
  nohup "$venv/bin/python" -I "$script" -c "$rundir/config.toml" >> bridge.log 2>&1 &
  sleep 2
  [[ -n $(pids) ]] && echo "started $(pids | xargs), log: $rundir/bridge.log" || { tail -20 bridge.log; exit 1; }
}

stop() {
  local p; p=$(pids)
  [[ -z $p ]] && { echo "not running"; return; }
  kill $p
  for _ in 1 2 3 4 5 6 7 8 9 10; do [[ -z $(pids) ]] && break; sleep 0.5; done
  echo "stopped $p"
}

case $cmd in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status) p=$(pids); [[ -n $p ]] && { echo "running: $(echo $p)"; grep ' stats ' "$rundir/bridge.log" | tail -1; } || echo "not running" ;;
  log) exec tail -f "$rundir/bridge.log" ;;
  *) echo "unknown command $cmd" >&2; exit 1 ;;
esac
