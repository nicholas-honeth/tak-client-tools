# tak-client-tools

Client-side tools for an [OpenTAKServer](https://github.com/brian7704/OpenTAKServer) (OTS) reached over WireGuard.

| Path | What |
|---|---|
| `tak-lan-bridge/` | **tak-lan-bridge** (v0.3.0): bridges a LAN's TAK Mesh SA multicast and/or a Meshtastic node to an OTS over TLS. Single Python file, stdlib plus optional `takproto`/`meshtastic` |
| `tools/ots-client-cert.sh` | Enrol a cert-only OTS client: key + CSR generated locally, signed by the OTS CA over SSH, `ca.pem` fetched and verified |
| `tools/install-bridge.sh` | Install the bridge as a systemd service (`/opt/tak-lan-bridge`, `/etc/tak-lan-bridge`, user `tak-bridge`) |
| `tools/run-gateway.sh` | Start/stop/status/log for a bridge run by hand from a runtime directory (laptop, WSL) |

Nothing secret lives in this repo. Configs, keys, certs and logs stay in a runtime directory on each host (see `.gitignore`).

## tak-lan-bridge

- **LAN side**: SA multicast `239.2.3.1:6969` and GeoChat `224.10.10.1:17012` (XML or TAK protocol v1 protobuf in, XML out)
- **Server side**: one TLS stream with a client cert, XML CoT
- **Meshtastic** (USB serial or TCP 4403): nodes become map markers (2525 symbols by role), one channel ⇄ a GeoChat room that works in ATAK and WinTAK, `@node text` sends a Meshtastic DM
- **Loopback**: a DM to the bridge contact is echoed. `help`, `stats` and `roomtest` are commands
- **Channel rooms**: `channel add <https://meshtastic.org/e/#… link>` in a DM to the bridge contact adds that channel to the node (free secondary slot, LoRa settings untouched) with its own GeoChat room; `channel list`, `channel remove <name>`. Registry in `channels_file` (names only). Open to every TAK user; permission checks go through `Bridge._may()` so an allowlist can be added there
- Loop protection: `_flow-tags_`, `(uid, time, type)` dedupe, multicast loopback off, own IP ignored
- Set `[lan] enabled = false` for a Meshtastic-only gateway, e.g. behind NAT

Every key is documented in `tak-lan-bridge/config.example.toml`.

Run only **one bridge per LAN**, and only one per Meshtastic node. The node's TCP API takes one client at a time.

### Requirements

Python ≥ 3.11 (`tomllib`) and `openssl`. For the bridge host: WireGuard to the OTS network (split tunnel is enough) and an OTS user with a client cert.

## Setup on a new host

```bash
git clone git@github.com:nicholas-honeth/tak-client-tools.git ~/tak-client-tools
cd ~/tak-client-tools
```

### 1. Client cert

The OTS username is the cert CN. With SSH access to the OTS host (`OTS_SSH`, required; compose dir `OTS_DIR`, default `~/tak`):

```bash
mkdir -p ~/tak-client && cd ~/tak-client
OTS_SSH=my-ots-host ~/tak-client-tools/tools/ots-client-cert.sh --create-user meshbridge-site2 meshbridge-site2
# → ~/tak-client/meshbridge-site2/{meshbridge-site2.key,meshbridge-site2.pem,ca.pem}
```

Leave out `--create-user` if the OTS user already exists. Set `OTS_DIR=path` if the compose project lives elsewhere. Run `tools/ots-client-cert.sh -h` (or read its header) for the other options.

### 2a. Systemd service (Raspberry Pi, any Debian-like host)

```bash
sudo tools/install-bridge.sh                 # add --no-meshtastic for LAN-only
sudo cp ~/tak-client/NAME/NAME.pem /etc/tak-lan-bridge/client.pem
sudo cp ~/tak-client/NAME/NAME.key /etc/tak-lan-bridge/client.key
sudo cp ~/tak-client/NAME/ca.pem   /etc/tak-lan-bridge/ca.pem
sudo chgrp tak-bridge /etc/tak-lan-bridge/* && sudo chmod 640 /etc/tak-lan-bridge/*
sudoedit /etc/tak-lan-bridge/config.toml     # [server] host (required), [bridge] name/callsign/lat/lon, [lan] interface, [meshtastic]
sudo systemctl restart tak-lan-bridge && journalctl -u tak-lan-bridge -f
```

Re-run `install-bridge.sh` after a `git pull` to update the code. Config and certs are left alone.

### 2b. By hand (laptop / WSL gateway)

```bash
cp tak-lan-bridge/config.example.toml ~/tak-client/NAME/config.toml   # point [server] cert/key/ca at the files above
tools/run-gateway.sh start ~/tak-client/NAME     # creates ./.venv on first run
tools/run-gateway.sh status ~/tak-client/NAME
tools/run-gateway.sh log ~/tak-client/NAME
tools/run-gateway.sh stop ~/tak-client/NAME
```

`start` won't start a second bridge in a runtime directory that already has one running.

## Tests

```bash
python3 tak-lan-bridge/tests/smoke_test.py eth0   # fake TLS TAK server + multicast on one interface
.venv/bin/python -I tak-lan-bridge/tests/channels_test.py   # channel add/list/remove on a stub node (needs meshtastic)
```

## License

Copyright (C) 2026 Nicholas Honeth. GNU General Public License v3.0 or later (`GPL-3.0-or-later`), see `LICENSE`.
Each source file carries an SPDX header.

The Meshtastic gateway uses the [`meshtastic`](https://github.com/meshtastic/python) library (GPL-3.0-only),
so a bridge running with it is distributed under GPLv3. [`takproto`](https://github.com/snstac/takproto) is MIT.
