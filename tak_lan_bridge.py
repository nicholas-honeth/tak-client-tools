#!/usr/bin/env python3
"""tak-lan-bridge: bridge a LAN's TAK Mesh SA multicast to a TAK server and back.

LAN side:    SA multicast 239.2.3.1:6969 and GeoChat multicast 224.10.10.1:17012
             (XML or TAK protocol v1 mesh protobuf in, XML out).
Server side: one streaming connection (TLS with a client cert, or plain TCP) carrying XML CoT.
Optional:    a Meshtastic node on USB serial or TCP. Mesh nodes with a position become map
             markers (refreshed from the node database), broadcast texts on one channel go to a
             GeoChat room, and messages posted in that room are sent to the mesh.
             Direct messages to the bridge contact are a loopback/debug channel: they are logged and
             echoed, and "@<node> text" sends a Meshtastic direct message (replies come back there).
             The LAN side can be switched off ([lan] enabled = false) to run as a pure
             Meshtastic gateway, e.g. on a laptop behind NAT.

Loop protection: a _flow-tags_ marker on every event this bridge forwards, a (uid, time, type)
dedupe cache, multicast loopback off, and packets from our own LAN address are ignored.

Prototype. See the vault note "TAK LAN Bridge Pi" for the spec.
"""
import argparse
import asyncio
import collections
import fcntl
import logging
import socket
import ssl
import struct
import sys
import time
import tomllib
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

__version__ = "0.3.0"
log = logging.getLogger("tak-lan-bridge")

MESH_HEADER = b"\xbf\x01\xbf"
SERVER_ENDPOINT = "*:-1:stcp"  # how a server-connected ATAK advertises itself
ALL_CHAT = "All Chat Rooms"

# Meshtastic device role -> CoT type (MIL-STD-2525 via ATAK). Neutral: public nodes are not our units.
# Override per role in [meshtastic.role_types]; roles not listed use cot_type.
ROLE_TYPES = {
    "CLIENT": "a-n-G-U-U-S-R",          # signal unit, radio
    "CLIENT_MUTE": "a-n-G-U-U-S-R",
    "CLIENT_HIDDEN": "a-n-G-U-U-S-R",
    "CLIENT_BASE": "a-n-G-U-U-S-R",
    "ROUTER": "a-n-G-U-U-S-R-W",        # signal unit, radio relay
    "ROUTER_LATE": "a-n-G-U-U-S-R-W",
    "ROUTER_CLIENT": "a-n-G-U-U-S-R-W",
    "REPEATER": "a-n-G-U-U-S-R-W",
    "SENSOR": "a-n-G-E-S",              # ground equipment, sensor
    "TRACKER": "a-n-G-E",               # ground equipment
    "LOST_AND_FOUND": "a-n-G-E",
    "TAK": "a-n-G-U-C-I",               # infantry: a person with ATAK + the Meshtastic plugin
    "TAK_TRACKER": "a-n-G-U-C-I",
}
SIOCGIFADDR = 0x8915


# ---------------------------------------------------------------- helpers

def iface_ipv4(name):
    """IPv4 address of a network interface (Linux)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        packed = fcntl.ioctl(s.fileno(), SIOCGIFADDR, struct.pack("256s", name[:15].encode()))
    return socket.inet_ntoa(packed[20:24])


def parse_hostport(text):
    host, port = text.rsplit(":", 1)
    return host, int(port)


def cot_time(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def ms_to_cot_time(ms):
    return cot_time(datetime.fromtimestamp(ms / 1000, timezone.utc))


def parse_cot_time(text):
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None


def utcnow():
    return datetime.now(timezone.utc)


def new_event(uid, cot_type, how, lat, lon, stale_after, hae=9999999.0, ce=9999999.0, le=9999999.0):
    now = utcnow()
    ev = ET.Element("event", version="2.0", uid=uid, type=cot_type, how=how,
                    time=cot_time(now), start=cot_time(now), stale=cot_time(now + stale_after))
    ET.SubElement(ev, "point", lat=f"{lat:.7f}", lon=f"{lon:.7f}",
                  hae=str(hae), ce=str(ce), le=str(le))
    ET.SubElement(ev, "detail")
    return ev


def detail_of(ev):
    d = ev.find("detail")
    if d is None:
        d = ET.SubElement(ev, "detail")
    return d


def argb_int(hex_color):
    """"#RRGGBB" or "#AARRGGBB" -> the signed 32-bit ARGB int ATAK uses in CoT colors."""
    h = hex_color.lstrip("#")
    v = int(h if len(h) == 8 else "ff" + h, 16)
    return v - (1 << 32) if v >= 1 << 31 else v


def geochat_event(sender_uid, callsign, text, lat=0.0, lon=0.0, room_id=ALL_CHAT, room_name=None,
                  members=()):
    """GeoChat message in the shape ATAK sends it. Default: All Chat Rooms. With room_id/room_name
    it is a named group chat; ATAK opens a conversation for an unknown room id on first receipt,
    and replies go back to the room id (members are the chatgrp uids after the sender)."""
    msg_id = str(uuid.uuid4())
    room_name = room_name or room_id
    ev = new_event(f"GeoChat.{sender_uid}.{room_id}.{msg_id}", "b-t-f", "h-g-i-g-o",
                   lat, lon, timedelta(days=1))
    d = detail_of(ev)
    chat = ET.SubElement(d, "__chat", parent="RootContactGroup", groupOwner="false",
                         messageId=msg_id, chatroom=room_name, id=room_id, senderCallsign=callsign)
    uids = {"uid0": sender_uid}
    for i, m in enumerate(members or ([room_id] if room_id == ALL_CHAT else []), start=1):
        uids[f"uid{i}"] = m
    ET.SubElement(chat, "chatgrp", id=room_id, **uids)
    ET.SubElement(d, "link", uid=sender_uid, type="a-f-G-U-C", relation="p-p")
    remarks = ET.SubElement(d, "remarks", source=f"BAO.F.ATAK.{sender_uid}", to=room_id,
                            time=ev.get("time"))
    remarks.text = text
    return ev


def proto_to_event(data):
    """TAK protocol v1 (mesh header) -> XML <event> element, or None."""
    try:
        import takproto
    except ImportError:
        return None
    msg = takproto.parse_proto(bytearray(data))
    if msg is None or not msg.HasField("cotEvent"):
        return None
    ce = msg.cotEvent
    ev = ET.Element("event", version="2.0", uid=ce.uid, type=ce.type, how=ce.how,
                    time=ms_to_cot_time(ce.sendTime), start=ms_to_cot_time(ce.startTime),
                    stale=ms_to_cot_time(ce.staleTime))
    ET.SubElement(ev, "point", lat=repr(ce.lat), lon=repr(ce.lon), hae=repr(ce.hae),
                  ce=repr(ce.ce), le=repr(ce.le))
    d = ET.SubElement(ev, "detail")
    det = ce.detail
    if det.xmlDetail:
        for child in ET.fromstring(f"<detail>{det.xmlDetail}</detail>"):
            d.append(child)
    if det.HasField("contact"):
        c = ET.SubElement(d, "contact", callsign=det.contact.callsign)
        if det.contact.endpoint:
            c.set("endpoint", det.contact.endpoint)
    if det.HasField("group"):
        ET.SubElement(d, "__group", name=det.group.name, role=det.group.role)
    if det.HasField("precisionLocation"):
        ET.SubElement(d, "precisionlocation", geopointsrc=det.precisionLocation.geopointsrc,
                      altsrc=det.precisionLocation.altsrc)
    if det.HasField("status"):
        ET.SubElement(d, "status", battery=str(det.status.battery))
    if det.HasField("takv"):
        t = det.takv
        ET.SubElement(d, "takv", device=t.device, platform=t.platform, os=t.os, version=t.version)
    if det.HasField("track"):
        ET.SubElement(d, "track", speed=repr(det.track.speed), course=repr(det.track.course))
    return ev


def parse_datagram(data):
    """Raw multicast payload -> <event> element or None."""
    if data.startswith(MESH_HEADER):
        return proto_to_event(data)
    if data.lstrip()[:1] == b"<":
        ev = ET.fromstring(data)
        return ev if ev.tag == "event" else None
    return None


# ---------------------------------------------------------------- LAN multicast

class _McastRx(asyncio.DatagramProtocol):
    def __init__(self, bridge, label):
        self.bridge, self.label = bridge, label

    def datagram_received(self, data, addr):
        self.bridge.on_lan(data, addr, self.label)

    def error_received(self, exc):
        log.warning("multicast %s error: %s", self.label, exc)


def mcast_rx_socket(group, port, lan_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind((group, port))  # Linux: binding to the group filters out other groups on this port
    mreq = socket.inet_aton(group) + socket.inet_aton(lan_ip)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    s.setblocking(False)
    return s


def mcast_tx_socket(lan_ip, ttl, loop):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(lan_ip))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1 if loop else 0)
    return s


# ---------------------------------------------------------------- Meshtastic

class MeshtasticLink:
    """Owns the meshtastic interface. Its callbacks run on meshtastic's thread and
    are handed to the asyncio loop."""

    def __init__(self, bridge, cfg, loop):
        from pubsub import pub
        self.bridge, self.cfg, self.loop = bridge, cfg, loop
        self.last_send = 0.0
        pub.subscribe(self._on_receive, "meshtastic.receive")
        if cfg.get("host"):
            import meshtastic.tcp_interface
            self.iface = meshtastic.tcp_interface.TCPInterface(cfg["host"])
        else:
            import meshtastic.serial_interface
            self.iface = meshtastic.serial_interface.SerialInterface(devPath=cfg.get("device"))
        my = getattr(self.iface, "myInfo", None)
        self.my_num = getattr(my, "my_node_num", None)
        log.info("meshtastic connected, my node %s, %d nodes in its database",
                 self.my_num, len(self.iface.nodes or {}))

    def _on_receive(self, packet, interface):
        self.loop.call_soon_threadsafe(self.bridge.on_mesh_packet, packet)

    def node(self, node_id):
        return (self.iface.nodes or {}).get(node_id) or {}

    def node_name(self, node_id):
        user = self.node(node_id).get("user") or {}
        return user.get("longName") or user.get("shortName") or node_id

    def nodes(self):
        return list((self.iface.nodes or {}).items())

    async def send_text(self, text, channel=0):
        await self.loop.run_in_executor(None, lambda: self.iface.sendText(text, channelIndex=channel))

    async def send_dm(self, text, dest_num):
        """Direct message with wantAck. Returns the packet id; the ack/nak arrives as a
        ROUTING_APP packet with decoded.requestId == that id."""
        pkt = await self.loop.run_in_executor(
            None, lambda: self.iface.sendText(text, destinationId=dest_num, wantAck=True))
        return pkt.id

    def find_nodes(self, query):
        """Match "!a1b2c3d4" / "a1b2c3d4", a short name or a long name (case-insensitive)."""
        q = query.strip().lower()
        hits = []
        for node_id, node in self.nodes():
            user = node.get("user") or {}
            if q in (node_id.lower(), node_id.lstrip("!").lower(),
                     (user.get("shortName") or "").lower(), (user.get("longName") or "").lower()):
                hits.append((node_id, node))
        return hits

    def close(self):
        try:
            self.iface.close()
        except Exception:  # best effort on shutdown
            pass


# ---------------------------------------------------------------- bridge

class Bridge:
    def __init__(self, cfg):
        self.cfg = cfg
        b, lan, srv = cfg["bridge"], cfg["lan"], cfg["server"]
        self.name = b["name"]
        self.flow_tag = f"tak-lan-bridge-{self.name}"
        self.uid = f"LANBRIDGE-{self.name}"
        self.dedupe_s = float(b.get("dedupe_seconds", 30))
        self.lan_enabled = lan.get("enabled", True)
        self.sa_group = parse_hostport(lan.get("sa_group", "239.2.3.1:6969"))
        self.chat_group = parse_hostport(lan.get("chat_group", "224.10.10.1:17012"))
        self.ignore_own_ip = lan.get("ignore_own_ip", True)
        self.lan_ip, self.tx = None, None
        if self.lan_enabled:
            self.lan_ip = lan.get("address") or iface_ipv4(lan["interface"])
            self.tx = mcast_tx_socket(self.lan_ip, int(lan.get("ttl", 1)), lan.get("multicast_loop", False))
        self.srv = srv
        up, down = cfg.get("uplink", {}), cfg.get("downlink", {})
        self.rewrite_endpoint = up.get("rewrite_endpoint", True)
        self.allow_types = tuple(down.get("allow_type_prefixes", ["a-", "b-t-f", "b-m-p", "u-d-", "b-a-"]))
        self.deny_uids = tuple(down.get("deny_uid_prefixes", []))
        self.min_interval = float(down.get("min_interval_seconds", 5))
        self.mesh_cfg = m = cfg.get("meshtastic", {})
        self.mesh = None
        self.mesh_channel = int(m.get("channel_index", 0))
        room = m.get("chatroom", ALL_CHAT)
        self.mesh_room_name = room
        self.mesh_room_id = room if room == ALL_CHAT else m.get("chatroom_id", f"MESHTASTIC-{room}")
        self.mesh_max_age = timedelta(minutes=float(m.get("marker_max_age_minutes", 180)))
        # "dot": ATAK spot-map marker (small coloured dot, own "Spot Map" overlay group);
        # "symbol": a 2525 symbol of cot_type (e.g. the neutral green square a-n-G)
        self.mesh_style = m.get("marker_style", "symbol")
        self.mesh_dot_argb = argb_int(m.get("dot_color", "#67EA94"))   # Meshtastic green
        self.role_types = {**ROLE_TYPES, **m.get("role_types", {})}
        if "relay_cot_type" in m:   # v0.3 config key
            for r, t in ROLE_TYPES.items():
                if t == "a-n-G-U-U-S-R-W" and r not in m.get("role_types", {}):
                    self.role_types[r] = m["relay_cot_type"]
        self.callsign = b.get("callsign", self.uid)
        self.pending_dm = {}     # mesh packet id -> (atak uid, atak callsign, node_id, sent monotonic)
        self.dm_peer = {}        # mesh node_id -> (atak uid, atak callsign) that last wrote to it
        self.last_loopback = None
        self.loop_log = None
        if b.get("loopback_log"):
            self.loop_log = logging.getLogger("tak-lan-bridge.loopback")
            h = logging.FileHandler(b["loopback_log"])
            h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
            self.loop_log.addHandler(h)
            self.loop_log.propagate = False   # _loop_log already writes to the main log
        self.to_server = asyncio.Queue(maxsize=int(srv.get("queue_size", 1000)))
        self.seen = {}
        self.last_down = {}
        self.stats = collections.Counter()
        self.connected = False

    # ---- common filters

    def _is_dup(self, ev):
        now = time.monotonic()
        if len(self.seen) > 10000:
            self.seen = {k: t for k, t in self.seen.items() if t > now}
        key = (ev.get("uid"), ev.get("time"), ev.get("type"))
        if self.seen.get(key, 0) > now:
            return True
        self.seen[key] = now + self.dedupe_s
        return False

    def _has_our_tag(self, ev):
        tags = ev.find("detail/_flow-tags_")
        return tags is not None and self.flow_tag in tags.attrib

    def _tag(self, ev):
        d = detail_of(ev)
        tags = d.find("_flow-tags_")
        if tags is None:
            tags = ET.SubElement(d, "_flow-tags_")
        tags.set(self.flow_tag, cot_time(utcnow()))

    def _enqueue_server(self, ev):
        if self.to_server.full():  # keep the newest when the server is down
            self.to_server.get_nowait()
            self.stats["server_queue_dropped"] += 1
        self.to_server.put_nowait(ev)

    def _send_lan(self, ev):
        if not self.lan_enabled:
            return
        group = self.chat_group if ev.get("type", "").startswith("b-t-f") else self.sa_group
        try:
            self.tx.sendto(ET.tostring(ev), group)
            self.stats["to_lan"] += 1
        except OSError as e:
            log.warning("multicast send failed: %s", e)

    # ---- LAN -> server

    def on_lan(self, data, addr, label):
        self.stats[f"lan_rx_{label}"] += 1
        if self.ignore_own_ip and addr[0] == self.lan_ip:
            return
        try:
            ev = parse_datagram(data)
        except ET.ParseError as e:
            self.stats["lan_bad"] += 1
            log.debug("bad datagram from %s: %s", addr[0], e)
            return
        if ev is None:
            self.stats["lan_unparsed"] += 1
            return
        if ev.get("type", "").startswith("t-x") or self._has_our_tag(ev) or self._is_dup(ev):
            self.stats["lan_dropped"] += 1
            return
        if self.rewrite_endpoint:
            contact = ev.find("detail/contact")
            if contact is not None and contact.get("endpoint"):
                contact.set("endpoint", SERVER_ENDPOINT)
        self._tag(ev)
        self._enqueue_server(ev)
        self.stats["lan_to_server"] += 1
        log.debug("LAN %s -> server: %s %s", addr[0], ev.get("type"), ev.get("uid"))
        if ev.get("type", "").startswith("b-t-f") and self.mesh_cfg.get("chat_from_lan", True):
            self._chat_to_mesh(ev)

    # ---- server -> LAN

    def on_server(self, raw):
        self.stats["server_rx"] += 1
        try:
            ev = ET.fromstring(raw)
        except ET.ParseError:
            self.stats["server_bad"] += 1
            return
        cot_type, uid = ev.get("type", ""), ev.get("uid", "")
        if (cot_type.startswith("t-x") or self._has_our_tag(ev)
                or not cot_type.startswith(self.allow_types) or uid.startswith(self.deny_uids)
                or self._is_dup(ev)):
            self.stats["server_dropped"] += 1
            return
        is_chat = cot_type.startswith("b-t-f")
        if not is_chat:
            now = time.monotonic()
            if now - self.last_down.get(uid, -1e9) < self.min_interval:
                self.stats["server_rate_limited"] += 1
                return
            self.last_down[uid] = now
        if is_chat and self._is_dm_to_us(ev):
            self.on_loopback(ev)
            return
        self._tag(ev)
        self._send_lan(ev)
        log.debug("server -> LAN: %s %s", cot_type, uid)
        if is_chat:
            self._chat_to_mesh(ev)

    # ---- Meshtastic

    def on_mesh_packet(self, packet):
        dec = packet.get("decoded") or {}
        port = dec.get("portnum")
        if self.mesh is None:
            return
        self.stats[f"mesh_rx_{port or 'ENCRYPTED'}"] += 1   # what the node passes us, by port
        if port == "ROUTING_APP":
            return self._on_routing(packet)
        if packet.get("from") == self.mesh.my_num:
            return
        node_id = packet.get("fromId") or f"!{packet.get('from', 0):08x}"
        if port == "TEXT_MESSAGE_APP" and packet.get("to") == self.mesh.my_num:
            return self._mesh_dm_in(node_id, dec.get("text", ""))
        if port == "POSITION_APP":
            self.stats["mesh_position_rx"] += 1
            ev = self._mesh_marker(node_id, dec.get("position") or {}, utcnow(), packet)
            if ev is None:
                return
            self.stats["mesh_pli"] += 1
        elif port == "TEXT_MESSAGE_APP" and packet.get("toId") == "^all":
            if int(packet.get("channel", 0)) != self.mesh_channel:
                self.stats["mesh_chat_other_channel"] += 1
                return
            ev = self._mesh_chat(node_id, dec.get("text", ""))
            self.stats["mesh_chat"] += 1
            log.info("mesh chat %s: %s", self.mesh.node_name(node_id), dec.get("text", ""))
        else:
            return
        self._forward_mesh(ev)

    def _forward_mesh(self, ev):
        self._tag(ev)
        self._enqueue_server(ev)
        if self.mesh_cfg.get("to_lan", True):
            self._send_lan(ev)

    def _mesh_chat(self, node_id, text):
        uid = f"MESHTASTIC-{node_id.lstrip('!')}"
        name = self.mesh.node_name(node_id)
        if self.mesh_room_id == ALL_CHAT:
            return geochat_event(uid, name, text)
        return geochat_event(uid, name, text, room_id=self.mesh_room_id, room_name=self.mesh_room_name,
                             members=[self.uid])

    def _mesh_marker(self, node_id, pos, heard, packet=None):
        """A mesh node as a map marker (not a TAK contact: no endpoint, no team).
        Stale = last heard + marker_max_age_minutes, so silent nodes fade out on their own."""
        lat = pos.get("latitude", pos.get("latitudeI", 0) * 1e-7)
        lon = pos.get("longitude", pos.get("longitudeI", 0) * 1e-7)
        if not lat and not lon:
            return None
        stale = heard + self.mesh_max_age - utcnow()
        if stale <= timedelta(0):
            return None
        node = self.mesh.node(node_id)
        user = node.get("user") or {}
        uid = f"MESHTASTIC-{node_id.lstrip('!')}"
        dot = self.mesh_style == "dot"
        role = str(user.get("role", "CLIENT"))
        if dot:
            cot_type = "b-m-p-s-m"
        else:
            cot_type = self.role_types.get(role) or self.mesh_cfg.get("cot_type", "a-n-G-U-U-S-R")
        ev = new_event(uid, cot_type, "m-g", lat, lon, stale, hae=pos.get("altitude", 9999999.0))
        ev.set("start", cot_time(heard))
        d = detail_of(ev)
        if dot:
            ET.SubElement(d, "usericon", iconsetpath=f"COT_MAPPING_SPOTMAP/b-m-p-s-m/{self.mesh_dot_argb}")
            ET.SubElement(d, "color", argb=str(self.mesh_dot_argb))
        ET.SubElement(d, "contact", callsign=user.get("longName") or user.get("shortName") or node_id)
        bits = [f"Meshtastic {node_id}"]
        if user.get("shortName"):
            bits.append(f"short {user['shortName']}")
        if user.get("hwModel"):
            bits.append(str(user["hwModel"]))
        bits.append("LOST AND FOUND" if role == "LOST_AND_FOUND" else f"role {role}")
        hops = node.get("hopsAway")
        if packet and packet.get("hopStart") is not None and packet.get("hopLimit") is not None:
            hops = packet["hopStart"] - packet["hopLimit"]
        if hops is not None:
            bits.append(f"hops {hops}")
        snr = (packet or {}).get("rxSnr", node.get("snr"))
        if snr is not None:
            bits.append(f"SNR {snr} dB")
        batt = (node.get("deviceMetrics") or {}).get("batteryLevel")
        if batt is not None:
            bits.append("powered" if batt > 100 else f"battery {batt}%")
        bits.append("heard " + heard.astimezone().strftime("%Y-%m-%d %H:%M"))
        bits.append(f"via {self.name}")
        bits.append(f"DM: '@{node_id} text' to {self.callsign}")
        ET.SubElement(d, "remarks").text = ", ".join(bits)
        ET.SubElement(d, "precisionlocation", geopointsrc="GPS", altsrc="GPS")
        return ev

    async def mesh_sweep_loop(self):
        """Publish every node in the node database that has a position and was heard recently.
        Fills the map at start-up and keeps markers alive between (infrequent) position packets."""
        interval = float(self.mesh_cfg.get("sweep_interval_seconds", 300))
        while True:
            n, roles = 0, collections.Counter()
            for node_id, node in self.mesh.nodes():
                last = node.get("lastHeard") or (node.get("position") or {}).get("time")
                if not last:
                    continue
                heard = datetime.fromtimestamp(last, timezone.utc)
                ev = self._mesh_marker(node_id, node.get("position") or {}, heard)
                if ev is not None:
                    self._forward_mesh(ev)
                    n += 1
                    roles[str((node.get("user") or {}).get("role", "CLIENT"))] += 1
            self.stats["mesh_sweep_markers"] = n
            log.info("mesh sweep: %d node markers published, roles %s", n, dict(roles.most_common()))
            await asyncio.sleep(interval)

    def _chat_to_mesh(self, ev):
        if self.mesh is None or not self.mesh_cfg.get("chat_to_mesh", True):
            return
        chat = ev.find("detail/__chat")
        remarks = ev.find("detail/remarks")
        if chat is None or remarks is None:
            return
        if chat.get("id") != self.mesh_room_id and not (
                chat.get("id") == ALL_CHAT and self.mesh_cfg.get("all_chat_to_mesh", False)):
            return
        link = ev.find("detail/link")
        if link is not None and link.get("uid", "").startswith("MESHTASTIC-"):
            return
        now = time.monotonic()
        if now - self.mesh.last_send < float(self.mesh_cfg.get("chat_min_interval_seconds", 15)):
            self.stats["mesh_chat_rate_limited"] += 1
            log.info("mesh chat rate-limited, dropped: %s", remarks.text)
            return
        self.mesh.last_send = now
        text = f"{chat.get('senderCallsign', '?')}: {remarks.text or ''}"[:200]
        asyncio.get_running_loop().create_task(self.mesh.send_text(text))
        self.stats["chat_to_mesh"] += 1
        log.info("chat -> mesh channel %d: %s", self.mesh_channel, text)

    # ---- loopback / direct messages via the bridge contact

    def _is_dm_to_us(self, ev):
        chat = ev.find("detail/__chat")
        return chat is not None and chat.get("id") == self.uid

    def dm_event(self, to_uid, to_callsign, text):
        """Direct GeoChat from the bridge contact to one TAK user (routed by <marti><dest>)."""
        b = self.cfg["bridge"]
        msg_id = str(uuid.uuid4())
        ev = new_event(f"GeoChat.{self.uid}.{to_uid}.{msg_id}", "b-t-f", "h-g-i-g-o",
                       float(b.get("lat", 0)), float(b.get("lon", 0)), timedelta(days=1))
        d = detail_of(ev)
        chat = ET.SubElement(d, "__chat", parent="RootContactGroup", groupOwner="false",
                             messageId=msg_id, chatroom=to_callsign, id=to_uid,
                             senderCallsign=self.callsign)
        ET.SubElement(chat, "chatgrp", uid0=self.uid, uid1=to_uid, id=to_uid)
        ET.SubElement(d, "link", uid=self.uid, type=b.get("cot_type", "a-f-G-E-S"), relation="p-p")
        remarks = ET.SubElement(d, "remarks", source=f"BAO.F.ATAK.{self.uid}", to=to_uid,
                                time=ev.get("time"))
        remarks.text = text
        marti = ET.SubElement(d, "marti")
        ET.SubElement(marti, "dest", callsign=to_callsign)
        return ev

    def reply(self, to_uid, to_callsign, text):
        self._loop_log("TX", to_callsign, text)
        ev = self.dm_event(to_uid, to_callsign, text)
        self._tag(ev)
        self._enqueue_server(ev)

    def _loop_log(self, direction, who, text):
        line = f"LOOPBACK {direction} {who}: {text}"
        log.info(line)
        if self.loop_log:
            self.loop_log.info(line)

    def on_loopback(self, ev):
        chat = ev.find("detail/__chat")
        grp = chat.find("chatgrp")
        sender_uid = grp.get("uid0") if grp is not None else None
        link = ev.find("detail/link")
        sender_uid = sender_uid or (link.get("uid") if link is not None else "?")
        callsign = chat.get("senderCallsign", sender_uid)
        text = (ev.findtext("detail/remarks") or "").strip()
        self.stats["loopback_rx"] += 1
        self.last_loopback = (sender_uid, callsign)
        self._loop_log("RX", f"{callsign} ({sender_uid})", text)
        sent = parse_cot_time(ev.get("time"))
        lag = f"{(utcnow() - sent).total_seconds():.1f} s" if sent else "?"
        if text.lower() in ("help", "?"):
            self.reply(sender_uid, callsign,
                       "MESH-GW loopback. Anything: echoed. '@<node> text': Meshtastic DM to a node "
                       "(!id, short or long name; quote names with spaces: @\"Long Name\" hi). "
                       "'stats': bridge counters. Mesh replies to DMs arrive here.")
        elif text.lower() == "stats":
            self.reply(sender_uid, callsign, ", ".join(f"{k}={v}" for k, v in sorted(self.stats.items())))
        elif text.startswith("@"):
            self._dm_to_mesh(sender_uid, callsign, text[1:])
        else:
            self.reply(sender_uid, callsign, f"echo: {text!r} (ATAK -> server -> bridge {lag})")

    def _dm_to_mesh(self, sender_uid, callsign, rest):
        if rest.startswith('"') and '"' in rest[1:]:
            target, _, body = rest[1:].partition('"')
        else:
            target, _, body = rest.partition(" ")
        body = body.strip()
        if self.mesh is None:
            return self.reply(sender_uid, callsign, "no Meshtastic node connected")
        if not target or not body:
            return self.reply(sender_uid, callsign, "usage: @<node> message")
        hits = self.mesh.find_nodes(target)
        if not hits:
            return self.reply(sender_uid, callsign, f"no node matches {target!r}")
        if len(hits) > 1:
            names = "; ".join(f"{i} {(n.get('user') or {}).get('longName', '')}" for i, n in hits[:6])
            return self.reply(sender_uid, callsign, f"{len(hits)} nodes match {target!r}: {names}. Use the !id")
        node_id, node = hits[0]
        now = time.monotonic()
        if now - self.mesh.last_send < float(self.mesh_cfg.get("chat_min_interval_seconds", 15)):
            self.stats["mesh_dm_rate_limited"] += 1
            return self.reply(sender_uid, callsign, "rate-limited (duty cycle), try again in a few seconds")
        self.mesh.last_send = now
        text = f"{callsign}: {body}"[:200]
        name = self.mesh.node_name(node_id)
        self.dm_peer[node_id] = (sender_uid, callsign)

        async def go():
            try:
                pid = await self.mesh.send_dm(text, node["num"])
            except Exception as e:  # interface down, bad node num, ...
                self.reply(sender_uid, callsign, f"send to {name} failed: {e}")
                return
            self.pending_dm[pid] = (sender_uid, callsign, node_id, time.monotonic())
            self.stats["mesh_dm_tx"] += 1
            self.reply(sender_uid, callsign, f"-> {name} ({node_id}): sent, waiting for ack")
        asyncio.get_running_loop().create_task(go())

    def _on_routing(self, packet):
        """Ack/nak for a DM we sent. An ack from the destination = delivered; an ack from our own
        node only means a neighbour rebroadcast it (implicit ack)."""
        dec = packet.get("decoded") or {}
        pend = self.pending_dm.get(dec.get("requestId"))
        if pend is None:
            return
        sender_uid, callsign, node_id, t0 = pend
        reason = (dec.get("routing") or {}).get("errorReason", "NONE")
        name = self.mesh.node_name(node_id)
        dt = time.monotonic() - t0
        from_id = packet.get("fromId") or f"!{packet.get('from', 0):08x}"
        if reason != "NONE":
            del self.pending_dm[dec["requestId"]]
            self.stats["mesh_dm_nak"] += 1
            self.reply(sender_uid, callsign, f"-> {name}: FAILED {reason} after {dt:.0f} s")
        elif from_id == node_id:
            del self.pending_dm[dec["requestId"]]
            self.stats["mesh_dm_ack"] += 1
            self.reply(sender_uid, callsign, f"-> {name}: delivered (ack after {dt:.0f} s)")
        else:
            self.reply(sender_uid, callsign, f"-> {name}: relayed by {from_id} after {dt:.0f} s, "
                                             "no end-to-end ack yet")

    def _mesh_dm_in(self, node_id, text):
        """A Meshtastic DM to our node: to whoever last wrote to that node, else the last
        loopback user."""
        peer = self.dm_peer.get(node_id) or self.last_loopback
        name = self.mesh.node_name(node_id)
        self.stats["mesh_dm_rx"] += 1
        if peer is None:
            log.info("mesh DM from %s (%s) with no TAK peer yet: %s", name, node_id, text)
            return
        self.reply(peer[0], peer[1], f"[{name} {node_id}] {text}")

    # ---- own presence

    def own_sa(self):
        b = self.cfg["bridge"]
        ev = new_event(self.uid, b.get("cot_type", "a-f-G-E-S"), "h-g-i-g-o",
                       float(b.get("lat", 0)), float(b.get("lon", 0)), timedelta(minutes=3))
        d = detail_of(ev)
        ET.SubElement(d, "contact", callsign=b.get("callsign", self.uid), endpoint=SERVER_ENDPOINT)
        if b.get("team", "Cyan"):   # team members are drawn as team dots; "" shows the 2525 symbol
            ET.SubElement(d, "__group", name=b.get("team", "Cyan"), role=b.get("role", "HQ"))
        ET.SubElement(d, "takv", device=socket.gethostname(), platform="tak-lan-bridge",
                      os="Linux", version=__version__)
        ET.SubElement(d, "remarks").text = f"LAN bridge {self.lan_ip or 'no LAN'}: " + ", ".join(
            f"{k}={v}" for k, v in sorted(self.stats.items()))
        return ev

    @staticmethod
    def ping():
        return new_event("takPing", "t-x-c-t", "m-g", 0, 0, timedelta(seconds=20))

    # ---- server connection

    def _ssl_context(self):
        s = self.srv
        if not s.get("tls", True):
            return None
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=s.get("ca"))
        ctx.load_cert_chain(s["cert"], s["key"], password=s.get("key_password"))
        if not s.get("verify_hostname", True):
            ctx.check_hostname = False
        return ctx

    async def server_loop(self):
        backoff = 1
        ctx = self._ssl_context()
        host, port = self.srv["host"], int(self.srv.get("port", 8089))
        while True:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx,
                                            server_hostname=self.srv.get("server_hostname", host) if ctx else None),
                    timeout=15)
            except (OSError, asyncio.TimeoutError, ssl.SSLError) as e:
                log.warning("server %s:%s unreachable: %s (retry in %ss)", host, port, e, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)
                continue
            log.info("connected to server %s:%s", host, port)
            self.connected, backoff = True, 1
            tasks = [asyncio.create_task(self._writer(writer)), asyncio.create_task(self._reader(reader))]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            for t in done:
                if t.exception():
                    log.warning("server session ended: %s", t.exception())
            self.connected = False
            writer.close()
            await asyncio.sleep(1)

    async def _writer(self, writer):
        interval = float(self.cfg["bridge"].get("sa_interval_seconds", 60))
        writer.write(ET.tostring(self.own_sa()))
        next_sa = time.monotonic() + interval
        while True:
            try:
                ev = await asyncio.wait_for(self.to_server.get(), timeout=max(0.1, next_sa - time.monotonic()))
            except asyncio.TimeoutError:
                ev = None
            if ev is not None:
                stale = parse_cot_time(ev.get("stale"))
                if stale is not None and stale < utcnow():
                    self.stats["server_stale_dropped"] += 1
                else:
                    writer.write(ET.tostring(ev))
                    self.stats["to_server"] += 1
            if time.monotonic() >= next_sa:
                writer.write(ET.tostring(self.own_sa()) + ET.tostring(self.ping()))
                next_sa = time.monotonic() + interval
            await writer.drain()

    async def _reader(self, reader):
        buf = b""
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                raise ConnectionError("server closed the connection")
            buf += chunk
            while True:
                end = buf.find(b"</event>")
                if end < 0:
                    break
                start = buf.rfind(b"<event", 0, end)
                raw, buf = buf[start:end + 8], buf[end + 8:]
                if start >= 0:
                    self.on_server(raw)
            if len(buf) > 1_000_000:
                log.warning("discarding 1 MB of unframed server data")
                buf = b""

    async def stats_loop(self):
        while True:
            await asyncio.sleep(float(self.cfg["bridge"].get("stats_interval_seconds", 300)))
            log.info("stats connected=%s %s", self.connected, dict(sorted(self.stats.items())))

    async def run(self):
        loop = asyncio.get_running_loop()
        if self.lan_enabled:
            for label, (group, port) in (("sa", self.sa_group), ("chat", self.chat_group)):
                await loop.create_datagram_endpoint(lambda label=label: _McastRx(self, label),
                                                    sock=mcast_rx_socket(group, port, self.lan_ip))
            log.info("listening on %s:%s and %s:%s via %s", *self.sa_group, *self.chat_group, self.lan_ip)
        else:
            log.info("LAN multicast disabled")
        tasks = [self.server_loop(), self.stats_loop()]
        if self.mesh_cfg.get("enabled"):
            self.mesh = await loop.run_in_executor(None, MeshtasticLink, self, self.mesh_cfg, loop)
            log.info("mesh chat: channel %d <-> GeoChat room %r", self.mesh_channel, self.mesh_room_name)
            tasks.append(self.mesh_sweep_loop())
        try:
            await asyncio.gather(*tasks)
        finally:
            if self.mesh:
                self.mesh.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-c", "--config", default="/etc/tak-lan-bridge/config.toml")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    with open(args.config, "rb") as f:
        cfg = tomllib.load(f)
    try:
        asyncio.run(Bridge(cfg).run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
