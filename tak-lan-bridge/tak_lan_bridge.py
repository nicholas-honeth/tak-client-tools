#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Nicholas Honeth
"""tak-lan-bridge: bridge a LAN's TAK Mesh SA multicast to a TAK server and back.

LAN side:    SA multicast 239.2.3.1:6969 and GeoChat multicast 224.10.10.1:17012
             (XML or TAK protocol v1 mesh protobuf in, XML out).
Server side: one streaming connection (TLS with a client cert, or plain TCP) carrying XML CoT.
Optional:    a Meshtastic node on USB serial or TCP. Mesh nodes with a position become map
             markers (refreshed from the node database), broadcast texts on one channel go to a
             GeoChat room, and messages posted in that room are sent to the mesh.
             Direct messages to the bridge contact are a loopback/debug channel: they are logged and
             echoed, and "@<node> text" sends a Meshtastic direct message (replies come back there).
             "channel add <link>" registers a Meshtastic channel link: the channel is added to the
             node (secondary slot, LoRa settings untouched) and gets its own GeoChat room.
             The LAN side can be switched off ([lan] enabled = false) to run as a pure
             Meshtastic gateway, e.g. on a laptop behind NAT.

Loop protection: a _flow-tags_ marker on every event this bridge forwards, a (uid, time, type)
dedupe cache, multicast loopback off, and packets from our own LAN address are ignored.

Prototype. See the vault note "TAK LAN Bridge Pi" for the spec.
"""
import argparse
import asyncio
import base64
import collections
import dataclasses
import fcntl
import hashlib
import json
import logging
import math
import os
import re
import socket
import ssl
import struct
import sys
import time
import tomllib
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

__version__ = "0.4.2"
log = logging.getLogger("tak-lan-bridge")
MESH_WATCH_SECONDS = 30            # how often mesh_watch_loop checks the node link

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
# OTS stores GeoChat text in geochat.remarks varchar(255) before routing it; a longer message fails
# to parse and is never delivered. Keep every chat message we send under this.
MAX_CHAT = 250
# Meshtastic channel links (https://meshtastic.org/e/#<base64 ChannelSet>, also "/e/?add=true#...").
# They carry the channel key, so they are redacted from our logs.
CHANNEL_LINK = re.compile(r"https?://meshtastic\.org/e/[^\s#]*#[A-Za-z0-9_\-+/=]+")


def chunk_text(text, limit=MAX_CHAT):
    """Split text into pieces of at most `limit` chars, preferring line then word boundaries."""
    out, cur = [], ""
    for line in text.split("\n"):
        while len(line) > limit:
            cut = line.rfind(" ", 0, limit)
            cut = cut if cut > 0 else limit
            if cur:
                out.append(cur)
                cur = ""
            out.append(line[:cut])
            line = line[cut:].lstrip()
        if cur and len(cur) + 1 + len(line) > limit:
            out.append(cur)
            cur = line
        else:
            cur = f"{cur}\n{line}" if cur else line
    if cur:
        out.append(cur)
    return out


def clip(text, limit=MAX_CHAT):
    return text if len(text) <= limit else text[:limit - 1] + "…"


# ---------------------------------------------------------------- helpers

def redact_links(text):
    return CHANNEL_LINK.sub("<channel link>", text)


def parse_channel_link(url):
    """Channel link -> apponly_pb2.ChannelSet. Raises ValueError. Unlike meshtastic's
    Node.setURL this neither exits the process on bad input nor touches the LoRa config."""
    from meshtastic.protobuf import apponly_pb2
    _, sep, b64 = url.strip().partition("#")
    if not sep or not b64:
        raise ValueError("not a Meshtastic channel link (https://meshtastic.org/e/#...)")
    b64 = b64.replace("-", "+").replace("_", "/")
    cs = apponly_pb2.ChannelSet()
    try:
        cs.ParseFromString(base64.b64decode(b64 + "=" * (-len(b64) % 4)))
    except Exception as e:
        raise ValueError(f"cannot decode the channel link: {e}") from None
    if not cs.settings:
        raise ValueError("the link contains no channels")
    return cs


def channel_room_id(settings):
    """Stable GeoChat room id for a Meshtastic channel: from its name and key, not from the bridge
    name, so several gateways on the same channel share one room (multi-gateway plan). Only a
    hash of the key is used."""
    key = hashlib.sha256(settings.psk).hexdigest()[:16]
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"tak-lan-bridge/channel/{settings.name}/{key}"))


@dataclasses.dataclass
class Room:
    """A GeoChat room bridged to one Meshtastic channel (index on our node)."""
    id: str
    name: str
    channel: int
    registered: dict = None     # registry entry for rooms added with "channel add"; None = the config room


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


def distance_m(a, b):
    """Equirectangular distance in metres between (lat, lon) pairs; fine at gateway scales."""
    x = math.radians(b[1] - a[1]) * math.cos(math.radians((a[0] + b[0]) / 2))
    return 6371000 * math.hypot(x, math.radians(b[0] - a[0]))


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
                  members=(), names=None):
    """GeoChat message in the shape ATAK sends it. Default: All Chat Rooms. With room_id/room_name
    it is a user group chat: chatgrp lists the sender + members, and a <hierarchy> block
    (Groups -> room -> contacts, names from `names`) lets ATAK build the group in its contact
    tree. Without the hierarchy ATAK only shows a notification; WinTAK shows the room anyway."""
    msg_id = str(uuid.uuid4())
    room_name = room_name or room_id
    ev = new_event(f"GeoChat.{sender_uid}.{room_id}.{msg_id}", "b-t-f", "h-g-i-g-o",
                   lat, lon, timedelta(days=1))
    d = detail_of(ev)
    # ATAK files its own custom group chats under "UserGroups" and lists every member;
    # it only opens a conversation for a group it is a member of (WinTAK is more lenient).
    parent = "RootContactGroup" if room_id == ALL_CHAT else "UserGroups"
    chat = ET.SubElement(d, "__chat", parent=parent, groupOwner="false",
                         messageId=msg_id, chatroom=room_name, id=room_id, senderCallsign=callsign)
    uids = {"uid0": sender_uid}
    for i, m in enumerate(members or ([room_id] if room_id == ALL_CHAT else []), start=1):
        uids[f"uid{i}"] = m
    ET.SubElement(chat, "chatgrp", id=room_id, **uids)
    if room_id != ALL_CHAT:
        names = names or {}
        hier = ET.SubElement(chat, "hierarchy")
        top = ET.SubElement(hier, "group", name="Groups", uid="UserGroups")
        grp = ET.SubElement(top, "group", name=room_name, uid=room_id)
        for u in dict.fromkeys(uids.values()):
            ET.SubElement(grp, "contact", name=names.get(u, callsign if u == sender_uid else u), uid=u)
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

class MeshLost(Exception):
    """The meshtastic link is gone. The bridge exits so systemd (Restart=always) starts it afresh."""


class MeshtasticLink:
    """Owns the meshtastic interface. Its callbacks run on meshtastic's thread and
    are handed to the asyncio loop."""

    def __init__(self, bridge, cfg, loop):
        from pubsub import pub
        self.bridge, self.cfg, self.loop = bridge, cfg, loop
        self.last_send = 0.0
        self.last_rx = time.monotonic()
        self.lost = False
        pub.subscribe(self._on_receive, "meshtastic.receive")
        pub.subscribe(self._on_lost, "meshtastic.connection.lost")
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
        self.last_rx = time.monotonic()
        self.loop.call_soon_threadsafe(self.bridge.on_mesh_packet, packet)

    def _on_lost(self, interface):
        # The library retries a dropped TCP socket once; after that its reader thread is dead.
        self.lost = True

    async def request_nodeinfo(self, dest_num):
        """Ask a node for its NODEINFO (name, short name, hw): send ours with wantResponse, as the
        Meshtastic apps do. The reply updates iface.nodes by itself."""
        from google.protobuf.json_format import ParseDict
        from meshtastic.protobuf import mesh_pb2, portnums_pb2
        user = ParseDict(self.iface.getMyUser() or {}, mesh_pb2.User(), ignore_unknown_fields=True)
        await self.loop.run_in_executor(None, lambda: self.iface.sendData(
            user.SerializeToString(), destinationId=dest_num,
            portNum=portnums_pb2.PortNum.NODEINFO_APP, wantResponse=True))

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

    # Channel table of our node. Blocking (admin messages to the node): call via run_in_executor.

    def channels(self):
        """Enabled channels (PRIMARY/SECONDARY) as protobuf Channel objects."""
        from meshtastic.protobuf import channel_pb2
        return [c for c in (self.iface.localNode.channels or [])
                if c.role != channel_pb2.Channel.Role.DISABLED]

    def channel_by_name(self, name):
        return next((c for c in self.channels() if c.settings.name == name), None)

    def add_channel(self, settings):
        """Write `settings` to the first free slot as a SECONDARY channel; returns its index.
        Only the channel is written, never the LoRa config (Node.setURL would also apply the
        link's LoRa settings and could move the node off its preset)."""
        from meshtastic.protobuf import channel_pb2
        node = self.iface.localNode
        ch = node.getDisabledChannel()
        if ch is None:
            raise ValueError("no free channel slot on the node (8 in use)")
        ch.settings.CopyFrom(settings)
        # Never uplink a private channel to an MQTT broker the node may be configured with
        ch.settings.uplink_enabled = ch.settings.downlink_enabled = False
        ch.role = channel_pb2.Channel.Role.SECONDARY
        try:
            node.writeChannel(ch.index)
        except BaseException:
            ch.role = channel_pb2.Channel.Role.DISABLED
            ch.settings.Clear()
            raise
        return ch.index

    def remove_channel(self, index):
        """Delete a SECONDARY channel. Later channels move up one slot."""
        from meshtastic.protobuf import channel_pb2
        node = self.iface.localNode
        if node.channels[index].role != channel_pb2.Channel.Role.SECONDARY:
            raise ValueError(f"channel {index} is not a secondary channel")
        node.deleteChannel(index)

    def own_position(self):
        """(gps_mode name, fixed_position flag, (lat, lon) or None) of our node, or None if the
        config isn't loaded."""
        from meshtastic.protobuf import config_pb2
        pc = getattr(self.iface.localNode.localConfig, "position", None)
        if pc is None or self.my_num is None:
            return None
        pos = self.node(f"!{self.my_num:08x}").get("position") or {}
        lat = pos.get("latitude", pos.get("latitudeI", 0) * 1e-7)
        lon = pos.get("longitude", pos.get("longitudeI", 0) * 1e-7)
        mode = config_pb2.Config.PositionConfig.GpsMode.Name(pc.gps_mode)
        return mode, pc.fixed_position, ((lat, lon) if lat or lon else None)

    def set_fixed_position(self, lat, lon, alt=0):
        """Give our node a fixed position; the firmware sets fixed_position and broadcasts it."""
        self.iface.localNode.setFixedPosition(float(lat), float(lon), int(alt))

    def lora_preset(self):
        """(region, modem preset) names of our node, or None."""
        from meshtastic.protobuf import config_pb2
        lora = getattr(self.iface.localNode.localConfig, "lora", None)
        if lora is None or not lora.ListFields():   # config not loaded yet
            return None
        L = config_pb2.Config.LoRaConfig
        return L.RegionCode.Name(lora.region), L.ModemPreset.Name(lora.modem_preset)

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
        # ATAK's own groups use UUIDs as ids; derive a stable one from bridge name + room name
        self.mesh_room_id = room if room == ALL_CHAT else m.get(
            "chatroom_id", str(uuid.uuid5(uuid.NAMESPACE_URL, f"tak-lan-bridge/{self.name}/{room}")))
        self.primary_room = Room(self.mesh_room_id, room, self.mesh_channel)
        self.rooms = {self.mesh_room_id: self.primary_room}   # GeoChat room id -> Room
        # Channels registered with "channel add": name -> {registered_by, registered_by_uid, registered_at}.
        # Names only; the keys live on the node.
        self.channels_file = m.get("channels_file", "channels.json")
        self.channel_reg = {}
        self.channel_prefix = m.get("channel_room_prefix", "Meshtastic ")
        self.channel_lock = asyncio.Lock()
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
        self.tak_users = {}      # TAK contacts seen via the server: uid -> callsign (room members)
        self.reply_times = {}    # uid -> monotonic times of recent bridge replies (circuit breaker)
        self.nodeinfo_asked, self.nodeinfo_last = {}, -1e9   # NODEINFO requests (rate limit)
        self.loop_log = None
        if b.get("loopback_log"):
            self.loop_log = logging.getLogger("tak-lan-bridge.loopback")
            h = logging.FileHandler(b["loopback_log"])
            h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
            self.loop_log.addHandler(h)
            self.loop_log.setLevel(logging.INFO)   # audit trail: whatever the main log level is
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
        contact = ev.find("detail/contact")
        if (cot_type.startswith("a-") and contact is not None and contact.get("endpoint")
                and uid != self.uid and not uid.startswith("MESHTASTIC-")):
            if uid not in self.tak_users:
                log.info("TAK user %s (%s) added to the mesh room members", contact.get("callsign"), uid)
            self.tak_users[uid] = contact.get("callsign", uid)
        if (cot_type.startswith("t-x") or self._has_our_tag(ev)
                or not cot_type.startswith(self.allow_types) or uid.startswith(self.deny_uids)
                or self._is_dup(ev)):
            self.stats["server_dropped"] += 1
            return
        # Exactly b-t-f: b-t-f-d / b-t-f-r / b-t-f-p are delivered/read/pending receipts. WinTAK sends
        # them with a plain __chat and no text; treating them as chat made the loopback echo every
        # receipt, which WinTAK acknowledged with another receipt (a 400-message loop).
        if cot_type.startswith("b-t-f-"):
            self.stats["server_chat_receipt"] += 1
            return
        is_chat = cot_type == "b-t-f"
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
            self._fanout_room(raw)

    def _fanout_room(self, raw):
        """TAK clients address a room reply only to the members they know (WinTAK: just MESH-GW),
        so pass room messages on to every other TAK member via <marti><dest>."""
        ev = ET.fromstring(raw)
        chat = ev.find("detail/__chat")
        room = self.rooms.get(chat.get("id")) if chat is not None else None
        if room is None or room.id == ALL_CHAT:
            return
        d = detail_of(ev)
        marti = d.find("marti")
        already = set()
        if marti is not None:
            for x in marti.findall("dest"):
                already.add(x.get("uid"))
                already.update(u for u, cs in self.tak_users.items() if cs == x.get("callsign"))
        grp = chat.find("chatgrp")
        sender = grp.get("uid0") if grp is not None else None
        targets = [u for u in self._room_members(room) if u != sender and u not in already]
        if not targets:
            return
        for el in (marti, d.find("__serverdestination")):
            if el is not None:
                d.remove(el)
        marti = ET.SubElement(d, "marti")
        for u in targets:
            ET.SubElement(marti, "dest", uid=u)   # by uid, see dm_event
        self._tag(ev)
        self._enqueue_server(ev)
        self.stats["room_fanout"] += 1
        log.info("room message from %s passed on to %s", chat.get("senderCallsign"),
                 ", ".join(self.tak_users[u] for u in targets))

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
            room = self._room_for_channel(int(packet.get("channel", 0)))
            if room is None:
                self.stats["mesh_chat_other_channel"] += 1
                return
            self._maybe_request_name(node_id, packet)
            ev = self._mesh_chat(node_id, dec.get("text", ""), room)
            self.stats["mesh_chat" if room is self.primary_room else "mesh_chat_channel_room"] += 1
            log.info("mesh chat ch%d (%s) %s: %s", room.channel, room.name, self.mesh.node_name(node_id),
                     dec.get("text", ""))
        else:
            return
        self._forward_mesh(ev)

    def _forward_mesh(self, ev):
        self._tag(ev)
        self._enqueue_server(ev)
        if self.mesh_cfg.get("to_lan", True):
            self._send_lan(ev)

    def _maybe_request_name(self, node_id, packet):
        """Text from a node we have no name for: ask it for NODEINFO, at most once per node per
        6 h and once per minute overall (airtime)."""
        if (self.mesh.node(node_id).get("user") or {}).get("longName"):
            return
        now = time.monotonic()
        if now - self.nodeinfo_asked.get(node_id, -1e9) < 6 * 3600 or now - self.nodeinfo_last < 60:
            return
        self.nodeinfo_asked[node_id] = self.nodeinfo_last = now
        self.stats["mesh_nodeinfo_requested"] += 1
        log.info("no name for %s yet, requesting its node info", node_id)
        asyncio.get_running_loop().create_task(self.mesh.request_nodeinfo(packet.get("from")))

    def _mesh_chat(self, node_id, text, room):
        uid = f"MESHTASTIC-{node_id.lstrip('!')}"
        name = self.mesh.node_name(node_id)
        if room.id == ALL_CHAT:
            return geochat_event(uid, name, text)
        # Sent *by the bridge contact*: every chatgrp member must be a reachable TAK contact, or ATAK
        # cannot send replies to the group. ATAK then shows MESH-GW as the author, so the node's
        # name and short name (usable for "@SHRT text" replies) go into the text.
        short = (self.mesh.node(node_id).get("user") or {}).get("shortName")
        if name == node_id:   # no NODEINFO yet: id only (a name request is on its way)
            label = f"{node_id} (name unknown)"
        else:
            label = f"{name} ({short})" if short and short != name else name
        text = clip(f"[{label}] {text}")
        return geochat_event(self.uid, name, text, room_id=room.id, room_name=room.name,
                             members=self._room_members(room), names=self._room_names())

    def _room_names(self):
        return {self.uid: self.callsign, **self.tak_users}

    def _room_for_channel(self, index):
        return next((r for r in self.rooms.values() if r.channel == index), None)

    def _room_members(self, room):
        """TAK users who get a room's messages: everyone seen via the server who may access it."""
        return sorted(u for u in self.tak_users if self._may("access", u, room))

    def _may(self, action, uid, room=None):
        """Authority hook for channel rooms. action: "register" (channel add), "remove" (channel
        remove) or "access" (read and write in a room). Every check goes through here.

        Policy for now: open, everyone may do everything. To restrict it later, decide here, e.g.
        from [meshtastic.channels] register_uids / remove_uids lists, and an access list per room
        kept in its registry entry (room.registered["access_uids"], managed by new "channel
        allow/deny" commands). The config room (room.registered is None) should stay open."""
        return True

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

    async def _sync_node_position(self):
        """node_position = "auto": a node without GNSS gets the bridge position ([bridge] lat/lon,
        or [meshtastic] node_lat/node_lon) as its fixed position, so it reports one on the mesh.
        Written only when missing or off by more than node_position_tolerance_m (saves flash).
        A node with gps_mode ENABLED is left alone; "off" never touches the node."""
        if self.mesh_cfg.get("node_position", "auto") != "auto":
            return
        b = self.cfg["bridge"]
        lat = float(self.mesh_cfg.get("node_lat", b.get("lat", 0)))
        lon = float(self.mesh_cfg.get("node_lon", b.get("lon", 0)))
        if not lat and not lon:
            return
        state = self.mesh.own_position()
        if state is None:
            log.warning("node position: node config not loaded, not checked")
            return
        mode, fixed, have = state
        if mode == "ENABLED":
            log.info("node position: node has GNSS (gps_mode ENABLED), left alone")
            return
        tol = float(self.mesh_cfg.get("node_position_tolerance_m", 50))
        if fixed and have and distance_m(have, (lat, lon)) <= tol:
            log.info("node position: fixed at %.5f, %.5f (gps_mode %s)", *have, mode)
            return
        try:
            await asyncio.get_running_loop().run_in_executor(
                None, self.mesh.set_fixed_position, lat, lon, int(self.mesh_cfg.get("node_alt", 0)))
        except BaseException as e:   # the meshtastic lib may sys.exit()
            log.warning("node position: setting fixed position failed: %r", e)
            return
        log.info("node position: set fixed %.5f, %.5f (gps_mode %s, was %s)", lat, lon, mode,
                 f"{'fixed' if fixed else 'not fixed'} at {have[0]:.5f}, {have[1]:.5f}" if have
                 else f"{'fixed' if fixed else 'not fixed'}, none")

    async def mesh_sweep_loop(self):
        """Publish nodes from the node database that have a position and were heard recently.
        Fills the map at start-up and keeps markers alive between (infrequent) position packets.
        Paced (sweep_rate per second) and incremental: only nodes heard since the last sweep, with
        a full sweep every full_sweep_every rounds. A burst of ~130 events every 5 min coincided
        with OTS missing its RabbitMQ heartbeat for this connection (~13 min after connect)."""
        interval = float(self.mesh_cfg.get("sweep_interval_seconds", 300))
        rate = float(self.mesh_cfg.get("sweep_rate", 10))
        full_every = int(self.mesh_cfg.get("full_sweep_every", 6))
        sent_heard = {}    # node_id -> lastHeard we last published
        own = f"!{self.mesh.my_num:08x}" if self.mesh.my_num is not None else None   # = the bridge marker
        rnd = 0
        while True:
            full = rnd % full_every == 0
            n, skipped, roles = 0, 0, collections.Counter()
            for node_id, node in self.mesh.nodes():
                if node_id == own:
                    continue
                last = node.get("lastHeard") or (node.get("position") or {}).get("time")
                if not last:
                    continue
                if not full and sent_heard.get(node_id) == last:
                    skipped += 1
                    continue
                heard = datetime.fromtimestamp(last, timezone.utc)
                ev = self._mesh_marker(node_id, node.get("position") or {}, heard)
                if ev is not None:
                    self._forward_mesh(ev)
                    sent_heard[node_id] = last
                    n += 1
                    roles[str((node.get("user") or {}).get("role", "CLIENT"))] += 1
                    await asyncio.sleep(1 / rate)
            self.stats["mesh_sweep_markers"] = n
            log.info("mesh sweep (%s): %d node markers published, %d unchanged, roles %s",
                     "full" if full else "changed", n, skipped, dict(roles.most_common()))
            rnd += 1
            await asyncio.sleep(interval)

    def _chat_to_mesh(self, ev):
        if self.mesh is None or not self.mesh_cfg.get("chat_to_mesh", True):
            return
        chat = ev.find("detail/__chat")
        remarks = ev.find("detail/remarks")
        if chat is None or remarks is None:
            return
        room = self.rooms.get(chat.get("id"))
        if room is None and chat.get("id") == ALL_CHAT and self.mesh_cfg.get("all_chat_to_mesh", False):
            room = self.primary_room
        if room is None:
            return
        link = ev.find("detail/link")
        if link is not None and link.get("uid", "").startswith("MESHTASTIC-"):
            return
        grp = chat.find("chatgrp")
        sender = (grp.get("uid0") if grp is not None else None) or (link.get("uid") if link is not None else "?")
        if not self._may("access", sender, room):
            self.stats["room_access_denied"] += 1
            log.info("%s may not write in %r, not sent to the mesh", chat.get("senderCallsign", sender), room.name)
            return
        body = (remarks.text or "").strip()
        if body.startswith("@"):
            # "@<node> text" in the room: a Meshtastic DM to that node instead of the public channel.
            # Status and the node's DM replies come back privately from the bridge contact.
            self.stats["room_mention_dm"] += 1
            self._dm_to_mesh(sender, chat.get("senderCallsign", sender), body[1:])
            return
        now = time.monotonic()
        if now - self.mesh.last_send < float(self.mesh_cfg.get("chat_min_interval_seconds", 15)):
            self.stats["mesh_chat_rate_limited"] += 1
            log.info("mesh chat rate-limited, dropped: %s", remarks.text)
            return
        self.mesh.last_send = now
        text = self._mesh_text(chat.get("senderCallsign", "?"), body)
        asyncio.get_running_loop().create_task(self.mesh.send_text(text, room.channel))
        self.stats["chat_to_mesh"] += 1
        log.info("chat -> mesh channel %d (%s) from %s: %s", room.channel, room.name,
                 chat.get("senderCallsign", "?"), text)
        if self.loop_log:
            self.loop_log.info(f"MESH ch{room.channel} ({room.name}) from {chat.get('senderCallsign', '?')}: {text}")

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
        # By uid: OTS binds the callsign route only at connect time, so a renamed client
        # would miss callsign-addressed messages until it reconnects. The uid never changes.
        ET.SubElement(marti, "dest", uid=to_uid)
        return ev

    def reply(self, to_uid, to_callsign, text):
        for part in chunk_text(text):
            self._reply_one(to_uid, to_callsign, part)

    def _reply_one(self, to_uid, to_callsign, text):
        # Circuit breaker: at most 8 messages per recipient per 10 s, whatever the cause
        # (a long reply such as 'help' is split into a few messages).
        now = time.monotonic()
        recent = [t for t in self.reply_times.get(to_uid, []) if now - t < 10]
        if len(recent) >= 8:
            self.stats["reply_suppressed"] += 1
            if len(recent) == 8:
                log.warning("reply rate limit hit for %s, suppressing replies for a few seconds", to_callsign)
            recent.append(now)
            self.reply_times[to_uid] = recent
            return
        recent.append(now)
        self.reply_times[to_uid] = recent
        self._loop_log("TX", to_callsign, text)
        ev = self.dm_event(to_uid, to_callsign, text)
        self._tag(ev)
        self._enqueue_server(ev)

    def _loop_log(self, direction, who, text):
        line = f"LOOPBACK {direction} {who}: {redact_links(text)}"
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
        if not text:   # never answer an empty message (receipts, client quirks): no reply loops
            self.stats["loopback_empty"] += 1
            return
        self.stats["loopback_rx"] += 1
        self.last_loopback = (sender_uid, callsign)
        self._loop_log("RX", f"{callsign} ({sender_uid})", text)
        sent = parse_cot_time(ev.get("time"))
        lag = f"{(utcnow() - sent).total_seconds():.1f} s" if sent else "?"
        if text.lower() in ("help", "?"):
            self.reply(sender_uid, callsign, "\n".join([
                f"{self.callsign} = Meshtastic gateway (node {self.mesh.node_name(f'!{self.mesh.my_num:08x}') if self.mesh else 'not connected'}).",
                f"ROOM '{self.mesh_room_name}' (mesh channel {self.mesh_channel}):",
                "- Messages show the mesh sender as [Long name (SHORT)].",
                "- Plain text is sent PUBLICLY on the channel, from the gateway node"
                + (" as '<your callsign>: text'." if self.mesh_cfg.get("show_tak_callsign", False)
                   else " (your TAK callsign is not shown on the mesh)."),
                "- '@SHORT text' sends a private Meshtastic DM to that node instead.",
                "  Also @!a1b2c3d4 or @\"Long Name\". Status and DM replies arrive here.",
                f"THIS CHAT ({self.callsign}):",
                "- '@SHORT text' / '@!id text': Meshtastic DM, same as in the room.",
                "- 'stats': bridge counters. 'roomtest': test message in the room (TAK only).",
                "CHANNELS (private Meshtastic channels, each with its own room under Groups):",
                "- 'channel add <meshtastic.org/e/# link>': add the channel to the gateway node.",
                "  Room messages then go out ENCRYPTED on that channel, not on the public one.",
                "- 'channel list', 'channel remove <name>'.",
                "- Anything else is echoed back (loopback test).",
                "Map: mesh nodes are neutral signal symbols (radio / radio relay); tap one for its @!id.",
                f"Mesh sends are limited to one per {int(float(self.mesh_cfg.get('chat_min_interval_seconds', 15)))} s (duty cycle).",
            ]))
        elif text.lower() == "roomtest":
            # A message into the mesh room from the bridge itself (TAK only, not sent to the mesh)
            self.tak_users.setdefault(sender_uid, callsign)
            ev = geochat_event(self.uid, self.callsign, f"room test for {callsign} ({len(self.tak_users)} TAK members)",
                               room_id=self.mesh_room_id, room_name=self.mesh_room_name,
                               members=sorted(self.tak_users), names=self._room_names())
            self._tag(ev)
            self._enqueue_server(ev)
            self.reply(sender_uid, callsign, f"posted a test message to {self.mesh_room_name!r}, "
                                             f"members: {', '.join(self.tak_users.values())}")
        elif text.lower() == "stats":
            self.reply(sender_uid, callsign, ", ".join(f"{k}={v}" for k, v in sorted(self.stats.items())))
        elif text.startswith("@"):
            self._dm_to_mesh(sender_uid, callsign, text[1:])
        elif text.lower().split(" ", 1)[0] in ("channel", "channels") or CHANNEL_LINK.match(text):
            self._channel_cmd(sender_uid, callsign, text)
        else:
            self.reply(sender_uid, callsign, f"echo: {text!r} (ATAK -> server -> bridge {lag})")

    # ---- channel rooms ("channel add/list/remove")

    def _load_channels(self):
        try:
            with open(self.channels_file) as f:
                self.channel_reg = json.load(f).get("channels", {})
        except FileNotFoundError:
            self.channel_reg = {}
        except (OSError, ValueError) as e:
            log.warning("cannot read %s: %s (no channel rooms)", self.channels_file, e)
            self.channel_reg = {}

    def _save_channels(self):
        tmp = f"{self.channels_file}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"channels": self.channel_reg}, f, indent=2, sort_keys=True)
        os.replace(tmp, self.channels_file)

    def _sync_channel_rooms(self):
        """Rebuild the channel rooms from the registry and the node's channel table (by name:
        indices shift when a channel is deleted)."""
        self.rooms = {self.primary_room.id: self.primary_room}
        if self.mesh is None:
            return
        for name, entry in self.channel_reg.items():
            ch = self.mesh.channel_by_name(name)
            if ch is None:
                log.warning("registered channel %r is not on the node (any more), no room", name)
                continue
            if ch.index == self.primary_room.channel:
                log.warning("registered channel %r is the config room's channel %d, skipped", name, ch.index)
                continue
            room = Room(channel_room_id(ch.settings), f"{self.channel_prefix}{name}", ch.index, entry)
            self.rooms[room.id] = room
        if len(self.rooms) > 1:
            log.info("channel rooms: %s", ", ".join(f"ch{r.channel} -> {r.name!r}"
                                                    for r in self.rooms.values() if r.registered))

    def _room_post(self, room, text):
        """A message from the bridge contact in a room (TAK only, nothing on air)."""
        ev = geochat_event(self.uid, self.callsign, text, room_id=room.id, room_name=room.name,
                           members=self._room_members(room), names=self._room_names())
        self._tag(ev)
        self._enqueue_server(ev)

    def _channel_cmd(self, sender_uid, callsign, text):
        words = text.split()
        if CHANNEL_LINK.match(text):
            words = ["channel", "add", text]
        sub = words[1].lower() if len(words) > 1 else "list"
        if self.mesh is None:
            return self.reply(sender_uid, callsign, "no Meshtastic node connected")
        if sub in ("add", "register") and len(words) > 2:
            coro = self._channel_add(sender_uid, callsign, words[2])
        elif sub in ("remove", "delete", "rm") and len(words) > 2:
            coro = self._channel_remove(sender_uid, callsign, " ".join(words[2:]))
        elif sub in ("list", "ls"):
            return self._channel_list(sender_uid, callsign)
        else:
            return self.reply(sender_uid, callsign,
                              "usage: channel add <https://meshtastic.org/e/#... link> | channel list | "
                              "channel remove <name>")
        asyncio.get_running_loop().create_task(self._channel_locked(sender_uid, callsign, coro))

    async def _channel_locked(self, sender_uid, callsign, coro):
        """One channel change at a time. The meshtastic library calls sys.exit() on some errors,
        so catch BaseException: a bad link must not take the gateway down."""
        async with self.channel_lock:
            try:
                await coro
            except BaseException as e:   # noqa: B036 (SystemExit from meshtastic's our_exit)
                if isinstance(e, (KeyboardInterrupt, asyncio.CancelledError)):
                    raise
                log.warning("channel command from %s failed: %r", callsign, e)
                self.reply(sender_uid, callsign, f"channel command failed: {e}")

    def _channel_list(self, sender_uid, callsign):
        lines = [f"ch{self.primary_room.channel} -> {self.primary_room.name!r} (config room, public)"]
        for r in sorted(self.rooms.values(), key=lambda r: r.channel):
            if r.registered and self._may("access", sender_uid, r):
                lines.append(f"ch{r.channel} -> {r.name!r}, added by {r.registered.get('registered_by', '?')} "
                             f"{r.registered.get('registered_at', '')[:10]}")
        missing = [n for n in self.channel_reg if not any(r.registered is self.channel_reg[n]
                                                          for r in self.rooms.values())]
        if missing:
            lines.append("registered but not on the node: " + ", ".join(missing))
        self.reply(sender_uid, callsign, "\n".join(lines))

    async def _channel_add(self, sender_uid, callsign, link):
        if not self._may("register", sender_uid):
            self.stats["channel_denied"] += 1
            return self.reply(sender_uid, callsign, "you may not register channels on this gateway")
        try:
            cs = parse_channel_link(link)
        except ValueError as e:
            return self.reply(sender_uid, callsign, str(e))
        loop = asyncio.get_running_loop()
        notes = []
        ours = self.mesh.lora_preset()
        if cs.HasField("lora_config") and cs.lora_config.use_preset and ours:
            from meshtastic.protobuf import config_pb2
            theirs = config_pb2.Config.LoRaConfig.ModemPreset.Name(cs.lora_config.modem_preset)
            if theirs != ours[1]:
                notes.append(f"note: the link is for {theirs}, this node runs {ours[1]} (not changed): "
                             "only nodes on the same preset are heard")
        for st in cs.settings:
            if not st.name:
                notes.append("skipped an unnamed channel (the default public channel)")
                continue
            existing = self.mesh.channel_by_name(st.name)
            if existing is not None and existing.settings.psk != st.psk:
                notes.append(f"{st.name!r}: a different channel with that name is already on the node, not changed")
                continue
            if existing is not None and existing.index == self.primary_room.channel:
                notes.append(f"{st.name!r} is the config room's channel already")
                continue
            if existing is None:
                index = await loop.run_in_executor(None, self.mesh.add_channel, st)
                log.info("channel %r added to the node in slot %d by %s (%s)", st.name, index, callsign, sender_uid)
                how = f"added to the node in slot {index}"
                self.stats["channel_added"] += 1
            else:
                how = f"already on the node in slot {existing.index}"
            self.channel_reg[st.name] = {"registered_by": callsign, "registered_by_uid": sender_uid,
                                         "registered_at": cot_time(utcnow())}
            try:
                self._save_channels()
            except OSError as e:
                notes.append(f"could not save {self.channels_file} ({e}): the room is forgotten on restart")
            self._sync_channel_rooms()
            room = self._room_for_channel(self.mesh.channel_by_name(st.name).index)
            self._room_post(room, f"room for Meshtastic channel {st.name!r} (ch{room.channel}), added by "
                                  f"{callsign}. Messages here go out encrypted on that channel.")
            notes.insert(0, f"channel {st.name!r} {how}. Room {room.name!r} is under Groups; "
                            "messages in it go out ENCRYPTED on that channel")
        self.reply(sender_uid, callsign, "\n".join(notes) or "nothing to add")

    async def _channel_remove(self, sender_uid, callsign, name):
        key = next((n for n in self.channel_reg if n.lower() == name.lower()), None)
        if key is None:
            return self.reply(sender_uid, callsign, f"no registered channel {name!r} (see 'channel list'). "
                                                    "Only channels added through the gateway can be removed")
        room = next((r for r in self.rooms.values() if r.registered is self.channel_reg[key]), None)
        if not self._may("remove", sender_uid, room):
            self.stats["channel_denied"] += 1
            return self.reply(sender_uid, callsign, f"you may not remove {key!r}")
        ch = self.mesh.channel_by_name(key)
        if ch is not None:
            if room is not None:
                self._room_post(room, f"channel {key!r} removed from the gateway by {callsign}: "
                                      "this room is no longer bridged")
            await asyncio.get_running_loop().run_in_executor(None, self.mesh.remove_channel, ch.index)
        del self.channel_reg[key]
        try:
            self._save_channels()
        except OSError as e:
            log.warning("cannot save %s: %s", self.channels_file, e)
        self._sync_channel_rooms()
        self.stats["channel_removed"] += 1
        log.info("channel %r removed by %s (%s)", key, callsign, sender_uid)
        self.reply(sender_uid, callsign, f"channel {key!r} removed" + ("" if ch else " (it was not on the node)")
                   + ". The old room can be deleted in ATAK/WinTAK")

    def _mesh_text(self, callsign, body):
        """Text as it goes out on the mesh. By default without the TAK callsign: Meshtastic users
        only see the gateway node. The callsign stays in the bridge/loopback logs."""
        if self.mesh_cfg.get("show_tak_callsign", False):
            body = f"{callsign}: {body}"
        return body[:200]

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
        text = self._mesh_text(callsign, body)
        log.info("DM -> mesh %s from %s: %s", node_id, callsign, text)
        if self.loop_log:
            self.loop_log.info(f"MESH DM {node_id} from {callsign}: {text}")
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

    async def mesh_watch_loop(self):
        """Exit when the node link is gone: meshtastic reports the connection lost, or nothing at all
        has been heard for mesh_idle_restart_minutes (a node that lost power leaves a half-open
        socket and no error). Before this, the bridge kept running without the node (2026-10-19)."""
        idle = float(self.mesh_cfg.get("mesh_idle_restart_minutes", 30)) * 60
        while True:
            await asyncio.sleep(MESH_WATCH_SECONDS)
            if self.mesh.lost:
                raise MeshLost("meshtastic connection lost")
            quiet = time.monotonic() - self.mesh.last_rx
            if idle > 0 and quiet > idle:
                self.mesh.lost = True
                raise MeshLost(f"nothing heard from the node for {quiet / 60:.0f} min")

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
            self._load_channels()
            self._sync_channel_rooms()
            await self._sync_node_position()
            tasks += [self.mesh_sweep_loop(), self.mesh_watch_loop()]
        try:
            await asyncio.gather(*tasks)
        except MeshLost:
            raise                # don't close(): it writes to the dead socket, which makes the library reconnect
        finally:
            if self.mesh and not self.mesh.lost:
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
    if not cfg.get("server", {}).get("host"):
        sys.exit(f"{args.config}: [server] host is required (the OTS address)")
    # Channel registry next to the config unless set (a read-only /etc needs channels_file in [meshtastic])
    cfg.setdefault("meshtastic", {}).setdefault(
        "channels_file", os.path.join(os.path.dirname(os.path.abspath(args.config)), "channels.json"))
    try:
        asyncio.run(Bridge(cfg).run())
    except KeyboardInterrupt:
        pass
    except MeshLost as e:
        log.error("%s, exiting so the service manager restarts the bridge", e)
        logging.shutdown()
        os._exit(1)          # meshtastic's heartbeat Timer is not a daemon thread and would keep us alive


if __name__ == "__main__":
    sys.exit(main())
