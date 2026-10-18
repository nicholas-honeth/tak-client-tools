#!/usr/bin/env python3
"""tak-lan-bridge: bridge a LAN's TAK Mesh SA multicast to a TAK server and back.

LAN side:    SA multicast 239.2.3.1:6969 and GeoChat multicast 224.10.10.1:17012
             (XML or TAK protocol v1 mesh protobuf in, XML out).
Server side: one streaming connection (TLS with a client cert, or plain TCP) carrying XML CoT.
Optional:    a Meshtastic node on USB serial or TCP. Its positions become PLI, its broadcast
             texts become GeoChat, and All Chat Rooms messages are sent to the mesh.

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

__version__ = "0.1.0"
log = logging.getLogger("tak-lan-bridge")

MESH_HEADER = b"\xbf\x01\xbf"
SERVER_ENDPOINT = "*:-1:stcp"  # how a server-connected ATAK advertises itself
ALL_CHAT = "All Chat Rooms"
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


def geochat_event(sender_uid, callsign, text, lat=0.0, lon=0.0):
    """GeoChat message to All Chat Rooms, in the shape ATAK sends it."""
    msg_id = str(uuid.uuid4())
    ev = new_event(f"GeoChat.{sender_uid}.{ALL_CHAT}.{msg_id}", "b-t-f", "h-g-i-g-o",
                   lat, lon, timedelta(days=1))
    d = detail_of(ev)
    chat = ET.SubElement(d, "__chat", parent="RootContactGroup", groupOwner="false",
                         messageId=msg_id, chatroom=ALL_CHAT, id=ALL_CHAT, senderCallsign=callsign)
    ET.SubElement(chat, "chatgrp", uid0=sender_uid, uid1=ALL_CHAT, id=ALL_CHAT)
    ET.SubElement(d, "link", uid=sender_uid, type="a-f-G-U-C", relation="p-p")
    remarks = ET.SubElement(d, "remarks", source=f"BAO.F.ATAK.{sender_uid}", to=ALL_CHAT,
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
        log.info("meshtastic connected, my node %s", self.my_num)

    def _on_receive(self, packet, interface):
        self.loop.call_soon_threadsafe(self.bridge.on_mesh_packet, packet)

    def node_name(self, node_id):
        node = (self.iface.nodes or {}).get(node_id) or {}
        user = node.get("user") or {}
        return user.get("longName") or user.get("shortName") or node_id

    async def send_text(self, text):
        await self.loop.run_in_executor(None, self.iface.sendText, text)

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
        self.lan_ip = lan.get("address") or iface_ipv4(lan["interface"])
        self.sa_group = parse_hostport(lan.get("sa_group", "239.2.3.1:6969"))
        self.chat_group = parse_hostport(lan.get("chat_group", "224.10.10.1:17012"))
        self.ignore_own_ip = lan.get("ignore_own_ip", True)
        self.tx = mcast_tx_socket(self.lan_ip, int(lan.get("ttl", 1)), lan.get("multicast_loop", False))
        self.srv = srv
        up, down = cfg.get("uplink", {}), cfg.get("downlink", {})
        self.rewrite_endpoint = up.get("rewrite_endpoint", True)
        self.allow_types = tuple(down.get("allow_type_prefixes", ["a-", "b-t-f", "b-m-p", "u-d-", "b-a-"]))
        self.deny_uids = tuple(down.get("deny_uid_prefixes", []))
        self.min_interval = float(down.get("min_interval_seconds", 5))
        self.mesh_cfg = cfg.get("meshtastic", {})
        self.mesh = None
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
        self._tag(ev)
        self._send_lan(ev)
        log.debug("server -> LAN: %s %s", cot_type, uid)
        if is_chat:
            self._chat_to_mesh(ev)

    # ---- Meshtastic

    def on_mesh_packet(self, packet):
        dec = packet.get("decoded") or {}
        port = dec.get("portnum")
        if self.mesh is None or packet.get("from") == self.mesh.my_num:
            return
        node_id = packet.get("fromId") or f"!{packet.get('from', 0):08x}"
        uid = f"MESHTASTIC-{node_id.lstrip('!')}"
        name = self.mesh.node_name(node_id)
        if port == "POSITION_APP":
            pos = dec.get("position") or {}
            lat = pos.get("latitude", pos.get("latitudeI", 0) * 1e-7)
            lon = pos.get("longitude", pos.get("longitudeI", 0) * 1e-7)
            if not lat and not lon:
                return
            ev = new_event(uid, self.mesh_cfg.get("cot_type", "a-f-G-U-C"), "m-g", lat, lon,
                           timedelta(minutes=float(self.mesh_cfg.get("pli_stale_minutes", 15))),
                           hae=pos.get("altitude", 9999999.0))
            d = detail_of(ev)
            ET.SubElement(d, "contact", callsign=name, endpoint=SERVER_ENDPOINT)
            ET.SubElement(d, "__group", name=self.mesh_cfg.get("team", "Green"), role="Team Member")
            ET.SubElement(d, "remarks").text = f"Meshtastic {node_id} via {self.name}"
            self.stats["mesh_pli"] += 1
        elif port == "TEXT_MESSAGE_APP" and packet.get("toId") == "^all":
            ev = geochat_event(uid, name, dec.get("text", ""))
            self.stats["mesh_chat"] += 1
        else:
            return
        self._tag(ev)
        self._enqueue_server(ev)
        if self.mesh_cfg.get("to_lan", True):
            self._send_lan(ev)

    def _chat_to_mesh(self, ev):
        if self.mesh is None or not self.mesh_cfg.get("chat_to_mesh", True):
            return
        chat = ev.find("detail/__chat")
        remarks = ev.find("detail/remarks")
        if chat is None or remarks is None or chat.get("id") != ALL_CHAT:
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

    # ---- own presence

    def own_sa(self):
        b = self.cfg["bridge"]
        ev = new_event(self.uid, b.get("cot_type", "a-f-G-E-S"), "h-g-i-g-o",
                       float(b.get("lat", 0)), float(b.get("lon", 0)), timedelta(minutes=3))
        d = detail_of(ev)
        ET.SubElement(d, "contact", callsign=b.get("callsign", self.uid), endpoint=SERVER_ENDPOINT)
        ET.SubElement(d, "__group", name=b.get("team", "Cyan"), role=b.get("role", "HQ"))
        ET.SubElement(d, "takv", device=socket.gethostname(), platform="tak-lan-bridge",
                      os="Linux", version=__version__)
        ET.SubElement(d, "remarks").text = f"LAN bridge {self.lan_ip}: " + ", ".join(
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
        for label, (group, port) in (("sa", self.sa_group), ("chat", self.chat_group)):
            await loop.create_datagram_endpoint(lambda label=label: _McastRx(self, label),
                                                sock=mcast_rx_socket(group, port, self.lan_ip))
        log.info("listening on %s:%s and %s:%s via %s", *self.sa_group, *self.chat_group, self.lan_ip)
        if self.mesh_cfg.get("enabled"):
            self.mesh = await loop.run_in_executor(None, MeshtasticLink, self, self.mesh_cfg, loop)
        try:
            await asyncio.gather(self.server_loop(), self.stats_loop())
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
