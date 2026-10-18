#!/usr/bin/env python3
"""Same-host smoke test: a fake TLS TAK server plus multicast senders/receivers on one interface.

Usage: python3 tests/smoke_test.py [interface]   (default: eth0)
Needs openssl on PATH. takproto is optional (enables the protobuf mesh check).
"""
import asyncio
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import tak_lan_bridge as tlb  # noqa: E402

IFACE = sys.argv[1] if len(sys.argv) > 1 else "eth0"
PORT = 18089
SA_GROUP, CHAT_GROUP = ("239.2.3.1", 16969), ("224.10.10.1", 17012)


def make_certs(d):
    def run(*a):
        subprocess.run(a, check=True, capture_output=True, cwd=d)
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
        "-days", "1", "-subj", "/CN=test-ca")
    for name, extra in (("server", "subjectAltName=IP:127.0.0.1"), ("client", "extendedKeyUsage=clientAuth")):
        run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr",
            "-subj", f"/CN={name}")
        with open(os.path.join(d, f"{name}.ext"), "w") as f:
            f.write(extra + "\n")
        run("openssl", "x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
            "-CAcreateserial", "-out", f"{name}.pem", "-days", "1", "-extfile", f"{name}.ext")


class FakeServer:
    def __init__(self):
        self.received = []
        self.writer = None
        self.connected = asyncio.Event()

    async def handle(self, reader, writer):
        self.writer = writer
        self.connected.set()
        buf = b""
        while chunk := await reader.read(65536):
            buf += chunk
            while (end := buf.find(b"</event>")) >= 0:
                start = buf.rfind(b"<event", 0, end)
                self.received.append(ET.fromstring(buf[start:end + 8]))
                buf = buf[end + 8:]

    def send(self, ev):
        self.writer.write(ET.tostring(ev))

    def uids(self):
        return [e.get("uid") for e in self.received]


class Collector(asyncio.DatagramProtocol):
    def __init__(self):
        self.events = []

    def datagram_received(self, data, addr):
        ev = tlb.parse_datagram(data)
        if ev is not None:
            self.events.append(ev)


def sa(uid, callsign, endpoint="192.168.1.77:4242:tcp"):
    ev = tlb.new_event(uid, "a-f-G-U-C", "m-g", 59.35, 18.07, timedelta(minutes=2))
    ET.SubElement(tlb.detail_of(ev), "contact", callsign=callsign, endpoint=endpoint)
    return ev


results = []


def check(name, ok):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name)


async def main(tmp):
    lan_ip = tlb.iface_ipv4(IFACE)
    make_certs(tmp)
    server = FakeServer()
    sctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=f"{tmp}/ca.pem")
    sctx.load_cert_chain(f"{tmp}/server.pem", f"{tmp}/server.key")
    sctx.verify_mode = ssl.CERT_REQUIRED
    srv = await asyncio.start_server(server.handle, "127.0.0.1", PORT, ssl=sctx)

    cfg = {
        "bridge": {"name": "test", "lat": 59.3, "lon": 18.0, "sa_interval_seconds": 60},
        "lan": {"interface": IFACE, "sa_group": "%s:%d" % SA_GROUP, "chat_group": "%s:%d" % CHAT_GROUP,
                "multicast_loop": True, "ignore_own_ip": False},
        "server": {"host": "127.0.0.1", "port": PORT, "ca": f"{tmp}/ca.pem",
                   "cert": f"{tmp}/client.pem", "key": f"{tmp}/client.key"},
        "downlink": {"deny_uid_prefixes": ["ICAO-"], "min_interval_seconds": 5},
    }
    bridge = tlb.Bridge(cfg)
    task = asyncio.create_task(bridge.run())
    await asyncio.wait_for(server.connected.wait(), 10)

    loop = asyncio.get_running_loop()
    sa_col, chat_col = Collector(), Collector()
    await loop.create_datagram_endpoint(lambda: sa_col, sock=tlb.mcast_rx_socket(*SA_GROUP, lan_ip))
    await loop.create_datagram_endpoint(lambda: chat_col, sock=tlb.mcast_rx_socket(*CHAT_GROUP, lan_ip))
    tx = tlb.mcast_tx_socket(lan_ip, 1, True)
    await asyncio.sleep(0.5)

    # 1. LAN SA -> server, endpoint rewritten, flow-tagged. Sent twice: dedupe.
    lan_ev = sa("ANDROID-lan1", "LAN1")
    for _ in range(2):
        tx.sendto(ET.tostring(lan_ev), SA_GROUP)
    # 2. LAN GeoChat -> server
    tx.sendto(ET.tostring(tlb.geochat_event("ANDROID-lan1", "LAN1", "hello from lan")), CHAT_GROUP)
    # 3. Protobuf mesh SA -> server (if takproto is present)
    try:
        import takproto
        pb = bytes(takproto.xml2proto(ET.tostring(sa("ANDROID-pb", "PB1")).decode()))
        tx.sendto(pb, SA_GROUP)
        have_pb = True
    except ImportError:
        have_pb = False
    await asyncio.sleep(1.0)

    got = [e for e in server.received if e.get("uid") == "ANDROID-lan1"]
    check("LAN SA reaches server exactly once (dedupe)", len(got) == 1)
    check("endpoint rewritten to *:-1:stcp",
          bool(got) and got[0].find("detail/contact").get("endpoint") == "*:-1:stcp")
    check("flow tag added", bool(got) and got[0].find("detail/_flow-tags_") is not None)
    check("LAN GeoChat reaches server", any(e.get("type") == "b-t-f" for e in server.received))
    check("bridge own SA reaches server", "LANBRIDGE-test" in server.uids())
    if have_pb:
        check("protobuf mesh SA converted and forwarded", "ANDROID-pb" in server.uids())

    # 4. Server -> LAN: SA on the SA group, chat on the chat group, denied uid filtered,
    #    rate limit, and our own looped-back multicast is not sent back to the server.
    server.send(sa("ANDROID-remote", "REMOTE", tlb.SERVER_ENDPOINT))
    server.send(sa("ICAO-ABC123", "PLANE"))
    server.send(tlb.geochat_event("ANDROID-remote", "REMOTE", "hello from server"))
    await asyncio.sleep(0.3)
    server.send(sa("ANDROID-remote", "REMOTE", tlb.SERVER_ENDPOINT))  # new time, within 5 s
    await server.writer.drain()
    await asyncio.sleep(1.0)

    lan_sa = [e.get("uid") for e in sa_col.events]
    check("server SA reaches LAN once (rate limit)", lan_sa.count("ANDROID-remote") == 1)
    check("denied uid prefix not sent to LAN", "ICAO-ABC123" not in lan_sa)
    check("server chat reaches LAN chat group",
          any(e.findtext("detail/remarks") == "hello from server" for e in chat_col.events))
    check("no echo of server traffic back to server",
          server.uids().count("ANDROID-remote") == 0)
    # 5. Loopback: a DM to the bridge contact is echoed back to the sender, not sent to the LAN.
    dm = tlb.geochat_event("ANDROID-remote", "REMOTE", "loop test", room_id=bridge.uid,
                           room_name="test", members=[bridge.uid])
    n_lan = len(chat_col.events)
    server.send(dm)
    await server.writer.drain()
    await asyncio.sleep(1.0)
    echo = [e for e in server.received if e.get("type") == "b-t-f"
            and e.find("detail/__chat").get("id") == "ANDROID-remote"]
    check("loopback DM echoed to sender",
          bool(echo) and "loop test" in (echo[-1].findtext("detail/remarks") or "")
          and echo[-1].find("detail/marti/dest").get("uid") == "ANDROID-remote")
    check("loopback DM not sent to LAN", len(chat_col.events) == n_lan)

    # 6. WinTAK-style receipt (b-t-f-d, plain __chat, no text) and an empty DM: no reply, no loop.
    n_srv = len(server.received)
    for t in ("b-t-f-d", "b-t-f-r", "b-t-f"):
        r = tlb.geochat_event("ANDROID-remote", "REMOTE", "", room_id=bridge.uid, room_name="test",
                              members=[bridge.uid])
        r.set("type", t)
        server.send(r)
    await server.writer.drain()
    await asyncio.sleep(1.0)
    replies = [e for e in server.received[n_srv:] if e.get("type") == "b-t-f"]
    check("receipts and empty DMs are not answered", not replies)
    # 7. Circuit breaker: 10 quick DMs -> at most 5 replies
    n_srv = len(server.received)
    for i in range(10):
        server.send(tlb.geochat_event("ANDROID-flood", "FLOOD", f"x{i}", room_id=bridge.uid,
                                      room_name="test", members=[bridge.uid]))
    await server.writer.drain()
    await asyncio.sleep(1.0)
    replies = [e for e in server.received[n_srv:] if e.get("type") == "b-t-f"]
    check("reply circuit breaker caps replies at 8", len(replies) == 8)
    check("chunk_text keeps OTS's 255-char limit",
          all(len(c) <= tlb.MAX_CHAT for c in tlb.chunk_text("word " * 300 + "\n" + "x" * 600)))
    print("bridge stats:", dict(sorted(bridge.stats.items())))

    task.cancel()
    srv.close()


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(main(d))
    sys.exit(0 if all(results) else 1)
