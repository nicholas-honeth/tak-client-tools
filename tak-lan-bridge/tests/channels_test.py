#!/usr/bin/env python3
"""Channel rooms ("channel add/list/remove") against meshtastic's real Node channel table, no radio.

Usage: .venv/bin/python -I tak-lan-bridge/tests/channels_test.py   (needs the meshtastic package)
"""
import asyncio
import base64
import json
import logging
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import tak_lan_bridge as tlb  # noqa: E402
from meshtastic.node import Node  # noqa: E402
from meshtastic.protobuf import apponly_pb2, channel_pb2, config_pb2  # noqa: E402

results = []


def check(name, ok):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name)


def link(*channels, preset=config_pb2.Config.LoRaConfig.ModemPreset.MEDIUM_FAST, add=False):
    cs = apponly_pb2.ChannelSet()
    for name, psk in channels:
        s = cs.settings.add()
        s.name, s.psk = name, psk
    cs.lora_config.use_preset, cs.lora_config.modem_preset = True, preset
    b64 = base64.urlsafe_b64encode(cs.SerializeToString()).decode().rstrip("=")
    return f"https://meshtastic.org/e/{'?add=true' if add else ''}#{b64}"


class FakeIface:
    def __init__(self):
        self.localNode = Node(self, 1, noProto=True)   # real channel logic, no admin packets sent
        self.localNode.channels = []
        primary = channel_pb2.Channel(role=channel_pb2.Channel.Role.PRIMARY)
        primary.settings.psk = b"\x01"                 # default key, unnamed = public MediumFast
        self.localNode.channels.append(primary)
        self.localNode._fixupChannels()
        lora = self.localNode.localConfig.lora
        lora.use_preset, lora.modem_preset = True, config_pb2.Config.LoRaConfig.ModemPreset.MEDIUM_FAST
        lora.region = config_pb2.Config.LoRaConfig.RegionCode.EU_868
        self.written = []
        orig = self.localNode.writeChannel
        self.localNode.writeChannel = lambda i, adminIndex=0: (self.written.append(i), orig(i, adminIndex))
        self.sent = []
        self.nodes = {"!00001234": {"num": 0x1234, "user": {"longName": "Tester", "shortName": "TST"}}}

    def sendText(self, text, channelIndex=0, **kw):
        self.sent.append((channelIndex, text))


def make_link(bridge):
    m = tlb.MeshtasticLink.__new__(tlb.MeshtasticLink)
    m.bridge, m.cfg, m.loop = bridge, {}, asyncio.get_running_loop()
    m.iface, m.my_num, m.last_send = FakeIface(), 1, 0.0
    return m


def replies(bridge, since):
    return [e.findtext("detail/remarks") for e in bridge.queued[since:]
            if e.find("detail/__chat") is not None and e.find("detail/__chat").get("id") == "ANDROID-a"]


def room_msgs(bridge, room_id, since=0):
    return [e for e in bridge.queued[since:]
            if e.find("detail/__chat") is not None and e.find("detail/__chat").get("id") == room_id]


def dm(bridge, text):
    return tlb.geochat_event("ANDROID-a", "ALPHA", text, room_id=bridge.uid, room_name="x", members=[bridge.uid])


async def main(tmp):
    reg = os.path.join(tmp, "channels.json")
    looplog = os.path.join(tmp, "loopback.log")
    cfg = {"bridge": {"name": "t", "loopback_log": looplog}, "lan": {"enabled": False},
           "server": {"host": "127.0.0.1"},
           "meshtastic": {"enabled": True, "chatroom": "Meshtastic MediumFast", "channels_file": reg,
                          "chat_min_interval_seconds": 0}}
    bridge = tlb.Bridge(cfg)
    bridge.queued = []
    bridge._enqueue_server = bridge.queued.append
    bridge.mesh = make_link(bridge)
    bridge.tak_users = {"ANDROID-a": "ALPHA", "ANDROID-b": "BRAVO"}
    iface = bridge.mesh.iface

    async def say(text):
        n = len(bridge.queued)
        bridge.on_loopback(dm(bridge, text))
        await asyncio.sleep(0.05)
        async with bridge.channel_lock:
            pass
        return replies(bridge, n)

    # parse
    try:
        tlb.parse_channel_link("https://example.org/nothing")
        check("bad link rejected", False)
    except ValueError:
        check("bad link rejected", True)
    cs = tlb.parse_channel_link(link(("Team", b"k" * 32), add=True))
    check("parses the ?add=true form", cs.settings[0].name == "Team")

    # add
    key = os.urandom(32)
    url = link(("Team", key))
    r = await say(f"channel add {url}")
    team = iface.localNode.getChannelByName("Team")
    check("channel written to a free secondary slot",
          team is not None and team.index == 1 and team.role == channel_pb2.Channel.Role.SECONDARY
          and team.settings.psk == key and iface.written == [1])
    check("uplink/downlink to MQTT switched off", not team.settings.uplink_enabled
          and not team.settings.downlink_enabled)
    check("LoRa config untouched", iface.localNode.localConfig.lora.modem_preset
          == config_pb2.Config.LoRaConfig.ModemPreset.MEDIUM_FAST)
    room = bridge._room_for_channel(1)
    check("room created for the channel", room is not None and room.name == "Meshtastic Team"
          and room.id == tlb.channel_room_id(team.settings))
    check("add reply sent", bool(r) and "'Team' added to the node in slot 1" in r[0])
    check("room announcement posted with all TAK users", bool(room_msgs(bridge, room.id)) and
          {"ANDROID-a", "ANDROID-b"} <= set(room_msgs(bridge, room.id)[-1].find("detail/__chat/chatgrp").attrib.values()))
    saved = json.load(open(reg))
    check("registry saved, without the key", "Team" in saved["channels"] and
          base64.b64encode(key).decode() not in open(reg).read() and oct(os.stat(reg).st_mode)[-3:] == "600")
    with open(looplog) as f:
        log_text = f.read()
    check("channel link redacted in loopback.log", "<channel link>" in log_text and url.split("#")[1] not in log_text)

    # bare link, same channel again, conflicting key, other preset
    r = await say(url)
    check("bare link = channel add; existing channel kept", bool(r) and "already on the node in slot 1" in r[0]
          and iface.written == [1])
    r = await say("channel add " + link(("Team", b"x" * 32)))
    check("same name with another key refused", any("different channel with that name" in x for x in r))
    r = await say("channel add " + link(("Ops", b"o" * 32), preset=config_pb2.Config.LoRaConfig.ModemPreset.LONG_FAST))
    check("preset mismatch noted, channel still added", any("LONG_FAST" in x for x in r)
          and iface.localNode.getChannelByName("Ops").index == 2)

    # mesh -> room, room -> mesh on the right channel
    n = len(bridge.queued)
    bridge.on_mesh_packet({"from": 0x1234, "fromId": "!00001234", "toId": "^all", "channel": 1,
                           "decoded": {"portnum": "TEXT_MESSAGE_APP", "text": "hej team"}})
    got = room_msgs(bridge, room.id, n)
    check("mesh text on ch1 goes to the Team room", len(got) == 1 and "hej team" in got[0].findtext("detail/remarks"))
    n = len(bridge.queued)
    bridge.on_mesh_packet({"from": 0x1234, "fromId": "!00001234", "toId": "^all", "channel": 0,
                           "decoded": {"portnum": "TEXT_MESSAGE_APP", "text": "hej alla"}})
    check("mesh text on ch0 still goes to the config room",
          len(room_msgs(bridge, bridge.primary_room.id, n)) == 1 and not room_msgs(bridge, room.id, n))
    reply_ev = tlb.geochat_event("ANDROID-b", "BRAVO", "svar", room_id=room.id, room_name=room.name,
                                 members=[bridge.uid])
    import xml.etree.ElementTree as ET
    bridge._chat_to_mesh(reply_ev)
    await asyncio.sleep(0.05)
    check("room reply sent on the channel's index", iface.sent[-1] == (1, "svar"))
    n = len(bridge.queued)
    bridge._fanout_room(ET.tostring(reply_ev))
    fan = bridge.queued[n:]
    check("room reply fanned out to the other members",
          len(fan) == 1 and [d.get("uid") for d in fan[0].findall("detail/marti/dest")] == ["ANDROID-a"])

    # list, remove (index shift), restart
    r = await say("channel list")
    check("list shows both rooms", bool(r) and "'Meshtastic Team'" in r[0] and "'Meshtastic Ops'" in r[0])
    r = await say("channel remove team")
    check("remove deletes the channel, case-insensitive name", iface.localNode.getChannelByName("Team") is None
          and "Team" not in json.load(open(reg))["channels"])
    ops = iface.localNode.getChannelByName("Ops")
    check("later channel moved up and its room follows", ops.index == 1 and bridge._room_for_channel(1).name == "Meshtastic Ops"
          and room.id not in bridge.rooms)
    r = await say("channel remove LongFast")
    check("unregistered channel cannot be removed", any("no registered channel" in x for x in r))
    bridge2 = tlb.Bridge(cfg)
    bridge2.mesh = bridge.mesh
    bridge2._load_channels()
    bridge2._sync_channel_rooms()
    check("rooms restored after a restart", [r.name for r in bridge2.rooms.values() if r.registered] == ["Meshtastic Ops"])

    # the authority hook is consulted everywhere
    bridge._may = lambda action, uid, room=None: action != "register"
    r = await say("channel add " + link(("Nope", b"n" * 32)))
    check("register denied via _may", any("may not register" in x for x in r)
          and iface.localNode.getChannelByName("Nope") is None)
    bridge._may = lambda action, uid, room=None: not (action == "access" and uid == "ANDROID-b" and room.registered)
    ops_room = bridge._room_for_channel(1)
    check("access hook filters room members", bridge._room_members(ops_room) == ["ANDROID-a"]
          and bridge._room_members(bridge.primary_room) == ["ANDROID-a", "ANDROID-b"])
    n_sent = len(iface.sent)
    bridge._chat_to_mesh(tlb.geochat_event("ANDROID-b", "BRAVO", "x", room_id=ops_room.id, room_name=ops_room.name,
                                           members=[bridge.uid]))
    await asyncio.sleep(0.05)
    check("write denied via _may", len(iface.sent) == n_sent and bridge.stats["room_access_denied"] == 1)

    # library sys.exit() does not kill the bridge
    def boom(*a):
        sys.exit("Warning: No free channels were found")
    bridge._may = lambda *a, **k: True
    iface.localNode.getDisabledChannel = boom
    bridge.reply_times.clear()   # earlier commands used up the reply circuit breaker
    r = await say("channel add " + link(("Full", b"f" * 32)))
    check("library sys.exit() is caught and reported", any("channel command failed" in x for x in r))


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    with tempfile.TemporaryDirectory() as d:
        asyncio.run(main(d))
    print(f"{sum(results)}/{len(results)} passed")
    sys.exit(0 if all(results) else 1)
