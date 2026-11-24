"""Offline tests: cloud discovery fields, XM over PPCS, wake, transport choice."""
from __future__ import annotations

import json
import os
import stat
import struct

import pytest

from baseus_bridge import bridge, cloud_p2p, orchestrator
from baseus_bridge import protocol as P
from baseus_bridge.cloud import BaseusCloud
from baseus_bridge.ppcs import PpcsError, ReceiveTimeout
from baseus_bridge.wake import WakeError, wake_message, wake_reply, wants_tls

P2P_PW = "synthetic-p2p-pw"
CAM = {
    "slug": "garden", "host": "192.168.1.20", "device_sn": "SYNSOLO0001",
    "camera_sn": "SYNSOLO0001", "channel": 0, "p2p_password": P2P_PW,
    "device_did": "ABCD-12345-WXYZ", "service_string": "AAAA",
    "wake_key": "synthetic-wake-key", "product_id": "synthetic-product",
    "is_homebase_child": False,
}


def av_packet(payload: bytes, *, fn=1, vfm=1) -> bytes:
    h = bytearray(24)
    h[0:4] = struct.pack("<I", P.MAGIC_TO_APP)
    h[4] = 0x10
    h[5] = vfm
    h[6:8] = struct.pack("<H", fn)
    h[8:10] = struct.pack("<H", 1)
    h[10:12] = struct.pack("<H", 1)
    h[12:14] = struct.pack("<H", len(payload))
    return bytes(h) + payload


def reply_frame(cmd: int, obj: dict, key: bytes) -> bytes:
    frame = bytearray(P.build_command(cmd, json.dumps(obj).encode(), key=key))
    frame[0:4] = struct.pack("<I", P.MAGIC_TO_APP)
    return bytes(frame)


class FakeSession:
    def __init__(self, script):
        self.script = list(script)
        self.sent = []
        self.budget = None

    def wait_until_ready(self, _timeout):
        return "alive"

    def set_ack_budget(self, **kw):
        self.budget = kw

    def pending(self, _ch=0):
        return 0

    def retry_unacked(self, _ch=0):
        return 0

    def send(self, channel, data):
        self.sent.append((channel, data))

    def recv(self, _deadline):
        if not self.script:
            raise ReceiveTimeout("idle")
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def sent_commands(self, key):
        out = []
        for _ch, data in self.sent:
            cmd, entype, body = P.parse_command_response(data)
            out.append((cmd, json.loads(P.aes_decrypt(key, body)) if entype and body else None))
        return out


# --- protocol -------------------------------------------------------------
def test_build_command_default_is_unchanged_and_key_encrypts():
    plain = P.build_command(P.CMD_LOGIN, b"{}")
    assert plain[4] == 0x10 and plain[5] == 210 and plain[24:] == b"{}"
    key = P.aes_key(P2P_PW)
    enc = P.build_command(P.CMD_LOGIN, b'{"a":1}', key=key)
    cmd, entype, body = P.parse_command_response(enc)
    assert (cmd, entype) == (P.CMD_LOGIN, 1)
    assert P.aes_decrypt(key, body) == b'{"a":1}'
    hb = P.build_command(P.CMD_HEARTBEAT, b"", model=0xE0)
    assert hb[5] == 0xE0 and len(hb) == 24


# --- XM over PPCS ---------------------------------------------------------
def test_xm_login_sends_encrypted_login_and_accepts_reply():
    key = P.aes_key(P2P_PW)
    session = FakeSession([(0, b"junk" + reply_frame(P.CMD_LOGIN, {"result": "ok"}, key))])
    assert cloud_p2p.xm_login(session, CAM) is True
    (cmd, obj), = session.sent_commands(key)
    assert cmd == P.CMD_LOGIN and obj["username"] == CAM["device_sn"]
    assert obj["auth"] == P.login_auth(CAM["device_sn"], obj["random"], P2P_PW)
    assert P2P_PW.encode() not in session.sent[0][1]
    assert session.budget == {}  # restored to default after login


def test_xm_login_rejected_and_closed_session():
    key = P.aes_key(P2P_PW)
    assert cloud_p2p.xm_login(FakeSession([(0, reply_frame(1, {"result": "fail"}, key))]), CAM) is False
    assert cloud_p2p.xm_login(FakeSession([PpcsError("PPCS peer closed the session")]), CAM) is False


def test_stream_opens_video_and_emits_annexb_frames():
    key = P.aes_key(P2P_PW)
    sps = b"\x00\x00\x00\x01\x27" + b"\x42" * 12
    session = FakeSession([
        (0, reply_frame(P.CMD_LOGIN, {"result": "ok"}, key)),
        (2, av_packet(b"\x00" * 8, vfm=0)),          # audio channel ignored
        (1, av_packet(sps, fn=7)),
    ])
    got = []

    def sink(frame):
        got.append(frame)
        raise BrokenPipeError

    assert cloud_p2p.stream(session, CAM, sink) == "sink_closed"
    assert [f.data for f in got] == [sps]
    cmds = [c for c, _ in session.sent_commands(key)]
    assert cmds[:2] == [P.CMD_LOGIN, P.CMD_OPENVIDEO]


def test_open_video_enables_homebase_child_first():
    key = P.aes_key(P2P_PW)
    session = FakeSession([])
    cloud_p2p.open_video(session, dict(CAM, is_homebase_child=True, channel=1, camera_sn="SYNCAM"))
    (c1, o1), (c2, o2) = session.sent_commands(key)
    assert c1 == P.CMD_HOMEBASE_LIVE_ENABLE and o1["list"][0]["sn"] == "SYNCAM"
    assert c2 == P.CMD_OPENVIDEO and o2["channel"] == 1


def test_connect_starts_requests_before_wake_and_closes_discovery():
    order = []

    class FakeDisc:
        error = None

        def __init__(self, *a, **k):
            order.append("init")

        def start(self):
            order.append("start")

        def mark_wake(self):
            order.append("mark")

        def wait(self):
            return ("192.168.1.20", 1)

        def take_session(self):
            return "session"

        def close(self):
            order.append("close")

    assert cloud_p2p.connect(CAM, wake=lambda cam: order.append("wake"),
                             discovery_cls=FakeDisc) == "session"
    assert order == ["init", "start", "wake", "mark", "close"]


def test_connect_raises_discovery_error_when_no_peer():
    class NoPeer:
        error = PpcsError("PPCS: direct peer not established")

        def __init__(self, *a, **k): pass
        def start(self): pass
        def mark_wake(self): pass
        def wait(self): return None
        def close(self): pass

    with pytest.raises(PpcsError, match="direct peer"):
        cloud_p2p.connect(CAM, wake=lambda cam: "skipped", discovery_cls=NoPeer)


def test_maybe_wake_skips_without_inputs_or_settings(tmp_path, monkeypatch):
    monkeypatch.setattr(cloud_p2p, "MQTT_FILE", tmp_path / "missing.json")
    assert cloud_p2p.maybe_wake(dict(CAM, wake_key="")) == "skipped"
    assert cloud_p2p.maybe_wake(CAM) == "skipped"


# --- wake -----------------------------------------------------------------
def test_wake_message_and_reply_correlation():
    msg = wake_message("SN1", "PID", "WK", "42", 123)
    assert msg["actionId"] == "WatchDevice" and msg["expands"] == {
        "productId": "PID", "sn": "SN1", "wake_key": "WK"}
    assert wake_reply({"seq": "42", "actionId": "WatchDevice", "result": True}, "42", False) is True
    assert wake_reply({"seq": "42", "actionId": "WatchDevice", "result": True}, "42", True) is None
    assert wake_reply({"seq": "41", "actionId": "WatchDevice", "result": True}, "42", False) is None
    with pytest.raises(WakeError):
        wake_message("SN1", "", "WK", "1", 1)


def test_wants_tls():
    assert wants_tls({"port": 8883}) and not wants_tls({"port": 1883})
    assert not wants_tls({"port": 8883, "ssl": False}) and wants_tls({"port": 1883, "tls": "yes"})


# --- cloud discovery ------------------------------------------------------
def _device_list():
    return {"payload": {"device_list": [{
        "device_sn": "SYNSOLO0001", "device_name": "Garden", "device_model": "X1",
        "online_status": 1, "product_id": "synthetic-product",
        "device_extend": {"platform": {
            "p2p_password": P2P_PW, "device_did": "ABCD-12345-WXYZ",
            "service_string": "SVC-SECRET", "wake_key": "synthetic-wake-key"}},
        "device_info": {"lan": "192.168.1.20"},
    }]}}


def test_discover_cameras_carries_ppcs_fields_and_redacts_them(monkeypatch):
    c = BaseusCloud("a", "b")
    monkeypatch.setattr(c, "raw_device_list", _device_list)
    cam, = c.discover_cameras()
    assert (cam.service_string, cam.wake_key, cam.product_id) == (
        "SVC-SECRET", "synthetic-wake-key", "synthetic-product")
    red = json.dumps(cam.redacted())
    assert "SVC-SECRET" not in red and "synthetic-wake-key" not in red and P2P_PW not in red


def test_mqtt_settings_file_is_mode_600(tmp_path, monkeypatch):
    monkeypatch.setattr(orchestrator, "RUNTIME_DIR", tmp_path)
    monkeypatch.setattr(orchestrator, "MQTT_FILE", tmp_path / "mqtt.json")
    monkeypatch.delenv("BASEUS_TRANSPORT", raising=False)

    class FakeCloud:
        def mqtt_config(self):
            return {"host": "mqtt.example.invalid", "password": "pw"}

    class Cam:
        wake_key = "wk"

    orchestrator._write_mqtt_file(FakeCloud(), [Cam()])
    path = tmp_path / "mqtt.json"
    assert json.loads(path.read_text())["host"] == "mqtt.example.invalid"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_mqtt_settings_not_fetched_for_lan_transport(tmp_path, monkeypatch):
    monkeypatch.setattr(orchestrator, "MQTT_FILE", tmp_path / "mqtt.json")
    monkeypatch.setenv("BASEUS_TRANSPORT", "lan")

    class Boom:
        def mqtt_config(self):
            raise AssertionError("must not be called")

    class Cam:
        wake_key = "wk"

    orchestrator._write_mqtt_file(Boom(), [Cam()])
    assert not (tmp_path / "mqtt.json").exists()


# --- transport selection --------------------------------------------------
@pytest.mark.parametrize("mode,cam,monitor,expected", [
    ("auto", CAM, False, "auto"),
    ("cloud", CAM, False, "cloud"),
    ("lan", CAM, False, "lan"),
    ("cloud", dict(CAM, service_string=""), False, "lan"),
    ("auto", dict(CAM, device_did=""), False, "lan"),
    ("cloud", CAM, True, "lan"),
    ("bogus", CAM, False, "auto"),
])
def test_transport_for(monkeypatch, mode, cam, monitor, expected):
    monkeypatch.setattr(bridge, "TRANSPORT", mode)
    assert bridge._transport_for(cam, monitor) == expected


def test_auto_tries_lan_once_then_cloud(monkeypatch):
    import asyncio
    calls = []

    async def fake_find(cam, attempts):
        calls.append(("lan", attempts))
        return None

    monkeypatch.setattr(bridge, "TRANSPORT", "auto")
    monkeypatch.setattr(bridge, "_find_on_lan", fake_find)
    monkeypatch.setattr(cloud_p2p, "run",
                        lambda cam, *a, **k: calls.append(("cloud",)) or "sink_closed")
    asyncio.run(bridge._main(dict(CAM)))
    assert calls == [("lan", 1), ("cloud",)]


def test_lan_mode_keeps_original_retries_and_never_uses_cloud(monkeypatch):
    import asyncio
    calls = []

    async def fake_find(cam, attempts):
        calls.append(attempts)
        return None

    monkeypatch.setattr(bridge, "TRANSPORT", "lan")
    monkeypatch.setattr(bridge, "_find_on_lan", fake_find)
    monkeypatch.setattr(cloud_p2p, "run", lambda cam, *a, **k: pytest.fail("cloud used"))
    with pytest.raises(SystemExit, match="discovery failed"):
        asyncio.run(bridge._main(dict(CAM)))
    assert calls == [3]


def test_cloud_mode_skips_lan(monkeypatch):
    import asyncio
    monkeypatch.setattr(bridge, "TRANSPORT", "cloud")

    async def no_lan(cam, attempts):
        pytest.fail("LAN used")

    monkeypatch.setattr(bridge, "_find_on_lan", no_lan)

    def boom(cam, *a, **k):
        raise PpcsError("PPCS: direct peer not established")

    monkeypatch.setattr(cloud_p2p, "run", boom)
    with pytest.raises(SystemExit, match="cloud PPCS connect failed"):
        asyncio.run(bridge._main(dict(CAM)))


class _Reason:
    is_failure = False


class FakeMqtt:
    """Drives paho-style VERSION2 callbacks synchronously."""

    def __init__(self, answer=True):
        self.answer = answer
        self.published = []

    def username_pw_set(self, *_a):
        pass

    def tls_set(self, **_k):
        self.tls = True

    def connect(self, *_a, **_k):
        self.on_connect(self, None, None, _Reason(), None)

    def loop_start(self):
        pass

    def loop_stop(self):
        pass

    def disconnect(self):
        pass

    def subscribe(self, *_a, **_k):
        self.on_subscribe(self, None, 1, [_Reason()], None)
        return 0, 1

    def publish(self, topic, payload, **_k):
        self.published.append(topic)
        msg = json.loads(payload)

        class M:
            retain = False
            payload = json.dumps({"seq": msg["seq"], "actionId": "WatchDevice",
                                  "result": self.answer}).encode()
        self.on_message(self, None, M())


MQTT = {"host": "mqtt.example.invalid", "port": 8883, "client_id": "c", "username": "u",
        "password": "p", "publish": "pub/topic", "subscribe": "sub/topic"}


def test_wake_camera_waits_for_correlated_reply():
    from baseus_bridge.wake import wake_camera
    fake = FakeMqtt()
    wake_camera(MQTT, "SN1", "PID", "WK", timeout=2, client_factory=lambda s: fake)
    assert fake.published == ["pub/topic"] and fake.tls


def test_wake_camera_rejected_and_bad_config():
    from baseus_bridge.wake import wake_camera
    with pytest.raises(WakeError, match="rejected"):
        wake_camera(MQTT, "SN1", "PID", "WK", timeout=2, client_factory=lambda s: FakeMqtt(False))
    with pytest.raises(WakeError, match="missing field"):
        wake_camera(dict(MQTT, username=""), "SN1", "PID", "WK", timeout=1)
    with pytest.raises(WakeError, match="not a URL"):
        wake_camera(dict(MQTT, host="mqtts://x"), "SN1", "PID", "WK", timeout=1)


def test_xm_login_over_real_udp_session():
    """End-to-end on the PPCS session class with a scripted socket."""
    from baseus_bridge.ppcs import UdpSession, ack_frame, data_frame, frame
    from tests.test_ppcs import Clock, FakeSock
    peer = ("192.168.1.20", 55555)
    key = P.aes_key(P2P_PW)
    sock = FakeSock([
        (frame(0xE0), peer),
        *[None] * 10,  # quiet until the login is on the wire
        (ack_frame(0, [0]), peer),
        (data_frame(0, 0, reply_frame(P.CMD_LOGIN, {"result": "ok"}, key)), peer),
    ])
    session = UdpSession(sock, peer, b"", did=CAM["device_did"], clock=Clock())
    assert cloud_p2p.xm_login(session, CAM, clock=session._clock) is True
    assert session.pending(0) == 0


# --- dual-lens on the cloud transport ---------------------------------------
def test_cloud_stream_feeds_hub_both_lenses_and_stops_when_idle():
    """Right-lens frames (command bit 0x4000) reach the hub sink as VideoFrames."""
    from baseus_bridge.demux import LEFT, RIGHT, LensDemux
    key = P.aes_key(P2P_PW)
    vps = b"\x00\x00\x00\x01\x40\x01" + b"\x0c" * 10     # HEVC VPS starts output
    left = P.build_av_packet(vps, fn=1, command=0x8000)
    right = P.build_av_packet(vps, fn=1, command=0x8000 | 0x4000)
    session = FakeSession([
        (0, reply_frame(P.CMD_LOGIN, {"result": "ok"}, key)),
        (1, left + right),
    ])
    demux = LensDemux()
    lenses = []

    def sink(frame):
        lenses.append(demux.push(frame))

    stop = {"n": 0}

    def idle():
        stop["n"] += 1
        return len(lenses) >= 2

    assert cloud_p2p.stream(session, CAM, sink, should_stop=idle) == "stopped"
    assert lenses == [LEFT, RIGHT]


def test_hub_main_passes_on_frame_and_idle_check_to_cloud(monkeypatch):
    import asyncio
    seen = {}

    def fake_run(cam, sink=None, *, should_stop=None):
        seen["sink"], seen["stop"] = sink, should_stop
        return "stopped"

    monkeypatch.setattr(bridge, "TRANSPORT", "cloud")
    monkeypatch.setattr(cloud_p2p, "run", fake_run)
    marker_sink, marker_stop = object(), object()
    asyncio.run(bridge._main(dict(CAM), on_frame=marker_sink, idle_check=marker_stop))
    assert seen == {"sink": marker_sink, "stop": marker_stop}
