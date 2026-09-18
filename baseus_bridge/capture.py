"""Decode a packet capture of the app <-> device P2P command channel.

Interoperability aid for your **own** cameras: reuse the existing XM command
parser + AES key (derived from your device's ``p2p_password``) to read which
command IDs and JSON payloads the official app uses when you change a setting.

Workflow:
  1. Capture the traffic between the Baseus app and your HomeStation on your own
     network -- e.g. a UniFi switch **port mirror** of the HomeStation's port, or
     ``tcpdump -i <iface> -w baseus.pcap host <homestation-ip>``. Save as a
     classic ``.pcap`` (not pcapng).
  2. Toggle one setting in the app (e.g. the status light) so its "set" command
     is in the capture.
  3. ``python -m baseus_bridge decode-capture baseus.pcap``

No application binaries are inspected or modified; this only decodes network
frames you captured from hardware you own. Secrets are redacted in the output.
"""
from __future__ import annotations

import json
import struct
import sys

from . import protocol as P

# Link-layer types we understand from the pcap global header.
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_NULL = 0


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def _read_pcap(path: str):
    """Yield (timestamp, link_type, frame_bytes) from a classic pcap file."""
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 24:
        raise SystemExit(f"{path}: too small to be a pcap")
    magic = data[:4]
    if magic == b"\xa1\xb2\xc3\xd4":       # big-endian, microsecond
        endian, nano = ">", False
    elif magic == b"\xd4\xc3\xb2\xa1":     # little-endian, microsecond
        endian, nano = "<", False
    elif magic == b"\xa1\xb2\x3c\x4d":     # big-endian, nanosecond
        endian, nano = ">", True
    elif magic == b"\x4d\x3c\xb2\xa1":     # little-endian, nanosecond
        endian, nano = "<", True
    else:
        raise SystemExit(
            f"{path}: not a classic pcap (magic {magic.hex()}). "
            "In Wireshark use 'Save As -> Wireshark/tcpdump pcap', or capture "
            "with tcpdump which writes classic pcap."
        )
    link_type = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    n = len(data)
    while off + 16 <= n:
        _ts_sec, _ts_frac, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if off + incl > n:
            break
        ts = _ts_sec + _ts_frac / (1e9 if nano else 1e6)
        yield ts, link_type, data[off:off + incl]
        off += incl


def _udp_payload(link_type: int, frame: bytes):
    """Extract the UDP payload from a captured link-layer frame (IPv4 only)."""
    if link_type == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack(">H", frame[12:14])[0]
        ip_off = 14
        if ethertype == 0x8100:  # 802.1Q VLAN tag
            if len(frame) < 18:
                return None
            ethertype = struct.unpack(">H", frame[16:18])[0]
            ip_off = 18
        if ethertype != 0x0800:
            return None
    elif link_type == LINKTYPE_RAW:
        ip_off = 0
    elif link_type == LINKTYPE_NULL:
        ip_off = 4  # BSD loopback family header
    else:
        return None

    if len(frame) < ip_off + 20:
        return None
    ver_ihl = frame[ip_off]
    if (ver_ihl >> 4) != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if frame[ip_off + 9] != 17:  # not UDP
        return None
    udp_off = ip_off + ihl
    if len(frame) < udp_off + 8:
        return None
    ulen = struct.unpack(">H", frame[udp_off + 4:udp_off + 6])[0]
    end = udp_off + ulen if 8 <= ulen <= (len(frame) - udp_off) else len(frame)
    return frame[udp_off + 8:end]


def _command_frames(udp: bytes):
    """From a UDP payload, yield XM command-channel frames (raw bytes).

    PPPP 'Drw' packet:  f1 d0 <len:2>  d1 <channel> <idx:2> <XM frame...>
    We only care about the Command channel (0); video/audio are ignored.
    """
    if len(udp) < 8 or udp[0] != 0xF1 or udp[1] != 0xD0:
        return
    length = struct.unpack(">H", udp[2:4])[0]
    drw = udp[4:4 + length]
    if len(drw) < 4 or drw[0] != 0xD1:
        return
    channel = drw[1]
    if channel != 0:  # 0 == Command channel
        return
    yield drw[4:]


def decode_capture(path: str):
    """Decode command frames in a capture; print (dir, cmd, JSON) per line."""
    from .orchestrator import _cloud_from_env, _redact

    cloud = _cloud_from_env()
    cloud.login()
    cams = cloud.discover_cameras()

    # Distinct AES keys to try (one per device password).
    keys = []
    seen = set()
    for cam in cams:
        pw = getattr(cam, "p2p_password", "") or ""
        if pw and pw not in seen:
            seen.add(pw)
            keys.append(P.aes_key(pw))
    if not keys:
        log("[decode] warning: no device passwords found; encrypted frames "
            "will not be decodable")

    def try_decode_json(entype: int, body: bytes):
        candidates = [body] if not entype else [P.aes_decrypt(k, body) for k in keys]
        for dec in candidates:
            if dec[:1] == b"{":
                try:
                    return json.loads(dec.decode("utf-8", "replace"))
                except ValueError:
                    continue
        return None

    count = 0
    for ts, link_type, frame in _read_pcap(path):
        udp = _udp_payload(link_type, frame)
        if not udp:
            continue
        for xm in _command_frames(udp):
            parsed = P.parse_command_response(xm)
            if not parsed:
                continue
            cmd, entype, body = parsed
            magic = struct.unpack_from("<I", xm, 0)[0]
            direction = "app->dev" if magic == P.MAGIC_TO_DEV else "dev->app"
            js = try_decode_json(entype, body)
            count += 1
            print(json.dumps({
                "t": round(ts, 3),
                "dir": direction,
                "cmd": cmd,
                "enc": bool(entype),
                "json": _redact(js) if isinstance(js, (dict, list)) else None,
            }, ensure_ascii=False))
    log(f"[decode] {count} command frame(s) decoded from {path}")
    if count == 0:
        log("[decode] none found -- ensure the capture includes the HomeStation's "
            "P2P traffic and that a setting was toggled during capture")
