"""XM / Baseus P2P wire protocol: command framing, AES, and AV reassembly.

Reverse-engineered from the Baseus Security app (com.xm.sdk). The HomeStation and
cameras speak a proprietary command layer on top of the PPPP transport:

  * 24-byte little-endian command header, magic 0x55AA55AA (app->device) /
    0x55BB55BB (device->app). Byte[4] low nibble = encryption type (EnType).
  * Command payloads are JSON. Login is command 1; video is command 2.
  * When EnType > 0 the payload/frame is AES-ECB/PKCS7 with
    key = md5(p2p_password + "xmitech")  (EnType == 4 would be CBC; unused here).
  * The live A/V stream is a sequence of 24-byte AV packet headers + payload.
    A video frame spans CurPacketNum 1..PacketCnt; the concatenated payload is
    AES-decrypted as one blob, yielding an Annex-B H.264/H.265 frame.

This module is transport-agnostic: feed it raw bytes, get decrypted frames.
"""
from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from typing import Iterator

MAGIC_TO_DEV = 0x55AA55AA
MAGIC_TO_APP = 0x55BB55BB
MAGICS = (MAGIC_TO_DEV, MAGIC_TO_APP)

try:
    from Crypto.Cipher import AES  # pycryptodome
except ImportError as exc:  # pragma: no cover
    raise ImportError("pycryptodome is required: pip install pycryptodome") from exc


# --- command IDs (subset; read/stream only) ---
CMD_LOGIN = 1
CMD_OPENVIDEO = 2
CMD_CLOSEVIDEO = 3
CMD_DEVINFO = 100
CMD_GET_CAMERA_LIST = 376
CMD_HOMEBASE_LIVE_ENABLE = 390
CMD_HEARTBEAT = 2001


def md5hex(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def aes_key(password: str) -> bytes:
    """AES key used for both command responses and A/V frames."""
    return hashlib.md5((password + "xmitech").encode()).digest()


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    """AES-ECB/PKCS7 decrypt; returns data unchanged if length is not a block."""
    if not data or len(data) % 16:
        return data
    pt = AES.new(key, AES.MODE_ECB).decrypt(data)
    pad = pt[-1]
    if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
        pt = pt[:-pad]
    return pt


def aes_encrypt(key: bytes, data: bytes) -> bytes:
    """AES-ECB/PKCS7 encrypt (XM EnType 1)."""
    pad = 16 - (len(data) % 16)
    return AES.new(key, AES.MODE_ECB).encrypt(data + bytes([pad]) * pad)


def build_command(cmd: int, payload: bytes, *, key: bytes | None = None,
                  model: int = 210) -> bytes:
    """Build a 24-byte-header app->device command frame.

    With ``key`` the payload is AES-encrypted and EnType is set to 1 (what the
    app sends over the cloud-brokered PPCS session). ``model`` is the frame
    model byte: 210 (0xD2) for normal commands, 0xE0 for the empty heartbeat.
    """
    if key is not None:
        payload = aes_encrypt(key, payload)
    h = bytearray(24)
    h[0:4] = struct.pack("<I", MAGIC_TO_DEV)
    h[4] = 0x10 | (1 if key is not None else 0)
    h[5:7] = struct.pack("<H", model & 0xFF)
    h[8:10] = struct.pack("<H", 1)
    h[10:12] = struct.pack("<H", 1)
    h[12:14] = struct.pack("<H", len(payload))
    h[14:16] = struct.pack("<H", cmd)
    return bytes(h) + payload


def command_json(cmd: int, obj: dict) -> bytes:
    return build_command(cmd, json.dumps(obj, separators=(",", ":")).encode())


def login_auth(username: str, random: str, password: str) -> str:
    return md5hex(f"{username}:{random}:{password}")


def parse_command_response(raw: bytes):
    """Parse a device->app command frame. Returns (cmd, entype, body) or None."""
    if len(raw) < 24 or struct.unpack_from("<I", raw, 0)[0] not in MAGICS:
        return None
    entype = raw[4] & 0x0F
    ln = struct.unpack_from("<H", raw, 12)[0]
    cmd = struct.unpack_from("<H", raw, 14)[0]
    return cmd, entype, raw[24:24 + ln]

def parse_av_header(buf: bytes, off: int = 0):
    """Parse one 24-byte XM AV/command header. Returns a dict or None."""
    if off + 24 > len(buf):
        return None
    magic, flags, vfm, fn, pkt_cnt, cur_pkt, dsize, command, timestamp = struct.unpack_from(
        "<IBBHHHHHQ", buf, off)
    if magic not in MAGICS:
        return None
    return {
        "magic": magic,
        "flags": flags,
        "entype": flags & 0x0F,
        "version": flags >> 4,
        "vfm": vfm,
        "fn": fn,
        "pkt_cnt": pkt_cnt,
        "cur_pkt": cur_pkt,
        "dsize": dsize,
        "command": command,
        "timestamp": timestamp,
    }


def build_av_packet(payload: bytes, *, vfm: int = 1, fn: int = 1, pkt_cnt: int = 1,
                    cur_pkt: int = 1, command: int = 0, timestamp: int = 0,
                    entype: int = 0, version: int = 1, magic: int = MAGIC_TO_APP) -> bytes:
    """Build a single-packet (or one part of a) video frame. No encryption."""
    flags = ((version & 0x0F) << 4) | (entype & 0x0F)
    header = struct.pack("<IBBHHHHHQ", magic, flags, vfm & 0xFF, fn & 0xFFFF,
                         pkt_cnt & 0xFFFF, cur_pkt & 0xFFFF, len(payload) & 0xFFFF,
                         command & 0xFFFF, int(timestamp) & 0xFFFFFFFFFFFFFFFF)
    return header + payload


@dataclass(frozen=True)
class VideoFrame:
    """One reassembled, decrypted Annex-B video frame plus XM header fields."""

    data: bytes
    vfm: int
    fn: int
    command: int
    timestamp: int
    entype: int
    pkt_cnt: int
    drw_channel: int = 1

    @property
    def hevc_flag(self) -> bool:
        # Bit 15 is the SDK HEVC flag; it is not always set on HEVC payloads.
        return bool(self.command & 0x8000)


class VideoReassembler:
    """Turns a raw A/V byte stream into decrypted Annex-B video frames.

    Feed arbitrary chunks via :meth:`feed` (bytes) or :meth:`feed_frames`
    (VideoFrame). Output is gated to start at the first H.264 SPS or HEVC
    VPS/SPS so a decoder can initialise. Audio packets and the wrong-key
    SD-cache pre-roll are dropped automatically.

    Partial frames are assembled per (fn, command, timestamp) so two
    lenses muxed on one DRW channel are not dropped as "other substream".
    """

    _MAX_PARTIAL = 8

    def __init__(self, key: bytes, start_on_sps: bool = True):
        self.key = key
        self.start_on_sps = start_on_sps
        self._buf = bytearray()
        self._partial: dict[tuple, dict] = {}
        self._started = not start_on_sps
        self.frames = 0
        self.emitted = 0
        self._drw_channel = 1
        # Backward-compat fields used by older callers.
        self._fbuf = bytearray()
        self._f_en = 0
        self._f_fn = -1
        self._f_next = 0

    def feed(self, chunk: bytes, drw_channel: int = 1) -> Iterator[bytes]:
        for frame in self.feed_frames(chunk, drw_channel=drw_channel):
            yield frame.data

    def feed_frames(self, chunk: bytes, drw_channel: int = 1) -> Iterator[VideoFrame]:
        self._drw_channel = int(drw_channel)
        self._buf += chunk
        if len(self._buf) > 8 * 1024 * 1024:
            del self._buf[:-1024 * 1024]
        yield from self._parse()

    def _parse(self) -> Iterator[VideoFrame]:
        buf = self._buf
        off = 0
        n = len(buf)
        while True:
            while off + 24 <= n:
                if struct.unpack_from("<I", buf, off)[0] in MAGICS:
                    break
                off += 1
            if off + 24 > n:
                break
            dsize = struct.unpack_from("<H", buf, off + 12)[0]
            if off + 24 + dsize > n:
                break
            hdr = parse_av_header(buf, off)
            payload = bytes(buf[off + 24:off + 24 + dsize])
            off += 24 + dsize
            if hdr is None:
                continue
            frame = self._feed_packet(hdr, payload)
            if frame is not None:
                yield frame
        del buf[:off]

    def _feed_packet(self, hdr: dict, payload: bytes):
        vfm = hdr["vfm"]
        if vfm not in (1, 2):  # 1/2 = video; others = audio/other
            return None
        fn = hdr["fn"]
        pkt_cnt = hdr["pkt_cnt"]
        cur_pkt = hdr["cur_pkt"]
        key = (fn, hdr["command"], hdr["timestamp"], pkt_cnt, vfm)
        if cur_pkt == 1:
            part = {
                "buf": bytearray(payload),
                "next": 2,
                "hdr": hdr,
                "drw": self._drw_channel,
            }
            self._partial[key] = part
            if len(self._partial) > self._MAX_PARTIAL:
                oldest = next(iter(self._partial))
                if oldest != key:
                    self._partial.pop(oldest, None)
            if pkt_cnt == 1:
                part["next"] = 0
                self._partial.pop(key, None)
                return self._finish(bytes(part["buf"]), hdr, part["drw"])
            return None
        part = self._partial.get(key)
        if part is not None and cur_pkt == part["next"]:
            part["buf"] += payload
            part["next"] += 1
            if cur_pkt == pkt_cnt:
                self._partial.pop(key, None)
                return self._finish(bytes(part["buf"]), part["hdr"], part["drw"])
            return None
        self._partial.pop(key, None)
        return None

    def _finish(self, data: bytes, hdr: dict, drw_channel: int):
        self.frames += 1
        entype = hdr["entype"]
        if entype:
            if len(data) % 16:
                return None
            data = aes_decrypt(self.key, data)
        if data[:1] != b"\x00":  # wrong-key / cached frame
            return None
        if not self._started:
            if not annexb_has_parameter_set(data):
                return None
            self._started = True
        self.emitted += 1
        return VideoFrame(
            data=data,
            vfm=hdr["vfm"],
            fn=hdr["fn"],
            command=hdr["command"],
            timestamp=hdr["timestamp"],
            entype=entype,
            pkt_cnt=hdr["pkt_cnt"],
            drw_channel=int(drw_channel),
        )


def _iter_nal_starts(data: bytes):
    i, n = 0, len(data)
    while i + 3 < n:
        if data[i:i + 4] == b"\x00\x00\x00\x01":
            yield i + 4
            i += 4
            continue
        if data[i:i + 3] == b"\x00\x00\x01":
            yield i + 3
            i += 3
            continue
        i += 1


def annexb_has_parameter_set(data: bytes) -> bool:
    """True if Annex-B data contains H.264 SPS (type 7) or HEVC VPS/SPS (32/33)."""
    n = len(data)
    for pos in _iter_nal_starts(data):
        if pos >= n:
            break
        first = data[pos]
        if (first & 0x80) == 0 and (first & 0x1F) == 7:
            return True
        if pos + 1 < n and (first & 1) == 0:
            ntype = (first >> 1) & 63
            if ntype in (32, 33):
                return True
    return False


def annexb_codec_hint(data: bytes) -> str | None:
    """Return 'h264', 'hevc', or None from parameter-set NALs."""
    hints = set()
    n = len(data)
    for pos in _iter_nal_starts(data):
        if pos >= n:
            break
        first = data[pos]
        hevc = (pos + 1 < n and (first & 1) == 0
                and (data[pos + 1] & 0xF8) == 0 and (data[pos + 1] & 7))
        if (first & 0x80) == 0 and (first & 0x1F) in (7, 8) and not hevc:
            hints.add("h264")
        if hevc and ((first >> 1) & 63) in (32, 33, 34):
            hints.add("hevc")
    if len(hints) == 1:
        return next(iter(hints))
    return None


def annexb_sps_fingerprint(data: bytes) -> str | None:
    """Short hash of the first SPS NAL, or None."""
    import hashlib
    n = len(data)
    starts = list(_iter_nal_starts(data))
    for i, pos in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else n
        # rewind over the start code we skipped; fingerprint the NAL payload
        first = data[pos]
        is_h264_sps = (first & 0x80) == 0 and (first & 0x1F) == 7
        is_hevc_sps = (first & 1) == 0 and ((first >> 1) & 63) in (32, 33)
        if is_h264_sps or is_hevc_sps:
            return hashlib.sha1(data[pos:end]).hexdigest()[:8]
    return None


def annexb_nal_types(data: bytes) -> str:
    """Comma-separated NAL type labels for a log line (no payloads)."""
    labels = []
    n = len(data)
    for pos in _iter_nal_starts(data):
        if pos >= n:
            break
        first = data[pos]
        if (first & 1) == 0 and pos + 1 < n and (data[pos + 1] & 0xF8) == 0:
            ntype = (first >> 1) & 63
            labels.append({32: "vps", 33: "sps", 34: "pps", 19: "idr", 20: "idr",
                           1: "slice"}.get(ntype, f"h{ntype}"))
        else:
            ntype = first & 0x1F
            labels.append({7: "sps", 8: "pps", 5: "idr", 1: "slice"}.get(ntype, f"a{ntype}"))
    return ",".join(labels) or "none"
