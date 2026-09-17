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


def build_command(cmd: int, payload: bytes) -> bytes:
    """Build a 24-byte-header app->device command frame."""
    h = bytearray(24)
    h[0:4] = struct.pack("<I", MAGIC_TO_DEV)
    h[4] = 0x10
    h[5:7] = struct.pack("<H", 210)
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


class VideoReassembler:
    """Turns a raw A/V byte stream into decrypted Annex-B video frames.

    Feed arbitrary chunks via :meth:`feed`; it yields complete video frames.
    Output is gated to start at the first SPS so a decoder can initialise.
    Audio packets and the wrong-key SD-cache pre-roll are dropped automatically.
    """

    def __init__(self, key: bytes, start_on_sps: bool = True):
        self.key = key
        self.start_on_sps = start_on_sps
        self._buf = bytearray()
        self._fbuf = bytearray()
        self._f_en = 0
        self._f_fn = -1
        self._f_next = 0
        self._started = not start_on_sps
        self.frames = 0
        self.emitted = 0

    def feed(self, chunk: bytes) -> Iterator[bytes]:
        self._buf += chunk
        # guard against unbounded growth on desync
        if len(self._buf) > 8 * 1024 * 1024:
            del self._buf[:-1024 * 1024]
        yield from self._parse()

    def _parse(self) -> Iterator[bytes]:
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
            entype = buf[off + 4] & 0x0F
            vfm = buf[off + 5]
            fn = struct.unpack_from("<H", buf, off + 6)[0]
            pkt_cnt = struct.unpack_from("<H", buf, off + 8)[0]
            cur_pkt = struct.unpack_from("<H", buf, off + 10)[0]
            payload = bytes(buf[off + 24:off + 24 + dsize])
            off += 24 + dsize
            frame = self._feed_packet(entype, vfm, fn, pkt_cnt, cur_pkt, payload)
            if frame is not None:
                yield frame
        del buf[:off]

    def _feed_packet(self, entype, vfm, fn, pkt_cnt, cur_pkt, payload):
        if vfm not in (1, 2):  # 1/2 = video; others = audio/other
            return None
        if cur_pkt == 1:
            self._fbuf = bytearray(payload)
            self._f_en = entype
            self._f_fn = fn
            self._f_next = 2
            if pkt_cnt == 1:
                self._f_next = 0
                return self._finish(bytes(self._fbuf), entype)
        elif self._f_next and cur_pkt == self._f_next and fn == self._f_fn:
            self._fbuf += payload
            self._f_next += 1
            if cur_pkt == pkt_cnt:
                self._f_next = 0
                return self._finish(bytes(self._fbuf), self._f_en)
        else:
            self._f_next = 0  # loss / other substream -> drop partial
        return None

    def _finish(self, data: bytes, entype: int):
        self.frames += 1
        if entype:
            if len(data) % 16:
                return None
            data = aes_decrypt(self.key, data)
        if data[:1] != b"\x00":  # wrong-key / cached frame
            return None
        if not self._started:
            if b"\x00\x00\x00\x01\x27" not in data[:8] and b"\x00\x00\x01\x27" not in data[:8]:
                return None
            self._started = True
        self.emitted += 1
        return data
