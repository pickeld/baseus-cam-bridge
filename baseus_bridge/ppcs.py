"""Cloud-assisted PPCS (F1) UDP transport for cameras LAN discovery cannot find.

Some cameras (seen on X1 Pro Dual units) never answer aiopppp's LAN search, so
``find_device(lan_ip)`` times out even though the camera is on the same
network. The official app instead asks the vendor P2P servers for the camera's
current address and hole-punches to it. This module does the same:

  1. decode the three P2P server hostnames from the cloud ``service_string``
  2. send Hello / P2PReq (DID + our local address) to those servers
  3. punch every candidate address the servers announce, LAN first
  4. once the camera answers with its DID, run reliable DRW channels on that
     socket (ACKs, retransmit, in-order delivery, alive replies)

Only the direct (hole-punched) path is implemented. There is no TCP/relay
fallback: if no peer answers, :class:`PpcsError` is raised and nothing is
reported as connected. Video still flows peer-to-peer on your LAN; the vendor
servers only broker the rendezvous, exactly like the official app.

Logs never include DIDs, keys or full IP addresses (subnet + last octet only).
"""
from __future__ import annotations

import ipaddress
import math
import re
import socket
import struct
import sys
import threading
import time
from collections import Counter

from aiopppp.encrypt import XOR1_KEY_TABLE as _XOR1_TABLE

P2P_SERVER_PORTS = (32100, 32101, 32102)
MAX_CANDIDATES = 42
MAX_ANNOUNCEMENTS = 6
PORT_WINDOW = 3
# After the camera's first PunchPkt (0x41), keep punching until P2PRdy (0x42)
# or this wait elapses; returning on 0x41 alone gives a half-open session.
PUNCH_READY_WAIT_SEC = 6.0

# Vendor DecodeString table (54 bytes) used to recover the discovery hosts
# from the encoded service_string prefix.
_STRING_TABLE = bytes((
    73, 89, 67, 61, 181, 191, 109, 163, 71, 83, 79, 97,
    101, 227, 113, 233, 103, 127, 2, 3, 11, 173, 179, 137,
    43, 47, 53, 193, 107, 139, 149, 151, 17, 229, 167, 13,
    239, 241, 5, 7, 131, 251, 157, 59, 197, 199, 19, 23,
    29, 31, 37, 41, 211, 223,
))

_DID_RE = re.compile(r"^([A-Za-z]{1,7})-?(\d{1,10})-?([A-Za-z]{1,7})$")
_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")

# Message types
MSG_HELLO = 0x00
MSG_P2P_REQ = 0x20
MSG_P2P_REQ_ACK = 0x21
MSG_PUNCH_TO = 0x40
MSG_PUNCH = 0x41
MSG_P2P_RDY = 0x42
MSG_DRW = 0xD0
MSG_DRW_ACK = 0xD1
MSG_ALIVE = 0xE0
MSG_ALIVE_ACK = 0xE1
MSG_CLOSE = 0xF0
_SESSION_TYPES = {MSG_PUNCH, MSG_P2P_RDY, MSG_DRW, MSG_DRW_ACK, MSG_ALIVE, MSG_ALIVE_ACK}


class PpcsError(RuntimeError):
    pass


class ReceiveTimeout(PpcsError):
    """A polling deadline elapsed; the established session remains usable."""


def _log(log, msg: str) -> None:
    (log or (lambda m: print(m, file=sys.stderr, flush=True)))(msg)


def redacted_host(ip: str) -> str:
    """'a.b.c.0/24 last_octet=N' for private IPv4, 'public' otherwise. Never a full IP."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return "unparseable"
    if not addr.is_private:
        return "public"
    a, b, c, d = str(addr).split(".")
    return f"{a}.{b}.{c}.0/24 last_octet={d}"


def _where(source) -> str:
    return f"{redacted_host(source[0])} port={source[1]}"


# --------------------------------------------------------------------------
# Wire codecs
# --------------------------------------------------------------------------
def frame(message_type: int, payload: bytes = b"") -> bytes:
    if not 0 <= message_type <= 255 or len(payload) > 65535:
        raise PpcsError("invalid PPCS frame")
    return struct.pack(">BBH", 0xF1, message_type, len(payload)) + payload


def parse_frame(data: bytes) -> tuple[int, bytes]:
    """Return (message_type, payload)."""
    if len(data) < 4 or data[0] != 0xF1:
        raise PpcsError("invalid PPCS header")
    end = 4 + struct.unpack_from(">H", data, 2)[0]
    if len(data) < end:
        raise PpcsError("truncated PPCS frame")
    return data[1], data[4:end]


def protect(data: bytes, key: bytes, *, decrypt: bool = False) -> bytes:
    """Optional transport-key XOR from the service_string suffix. Empty key = identity."""
    if not key or not data:
        return data
    if len(key) > 20 or b"\0" in key:
        raise PpcsError("invalid PPCS transport key")
    total = sum(key) & 255
    xor = 0
    for byte in key:
        xor ^= byte
    state = (total, (-sum(key)) & 255, sum(byte // 3 for byte in key) & 255, xor)
    out = bytearray([data[0] ^ _XOR1_TABLE[total]])
    for i in range(1, len(data)):
        previous = data[i - 1] if decrypt else out[-1]
        out.append(data[i] ^ _XOR1_TABLE[(previous + state[previous & 3]) & 255])
    return bytes(out)


def encode_service_prefix(hosts_ascii: str) -> str:
    """Inverse of :func:`decode_service_prefix` (used by tests)."""
    acc = 0x39
    out = []
    for i, byte in enumerate(hosts_ascii.encode("ascii")):
        pair = (acc ^ byte ^ _STRING_TABLE[i % 54]) & 255
        acc ^= byte
        out.append(chr(ord("A") + (pair // 16)))
        out.append(chr(ord("A") + (pair % 16)))
    return "".join(out)


def decode_service_prefix(encoded: str) -> bytes:
    if not isinstance(encoded, str) or not 2 <= len(encoded) <= 2047 or len(encoded) % 2:
        raise PpcsError("invalid service string length")
    if any(not "A" <= c <= "P" for c in encoded):
        raise PpcsError("invalid service string encoding")
    out = bytearray()
    acc = 0x39
    for i in range(len(encoded) // 2):
        pair = (ord(encoded[2 * i]) * 16 + ord(encoded[2 * i + 1]) - 0x51) & 255
        byte = acc ^ pair ^ _STRING_TABLE[i % 54]
        out.append(byte)
        acc ^= byte
    return bytes(out)


def parse_service_string(value: str) -> tuple[tuple[str, ...], bytes]:
    """Return (three discovery hostnames, transport key). Key is b'' with no suffix."""
    if not value:
        raise PpcsError("missing service string")
    prefix, _sep, suffix = value.partition(":")
    try:
        text = decode_service_prefix(prefix).decode("ascii")
    except UnicodeError as exc:
        raise PpcsError("service string is not ASCII hosts") from exc
    hosts = text.split(",")
    if hosts and hosts[-1] == "":
        hosts.pop()
    if len(hosts) != 3:
        raise PpcsError("service string did not yield three discovery hosts")
    for host in hosts:
        if not host or len(host) > 253 or any(
                not _HOST_LABEL.fullmatch(label) for label in host.split(".")):
            raise PpcsError("invalid discovery host")
    if len(suffix) > 20 or any(not 33 <= ord(c) <= 126 for c in suffix):
        raise PpcsError("invalid transport key suffix")
    return tuple(hosts), suffix.encode("ascii")


def device_id_to_bytes(did: str) -> bytes:
    match = _DID_RE.fullmatch(did or "") if isinstance(did, str) and len(did) <= 32 else None
    if not match or int(match[2]) > 0x7FFFFFFF:
        raise PpcsError("invalid device id")
    return (match[1].encode("ascii").ljust(8, b"\0")
            + struct.pack(">I", int(match[2]))
            + match[3].encode("ascii").ljust(8, b"\0"))


def address_to_bytes(ip: str, port: int) -> bytes:
    """Vendor sockaddr: family 0x0002, port little-endian, IPv4 octets reversed."""
    if type(port) is not int or not 0 <= port <= 65535:
        raise PpcsError("invalid PPCS port")
    return b"\0\x02" + struct.pack("<H", port) + ipaddress.IPv4Address(ip).packed[::-1] + b"\0" * 8


def parse_address(data: bytes) -> tuple[str, int]:
    if len(data) != 16 or data[:2] != b"\0\x02" or any(data[8:]):
        raise PpcsError("invalid PPCS sockaddr")
    return str(ipaddress.IPv4Address(data[4:8][::-1])), int.from_bytes(data[2:4], "little")


def p2p_request(did: str, local_ip: str, local_port: int) -> bytes:
    return frame(MSG_P2P_REQ, device_id_to_bytes(did) + address_to_bytes(local_ip, local_port))


def punch_packet(did: str, *, ready: bool = False) -> bytes:
    return frame(MSG_P2P_RDY if ready else MSG_PUNCH, device_id_to_bytes(did))


def data_frame(channel: int, sequence: int, payload: bytes) -> bytes:
    if not 0 <= channel < 8 or not 0 <= sequence <= 65535:
        raise PpcsError("invalid DRW header")
    return frame(MSG_DRW, struct.pack(">BBH", 0xD1, channel, sequence) + payload)


def ack_frame(channel: int, sequences: list[int]) -> bytes:
    if not 0 <= channel < 8 or not 1 <= len(sequences) <= 32765:
        raise PpcsError("invalid ACK")
    return frame(MSG_DRW_ACK, struct.pack(">BBH", 0xD1, channel, len(sequences))
                 + struct.pack(">" + "H" * len(sequences), *sequences))


def parse_data(payload: bytes) -> tuple[int, int, bytes]:
    if len(payload) < 4 or payload[0] != 0xD1 or not 0 <= payload[1] < 8:
        raise PpcsError("invalid DRW")
    return payload[1], struct.unpack_from(">H", payload, 2)[0], payload[4:]


def parse_ack(payload: bytes) -> tuple[int, tuple[int, ...]]:
    if len(payload) < 4 or payload[0] != 0xD1:
        raise PpcsError("invalid ACK")
    count = struct.unpack_from(">H", payload, 2)[0]
    if count == 0 or len(payload) != 4 + 2 * count:
        raise PpcsError("invalid ACK length")
    return payload[1], struct.unpack_from(">" + "H" * count, payload, 4)


def request_ack_status(payload: bytes) -> int:
    """P2PReqAck: one status byte + three zeros. It is NOT peer readiness."""
    if len(payload) != 4 or any(payload[1:]):
        raise PpcsError("invalid P2PReqAck")
    return payload[0]


def same_slash24(ip_a: str, ip_b: str) -> bool:
    try:
        return ipaddress.IPv4Address(ip_a).packed[:3] == ipaddress.IPv4Address(ip_b).packed[:3]
    except ValueError:
        return False


def is_lan(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return addr.is_private and not addr.is_loopback


def punch_order(candidates, expected_lan: str = ""):
    """Exact cloud-reported LAN IP first, then same /24, other RFC1918, public."""
    def rank(item):
        ip, port = item
        if expected_lan and ip == expected_lan:
            r = 0
        elif expected_lan and same_slash24(ip, expected_lan):
            r = 1
        elif is_lan(ip):
            r = 2
        else:
            r = 3
        return (r, port, ip)
    return sorted(candidates, key=rank)


# --------------------------------------------------------------------------
# Reliable DRW windows
# --------------------------------------------------------------------------
class ReceiveWindow:
    """In-order delivery for one DRW channel; drops duplicates, buffers gaps."""

    def __init__(self, *, start: int = 0, max_packets: int = 2048, max_bytes: int = 262144):
        self.expected = start
        self.max_packets = max_packets
        self.max_bytes = max_bytes
        self._pending: dict[int, bytes] = {}
        self.buffered_bytes = 0

    def feed(self, sequence: int, payload: bytes) -> bytes:
        distance = (sequence - self.expected) & 65535
        if distance >= 32768 or sequence in self._pending:
            return b""  # already delivered, or a duplicate retransmission
        if distance >= self.max_packets or self.buffered_bytes + len(payload) > self.max_bytes:
            raise PpcsError("PPCS receive window overflow")
        self._pending[sequence] = payload
        self.buffered_bytes += len(payload)
        chunks = []
        while self.expected in self._pending:
            chunk = self._pending.pop(self.expected)
            self.buffered_bytes -= len(chunk)
            chunks.append(chunk)
            self.expected = (self.expected + 1) & 65535
        return b"".join(chunks)


class SendWindow:
    """Outgoing DRW with per-sequence retransmit until ACKed."""

    def __init__(self, channel: int, *, max_packets: int = 128):
        self.channel = channel
        self.max_packets = max_packets
        self.next_sequence = 0
        self._pending: dict[int, list] = {}  # seq -> [wire, sent_at, attempts]

    def queue(self, payload: bytes, now: float) -> list[bytes]:
        chunks = [payload[i:i + 1024] for i in range(0, len(payload), 1024)] or [b""]
        if len(self._pending) + len(chunks) > self.max_packets:
            raise PpcsError("PPCS send window full")
        wires = []
        for chunk in chunks:
            seq = self.next_sequence
            wire = data_frame(self.channel, seq, chunk)
            self._pending[seq] = [wire, now, 1]
            wires.append(wire)
            self.next_sequence = (seq + 1) & 65535
        return wires

    def acknowledge(self, sequences) -> int:
        return sum(1 for seq in sequences if self._pending.pop(seq, None) is not None)

    def retransmit(self, now: float, *, interval: float = 0.3, max_attempts: int = 6) -> list[bytes]:
        due = [item for item in self._pending.values() if now - item[1] >= interval]
        if any(item[2] >= max_attempts for item in due):
            raise PpcsError("PPCS ACK retries exhausted")
        for item in due:
            item[1] = now
            item[2] += 1
        return [item[0] for item in due]

    def retry_unacked(self, now: float) -> list[bytes]:
        """Resend everything pending with the same sequence numbers; reset attempts."""
        for item in self._pending.values():
            item[1] = now
            item[2] = 1
        return [item[0] for item in self._pending.values()]

    def pending_count(self) -> int:
        return len(self._pending)


# --------------------------------------------------------------------------
# Rendezvous + hole punch
# --------------------------------------------------------------------------
def resolve_servers(hosts) -> set[tuple[str, int]]:
    servers = set()
    for host in hosts:
        answers = socket.getaddrinfo(host, P2P_SERVER_PORTS[0], socket.AF_INET, socket.SOCK_DGRAM)
        if answers:
            ip = answers[0][4][0]
            servers.update((ip, port) for port in P2P_SERVER_PORTS)
    if not servers:
        raise PpcsError("PPCS discovery DNS returned no IPv4")
    return servers


def _local_source_ip(servers) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect(next(iter(servers)))
        return route.getsockname()[0]


def handshake(sock, servers, did: str, local_ip: str, local_port: int, key: bytes,
              timeout: float, expected_lan: str = "", *, clock=time.monotonic, log=None,
              deadline_fn=None, stop_fn=None):
    """Talk to the P2P servers and punch the announced candidates; return peer (ip, port).

    ``deadline_fn()`` (optional) is re-read every loop so a caller can start the
    request loop *before* waking a battery camera and extend the wait after.
    """
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 300:
        raise PpcsError("invalid PPCS timeout")
    t_start = clock()
    did_bytes = device_id_to_bytes(did)
    request = protect(p2p_request(did, local_ip, local_port), key)
    punch = protect(punch_packet(did), key)
    ready = protect(punch_packet(did, ready=True), key)
    candidates: set[tuple[str, int]] = set()
    announcements: set[tuple[str, int]] = set()
    statuses: Counter = Counter()
    last_status = None
    observed = None
    observed_at = None
    rounds = received = ignored = 0
    next_send = next_punch = 0.0

    for server in servers:
        sock.sendto(protect(frame(MSG_HELLO), key), server)

    def deadline():
        base = float(deadline_fn()) if deadline_fn is not None else t_start + timeout
        if observed_at is not None:
            # Give P2PRdy a chance to arrive, but never exceed the hard budget.
            base = min(t_start + timeout, max(base, observed_at + PUNCH_READY_WAIT_SEC))
        return base

    def punch_targets():
        ordered = punch_order(candidates, expected_lan)
        if observed is not None:
            ordered = [observed] + [t for t in ordered if t != observed]
        return ordered

    def add_candidates(ip: str, port: int) -> None:
        for p in range(max(1, port - PORT_WINDOW), min(65535, port + PORT_WINDOW) + 1):
            if len(candidates) < MAX_CANDIDATES:
                candidates.add((ip, p))

    def accept(source):
        if source in servers:
            return "server"
        if observed is not None and source == observed:
            return "observed"
        if source in candidates:
            return "candidate"
        if local_ip and same_slash24(source[0], local_ip):
            return "same_subnet"
        return None

    while clock() < deadline():
        if stop_fn is not None and stop_fn():
            break
        now = clock()
        if observed_at is not None and now >= observed_at + PUNCH_READY_WAIT_SEC:
            _log(log, f"PPCS peer {_where(observed)}: punch seen, no P2PRdy; proceeding")
            return observed
        if now >= next_send and rounds < 200:
            for server in servers:
                sock.sendto(request, server)
            rounds += 1
            next_send = now + 1.0
        if (candidates or observed is not None) and now >= next_punch:
            for target in punch_targets():
                sock.sendto(punch, target)
            next_punch = now + 0.5
        sock.settimeout(max(0.001, min(0.1, deadline() - clock())))
        try:
            raw, source = sock.recvfrom(65535)
        except socket.timeout:
            continue
        received += 1
        why = accept(source)
        if why is None:
            ignored += 1
            continue
        try:
            msg_type, payload = parse_frame(protect(raw, key, decrypt=True))
            if why == "server":
                if msg_type == MSG_P2P_REQ_ACK:
                    status = request_ack_status(payload)
                    statuses[status] += 1
                    if status != last_status:
                        _log(log, f"PPCS server ack status {last_status} -> {status}")
                        last_status = status
                elif msg_type == MSG_PUNCH_TO:
                    ip, port = parse_address(payload)
                    if ip == "0.0.0.0" or not port or (ip, port) in announcements \
                            or len(announcements) >= MAX_ANNOUNCEMENTS:
                        continue
                    announcements.add((ip, port))
                    add_candidates(ip, port)
                    # The camera sometimes announces a sibling address on the
                    # same /24 as the cloud-reported LAN IP; punch both.
                    if expected_lan and ip != expected_lan and same_slash24(ip, expected_lan):
                        add_candidates(expected_lan, port)
                    _log(log, f"PPCS candidate {_where((ip, port))} (total {len(candidates)})")
                    for target in punch_targets():
                        sock.sendto(punch, target)
                    next_punch = clock() + 0.5
                continue
            if msg_type in (MSG_PUNCH, MSG_P2P_RDY):
                if payload[:20] != did_bytes:
                    ignored += 1
                    continue
                observed = source
                if msg_type == MSG_PUNCH:
                    sock.sendto(punch, source)
                    sock.sendto(ready, source)
                    if observed_at is None:
                        observed_at = clock()
                        _log(log, f"PPCS punch from {_where(source)}; waiting for P2PRdy")
                    continue
                sock.sendto(ready, source)
                _log(log, f"PPCS peer ready at {_where(source)} ({'lan' if is_lan(source[0]) else 'public'})")
                return source
            if msg_type in _SESSION_TYPES and why in ("candidate", "observed"):
                # DRW/alive carry no DID; only trust a source we already punched.
                sock.sendto(ready, source)
                _log(log, f"PPCS peer ready at {_where(source)} (type 0x{msg_type:02x})")
                return source
            ignored += 1
        except PpcsError:
            ignored += 1
    _log(log, f"PPCS discovery timeout: rounds={rounds} received={received} ignored={ignored} "
              f"candidates={len(candidates)} server_acks={dict(statuses)}")
    raise PpcsError("PPCS: direct peer not established (relay fallback not implemented)")


# --------------------------------------------------------------------------
# Established session
# --------------------------------------------------------------------------
class UdpSession:
    """Established peer: reliable DRW channels, retransmit, alive replies."""

    def __init__(self, sock, peer, key: bytes = b"", *, did: str = "",
                 clock=time.monotonic, log=None):
        self._socket = sock
        self._peer = peer
        self._key = key
        self._did_bytes = device_id_to_bytes(did) if did else b""
        self._clock = clock
        self._log = log
        self._send = [SendWindow(ch) for ch in range(8)]
        self._receive = [ReceiveWindow() for _ in range(8)]
        self._last_alive = clock()
        self._ack_interval = 0.3
        self._ack_max_attempts = 6
        self._stash = None
        self._closed = False
        self.peer_types: list[int] = []

    def _write(self, wire: bytes) -> None:
        if self._closed:
            raise PpcsError("PPCS session is closed")
        try:
            self._socket.sendto(protect(wire, self._key), self._peer)
        except OSError as exc:
            raise PpcsError("PPCS UDP send failed") from exc

    def send(self, channel: int, data: bytes) -> None:
        for wire in self._send[channel].queue(data, self._clock()):
            self._write(wire)

    def set_ack_budget(self, *, interval: float = 0.3, max_attempts: int = 6) -> None:
        """How long unacked DRW is retried before the session is declared dead."""
        self._ack_interval = float(interval)
        self._ack_max_attempts = int(max_attempts)

    def retry_unacked(self, channel: int = 0) -> int:
        wires = self._send[channel].retry_unacked(self._clock())
        for wire in wires:
            self._write(wire)
        return len(wires)

    def pending(self, channel: int = 0) -> int:
        return self._send[channel].pending_count()

    def recv(self, deadline: float) -> tuple[int, bytes]:
        """Return (channel, in-order bytes) or raise ReceiveTimeout at ``deadline``."""
        if self._stash is not None:
            item, self._stash = self._stash, None
            return item
        while self._clock() < deadline:
            now = self._clock()
            for window in self._send:
                for wire in window.retransmit(now, interval=self._ack_interval,
                                              max_attempts=self._ack_max_attempts):
                    self._write(wire)
            if now - self._last_alive >= 2:
                self._write(frame(MSG_ALIVE))
                self._last_alive = now
            self._socket.settimeout(max(0.001, min(0.1, deadline - now)))
            try:
                raw, source = self._socket.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as exc:
                raise PpcsError("PPCS UDP receive failed") from exc
            try:
                msg_type, payload = parse_frame(protect(raw, self._key, decrypt=True))
            except PpcsError:
                continue
            if source != self._peer:
                # The camera may finish the handshake from a different port on
                # the same host/subnet; follow it only if it proves its DID.
                if not (self._did_bytes and msg_type in (MSG_PUNCH, MSG_P2P_RDY)
                        and payload[:20] == self._did_bytes
                        and same_slash24(source[0], self._peer[0])):
                    continue
                self._peer = source
            if msg_type not in self.peer_types:
                self.peer_types.append(msg_type)
            if msg_type == MSG_DRW_ACK:
                channel, seqs = parse_ack(payload)
                self._send[channel].acknowledge(seqs)
            elif msg_type == MSG_DRW:
                channel, seq, body = parse_data(payload)
                chunk = self._receive[channel].feed(seq, body)
                self._write(ack_frame(channel, [seq]))
                if chunk:
                    return channel, chunk
            elif msg_type in (MSG_PUNCH, MSG_P2P_RDY) and self._did_bytes:
                # Keep answering punches after the handshake so the path stays up.
                if msg_type == MSG_PUNCH:
                    self._write(frame(MSG_PUNCH, self._did_bytes))
                self._write(frame(MSG_P2P_RDY, self._did_bytes))
            elif msg_type == MSG_ALIVE:
                self._write(frame(MSG_ALIVE_ACK))
            elif msg_type == MSG_CLOSE:
                raise PpcsError("PPCS peer closed the session")
        raise ReceiveTimeout("PPCS: data wait timed out")

    def wait_until_ready(self, timeout: float = 4.0) -> str:
        """Wait for P2PRdy / alive / DRW before the first command.

        On a cold wake the camera can be 'punched' before it ACKs DRW; sending
        the login straight away burns the ACK budget. An early DRW chunk is
        kept so the next :meth:`recv` still returns it.
        """
        ready = {MSG_P2P_RDY: "p2prdy", MSG_DRW: "drw", MSG_ALIVE: "alive", MSG_ALIVE_ACK: "alive"}
        deadline = self._clock() + max(0.2, float(timeout))
        while self._clock() < deadline:
            seen = set(self.peer_types)
            try:
                self._stash = self.recv(min(deadline, self._clock() + 0.2))
                return "drw"
            except ReceiveTimeout:
                new = [t for t in self.peer_types if t not in seen and t in ready]
                if new:
                    return ready[new[-1]]
        return "timeout"

    def close(self) -> None:
        if self._closed:
            return
        try:
            self._write(frame(MSG_CLOSE))
        except PpcsError:
            pass
        finally:
            self._closed = True
            try:
                self._socket.close()
            except OSError:
                pass


class PpcsDiscovery:
    """Run the server request loop in a thread so it can start *before* a wake.

    Battery cameras re-register with the P2P servers right after an MQTT wake.
    Having our P2PReq already queued means the servers can announce us to the
    camera immediately. Call :meth:`mark_wake` after the wake to extend the
    wait by ``post_wake`` seconds (capped by ``timeout``).
    """

    def __init__(self, did: str, service_string: str, *, expected_lan: str = "",
                 timeout: float = 60, post_wake: float = 30, clock=time.monotonic,
                 log=None, resolve=resolve_servers):
        self._did = did
        self._service = service_string
        self._expected_lan = expected_lan
        self._timeout = float(timeout)
        self._post_wake = float(post_wake)
        self._clock = clock
        self._log = log
        self._resolve = resolve
        self._sock = None
        self._key = b""
        self._t_start = None
        self._t_wake = None
        self._stop = threading.Event()
        self._done = threading.Event()
        self._thread = None
        self._peer = None
        self.error: PpcsError | None = None

    def start(self) -> None:
        hosts, self._key = parse_service_string(self._service)
        try:
            servers = self._resolve(hosts)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except OSError as exc:
            raise PpcsError("PPCS DNS/socket failed") from exc
        try:
            sock.bind(("0.0.0.0", 0))
            local_ip = _local_source_ip(servers)
            local_port = sock.getsockname()[1]
        except OSError:
            sock.close()
            raise PpcsError("PPCS DNS/socket failed") from None
        self._sock = sock
        self._t_start = self._clock()
        _log(self._log, f"PPCS request loop started from {_where((local_ip, local_port))}")
        self._thread = threading.Thread(
            target=self._run, args=(servers, local_ip, local_port),
            name="ppcs-discovery", daemon=True)
        self._thread.start()

    def _deadline(self) -> float:
        cap = self._t_start + self._timeout
        return cap if self._t_wake is None else min(cap, self._t_wake + self._post_wake)

    def _run(self, servers, local_ip, local_port) -> None:
        try:
            self._peer = handshake(
                self._sock, servers, self._did, local_ip, local_port, self._key,
                self._timeout, expected_lan=self._expected_lan, clock=self._clock,
                log=self._log, deadline_fn=self._deadline, stop_fn=self._stop.is_set)
        except PpcsError as exc:
            self.error = exc
        except Exception as exc:  # noqa: BLE001 - surface as a transport error
            self.error = PpcsError(f"PPCS discovery failed ({type(exc).__name__})")
        finally:
            self._done.set()

    def mark_wake(self) -> None:
        self._t_wake = self._clock()

    def wait(self, timeout=None):
        """Block until peer-ready, deadline or failure. Returns (ip, port) or None."""
        if self._thread is None:
            return None
        if timeout is None:
            timeout = max(0.1, self._deadline() - self._clock() + 0.5)
        self._done.wait(timeout=timeout)
        return self._peer

    def take_session(self) -> UdpSession | None:
        """Hand the punched socket to a :class:`UdpSession` (caller closes it)."""
        if self._peer is None or self._sock is None:
            return None
        sock, self._sock = self._sock, None
        return UdpSession(sock, self._peer, self._key, did=self._did,
                          clock=self._clock, log=self._log)

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
