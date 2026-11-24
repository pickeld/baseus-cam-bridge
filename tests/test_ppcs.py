"""Offline tests for the cloud-brokered PPCS transport. No network, no real IDs.

Addresses are RFC 1918 / RFC 5737 examples; the DID is synthetic.
"""
from __future__ import annotations

import socket

import pytest

from baseus_bridge import ppcs
from baseus_bridge.ppcs import (
    PpcsError, ReceiveTimeout, ReceiveWindow, SendWindow, UdpSession,
    address_to_bytes, data_frame, decode_service_prefix, device_id_to_bytes,
    encode_service_prefix, frame, handshake, parse_address, parse_frame,
    parse_service_string, protect, punch_order, punch_packet, redacted_host,
)

DID = "ABCD-12345-WXYZ"
LAN = "192.168.1.20"
ME = ("192.168.1.5", 40000)
SERVER = ("203.0.113.10", 32100)
HOSTS = "p2p-a.example.invalid,p2p-b.example.invalid,p2p-c.example.invalid,"


class Clock:
    def __init__(self, step=0.05):
        self.now = 1000.0
        self.step = step

    def __call__(self):
        self.now += self.step
        return self.now


class FakeSock:
    """Scripted UDP socket: recvfrom pops replies, sendto is recorded."""

    def __init__(self, replies=()):
        self.replies = list(replies)
        self.sent = []
        self.closed = False

    def settimeout(self, _value):
        pass

    def sendto(self, data, addr):
        self.sent.append((addr, data))

    def recvfrom(self, _size):
        item = self.replies.pop(0) if self.replies else None
        if item is None:  # None in the script = one quiet poll
            raise socket.timeout()
        return item

    def close(self):
        self.closed = True

    def types_sent_to(self, addr):
        return [data[1] for a, data in self.sent if a == addr]


# --- codecs ---------------------------------------------------------------
def test_service_string_roundtrip_without_key():
    enc = encode_service_prefix(HOSTS)
    assert decode_service_prefix(enc).decode() == HOSTS
    hosts, key = parse_service_string(enc)
    assert hosts == ("p2p-a.example.invalid", "p2p-b.example.invalid", "p2p-c.example.invalid")
    assert key == b""


def test_service_string_with_transport_key_suffix():
    hosts, key = parse_service_string(encode_service_prefix(HOSTS) + ":abcdef")
    assert len(hosts) == 3 and key == b"abcdef"


@pytest.mark.parametrize("bad", ["", "AB", "zzzz", encode_service_prefix("one.example,two.example,")])
def test_service_string_rejects_garbage(bad):
    with pytest.raises(PpcsError):
        parse_service_string(bad)


def test_protect_is_identity_without_key_and_roundtrips_with_key():
    wire = frame(0xD0, b"\xd1\x00\x00\x01" + b"z" * 40)
    assert protect(wire, b"") == wire
    enc = protect(wire, b"abcdefgh")
    assert enc != wire
    assert protect(enc, b"abcdefgh", decrypt=True) == wire


def test_device_id_and_sockaddr_layout():
    raw = device_id_to_bytes(DID)
    assert len(raw) == 20 and raw[:4] == b"ABCD" and raw[8:12] == (12345).to_bytes(4, "big")
    addr = address_to_bytes(LAN, 32108)
    assert addr[:2] == b"\0\x02" and len(addr) == 16
    assert parse_address(addr) == (LAN, 32108)
    with pytest.raises(PpcsError):
        device_id_to_bytes("not a did")


def test_frame_parse_rejects_bad_header_and_truncation():
    assert parse_frame(frame(0x41, b"abc")) == (0x41, b"abc")
    with pytest.raises(PpcsError):
        parse_frame(b"\x00\x41\x00\x00")
    with pytest.raises(PpcsError):
        parse_frame(frame(0x41, b"abc")[:-1])


def test_punch_order_prefers_cloud_lan_then_subnet_then_private_then_public():
    cands = [("8.8.8.8", 1), ("10.0.0.9", 1), ("192.168.1.99", 1), (LAN, 2)]
    assert [ip for ip, _ in punch_order(cands, LAN)] == [LAN, "192.168.1.99", "10.0.0.9", "8.8.8.8"]


def test_redacted_host_never_returns_full_ip():
    assert redacted_host(LAN) == "192.168.1.0/24 last_octet=20"
    assert redacted_host("8.8.8.8") == "public"


# --- reliable windows -----------------------------------------------------
def test_receive_window_orders_and_drops_duplicates():
    win = ReceiveWindow()
    assert win.feed(1, b"B") == b""
    assert win.feed(0, b"A") == b"AB"
    assert win.feed(0, b"A") == b""  # duplicate of delivered
    assert win.feed(2, b"C") == b"C"


def test_send_window_default_budget_exhausts_and_same_index_retry_resets():
    win = SendWindow(0)
    win.queue(b"login", 0.0)
    for t in (0.4, 0.8, 1.2, 1.6, 2.0):  # 1 send + 5 resends = 6 attempts
        win.retransmit(t)
    with pytest.raises(PpcsError, match="retries exhausted"):
        win.retransmit(2.4)
    assert len(win.retry_unacked(2.4)) == 1
    win.retransmit(5.0, interval=0.5, max_attempts=16)  # longer login budget survives
    assert win.acknowledge([0]) == 1 and win.pending_count() == 0


# --- handshake ------------------------------------------------------------
def test_handshake_punches_lan_candidate_and_returns_on_p2prdy():
    logs = []
    sock = FakeSock([
        (frame(0x21, b"\x00\x00\x00\x00"), SERVER),
        (frame(0x40, address_to_bytes(LAN, 32108)), SERVER),
        (frame(0x40, address_to_bytes("198.51.100.7", 40000)), SERVER),
        (punch_packet(DID, ready=True), (LAN, 32108)),
    ])
    peer = handshake(sock, {SERVER}, DID, *ME, b"", timeout=5, expected_lan=LAN,
                     clock=Clock(), log=logs.append)
    assert peer == (LAN, 32108)
    assert 0x41 in sock.types_sent_to((LAN, 32108))
    assert 0x00 in sock.types_sent_to(SERVER) and 0x20 in sock.types_sent_to(SERVER)
    text = "\n".join(logs)
    assert LAN not in text and "198.51.100.7" not in text and DID not in text


def test_handshake_waits_for_p2prdy_after_first_punch():
    logs = []
    sock = FakeSock([
        (punch_packet(DID), (LAN, 30500)),          # same /24 as us: accepted
        (frame(0x40, address_to_bytes(LAN, 30500)), SERVER),
        (punch_packet(DID, ready=True), (LAN, 30500)),
    ])
    peer = handshake(sock, {SERVER}, DID, *ME, b"", timeout=8, expected_lan=LAN,
                     clock=Clock(), log=logs.append)
    assert peer == (LAN, 30500)
    assert "waiting for P2PRdy" in "\n".join(logs)
    sent = sock.types_sent_to((LAN, 30500))
    assert 0x41 in sent and 0x42 in sent


def test_handshake_proceeds_on_punch_only_after_ready_wait():
    logs = []
    sock = FakeSock([(punch_packet(DID), (LAN, 31119))])
    peer = handshake(sock, {SERVER}, DID, *ME, b"", timeout=12, expected_lan=LAN,
                     clock=Clock(step=0.25), log=logs.append)
    assert peer == (LAN, 31119)
    assert "no P2PRdy; proceeding" in "\n".join(logs)


def test_handshake_ignores_wrong_did_and_unknown_sources():
    sock = FakeSock([
        (punch_packet("ZZZZ-99999-QQQQ", ready=True), (LAN, 32108)),
        (punch_packet(DID, ready=True), ("198.51.100.7", 1234)),  # not a candidate
    ])

    def clock():
        clock.n = getattr(clock, "n", 0) + 1
        return 0.0 if clock.n < 20 else 99.0

    with pytest.raises(PpcsError, match="direct peer not established"):
        handshake(sock, {SERVER}, DID, *ME, b"", timeout=2, expected_lan=LAN, clock=clock)


def test_handshake_timeout_reports_without_leaking_addresses():
    logs = []
    sock = FakeSock([(frame(0x21, b"\xfe\x00\x00\x00"), SERVER)])

    def clock():
        clock.n = getattr(clock, "n", 0) + 1
        return 0.0 if clock.n < 4 else 10.0

    with pytest.raises(PpcsError):
        handshake(sock, {SERVER}, DID, *ME, b"", timeout=1, expected_lan=LAN,
                  clock=clock, log=logs.append)
    text = "\n".join(logs)
    assert "PPCS discovery timeout" in text and "254" in text
    assert LAN not in text and SERVER[0] not in text


# --- session --------------------------------------------------------------
def test_session_acks_drw_answers_alive_and_punch():
    peer = (LAN, 55555)
    sock = FakeSock([
        (frame(0xE0), peer),
        (punch_packet(DID), peer),
        (data_frame(1, 0, b"video"), peer),
    ])
    session = UdpSession(sock, peer, b"", did=DID, clock=Clock())
    assert session.recv(2000.0) == (1, b"video")
    sent = sock.types_sent_to(peer)
    assert 0xE1 in sent and 0x41 in sent and 0x42 in sent and 0xD1 in sent


def test_session_follows_port_change_only_with_matching_did():
    peer = (LAN, 55555)
    moved = (LAN, 55556)
    sock = FakeSock([
        (data_frame(1, 0, b"spoof"), ("192.168.1.66", 1)),
        (punch_packet(DID, ready=True), moved),
        (data_frame(1, 0, b"real"), moved),
    ])
    session = UdpSession(sock, peer, b"", did=DID, clock=Clock())
    assert session.recv(2000.0) == (1, b"real")


def test_session_raises_on_close_and_times_out_cleanly():
    peer = (LAN, 55555)
    session = UdpSession(FakeSock([]), peer, b"", did=DID, clock=Clock())
    with pytest.raises(ReceiveTimeout):
        session.recv(1000.2)
    session = UdpSession(FakeSock([(frame(0xF0), peer)]), peer, b"", did=DID, clock=Clock())
    with pytest.raises(PpcsError, match="closed"):
        session.recv(2000.0)


def test_wait_until_ready_keeps_early_drw_for_next_recv():
    peer = (LAN, 55555)
    session = UdpSession(FakeSock([(data_frame(0, 0, b"early"), peer)]), peer, b"",
                         did=DID, clock=Clock())
    assert session.wait_until_ready(2.0) == "drw"
    assert session.recv(session._clock() + 1) == (0, b"early")


def test_wait_until_ready_accepts_alive():
    peer = (LAN, 55555)
    session = UdpSession(FakeSock([(frame(0xE0), peer)]), peer, b"", did=DID, clock=Clock())
    assert session.wait_until_ready(2.0) == "alive"


def test_discovery_take_session_hands_over_socket(monkeypatch):
    sock = FakeSock([(punch_packet(DID, ready=True), (LAN, 32108))])
    sock.bind = lambda addr: None
    sock.getsockname = lambda: ME
    monkeypatch.setattr(ppcs.socket, "socket", lambda *a, **k: sock)
    monkeypatch.setattr(ppcs, "_local_source_ip", lambda servers: ME[0])
    disc = ppcs.PpcsDiscovery(DID, encode_service_prefix(HOSTS), expected_lan=LAN,
                              timeout=5, resolve=lambda hosts: {SERVER}, log=lambda m: None)
    disc.start()
    disc.mark_wake()
    assert disc.wait(timeout=5) == (LAN, 32108)
    session = disc.take_session()
    assert isinstance(session, UdpSession)
    disc.close()
    assert not sock.closed  # session owns it now
    session.close()
    assert sock.closed
