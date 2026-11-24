"""Live stream over a cloud-brokered PPCS session (no LAN search).

Sequence (matches the official app for battery cameras):

  1. start the P2P server request loop (``ppcs.PpcsDiscovery``)
  2. MQTT ``WatchDevice`` wake, if the camera record has wake inputs
  3. wait for the hole-punched peer
  4. XM login (cmd 1) -> open video (cmd 2) -> heartbeat every few seconds
  5. reassemble/decrypt the video channel and hand each ``VideoFrame`` to
     ``sink`` (the dual-lens hub demuxes left/right from it)

Runs in a plain thread (the PPCS session is blocking). All logs are redacted.
"""
from __future__ import annotations

import json
import os
import secrets
import sys
import time
from pathlib import Path

from . import protocol as P
from .ppcs import PpcsDiscovery, PpcsError, ReceiveTimeout

RUNTIME_DIR = Path(os.environ.get("BASEUS_RUNTIME_DIR", "/run/baseus"))
MQTT_FILE = Path(os.environ.get("BASEUS_MQTT_FILE", str(RUNTIME_DIR / "mqtt.json")))
STREAM_TYPE = int(os.environ.get("BASEUS_STREAM_TYPE", "0"))
PPCS_TIMEOUT = float(os.environ.get("BASEUS_PPCS_TIMEOUT", "45"))
PPCS_POST_WAKE = float(os.environ.get("BASEUS_PPCS_POST_WAKE", "30"))
# Same knob name as the aiopppp path's heartbeat, 0 = off.
HEARTBEAT_SEC = float(os.environ.get("BASEUS_HEARTBEAT_SEC", "3") or 0)
STALL_SEC = 20
VIDEO_CHANNEL = 1

LOGIN_WAIT_READY_SEC = 4.0
# The camera can be punched before it ACKs DRW on a cold wake. Give the login
# ~8 s of retransmits (default budget is ~1.8 s) and one same-index resend.
LOGIN_ACK_INTERVAL = 0.5
LOGIN_ACK_MAX_ATTEMPTS = 16
LOGIN_ATTEMPTS = 2


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def can_use(cam: dict) -> bool:
    return bool(cam.get("device_did") and cam.get("service_string"))


def maybe_wake(cam: dict, *, timeout: float = 30) -> str:
    """Wake a battery camera over MQTT. Returns ok / skipped / failed. Never raises."""
    if not (cam.get("device_sn") and cam.get("product_id") and cam.get("wake_key")):
        return "skipped"
    try:
        settings = json.loads(MQTT_FILE.read_text())
    except (OSError, ValueError):
        log("wake skipped (no MQTT settings)")
        return "skipped"
    try:
        from .wake import wake_camera
        wake_camera(settings, cam["device_sn"], cam["product_id"], cam["wake_key"],
                    timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - camera may already be awake
        log(f"wake failed ({exc}); connecting anyway")
        return "failed"
    log("WatchDevice wake confirmed")
    return "ok"


def connect(cam: dict, *, wake=maybe_wake, discovery_cls=PpcsDiscovery):
    """Hello before wake, then wait for the punched peer. Returns a UdpSession."""
    disc = discovery_cls(cam["device_did"], cam["service_string"],
                         expected_lan=cam.get("host") or "",
                         timeout=PPCS_TIMEOUT, post_wake=PPCS_POST_WAKE, log=log)
    disc.start()
    try:
        wake(cam)
        disc.mark_wake()
        if disc.wait() is None:
            raise disc.error or PpcsError("PPCS: no peer")
        session = disc.take_session()
        if session is None:
            raise PpcsError("PPCS: no peer")
        return session
    finally:
        disc.close()


def _send_cmd(session, key: bytes, cmd: int, obj: dict) -> None:
    payload = json.dumps(obj, separators=(",", ":")).encode()
    session.send(0, P.build_command(cmd, payload, key=key))


def _login_reply(chunk: bytes, key: bytes):
    """Find an XM cmd-1 reply in a command-channel chunk; return its JSON dict."""
    off = 0
    while True:
        parsed = P.parse_command_response(chunk[off:])
        if parsed:
            cmd, entype, body = parsed
            if cmd == P.CMD_LOGIN:
                if entype:
                    body = P.aes_decrypt(key, body)
                try:
                    reply = json.loads(body.decode("utf-8", "replace"))
                except ValueError:
                    reply = None
                if isinstance(reply, dict):
                    return reply
        nxt = min((i for i in (chunk.find(b"\xaa\x55\xaa\x55", off + 1),
                               chunk.find(b"\xbb\x55\xbb\x55", off + 1)) if i >= 0),
                  default=-1)
        if nxt < 0:
            return None
        off = nxt


def xm_login(session, cam: dict, *, clock=time.monotonic) -> bool:
    user = cam["device_sn"]
    password = cam["p2p_password"]
    key = P.aes_key(password)
    reason = session.wait_until_ready(LOGIN_WAIT_READY_SEC)
    log(f">>> PPCS session ready ({reason}); logging in")
    session.set_ack_budget(interval=LOGIN_ACK_INTERVAL, max_attempts=LOGIN_ACK_MAX_ATTEMPTS)
    try:
        for attempt in range(1, LOGIN_ATTEMPTS + 1):
            if attempt == 1 or session.pending(0) == 0:
                rnd = "".join(str(secrets.randbelow(10)) for _ in range(6))
                _send_cmd(session, key, P.CMD_LOGIN, {
                    "username": user, "timestamp": int(time.time() * 1000), "random": rnd,
                    "user_id": "", "auth": P.login_auth(user, rnd, password),
                    "video": 0, "mic": 0, "res": 1})
            else:
                session.retry_unacked(0)  # same DRW index, fresh retry budget
            deadline = clock() + LOGIN_ACK_INTERVAL * LOGIN_ACK_MAX_ATTEMPTS + 2
            try:
                while clock() < deadline:
                    try:
                        channel, chunk = session.recv(min(deadline, clock() + 0.5))
                    except ReceiveTimeout:
                        continue
                    if channel == 0:
                        reply = _login_reply(chunk, key)
                        if reply is not None:
                            # Treat any cmd-1 reply as accepted unless it says otherwise.
                            ok = str(reply.get("result", "ok")).lower() in (
                                "ok", "success", "true", "0")
                            log(">>> login ok" if ok else ">>> login rejected")
                            return ok
            except PpcsError as exc:
                log(f">>> login attempt {attempt} failed ({exc})")
                if "closed" in str(exc):
                    return False
        log(">>> login timeout")
        return False
    finally:
        session.set_ack_budget()


def open_video(session, cam: dict) -> None:
    key = P.aes_key(cam["p2p_password"])
    ch, sn = cam.get("channel", 0), cam.get("camera_sn") or cam["device_sn"]
    if cam.get("is_homebase_child"):
        _send_cmd(session, key, P.CMD_HOMEBASE_LIVE_ENABLE,
                  {"channel": ch, "list": [{"sn": sn, "streamType": STREAM_TYPE}],
                   "videoKeepAlive_2": 1})
    _send_cmd(session, key, P.CMD_OPENVIDEO,
              {"channel": ch, "camera_sn": sn, "streamType": STREAM_TYPE,
               "videoKeepAlive_2": 1})


def stream(session, cam: dict, sink, *, should_stop=None, clock=time.monotonic) -> str:
    """Login, open video and push frames to ``sink`` until the session ends.

    Returns a short status: ``login_failed``, ``stall``, ``sink_closed``,
    ``stopped`` or ``ppcs_error``.
    """
    if not xm_login(session, cam, clock=clock):
        return "login_failed"
    open_video(session, cam)
    reasm = P.VideoReassembler(P.aes_key(cam["p2p_password"]))
    log(">>> video requested over cloud PPCS")
    now = clock()
    next_hb = now + HEARTBEAT_SEC if HEARTBEAT_SEC > 0 else float("inf")
    last_progress = now
    last_emitted = 0
    stalls = 0
    while True:
        if should_stop is not None and should_stop():
            return "stopped"
        now = clock()
        if now >= next_hb:
            session.send(0, P.build_command(P.CMD_HEARTBEAT, b"", model=0xE0))
            next_hb = now + HEARTBEAT_SEC
        if now - last_progress >= STALL_SEC:
            stalls += 1
            if stalls >= 3:
                log(">>> persistent stall; exiting")
                return "stall"
            log(f">>> stall #{stalls}; re-opening")
            open_video(session, cam)
            last_progress = now
        try:
            channel, chunk = session.recv(min(next_hb, now + 1.0))
        except ReceiveTimeout:
            continue
        except PpcsError as exc:
            log(f">>> PPCS session error ({exc})")
            return "ppcs_error"
        if channel != VIDEO_CHANNEL:
            continue
        try:
            for frame in reasm.feed_frames(chunk, drw_channel=channel):
                sink(frame)
        except (BrokenPipeError, ValueError):
            return "sink_closed"
        if reasm.emitted != last_emitted:
            last_emitted = reasm.emitted
            last_progress = clock()
            stalls = 0


def run(cam: dict, sink=None, *, should_stop=None) -> str:
    """Connect, stream to ``sink`` (default: Annex-B on stdout), always close.

    ``should_stop`` lets the dual-lens hub end the session when idle.
    """
    if sink is None:
        out = sys.stdout.buffer

        def sink(frame):
            out.write(frame.data)
            out.flush()
    log("connecting via cloud PPCS (P2P server rendezvous + hole punch)")
    session = connect(cam)
    try:
        return stream(session, cam, sink, should_stop=should_stop)
    finally:
        session.close()
        log(">>> PPCS session closed")
