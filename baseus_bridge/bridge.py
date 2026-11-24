"""Live Baseus camera -> H.264 bridge (one camera per process).

Maintains a PPPP session to the HomeStation/camera, logs in with the
cloud-provided credentials, opens the live stream, decrypts each frame and
writes a clean Annex-B H.264 elementary stream to stdout. Pipe stdout into
ffmpeg to publish RTSP/HLS/WebRTC (see the orchestrator / MediaMTX config).

Transports (``BASEUS_TRANSPORT``):
  * ``lan``   -- aiopppp LAN discovery of the cloud-reported IP (original path)
  * ``cloud`` -- cloud-brokered PPCS hole punch + MQTT wake (``cloud_p2p``),
                 for cameras that never answer LAN search (e.g. X1 Pro)
  * ``auto``  -- (default) one LAN discovery attempt, then cloud PPCS if the
                 camera record has the rendezvous data

All logging goes to stderr so stdout stays a pure video byte stream.

Credentials are resolved (in order):
  * --camera SLUG   -> looked up in the runtime cameras file (no secrets in argv)
  * explicit --host/--device-sn/--p2p-password/--channel/--camera-sn
  * BASEUS_* environment variables
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time

from aiopppp import find_device
from aiopppp.packets import DrwPkt, make_drw_ack_pkt
from aiopppp.session import BinarySession
from aiopppp.types import Channel

from . import protocol as P
from .demux import split_path_slug

KEEPALIVE_SEC = 20
# lan | cloud | auto (see module docstring)
TRANSPORT = os.environ.get("BASEUS_TRANSPORT", "auto").strip().lower() or "auto"
CAMERAS_FILE = os.environ.get("BASEUS_CAMERAS_FILE", "/run/baseus/cameras.json")
# 0 = main/HD stream, 1 = sub/SD stream. SD is lighter and often loads faster.
STREAM_TYPE = int(os.environ.get("BASEUS_STREAM_TYPE", "0"))


def log(*a):
    print(*a, file=sys.stderr, flush=True)


class CameraBridge(BinarySession):
    def __init__(self, cam, *a, on_frame=None, **kw):
        super().__init__(*a, **kw)
        self.cam = cam
        self.key = P.aes_key(cam["p2p_password"])
        self.reasm = P.VideoReassembler(self.key)
        self.login_ok = False
        self.logged_in = asyncio.Event()
        self.out = sys.stdout.buffer
        self.on_frame = on_frame
        self.dead = asyncio.Event()

    async def setup_device(self):
        self.device_is_ready.set()
        log(">>> PPPP up; logging in")
        asyncio.create_task(self.run_monitor() if getattr(self, "monitor", False) else self.run())

    def on_receive(self, data):
        # aiopppp's parse_packet raises ValueError on PPPP packet types it does
        # not enumerate (e.g. 0x43) instead of falling back to a generic packet.
        # The camera emits some of these; they are non-essential control frames,
        # so drop them quietly rather than spamming the async read callback.
        try:
            super().on_receive(data)
        except ValueError:
            self._dropped_pkts = getattr(self, "_dropped_pkts", 0) + 1

    async def _send_cmd(self, cmd, obj):
        # NB: named _send_cmd (not _send) to avoid shadowing aiopppp's
        # BinarySession._send(pkt), which the library calls during its handshake.
        idx = self.outgoing_command_idx
        self.outgoing_command_idx += 1
        await self.send(DrwPkt(Channel.Command.value, idx, P.command_json(cmd, obj)))

    async def handle_drw(self, pkt):
        raw = pkt.get_drw_payload()
        await self.send(make_drw_ack_pkt(pkt))
        if pkt._channel == Channel.Video:
            try:
                for frame in self.reasm.feed_frames(raw):
                    if self.on_frame is not None:
                        self.on_frame(frame)
                    else:
                        self.out.write(frame.data)
                if self.on_frame is None:
                    self.out.flush()
            except (BrokenPipeError, ValueError):
                self.dead.set()
            return
        if pkt._channel == Channel.Audio:
            return
        parsed = P.parse_command_response(raw)
        if parsed and parsed[0] == P.CMD_LOGIN and parsed[1] == 0:
            try:
                obj = json.loads(parsed[2].decode("utf-8", "replace"))
                self.login_ok = str(obj.get("result")).lower() in ("ok", "success")
            except Exception:
                pass
            self.logged_in.set()
        if getattr(self, "monitor", False) and parsed:
            self._log_command(*parsed)

    def _log_command(self, cmd, entype, body):
        """Decode + print one command-channel frame (secrets redacted)."""
        from .orchestrator import _redact

        data = P.aes_decrypt(self.key, body) if entype else body
        js = None
        if data[:1] == b"{":
            try:
                js = json.loads(data.decode("utf-8", "replace"))
            except ValueError:
                js = None
        print(json.dumps({
            "dir": "dev->app",
            "cmd": cmd,
            "enc": bool(entype),
            "json": _redact(js) if isinstance(js, (dict, list)) else None,
        }, ensure_ascii=False), flush=True)

    async def _open_video(self):
        ch, sn = self.cam["channel"], self.cam["camera_sn"]
        if self.cam.get("is_homebase_child", True):
            await self._send_cmd(P.CMD_HOMEBASE_LIVE_ENABLE,
                                 {"channel": ch, "list": [{"sn": sn, "streamType": STREAM_TYPE}],
                                  "videoKeepAlive_2": 0})
            await asyncio.sleep(1)
        await self._send_cmd(P.CMD_OPENVIDEO,
                             {"channel": ch, "camera_sn": sn,
                              "streamType": STREAM_TYPE, "videoKeepAlive_2": 0})

    async def _do_login(self) -> bool:
        await asyncio.sleep(0.5)
        user = self.cam["device_sn"]
        pw = self.cam["p2p_password"]
        rnd = "".join(str((int(time.time() * 1000) >> (i * 3)) % 10) for i in range(6))
        await self._send_cmd(P.CMD_LOGIN, {
            "username": user, "timestamp": int(time.time() * 1000), "random": rnd,
            "user_id": "", "auth": P.login_auth(user, rnd, pw),
            "video": 0, "mic": 0, "res": 1})
        try:
            await asyncio.wait_for(self.logged_in.wait(), 8)
        except asyncio.TimeoutError:
            log(">>> login timeout"); self.dead.set(); return False
        if not self.login_ok:
            log(">>> login failed"); self.dead.set(); return False
        return True

    async def run_monitor(self):
        """Log in and passively log every command-channel frame (no video)."""
        if not await self._do_login():
            return
        log(">>> login ok; MONITORING command channel.")
        log(">>> Now toggle ONE setting in the Baseus app (e.g. the status light).")
        while not self.dead.is_set():
            await asyncio.sleep(5)

    async def run(self):
        if not await self._do_login():
            return
        log(">>> login ok; opening video")
        await self._open_video()
        last = self.reasm.emitted
        stalls = 0
        while not self.dead.is_set():
            await asyncio.sleep(KEEPALIVE_SEC)
            if self.reasm.emitted == last:
                stalls += 1
                log(f">>> stall #{stalls}; re-opening")
                await self._open_video()
                if stalls >= 3:
                    log(">>> persistent stall; exiting"); self.dead.set()
            else:
                stalls = 0
            last = self.reasm.emitted



def load_camera(slug: str) -> dict:
    """Load a camera record by MediaMTX path slug (``name`` or ``name-right``)."""
    base, _lens = split_path_slug(slug)
    try:
        with open(CAMERAS_FILE) as fh:
            cams = json.load(fh)
    except OSError as e:
        raise SystemExit(f"cannot read {CAMERAS_FILE}: {e}")
    for c in cams:
        if c.get("slug") == base or c.get("slug") == slug:
            return c
    raise SystemExit(f"camera slug {base!r} not found in {CAMERAS_FILE}")


def resolve_camera(args) -> dict:
    if args.camera:
        try:
            with open(CAMERAS_FILE) as fh:
                cams = json.load(fh)
        except OSError as e:
            raise SystemExit(f"cannot read {CAMERAS_FILE}: {e}")
        base, _lens = split_path_slug(args.camera)
        for c in cams:
            if c.get("slug") == base or c.get("slug") == args.camera:
                return c
        raise SystemExit(f"camera slug {base!r} not found in {CAMERAS_FILE}")
    host = args.host or os.environ.get("BASEUS_HOST")
    device_sn = args.device_sn or os.environ.get("BASEUS_DEVICE_SN")
    p2p = args.p2p_password or os.environ.get("BASEUS_P2P_PASSWORD")
    if not (host and device_sn and p2p):
        raise SystemExit("provide --camera SLUG or --host/--device-sn/--p2p-password")
    return {
        "host": host, "device_sn": device_sn, "p2p_password": p2p,
        "channel": int(args.channel if args.channel is not None
                        else os.environ.get("BASEUS_CAM_CHANNEL", 0)),
        "camera_sn": args.camera_sn or os.environ.get("BASEUS_CAM_SN") or device_sn,
        "is_homebase_child": args.homebase,
    }


async def _find_on_lan(cam: dict, attempts: int):
    if not cam.get("host"):
        log(">>> no LAN IP in the camera record; skipping LAN discovery")
        return None
    log(f"discovering {cam['host']} ...")
    for attempt in range(1, attempts + 1):
        try:
            return await find_device(cam["host"], timeout=10)
        except Exception as e:  # noqa: BLE001 - report and retry
            log(f">>> discovery attempt {attempt}/{attempts} failed: {e}")
            await asyncio.sleep(1)
    return None


def _transport_for(cam: dict, monitor: bool) -> str:
    from .cloud_p2p import can_use
    mode = TRANSPORT if TRANSPORT in ("auto", "lan", "cloud") else "auto"
    if monitor:
        return "lan"  # command monitor is implemented on the aiopppp session only
    if mode != "lan" and not can_use(cam):
        if mode == "cloud":
            log(">>> cloud PPCS needs device_did + service_string; falling back to LAN")
        return "lan"
    return mode


async def _main(cam: dict, monitor: bool = False, on_frame=None, idle_check=None):
    mode = _transport_for(cam, monitor)
    device = None
    if mode != "cloud":
        device = await _find_on_lan(cam, 3 if mode == "lan" else 1)
    if device is None:
        if mode == "lan":
            raise SystemExit("device discovery failed after retries")
        if mode == "auto":
            log(">>> LAN discovery failed; trying cloud PPCS")
        from . import cloud_p2p
        try:
            status = await asyncio.to_thread(cloud_p2p.run, cam, on_frame,
                                             should_stop=idle_check)
        except Exception as e:  # noqa: BLE001 - PpcsError, socket errors
            raise SystemExit(f"cloud PPCS connect failed: {e}")
        log(f">>> session ended ({status})")
        return
    log(f"device: {device.dev_id}")
    session = None

    def on_disc(_d):
        log(">>> device lost")
        if session:
            session.dead.set()

    session = CameraBridge(cam, device, on_disconnect=on_disc,
                           login="admin", password="admin", on_frame=on_frame)
    session.monitor = monitor
    session.start()
    if idle_check is not None:
        while not session.dead.is_set():
            if idle_check():
                log(">>> hub idle; closing")
                session.dead.set()
                break
            try:
                await asyncio.wait_for(session.dead.wait(), 1.0)
            except asyncio.TimeoutError:
                pass
    else:
        await session.dead.wait()
    log(">>> session ended")
    try:
        session.stop()
    except Exception:
        pass


def run_monitor_for(cam: dict):
    """Connect to a camera and log the command channel until interrupted."""
    cam.setdefault("is_homebase_child", cam.get("camera_sn") != cam.get("device_sn"))
    try:
        asyncio.run(_main(cam, monitor=True))
    except KeyboardInterrupt:
        pass



def run_hub(cam: dict) -> None:
    """Hold one P2P session and feed left/right FIFOs for MediaMTX path processes."""
    from . import lens_session as S
    from .demux import LEFT, RIGHT, LensDemux, lens_has_parameter_set, path_for_lens
    from .protocol import annexb_codec_hint, annexb_has_parameter_set
    from .still_cache import cache_from_live

    slug = cam["slug"]
    if not S.acquire_lease(slug, timeout=3.0):
        log(f"[hub] lease busy slug={slug}; exiting")
        return
    S.write_hub_pid(slug)
    S.ensure_fifos(slug)
    pumps = {LEFT: S.FifoPump(slug, LEFT, log=log), RIGHT: S.FifoPump(slug, RIGHT, log=log)}
    demux = LensDemux(log=log)
    started: set[str] = set()
    close_after = float(os.environ.get("BASEUS_CLOSE_AFTER", "30") or 30)
    last_demand = time.monotonic()

    def on_frame(frame):
        lens = demux.push(frame)
        if not lens_has_parameter_set(started, lens, frame.data):
            return
        hint = annexb_codec_hint(frame.data)
        if hint:
            S.set_codec(slug, hint)
        pump = pumps[lens]
        if annexb_has_parameter_set(frame.data):
            pump.set_bootstrap(frame.data)
            S.set_ready(slug, lens)
        else:
            pump.push(frame.data)
        cache_from_live(path_for_lens(slug, lens), frame.data, log=log)

    def idle_check():
        nonlocal last_demand
        if S.demand_pending(slug):
            last_demand = time.monotonic()
            return False
        return (time.monotonic() - last_demand) >= close_after

    try:
        log(f"[hub] starting slug={slug}")
        asyncio.run(_main(cam, on_frame=on_frame, idle_check=idle_check))
    except KeyboardInterrupt:
        pass
    finally:
        for pump in pumps.values():
            pump.close()
        S.clear_ready(slug)
        S.clear_hub_pid(slug)
        S.release_lease(slug)
        log(f"[hub] stopped slug={slug}")


def ensure_hub(cam: dict, *, timeout: float = 30.0) -> bool:
    from . import lens_session as S
    slug = cam["slug"]
    if S.hub_pid(slug):
        return True
    cmd = [sys.executable, "-m", "baseus_bridge.bridge", "--hub", slug]
    try:
        subprocess.Popen(
            cmd,
            start_new_session=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
        )
    except OSError as exc:
        log(f"[publish] failed to start hub slug={slug}: {exc}")
        return False
    return S.wait_until(lambda: S.hub_pid(slug) is not None, timeout)


def run_publish(path_slug: str, cam: dict | None = None) -> int:
    """MediaMTX runOnDemand entry: join the shared hub and publish one lens."""
    import subprocess
    from . import lens_session as S
    from .demux import split_path_slug

    base, lens = split_path_slug(path_slug)
    if cam is None:
        cam = load_camera(base)
    S.mark_demand(base, lens)
    try:
        if not ensure_hub(cam):
            log(f"[publish] hub-start-failed slug={base}")
            return 1
        start_timeout = float(os.environ.get("BASEUS_START_TIMEOUT", "60") or 60)
        if not S.wait_until(lambda: S.get_codec(base) or S.is_ready(base, lens), start_timeout):
            log(f"[publish] no-frames slug={path_slug}")
            return 1
        fmt = S.get_codec(base) or "h264"
        fifo = S.fifo_path(base, lens)
        rtsp_port = os.environ.get("BASEUS_RTSP_PORT", "8554")
        framerate = os.environ.get("BASEUS_FRAMERATE", "25")
        url = f"rtsp://127.0.0.1:{rtsp_port}/{path_slug}"
        cmd = [
            "ffmpeg", "-hide_banner", "-loglevel", "warning",
            "-fflags", "+genpts", "-analyzeduration", "3M", "-probesize", "3M",
            "-f", fmt, "-framerate", framerate, "-i", str(fifo),
            "-c:v", "copy", "-f", "rtsp", "-rtsp_transport", "tcp", url,
        ]
        log(f"[publish] ffmpeg {fmt} slug={path_slug}")
        proc = subprocess.run(cmd)
        return proc.returncode or 0
    except KeyboardInterrupt:
        return 130
    finally:
        S.clear_demand(base, lens)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Baseus camera -> H.264 stdout bridge")
    ap.add_argument("--camera", help="camera slug to load from the runtime cameras file")
    ap.add_argument("--host")
    ap.add_argument("--device-sn")
    ap.add_argument("--p2p-password")
    ap.add_argument("--channel", type=int)
    ap.add_argument("--camera-sn")
    ap.add_argument("--homebase", action="store_true",
                    help="camera is behind a HomeStation base (default autodetect via --camera)")
    ap.add_argument("--monitor", action="store_true",
                    help="log the command channel instead of streaming video")
    ap.add_argument("--publish", action="store_true",
                    help="publish this MediaMTX path (starts or joins a shared hub)")
    ap.add_argument("--hub", metavar="SLUG",
                    help="run the shared dual-lens P2P hub for this camera slug")
    args = ap.parse_args(argv)
    if args.hub:
        cam = load_camera(args.hub)
        cam.setdefault("is_homebase_child", cam["camera_sn"] != cam["device_sn"])
        run_hub(cam)
        return
    cam = resolve_camera(args)
    # default is_homebase_child true only when we have a distinct base SN
    cam.setdefault("is_homebase_child", cam["camera_sn"] != cam["device_sn"])
    if args.publish:
        path_slug = args.camera or cam.get("slug")
        if not path_slug:
            raise SystemExit("--publish requires --camera SLUG")
        raise SystemExit(run_publish(path_slug, cam))
    try:
        asyncio.run(_main(cam, monitor=args.monitor))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
