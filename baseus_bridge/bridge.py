"""Live Baseus camera -> H.264 bridge (one camera per process).

Maintains a PPPP session to the HomeStation/camera, logs in with the
cloud-provided credentials, opens the live stream, decrypts each frame and
writes a clean Annex-B H.264 elementary stream to stdout. Pipe stdout into
ffmpeg to publish RTSP/HLS/WebRTC (see the orchestrator / MediaMTX config).

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
import sys
import time

from aiopppp import find_device
from aiopppp.packets import DrwPkt, make_drw_ack_pkt
from aiopppp.session import BinarySession
from aiopppp.types import Channel

from . import protocol as P

KEEPALIVE_SEC = 20
CAMERAS_FILE = os.environ.get("BASEUS_CAMERAS_FILE", "/run/baseus/cameras.json")


def log(*a):
    print(*a, file=sys.stderr, flush=True)


class CameraBridge(BinarySession):
    def __init__(self, cam, *a, **kw):
        super().__init__(*a, **kw)
        self.cam = cam
        self.key = P.aes_key(cam["p2p_password"])
        self.reasm = P.VideoReassembler(self.key)
        self.login_ok = False
        self.logged_in = asyncio.Event()
        self.out = sys.stdout.buffer
        self.dead = asyncio.Event()

    async def setup_device(self):
        self.device_is_ready.set()
        log(">>> PPPP up; logging in")
        asyncio.create_task(self.run())

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
                for frame in self.reasm.feed(raw):
                    self.out.write(frame)
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

    async def _open_video(self):
        ch, sn = self.cam["channel"], self.cam["camera_sn"]
        if self.cam.get("is_homebase_child", True):
            await self._send_cmd(P.CMD_HOMEBASE_LIVE_ENABLE,
                                 {"channel": ch, "list": [{"sn": sn, "streamType": 0}],
                                  "videoKeepAlive_2": 0})
            await asyncio.sleep(2)
        await self._send_cmd(P.CMD_OPENVIDEO,
                             {"channel": ch, "camera_sn": sn,
                              "streamType": 0, "videoKeepAlive_2": 0})

    async def run(self):
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
            log(">>> login timeout"); self.dead.set(); return
        if not self.login_ok:
            log(">>> login failed"); self.dead.set(); return
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


def resolve_camera(args) -> dict:
    if args.camera:
        try:
            with open(CAMERAS_FILE) as fh:
                cams = json.load(fh)
        except OSError as e:
            raise SystemExit(f"cannot read {CAMERAS_FILE}: {e}")
        for c in cams:
            if c.get("slug") == args.camera:
                return c
        raise SystemExit(f"camera slug {args.camera!r} not found in {CAMERAS_FILE}")
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


async def _main(cam: dict):
    log(f"discovering {cam['host']} ...")
    try:
        device = await find_device(cam["host"], timeout=15)
    except Exception as e:
        raise SystemExit(f"device discovery failed: {e}")
    log(f"device: {device.dev_id}")
    session = None

    def on_disc(_d):
        log(">>> device lost")
        if session:
            session.dead.set()

    session = CameraBridge(cam, device, on_disconnect=on_disc,
                           login="admin", password="admin")
    session.start()
    await session.dead.wait()
    log(">>> session ended")
    try:
        session.stop()
    except Exception:
        pass


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
    args = ap.parse_args(argv)
    cam = resolve_camera(args)
    # default is_homebase_child true only when we have a distinct base SN
    cam.setdefault("is_homebase_child", cam["camera_sn"] != cam["device_sn"])
    try:
        asyncio.run(_main(cam))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
