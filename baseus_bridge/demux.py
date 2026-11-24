"""Split a muxed dual-lens Annex-B stream into left and right.

On Baseus X1 Pro Dual cameras, one openvideo session carries both lenses
muxed on the same DRW video channel. The XM AV header ``command`` field
(uint16 at offset 14) has the lens in bit 14 (``0x4000``): clear is left,
set is right. The low byte (``0x1a`` vs ``0x2a``) is I-frame vs P-frame
and must not be used to pick a lens. Bit 15 (``0x8000``, the SDK HEVC
flag) is also ignored for the lens decision; it is often clear even when
the payload is HEVC.

Both lenses may share one SPS. Do not split on SPS fingerprint, DRW
channel, or first-seen command value. Login / cmd 2 does not select a
lens; a second openvideo is not sent. If only one lens bit is seen, the
right path simply receives no frames (log ``right-absent``).

Assignment: ``lens = right if (command & 0x4000) else left``.
"""
from __future__ import annotations

from collections import Counter

from .protocol import VideoFrame, annexb_has_parameter_set, annexb_nal_types, annexb_sps_fingerprint

LEFT = "left"
RIGHT = "right"

LENS_BIT = 0x4000  # bit 14: 0 = left, 1 = right
HEVC_BIT = 0x8000  # bit 15: SDK HEVC flag (not used for lens)


def lens_of_command(command: int) -> str:
    """Return 'left' or 'right' from the XM AV command field."""
    return RIGHT if (int(command) & LENS_BIT) else LEFT


def lens_has_parameter_set(started: set[str], lens: str, data: bytes) -> bool:
    """True once this lens has seen an SPS/VPS; drop earlier P-frames.

    VideoReassembler's start_on_sps flag is global, so a left IDR would
    otherwise let a later right P-frame through before that lens's IDR.
    """
    if lens in started:
        return True
    if annexb_has_parameter_set(data or b""):
        started.add(lens)
        return True
    return False


def split_path_slug(slug: str) -> tuple[str, str]:
    """Return (base_slug, 'left'|'right') for a MediaMTX path name."""
    value = (slug or "").strip()
    if value.endswith("-right") and len(value) > len("-right"):
        return value[: -len("-right")], RIGHT
    return value, LEFT


def right_path(base_slug: str) -> str:
    return f"{base_slug}-right"


def path_for_lens(base_slug: str, lens: str) -> str:
    return right_path(base_slug) if lens == RIGHT else base_slug


class LensDemux:
    """Map each VideoFrame to left or right from bit 14 of ``command``."""

    def __init__(self, *, log=None, header_log_frames: int = 24):
        self._log = log
        self._header_log_frames = max(0, int(header_log_frames))
        self._logged_cmds: set[int] = set()
        self.counts = Counter()
        self.cmd_counts = Counter()
        self.vfm_counts = Counter()
        self.drw_counts = Counter()
        self.sps_counts: Counter = Counter()
        self._frames_logged = 0
        self._summary_every = 50
        self._right_absent_logged = False

    def _assign(self, frame: VideoFrame) -> str:
        cmd = int(frame.command)
        lens = lens_of_command(cmd)
        if self._log and cmd not in self._logged_cmds:
            self._logged_cmds.add(cmd)
            self._log(f"[demux] map key=cmd=0x{cmd:x} -> {lens}")
        return lens

    def push(self, frame: VideoFrame) -> str:
        """Return 'left' or 'right' for this frame."""
        lens = self._assign(frame)
        self.counts[lens] += 1
        self.cmd_counts[frame.command] += 1
        self.vfm_counts[frame.vfm] += 1
        self.drw_counts[frame.drw_channel] += 1
        fp = annexb_sps_fingerprint(frame.data)
        if fp:
            self.sps_counts[fp] += 1
        self._log_frame(frame, lens, fp)
        return lens

    def _log_frame(self, frame: VideoFrame, lens: str, fp: str | None) -> None:
        if not self._log:
            return
        n = sum(self.counts.values())
        if self._frames_logged < self._header_log_frames:
            self._frames_logged += 1
            fp_s = f" sps={fp}" if fp else ""
            self._log(
                f"[demux] frame n={self._frames_logged} lens={lens} "
                f"vfm={frame.vfm} fn={frame.fn} cmd=0x{frame.command:x} "
                f"drw={frame.drw_channel} nal={annexb_nal_types(frame.data)}{fp_s}"
            )
        if n > 0 and n % self._summary_every == 0:
            self._log(self.summary())
            if not self.has_lens(RIGHT) and not self._right_absent_logged:
                self._right_absent_logged = True
                self._log("[demux] right-absent")

    def summary(self) -> str:
        cmds = ",".join(f"0x{c:x}:{n}" for c, n in sorted(self.cmd_counts.items()))
        vfms = ",".join(f"{v}:{n}" for v, n in sorted(self.vfm_counts.items()))
        drws = ",".join(f"{d}:{n}" for d, n in sorted(self.drw_counts.items()))
        sps = ",".join(f"{k}:{n}" for k, n in self.sps_counts.items()) or "none"
        return (
            f"[demux] summary left={self.counts[LEFT]} right={self.counts[RIGHT]} "
            f"cmd={cmds or 'none'} vfm={vfms or 'none'} drw={drws or 'none'} "
            f"sps_sets={len(self.sps_counts)} sps={sps} key=cmd&0x4000"
        )

    def has_lens(self, lens: str) -> bool:
        return self.counts[lens] > 0
