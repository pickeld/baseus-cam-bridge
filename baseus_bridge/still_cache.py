"""Lens-aware still JPEG cache, filled from live IDR frames."""
from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path

from .demux import path_for_lens, split_path_slug
from .lens_session import runtime_dir, safe_slug
from .protocol import annexb_codec_hint, annexb_has_parameter_set

_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")

# 1x1 JPEG, valid and tiny; used on cache miss so a still GET returns immediately.
_PLACEHOLDER = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    b"\xff\xdb\x00\x43\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\x09\x09"
    b"\x08\x0a\x0c\x14\x0d\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f"
    b"\x1e\x1d\x1a\x1c\x1c\x20\x24\x2e\x27\x20\x22\x2c\x23\x1c\x1c\x28\x37"
    b"\x29\x2c\x30\x31\x34\x34\x34\x1f\x27\x39\x3d\x38\x32\x3c\x2e\x33\x34"
    b"\x32\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00"
    b"\x14\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x08\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"
    b"\x2a\xff\xd9"
)


def still_slug(slug: str) -> str:
    value = (slug or "").strip()
    if value.endswith(".jpg") or value.endswith(".jpeg"):
        value = value.rsplit(".", 1)[0]
    if not _SLUG_RE.fullmatch(value):
        raise ValueError("invalid camera slug")
    return value


def stills_dir() -> Path:
    path = runtime_dir() / "stills"
    path.mkdir(parents=True, exist_ok=True)
    return path


def jpeg_path(slug: str) -> Path:
    return stills_dir() / f"{still_slug(slug)}.jpg"


def is_jpeg(data: bytes) -> bool:
    return bool(data) and data[:2] == b"\xff\xd8" and data[-2:] == b"\xff\xd9"


def placeholder_jpeg() -> bytes:
    return _PLACEHOLDER


def save_jpeg(slug: str, data: bytes) -> Path | None:
    if not is_jpeg(data):
        return None
    path = jpeg_path(slug)
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_bytes(data)
        tmp.replace(path)
        return path
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        return None


def load_jpeg(slug: str) -> bytes | None:
    try:
        data = jpeg_path(slug).read_bytes()
    except OSError:
        return None
    return data if is_jpeg(data) else None


def annexb_to_jpeg(data: bytes, fmt: str | None = None) -> bytes | None:
    """Decode one Annex-B frame to JPEG with ffmpeg. Returns None on failure."""
    if not data:
        return None
    codec = fmt or annexb_codec_hint(data) or "h264"
    if codec not in ("h264", "hevc"):
        codec = "h264"
    try:
        proc = subprocess.run(
            [
                "ffmpeg", "-hide_banner", "-loglevel", "error",
                "-f", codec, "-i", "pipe:0",
                "-frames:v", "1", "-q:v", "4",
                "-f", "image2pipe", "-vcodec", "mjpeg", "pipe:1",
            ],
            input=data,
            capture_output=True,
            timeout=8,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode == 0 and is_jpeg(proc.stdout):
        return proc.stdout
    return None


_last_still: dict[str, float] = {}


def cache_from_live(path_slug: str, data: bytes, *, min_interval: float = 5.0, log=None) -> bool:
    """If this frame has a parameter set, try to cache a still for the path."""
    if not annexb_has_parameter_set(data or b""):
        return False
    try:
        path_slug = still_slug(path_slug)
    except ValueError:
        return False
    now = time.monotonic()
    last = _last_still.get(path_slug, 0.0)
    if now - last < min_interval:
        return False
    jpeg = annexb_to_jpeg(data)
    if not jpeg:
        return False
    if save_jpeg(path_slug, jpeg) is None:
        return False
    _last_still[path_slug] = now
    if log:
        log(f"[still] cache-from-live slug={path_slug} valid JPEG {len(jpeg)}B")
    return True


def jpeg_for_get(slug: str) -> tuple[bytes, str]:
    """Return (jpeg_bytes, 'cache'|'placeholder') for a still GET."""
    try:
        slug = still_slug(slug)
    except ValueError:
        return placeholder_jpeg(), "placeholder"
    data = load_jpeg(slug)
    if data:
        return data, "cache"
    return placeholder_jpeg(), "placeholder"


# Re-export for callers that have a base slug + lens.
def path_slug_for(base: str, lens: str) -> str:
    return path_for_lens(safe_slug(base), lens)


def base_slug_of(path_slug: str) -> str:
    return split_path_slug(path_slug)[0]
