"""Lease, demand markers, and still cache (no network, no cameras)."""
from __future__ import annotations


from baseus_bridge import lens_session as S
from baseus_bridge import still_cache as cache
from baseus_bridge.demux import split_path_slug


def test_demand_pending_tracks_live_pid(tmp_path, monkeypatch):
    monkeypatch.setenv("BASEUS_RUNTIME_DIR", str(tmp_path))
    slug = "cam-a"
    assert not S.demand_pending(slug)
    S.mark_demand(slug, "right")
    assert S.demand_pending(slug)
    S.clear_demand(slug, "right")
    assert not S.demand_pending(slug)
    # Stale marker with a dead PID is ignored.
    dead = tmp_path / "cam-a.demand.left"
    dead.write_text("1")  # PID 1 may be alive on Linux; use a huge unused pid
    dead.write_text("99999999")
    assert not S.demand_pending(slug)
    assert not dead.exists()


def test_lease_is_exclusive(tmp_path, monkeypatch):
    monkeypatch.setenv("BASEUS_RUNTIME_DIR", str(tmp_path))
    slug = "cam-a"
    assert S.acquire_lease(slug, timeout=0.2)
    assert S.session_held(slug)
    # Same process already holds it.
    assert S.acquire_lease(slug, timeout=0.2)
    S.release_lease(slug)
    # After release, a new acquire should succeed.
    assert S.acquire_lease(slug, timeout=0.2)
    S.release_lease(slug)


def test_codec_and_bootstrap_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("BASEUS_RUNTIME_DIR", str(tmp_path))
    S.set_codec("cam-a", "hevc")
    assert S.get_codec("cam-a") == "hevc"
    S.set_bootstrap("cam-a", "right", b"\x00\x00\x00\x01\x40frame")
    assert S.get_bootstrap("cam-a", "right").endswith(b"frame")
    assert S.get_bootstrap("cam-a", "left") == b""


def test_still_get_returns_placeholder_then_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("BASEUS_RUNTIME_DIR", str(tmp_path))
    data, status = cache.jpeg_for_get("front-door-right")
    assert status == "placeholder"
    assert cache.is_jpeg(data)
    # Minimal cached JPEG (the built-in placeholder is itself a valid JPEG).
    assert cache.save_jpeg("front-door-right", cache.placeholder_jpeg())
    data2, status2 = cache.jpeg_for_get("front-door-right.jpg")
    assert status2 == "cache" and cache.is_jpeg(data2)
    base, lens = split_path_slug("front-door-right")
    assert base == "front-door" and lens == "right"


def test_still_slug_rejects_path_traversal():
    import pytest
    with pytest.raises(ValueError):
        cache.still_slug("../etc/passwd")
    with pytest.raises(ValueError):
        cache.still_slug("a/b")


# --- FIFO pump: publisher re-attach (live-test regression, 2026-11-24) ------
HEVC_IDR = (b"\x00\x00\x00\x01\x40\x01\x0c" + b"\x00\x00\x00\x01\x42\x01\x01"
            + b"\x00\x00\x00\x01\x44\x01\xc1" + b"\x00\x00\x00\x01\x26\x01" + b"I" * 32)


def _p_frame(i: int) -> bytes:
    return b"\x00\x00\x00\x01\x02\x01" + bytes([i]) * 16


def _read_fifo(path, want: int, timeout: float = 3.0) -> bytes:
    """Open like ffmpeg does (reader), read ``want`` bytes or until timeout."""
    import os
    import select
    import time
    fd = os.open(str(path), os.O_RDONLY | os.O_NONBLOCK)
    buf = b""
    deadline = time.monotonic() + timeout
    try:
        while len(buf) < want and time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.05)
            if ready:
                chunk = os.read(fd, 65536)
                if chunk:
                    buf += chunk
    finally:
        os.close(fd)
    return buf


def test_fifo_pump_serves_a_second_publisher_from_the_running_hub(tmp_path, monkeypatch):
    """Publisher 1 attaches, reads, detaches; publisher 2 must start at VPS/SPS/PPS+IDR."""
    import time
    monkeypatch.setenv("BASEUS_RUNTIME_DIR", str(tmp_path))
    pump = S.FifoPump("cam-a", "left")
    try:
        pump.set_bootstrap(HEVC_IDR)
        pump.push(_p_frame(1))
        first = _read_fifo(S.fifo_path("cam-a", "left"), len(HEVC_IDR) + 22)
        assert first.startswith(HEVC_IDR) and first.endswith(_p_frame(1))

        # Publisher 1 is gone; the hub keeps decoding (GOP continues, then a new IDR).
        for i in range(2, 6):
            pump.push(_p_frame(i))
            time.sleep(0.02)

        second = _read_fifo(S.fifo_path("cam-a", "left"), len(HEVC_IDR) + 4 * 22)
        assert second.startswith(HEVC_IDR), "re-attached publisher must start with VPS/SPS/PPS+IDR"
        # Frames since that IDR are replayed in order, so references stay valid.
        assert second[len(HEVC_IDR):].startswith(_p_frame(1) + _p_frame(2))
        assert pump.readers == 2
    finally:
        pump.close()


def test_fifo_pump_reattach_after_new_idr_starts_at_newest_idr(tmp_path, monkeypatch):
    monkeypatch.setenv("BASEUS_RUNTIME_DIR", str(tmp_path))
    pump = S.FifoPump("cam-b", "right")
    try:
        pump.set_bootstrap(HEVC_IDR)
        pump.push(_p_frame(1))
        assert _read_fifo(S.fifo_path("cam-b", "right"), len(HEVC_IDR) + 22).startswith(HEVC_IDR)
        newer = HEVC_IDR.replace(b"I" * 32, b"J" * 32)
        pump.push(_p_frame(2))
        pump.set_bootstrap(newer)
        pump.push(_p_frame(3))
        again = _read_fifo(S.fifo_path("cam-b", "right"), len(newer) + 22)
        assert again == newer + _p_frame(3)
    finally:
        pump.close()
