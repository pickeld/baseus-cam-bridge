"""Lease, demand markers, and FIFOs so left and right paths share one P2P session.

MediaMTX starts one process per path. A dual-lens camera must not be opened
twice. The first path to publish starts a background hub that holds the
camera session and writes each lens to a FIFO; the other path joins by
reading the sibling FIFO. Demand markers keep the hub alive while either
path still has a viewer.
"""
from __future__ import annotations

import errno
import fcntl
import os
import stat
import time
from pathlib import Path

LEFT = "left"
RIGHT = "right"
_DEMAND_STALE_SEC = 90.0


def runtime_dir() -> Path:
    path = Path(os.environ.get("BASEUS_RUNTIME_DIR", "/run/baseus"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_slug(slug: str) -> str:
    value = (slug or "").strip()
    if not value or "/" in value or "\\" in value or ".." in value:
        raise ValueError("invalid camera slug")
    return value


def _lens_name(lens: str) -> str:
    return RIGHT if lens in (RIGHT, "-right") else LEFT


def fifo_path(slug: str, lens: str) -> Path:
    return runtime_dir() / f"{safe_slug(slug)}.{_lens_name(lens)}.fifo"


def codec_path(slug: str) -> Path:
    return runtime_dir() / f"{safe_slug(slug)}.codec"


def hub_pid_path(slug: str) -> Path:
    return runtime_dir() / f"{safe_slug(slug)}.hub.pid"


def _demand_path(slug: str, lens: str) -> Path:
    return runtime_dir() / f"{safe_slug(slug)}.demand.{_lens_name(lens)}"


def _ready_path(slug: str, lens: str) -> Path:
    return runtime_dir() / f"{safe_slug(slug)}.{_lens_name(lens)}.ready"


def _lease_path(slug: str) -> Path:
    return runtime_dir() / f"{safe_slug(slug)}.lease"


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def mark_demand(slug: str, lens: str = LEFT) -> None:
    try:
        _demand_path(slug, lens).write_text(str(os.getpid()))
    except (OSError, ValueError):
        pass


def clear_demand(slug: str, lens: str | None = None) -> None:
    lenses = (lens,) if lens else (LEFT, RIGHT)
    for item in lenses:
        try:
            _demand_path(slug, item).unlink()
        except OSError:
            pass


def demand_pending(slug: str) -> bool:
    """True if any live publish process has announced demand for this camera."""
    try:
        slug = safe_slug(slug)
    except ValueError:
        return False
    now = time.time()
    pending = False
    for lens in (LEFT, RIGHT):
        path = _demand_path(slug, lens)
        try:
            raw = path.read_text().strip()
            mtime = path.stat().st_mtime
        except OSError:
            continue
        pid = None
        try:
            pid = int(raw)
        except ValueError:
            pid = None
        if pid is not None:
            if _pid_alive(pid):
                pending = True
                continue
            try:
                path.unlink()
            except OSError:
                pass
            continue
        if now - mtime <= _DEMAND_STALE_SEC:
            pending = True
        else:
            try:
                path.unlink()
            except OSError:
                pass
    return pending


def set_ready(slug: str, lens: str) -> None:
    try:
        _ready_path(slug, lens).write_text("1")
    except (OSError, ValueError):
        pass


def clear_ready(slug: str, lens: str | None = None) -> None:
    lenses = (lens,) if lens else (LEFT, RIGHT)
    for item in lenses:
        try:
            _ready_path(slug, item).unlink()
        except OSError:
            pass


def is_ready(slug: str, lens: str) -> bool:
    try:
        return _ready_path(slug, lens).is_file()
    except (OSError, ValueError):
        return False


def set_codec(slug: str, codec: str) -> None:
    if codec not in ("h264", "hevc"):
        return
    try:
        codec_path(slug).write_text(codec)
    except (OSError, ValueError):
        pass


def get_codec(slug: str) -> str | None:
    try:
        value = codec_path(slug).read_text().strip()
    except OSError:
        return None
    return value if value in ("h264", "hevc") else None


def ensure_fifos(slug: str) -> None:
    for lens in (LEFT, RIGHT):
        path = fifo_path(slug, lens)
        try:
            if path.exists() and not stat.S_ISFIFO(path.stat().st_mode):
                path.unlink()
            if not path.exists():
                os.mkfifo(path, 0o600)
        except OSError:
            pass


def open_fifo_writer(slug: str, lens: str):
    """Open a FIFO for writing without blocking if no reader is present.

    Opening RDWR means the writer is also a dummy reader, so write() will
    not raise ENXIO when the path process has not attached yet. Frames are
    dropped on EAGAIN.
    """
    path = fifo_path(slug, lens)
    try:
        fd = os.open(str(path), os.O_RDWR | os.O_NONBLOCK)
    except OSError:
        return None
    return fd


def write_fifo(fd, data: bytes) -> bool:
    if fd is None or not data:
        return False
    try:
        os.write(fd, data)
        return True
    except OSError as exc:
        if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EPIPE, errno.ECONNRESET):
            return False
        return False


def close_fd(fd) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def hub_pid(slug: str) -> int | None:
    try:
        pid = int(hub_pid_path(slug).read_text().strip())
    except (OSError, ValueError):
        return None
    if _pid_alive(pid):
        return pid
    try:
        hub_pid_path(slug).unlink()
    except OSError:
        pass
    return None


def write_hub_pid(slug: str) -> None:
    try:
        hub_pid_path(slug).write_text(str(os.getpid()))
    except (OSError, ValueError):
        pass


def clear_hub_pid(slug: str) -> None:
    try:
        path = hub_pid_path(slug)
        raw = path.read_text().strip()
        if raw == str(os.getpid()):
            path.unlink()
    except OSError:
        pass


_lease_fds: dict[str, object] = {}


def acquire_lease(slug: str, *, timeout: float = 5.0) -> bool:
    """Non-blocking-ish exclusive flock. Returns True if this process holds it."""
    try:
        slug = safe_slug(slug)
    except ValueError:
        return False
    if slug in _lease_fds:
        return True
    deadline = time.monotonic() + max(0.0, timeout)
    path = _lease_path(slug)
    while time.monotonic() <= deadline:
        try:
            fd = open(path, "a+")
        except OSError:
            return False
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fd.close()
            time.sleep(0.1)
            continue
        _lease_fds[slug] = fd
        return True
    return False


def release_lease(slug: str) -> None:
    try:
        slug = safe_slug(slug)
    except ValueError:
        return
    fd = _lease_fds.pop(slug, None)
    if fd is None:
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        fd.close()
    except OSError:
        pass


def session_held(slug: str) -> bool:
    try:
        slug = safe_slug(slug)
    except ValueError:
        return False
    if slug in _lease_fds:
        return True
    path = _lease_path(slug)
    try:
        fd = open(path, "a+")
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    except BlockingIOError:
        return True
    finally:
        fd.close()


def wait_until(predicate, timeout: float, interval: float = 0.2) -> bool:
    deadline = time.monotonic() + max(0.0, timeout)
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return bool(predicate())


def bootstrap_path(slug: str, lens: str) -> Path:
    return runtime_dir() / f"{safe_slug(slug)}.{_lens_name(lens)}.boot"


def set_bootstrap(slug: str, lens: str, data: bytes) -> None:
    if not data:
        return
    path = bootstrap_path(slug, lens)
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_bytes(data)
        tmp.replace(path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass


def get_bootstrap(slug: str, lens: str) -> bytes:
    try:
        return bootstrap_path(slug, lens).read_bytes()
    except OSError:
        return b""


class FifoPump:
    """Feed one lens FIFO to whichever ffmpeg publisher is attached right now.

    MediaMTX stops a ``runOnDemand`` publisher when its last reader leaves and
    starts a new one on the next request, while the hub (camera session) may
    still be running. So the pump must survive its reader going away: on
    EPIPE it closes the FIFO and waits for the next reader.

    Every new reader first gets the latest parameter-set frame (VPS/SPS/PPS +
    IDR) followed by the frames since it (the current GOP, bounded), so it can
    decode immediately with valid references. Live frames are dropped if the
    reader is too slow, rather than blocking the camera session.
    """

    MAX_QUEUE = 90
    MAX_GOP_FRAMES = 300
    MAX_GOP_BYTES = 8 * 1024 * 1024
    REOPEN_POLL_SEC = 0.1

    def __init__(self, slug: str, lens: str, *, log=None):
        import threading
        self.slug = slug
        self.lens = _lens_name(lens)
        self._log = log
        self._bootstrap = b""
        self._gop: list[bytes] = []
        self._gop_bytes = 0
        self._q: list[bytes] = []
        self._cv = threading.Condition()
        self._stop = False
        self._thread = None
        self.readers = 0  # publishers served so far (diagnostics/tests)

    def start(self) -> None:
        import threading
        if self._thread is not None and self._thread.is_alive():
            return
        ensure_fifos(self.slug)
        self._thread = threading.Thread(target=self._run, name=f"fifo-{self.slug}-{self.lens}",
                                        daemon=True)
        self._thread.start()

    def set_bootstrap(self, data: bytes) -> None:
        """Record a parameter-set/IDR frame and send it in stream order."""
        if not data:
            return
        set_bootstrap(self.slug, self.lens, data)
        with self._cv:
            self._bootstrap = data
            self._gop = []
            self._gop_bytes = 0
            self._enqueue(data)
        self.start()

    def push(self, data: bytes) -> None:
        if not data:
            return
        with self._cv:
            if self._bootstrap:
                if (len(self._gop) < self.MAX_GOP_FRAMES
                        and self._gop_bytes + len(data) <= self.MAX_GOP_BYTES):
                    self._gop.append(data)
                    self._gop_bytes += len(data)
                # else: very long GOP; a late reader resyncs at the next IDR
            self._enqueue(data)
        self.start()

    def _enqueue(self, data: bytes) -> None:
        if len(self._q) >= self.MAX_QUEUE:
            self._q.pop(0)
        self._q.append(data)
        self._cv.notify()

    def close(self) -> None:
        with self._cv:
            self._stop = True
            self._cv.notify()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _open_reader(self):
        """Wait (interruptibly) until a reader opens the FIFO; return a write fd."""
        path = fifo_path(self.slug, self.lens)
        while True:
            with self._cv:
                if self._stop:
                    return None
            try:
                fd = os.open(str(path), os.O_WRONLY | os.O_NONBLOCK)
            except OSError as exc:
                if exc.errno in (errno.ENXIO, errno.ENOENT):  # no reader yet
                    if exc.errno == errno.ENOENT:
                        ensure_fifos(self.slug)
                    time.sleep(self.REOPEN_POLL_SEC)
                    continue
                if self._log:
                    self._log(f"[hub] fifo-open-failed lens={self.lens} err={exc}")
                return None
            os.set_blocking(fd, True)
            return fd

    @staticmethod
    def _write_all(fd, data: bytes) -> bool:
        try:
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                view = view[n:]
            return True
        except OSError:
            return False  # EPIPE: the publisher went away

    def _run(self) -> None:
        while True:
            fd = self._open_reader()
            if fd is None:
                return
            with self._cv:
                # New reader: start at the latest IDR + its GOP; drop stale queue.
                start = [self._bootstrap] + list(self._gop) if self._bootstrap else []
                self._q.clear()
                self.readers += 1
            if self._log:
                self._log(f"[hub] publisher attached slug={self.slug} lens={self.lens} "
                          f"replay_frames={len(start)}")
            ok = all(self._write_all(fd, chunk) for chunk in start)
            while ok:
                with self._cv:
                    while not self._stop and not self._q:
                        self._cv.wait(timeout=0.5)
                    if self._stop:
                        break
                    chunk = self._q.pop(0)
                ok = self._write_all(fd, chunk)
            try:
                os.close(fd)
            except OSError:
                pass
            with self._cv:
                if self._stop:
                    return
            if self._log:
                self._log(f"[hub] publisher detached slug={self.slug} lens={self.lens}; "
                          "waiting for the next one")
