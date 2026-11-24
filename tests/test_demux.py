"""Dual-lens demux, AV header parse, and <slug>-right MediaMTX wiring."""
from __future__ import annotations

from baseus_bridge.demux import (
    HEVC_BIT, LEFT, LENS_BIT, RIGHT, LensDemux, lens_has_parameter_set,
    lens_of_command, right_path, split_path_slug,
)
from baseus_bridge.protocol import (
    VideoFrame, VideoReassembler, annexb_codec_hint, annexb_has_parameter_set,
    annexb_sps_fingerprint, build_av_packet, parse_av_header,
)


SPS_A = b"\x00\x00\x00\x01\x67\x42\x00\x0a"
SPS_B = b"\x00\x00\x00\x01\x67\x4d\x00\x0b"
PPS = b"\x00\x00\x00\x01\x68\x00"
IDR = b"\x00\x00\x00\x01\x65\x00"
SLC = b"\x00\x00\x00\x01\x61\x00"
# HEVC VPS (type 32) + SPS (type 33) start codes; forbidden_zero + type in byte0.
HEVC_VPS = b"\x00\x00\x00\x01\x40\x01\x0c\x01"
HEVC_SPS = b"\x00\x00\x00\x01\x42\x01\x01\x01"
HEVC_IDR = b"\x00\x00\x00\x01\x26\x01\x00"

# Observed X1 Pro Dual command values: I vs P is the low byte (0x1a / 0x2a),
# lens is bit 14 (0x4000).
CMD_LEFT_I = 0x0F1A
CMD_LEFT_P = 0x0F2A
CMD_RIGHT_I = 0x4F1A
CMD_RIGHT_P = 0x4F2A


def _pkt(payload, *, fn=1, command=0x0F1A, vfm=1, timestamp=1, cur_pkt=1, pkt_cnt=1):
    return build_av_packet(
        payload, vfm=vfm, fn=fn, command=command, timestamp=timestamp,
        cur_pkt=cur_pkt, pkt_cnt=pkt_cnt, entype=0,
    )


def test_split_path_slug_and_right_path():
    assert split_path_slug("front-door") == ("front-door", LEFT)
    assert split_path_slug("front-door-right") == ("front-door", RIGHT)
    assert split_path_slug("backyard-right") == ("backyard", RIGHT)
    assert right_path("backyard") == "backyard-right"
    assert split_path_slug("right") == ("right", LEFT)
    assert split_path_slug("-right") == ("-right", LEFT)


def test_parse_av_header_command_and_timestamp():
    payload = SPS_A + PPS + IDR
    raw = _pkt(payload, fn=9, command=0x4F1A, timestamp=123456789, vfm=2)
    hdr = parse_av_header(raw, 0)
    assert hdr is not None
    assert hdr["vfm"] == 2 and hdr["fn"] == 9
    assert hdr["command"] == 0x4F1A
    assert hdr["timestamp"] == 123456789
    assert hdr["dsize"] == len(payload)
    assert hdr["entype"] == 0


def test_reassembler_keeps_two_command_streams_interleaved():
    reasm = VideoReassembler(b"\x00" * 16, start_on_sps=True)
    left_idr = SPS_A + PPS + IDR
    right_idr = SPS_B + PPS + IDR
    left_p = SLC
    blob = (
        _pkt(left_idr, fn=1, command=0x0F1A, timestamp=10)
        + _pkt(right_idr, fn=1, command=0x4F1A, timestamp=11)
        + _pkt(left_p, fn=2, command=0x0F1A, timestamp=12, vfm=2)
    )
    frames = list(reasm.feed_frames(blob, drw_channel=1))
    assert len(frames) == 3
    assert [f.command for f in frames] == [0x0F1A, 0x4F1A, 0x0F1A]
    assert frames[0].data.startswith(SPS_A)
    assert frames[1].data.startswith(SPS_B)
    assert frames[2].data == left_p
    reasm2 = VideoReassembler(b"\x00" * 16, start_on_sps=True)
    raw_frames = list(reasm2.feed(blob))
    assert raw_frames == [f.data for f in frames]


def test_reassembler_assembles_parts_per_identity():
    reasm = VideoReassembler(b"\x00" * 16, start_on_sps=False)
    a1 = _pkt(b"\x00\x00\x00\x01\x61AA", fn=5, command=0x0F1A, timestamp=1, cur_pkt=1, pkt_cnt=2)
    b1 = _pkt(b"\x00\x00\x00\x01\x61BB", fn=5, command=0x4F1A, timestamp=2, cur_pkt=1, pkt_cnt=2)
    a2 = _pkt(b"CC", fn=5, command=0x0F1A, timestamp=1, cur_pkt=2, pkt_cnt=2)
    b2 = _pkt(b"DD", fn=5, command=0x4F1A, timestamp=2, cur_pkt=2, pkt_cnt=2)
    frames = list(reasm.feed_frames(a1 + b1 + a2 + b2))
    assert len(frames) == 2
    assert frames[0].command == 0x0F1A and frames[0].data.endswith(b"CC")
    assert frames[1].command == 0x4F1A and frames[1].data.endswith(b"DD")


def test_hevc_parameter_set_starts_the_reassembler():
    reasm = VideoReassembler(b"\x00" * 16, start_on_sps=True)
    p_frame = _pkt(SLC, fn=1, command=CMD_LEFT_P, timestamp=1)
    assert list(reasm.feed_frames(p_frame)) == []
    idr = HEVC_VPS + HEVC_SPS + HEVC_IDR
    frames = list(reasm.feed_frames(_pkt(idr, fn=2, command=CMD_LEFT_I, timestamp=2)))
    assert len(frames) == 1
    assert annexb_has_parameter_set(frames[0].data)
    assert annexb_codec_hint(frames[0].data) == "hevc"


def _vf(payload, command, *, fn=1, vfm=2, drw=1):
    return VideoFrame(payload, vfm=vfm, fn=fn, command=command,
                      timestamp=fn, entype=0, pkt_cnt=1, drw_channel=drw)


def test_lens_of_command_uses_bit14_ignores_ip_and_hevc():
    assert LENS_BIT == 0x4000 and HEVC_BIT == 0x8000
    assert lens_of_command(CMD_LEFT_I) == LEFT
    assert lens_of_command(CMD_LEFT_P) == LEFT
    assert lens_of_command(CMD_RIGHT_I) == RIGHT
    assert lens_of_command(CMD_RIGHT_P) == RIGHT
    assert lens_of_command(CMD_LEFT_I | HEVC_BIT) == LEFT
    assert lens_of_command(CMD_LEFT_P | HEVC_BIT) == LEFT
    assert lens_of_command(CMD_RIGHT_I | HEVC_BIT) == RIGHT
    assert lens_of_command(CMD_RIGHT_P | HEVC_BIT) == RIGHT
    assert lens_of_command(0xF1A) == lens_of_command(0xF2A) == LEFT
    assert (0x4F1A - 0x0F1A) == LENS_BIT
    assert (0x4F2A - 0x0F2A) == LENS_BIT


def test_lens_demux_x1pro_command_values():
    demux = LensDemux(log=None)
    left_idr = _vf(SPS_A + PPS + IDR, CMD_LEFT_I, fn=0)
    right_idr = _vf(SPS_A + PPS + IDR, CMD_RIGHT_I, fn=15)
    right_p = _vf(SLC, CMD_RIGHT_P, fn=16)
    assert annexb_sps_fingerprint(left_idr.data) == annexb_sps_fingerprint(right_idr.data)

    assert demux.push(left_idr) == LEFT
    for i in range(1, 14):
        assert demux.push(_vf(SLC, CMD_LEFT_P, fn=i)) == LEFT
    assert demux.push(right_idr) == RIGHT
    assert demux.push(_vf(SPS_A + PPS + IDR, CMD_LEFT_I, fn=14)) == LEFT
    assert demux.push(right_p) == RIGHT
    assert demux.push(_vf(SLC, CMD_LEFT_P, fn=15)) == LEFT

    assert demux.counts[LEFT] == 2 + 13 + 1
    assert demux.counts[RIGHT] == 2
    assert demux.cmd_counts[CMD_LEFT_I] == 2
    assert demux.cmd_counts[CMD_LEFT_P] == 14
    assert demux.cmd_counts[CMD_RIGHT_I] == 1
    assert demux.cmd_counts[CMD_RIGHT_P] == 1
    assert len(demux.sps_counts) == 1
    text = demux.summary()
    assert "left=16" in text and "right=2" in text
    assert "0xf1a:" in text and "0xf2a:" in text
    assert "0x4f1a:" in text and "0x4f2a:" in text
    assert "key=cmd&0x4000" in text
    assert "192.168" not in text


def test_lens_demux_does_not_split_on_drw_or_first_seen_cmd():
    demux = LensDemux(log=None)
    assert demux.push(_vf(SPS_A + PPS + IDR, CMD_LEFT_I, drw=1)) == LEFT
    assert demux.push(_vf(SLC, CMD_LEFT_P, fn=2, drw=1)) == LEFT
    assert demux.push(_vf(SLC, CMD_LEFT_P, fn=3, drw=2)) == LEFT
    assert demux.push(_vf(SPS_A + PPS + IDR, CMD_RIGHT_I, drw=1)) == RIGHT
    assert demux.counts[LEFT] == 3 and demux.counts[RIGHT] == 1


def test_per_lens_start_gate_drops_right_p_before_right_idr():
    started: set[str] = set()
    assert lens_has_parameter_set(started, LEFT, SPS_A + PPS + IDR)
    assert LEFT in started
    assert not lens_has_parameter_set(started, RIGHT, SLC)
    assert lens_has_parameter_set(started, RIGHT, SPS_A + PPS + IDR)
    assert lens_has_parameter_set(started, RIGHT, SLC)


def test_mediamtx_cfg_includes_right_paths():
    from baseus_bridge import orchestrator as O
    cfg = O._render_mediamtx_cfg([{"slug": "cam-a"}])
    assert "  cam-a:" in cfg
    assert "  cam-a-right:" in cfg
    assert cfg.count("runOnDemand:") == 2
    assert "--camera $MTX_PATH --publish" in cfg


def test_load_camera_resolves_right_slug(tmp_path, monkeypatch):
    import json
    from baseus_bridge import bridge as B
    cams = [{"slug": "backyard", "name": "back", "channel": 0}]
    path = tmp_path / "cameras.json"
    path.write_text(json.dumps(cams))
    monkeypatch.setattr(B, "CAMERAS_FILE", str(path))
    assert B.load_camera("backyard")["slug"] == "backyard"
    assert B.load_camera("backyard-right")["slug"] == "backyard"
