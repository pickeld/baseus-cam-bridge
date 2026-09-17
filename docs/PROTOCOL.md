# Protocol notes (high level)

This project interoperates with Baseus Security cameras that use the XM/PPPP
platform. A short overview of the moving parts:

- **Cloud login & device list.** The gateway performs the same account login and
  device-list request as the official app, using your credentials, to learn which
  cameras exist and how to reach them on your LAN.
- **Local transport.** Cameras/HomeStations are reached over the PPPP UDP
  transport (handled by the `aiopppp` library) on the local network.
- **Command layer.** A small JSON command layer runs on top of PPPP for login,
  device info and opening a live stream.
- **A/V framing.** The live stream arrives as framed A/V packets that are
  reassembled into standard H.264/H.265 elementary frames and handed to ffmpeg.

The implementation lives in:

- `baseus_bridge/cloud.py` — cloud login + camera discovery
- `baseus_bridge/protocol.py` — command framing + A/V reassembly
- `baseus_bridge/bridge.py` — one live camera session → H.264 on stdout
- `baseus_bridge/orchestrator.py` — discovery → MediaMTX config → serve

This is an interoperability project for hardware you own; it does not defeat any
account protection — it uses your own credentials the same way the app does.
