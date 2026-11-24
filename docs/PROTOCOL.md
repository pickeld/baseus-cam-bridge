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
- **Cloud-brokered PPCS (when LAN discovery gets no answer).** Some cameras
  (seen on X1 Pro) never reply to LAN search. The device list carries an encoded
  `service_string` naming three P2P servers. The bridge sends Hello/P2PReq
  (DID + its local address) to them, the servers announce the camera's
  addresses, and both sides hole-punch (PunchPkt 0x41 / P2PRdy 0x42). The
  reliable DRW channels then run directly between camera and bridge. Commands
  on this path are AES-encrypted (EnType 1) and an empty cmd 2001 heartbeat
  (frame model 0xE0) keeps live view open. No relay/TCP fallback exists.
- **Battery wake.** Before connecting, the app publishes an MQTT `WatchDevice`
  action (broker settings from XM `GetUserMQTTS`) and waits for the reply with
  the same `seq`. The bridge does the same when the record has a `wake_key`.

The implementation lives in:

- `baseus_bridge/cloud.py` — cloud login + camera discovery
- `baseus_bridge/protocol.py` — command framing + A/V reassembly
- `baseus_bridge/bridge.py` — one live camera session → H.264 on stdout
- `baseus_bridge/ppcs.py` — cloud-brokered PPCS rendezvous, hole punch, DRW
- `baseus_bridge/wake.py` — MQTT `WatchDevice` wake for battery cameras
- `baseus_bridge/cloud_p2p.py` — XM login/open-video/heartbeat over `ppcs`
- `baseus_bridge/orchestrator.py` — discovery → MediaMTX config → serve

This is an interoperability project for hardware you own; it does not defeat any
account protection — it uses your own credentials the same way the app does.
