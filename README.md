# Baseus Cam Bridge

Turn your **Baseus Security** cameras (the ones that use the HomeStation base and
the XM/PPPP cloud) into standard **RTSP / HLS / WebRTC** streams you can open in
VLC, Home Assistant, Frigate, Blue Iris, or any normal video client — running
entirely on your own network.

These cameras don't expose RTSP/ONVIF themselves; they only talk to the vendor
cloud over an encrypted P2P protocol. This project runs a small local gateway
that logs in with **your own Baseus account**, discovers **your own cameras**, and
republishes their live video locally. Nothing leaves your LAN except the initial
login/device-list call to the Baseus cloud (the same call the official app makes).

> Use this only with devices you own or are authorized to manage.

---

## What you get

- One RTSP URL per camera, e.g. `rtsp://<host>:8554/living-room`
- The same feeds as HLS (`http://<host>:8888/<cam>/index.m3u8`) and WebRTC
  (`http://<host>:8889/<cam>`)
- Automatic discovery of **all** cameras on your account
- Battery-friendly: a camera is only contacted while something is watching it

---

## Install as a Home Assistant add-on (easiest for HA users)

If you run Home Assistant OS/Supervised, install the bridge as an add-on so it
runs on the HA host itself:

1. **Settings → Add-ons → Add-on Store**, then the three-dot menu → **Repositories**.
2. Add `https://github.com/pickeld/baseus-cam-bridge`.
3. Install **Baseus Cam Bridge**, open **Configuration**, enter your Baseus
   account + password, and **Start**.

Streams are then at `rtsp://homeassistant.local:8554/<camera>`. Pair it with the
[Baseus Security HACS integration](https://github.com/pickeld/baseus-home-assistant)
for camera entities and sensors. See [`addon/DOCS.md`](addon/DOCS.md).

## Quick start (Docker, recommended)

You need a Linux host (a NAS, a Raspberry Pi, a mini-PC, etc.) on the **same
network** as your cameras, with Docker installed.

```bash
git clone https://github.com/pickeld/baseus-cam-bridge.git
cd baseus-cam-bridge

cp .env.example .env
# edit .env and put in your Baseus app email + password

docker compose up -d
```

That's it. Check which URLs were created:

```bash
docker compose logs | grep rtsp://
```

Open one in VLC: **File → Open Network** → `rtsp://<your-host-ip>:8554/<camera>`.

### First, list your cameras (optional sanity check)

```bash
docker compose run --rm baseus-cam-bridge python -m baseus_bridge discover
```

This prints your cameras (passwords redacted) so you can confirm login works.

To inspect everything the cloud reports about your devices (for mapping sensors,
with all secrets redacted):

```bash
docker compose run --rm baseus-cam-bridge python -m baseus_bridge dump
```

### Discover writable controls (safe)

Changing settings (status light, night vision, volumes, etc.) needs the cloud
"set" operation, whose exact Action + payload shape are not publicly documented
for this device family. The `probe-controls` command discovers them **safely**:
it toggles the benign HomeStation status LED, verifies the change by re-reading
the device list, then reverts it. A wrong Action simply errors, so nothing is
left changed.

```bash
docker compose run --rm baseus-cam-bridge python -m baseus_bridge probe-controls
```

If it prints a `confirmed_action` / `confirmed_shape`, pin them (env
`BASEUS_SET_ACTION` / `BASEUS_SET_SHAPE`, or the Home Assistant integration's
**Options**) to enable the switches/numbers. If it finds nothing, controls
aren't cloud-settable with the tried conventions and would need deeper work.

---

## Run without Docker

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
# also install ffmpeg and mediamtx and put them on your PATH

export BASEUS_ACCOUNT="you@example.com"
export BASEUS_PASSWORD="your-password"
export BASEUS_RUNTIME_DIR="./run"        # writable dir for generated config
python -m baseus_bridge serve
```

---

## Configuration

All settings are environment variables (see `.env.example`):

| Variable | Default | Meaning |
|---|---|---|
| `BASEUS_ACCOUNT` | – | Your Baseus app login (email/phone) |
| `BASEUS_PASSWORD` | – | Your Baseus app password |
| `BASEUS_REGION` | `AUTO` | `AUTO`, or force `US` / `EU` / `AU` |
| `BASEUS_COUNTRYCODE` | `1` | Phone country code used at login |
| `BASEUS_INCLUDE_OFFLINE` | `1` | Also create paths for offline cameras |
| `BASEUS_RTSP_PORT` | `8554` | RTSP port |
| `BASEUS_HLS_PORT` | `8888` | HLS port |
| `BASEUS_WEBRTC_PORT` | `8889` | WebRTC port |

Your credentials live only in `.env` (git-ignored) and a runtime file inside the
container (`tmpfs`, mode 600). Nothing sensitive is written to the repo.

---

## How it works

```
Baseus cloud  --login/device-list-->  orchestrator
                                          |  (discovers cameras + local creds)
                                          v
camera (P2P/LAN)  -->  bridge (Python)  -->  ffmpeg  -->  MediaMTX  -->  rtsp://.../<cam>
```

- `baseus_bridge.cloud` performs the same login + device-list as the app.
- `baseus_bridge.bridge` holds one camera's live session and outputs H.264.
- `baseus_bridge.orchestrator` writes a MediaMTX config where each camera is a
  `runOnDemand` path, so bridges start only when a client connects.

See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for protocol notes.

---

## Troubleshooting

- **No cameras found** — double-check the account/password and try setting
  `BASEUS_REGION` explicitly.
- **Stream won't open** — the camera may be offline/asleep (battery models wake on
  demand; give it ~10–15s on first connect). Confirm the host can reach the
  camera's LAN IP.
- **Docker on macOS/Windows** — `network_mode: host` behaves differently there;
  a Linux host is strongly recommended for LAN P2P.

---

## License

MIT — see [LICENSE](LICENSE).
