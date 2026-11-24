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
- For **X1 Pro Dual** cameras, a second path for the right lens:
  `rtsp://<host>:8554/living-room-right` (both lenses share one P2P session)
- The same feeds as HLS (`http://<host>:8888/<cam>/index.m3u8`) and WebRTC
  (`http://<host>:8889/<cam>`)
- Local still JPEGs (left and right) at `http://127.0.0.1:8099/<cam>.jpg`
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

Streams are then at `rtsp://homeassistant.local:8554/<camera>` and, for dual-lens models, `.../<camera>-right`. Pair it with the
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

> On the current Baseus/XM cloud, every write returns `-9999 "interface not
> currently supported"` — the cloud gateway is read-only. To control settings
> you need the **local P2P set-commands**, which you can learn by observing your
> own device (below).

### Learn the local set-commands by observing your own device

Settings are sent to the HomeStation over the local P2P command channel. You can
read the exact command IDs + JSON the official app uses, decoded with the same
crypto the bridge already uses (no app binaries are touched).

**Easiest — live monitor (no Wireshark needed):**

```bash
python -m baseus_bridge monitor            # or: monitor --camera <slug>
```

Leave it running and **toggle one setting in the Baseus app** (e.g. the status
light). If the HomeStation notifies connected sessions, you'll see a decoded
line like `{"dir":"dev->app","cmd":306,"json":{"light_status":0}}`. Send that.

**Definitive — packet capture (if the monitor sees nothing):**

1. **Capture** the app↔HomeStation packets. Cleanest on UniFi: mirror the
   HomeStation's switch port and capture with Wireshark, or on any host on the
   path:
   ```bash
   sudo tcpdump -i <iface> -w baseus.pcap host <homestation-ip>
   ```
   Save as a classic `.pcap` (Wireshark: *Save As → Wireshark/tcpdump pcap*).
2. **Toggle one setting** in the Baseus app while capturing (e.g. the status
   light), then stop the capture.
3. **Decode** it (secrets redacted):
   ```bash
   python -m baseus_bridge decode-capture baseus.pcap
   ```
   Each line is `{"dir": "app->dev", "cmd": <id>, "json": {...}}`. The line where
   you toggled the setting reveals the **command ID** and **payload key** — e.g.
   `cmd 306` with `{"light_status": 0}`. Those are exactly what a `set` needs.

Send those command IDs/payloads and they can be wired into the bridge (with
read-back + auto-revert safety) to make the Home Assistant switches work.

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
| `BASEUS_TRANSPORT` | `auto` | `auto` (one LAN discovery attempt, then cloud PPCS), `lan` (LAN discovery only, the original behaviour) or `cloud` (cloud PPCS only) |

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
  It reaches the camera either by LAN discovery (aiopppp) or, for cameras that
  never answer LAN search, through `baseus_bridge.ppcs`: the same P2P-server
  rendezvous + UDP hole punch the app uses, with an MQTT `WatchDevice` wake
  (`baseus_bridge.wake`) for battery cameras. Video still flows directly
  between the camera and the bridge; only the rendezvous uses the cloud.
- `baseus_bridge.orchestrator` writes a MediaMTX config where each camera is a
  `runOnDemand` path, so bridges start only when a client connects.

See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for protocol notes.

---


## Dual-lens cameras (X1 Pro Dual)

Some Baseus models mux both lenses on a single P2P session. The bridge splits
them using bit 14 (`0x4000`) of the XM AV header `command` field:

| Lens | RTSP | Still (on the HA / bridge host) |
|---|---|---|
| Left | `rtsp://<host>:8554/<slug>` | `http://127.0.0.1:8099/<slug>.jpg` |
| Right | `rtsp://<host>:8554/<slug>-right` | `http://127.0.0.1:8099/<slug>-right.jpg` |

Single-lens cameras still work on `<slug>`. Opening `<slug>-right` on a
single-lens camera will time out. X1 Pro video is HEVC/H.265; it plays in
clients that support HEVC (for example Safari or VLC). Many Chromium browsers
will not play it, and this project does not transcode to H.264.

In Home Assistant, add a **Generic Camera** for each lens (stream URL + still
URL). The still endpoint binds to `127.0.0.1` by default so it is not exposed
on the LAN. A cache miss returns a placeholder immediately; a real still is
filled from a live IDR after someone has watched the stream.

## Troubleshooting

- **No cameras found** — double-check the account/password and try setting
  `BASEUS_REGION` explicitly.
- **Stream won't open** — the camera may be offline/asleep (battery models wake on
  demand; give it ~10–15s on first connect). Confirm the host can reach the
  camera's LAN IP.
- **`discovery attempt 1/3 failed` on every open** — some models (seen on X1
  Pro) never answer LAN discovery. Set `BASEUS_TRANSPORT=cloud` (or leave
  `auto`) so the bridge connects through the P2P servers instead. The log then
  shows `PPCS peer ready ...`, `login ok` and `video requested over cloud PPCS`.
- **Docker on macOS/Windows** — `network_mode: host` behaves differently there;
  a Linux host is strongly recommended for LAN P2P.

---

## License

MIT — see [LICENSE](LICENSE).
