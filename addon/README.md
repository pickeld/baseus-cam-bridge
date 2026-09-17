# Home Assistant Add-on: Baseus Cam Bridge

Runs [baseus-cam-bridge](https://github.com/pickeld/baseus-cam-bridge) directly on
your Home Assistant host, so your Baseus Security cameras become standard
**RTSP / HLS / WebRTC** streams available at `homeassistant.local` — no separate
server needed.

Pair it with the [Baseus Security HACS integration](https://github.com/pickeld/baseus-home-assistant)
for camera entities plus battery/signal/connectivity, or just point VLC / Frigate
/ any client at the RTSP URLs.

## Install

1. In Home Assistant: **Settings → Add-ons → Add-on Store**.
2. Three-dot menu (top right) → **Repositories** → add
   `https://github.com/pickeld/baseus-cam-bridge`.
3. Install **Baseus Cam Bridge** from the store.
4. Open the **Configuration** tab, enter your Baseus app account + password, then
   **Start** the add-on.
5. Check the **Log** tab — it prints one `rtsp://<host>:8554/<camera>` URL per
   camera.

See [DOCS.md](DOCS.md) for all options and troubleshooting.
