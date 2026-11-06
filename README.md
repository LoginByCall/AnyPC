# AnyPC

AnyPC lets you see and control your computer from another one — even when both are behind routers or mobile networks. No port forwarding, no accounts.
Remote desktop for Windows that works through any NAT — one `AnyPC.exe` for both computers.
Landing page and download: https://www.turboseller.xyz · Описание на русском — `TZ.md`.

**Status: beta.** See *Security* and *Limitations* before relying on it.

## How it works
Both PCs keep a WebSocket connection to the signaling server (`anypc-server`), which only helps them find each other. The session itself is a WebRTC connection: direct (P2P) when the NATs allow it, otherwise relayed through coturn (TURN).
- **Transport:** WebRTC (ICE/STUN/TURN, DTLS-SRTP). Video and input never pass through the signaling server in clear.
- **Controlled side** (`agent/`): screen capture via FFmpeg `ddagrab` (DXGI) → H.264 → Pion WebRTC; input via `SendInput` scancodes; text clipboard sync; file transfer both ways with resume (one data channel per file; to the host's Downloads, or picked on the host via a file dialog; the app writes received files straight to disk).
- **Window** (`app/`): WebView2 + `ui/index.html` (7 languages). FFmpeg is embedded and extracted to `%LOCALAPPDATA%\AnyPC`. The browser web client (also for Linux/macOS controllers) runs the same CPace code compiled to WebAssembly (`wasm/`).
- **Linux** (`app/main_linux.go`, `agent/*_linux.go`, beta): `AnyPC-linux-amd64` runs the host and opens the same UI in the browser on `127.0.0.1` (token-protected local API). X11: FFmpeg `x11grab` + XTest; Wayland: xdg-desktop-portal RemoteDesktop/ScreenCast (one-time consent, restore token) + GStreamer `pipewiresrc`. Needs `zenity` (session notice), `ffmpeg` + `xclip` on X11, or `gstreamer1.0-pipewire` + `gstreamer1.0-plugins-ugly` + `wl-clipboard` on Wayland.
- **Server** (`server/`, `hub/`): signaling, time-limited TURN credentials, landing page (`site/`), downloads.

## Build
```sh
./build.sh          # downloads FFmpeg (SHA-256 checked), vet, tests, builds bin/anypc-server and bin/AnyPC.exe
```
Requires Go (toolchain auto-download), `curl`, `unzip`; `node` optional (translation check).

## Deploy the server (Ubuntu, root)
```sh
scp bin/anypc-server deploy/setup.sh root@VPS:/root/anypc-deploy/
ssh root@VPS sh /root/anypc-deploy/setup.sh any.example.com www.example.com
scp bin/AnyPC.exe bin/SHA256SUMS root@VPS:/srv/anypc/dl/
```
Later updates: `ANYPC_VPS=root@VPS deploy/publish.sh` (uploads only if `build.sh` passed).
Open ports: 80, 443/tcp, 3478/udp+tcp, 49152–65535/udp. The client's default server is set in `app/config.go`.

## Security
- A password set on the controlled PC is required; only an Argon2id hash is stored.
- **The password never leaves the controller PC:** after the WebRTC/DTLS channel is up, both sides run **CPace** (PAKE, `pake/`, `filippo.io/cpace`) with the input `Argon2id(password, host salt)`, bound to both DTLS certificate fingerprints and the host ID, followed by mutual key confirmation. The signaling server never sees the password or its hash; a server that swaps DTLS certificates (MITM) makes the keys differ and the login fails. Video, input and clipboard start only after that.
- 5 failed logins → temporary lockout. The controlled PC always shows a session notice with a Disconnect button.
- **Known gaps:** host ID is not yet bound to a key; the stored hash is password-equivalent (OPAQUE would fix it); the CPace implementation follows draft-haase-cpace-01 and has no independent audit; binaries are not code-signed. Review welcome.

## Limitations
No Ctrl+Alt+Del / UAC / lock screen yet (needs service mode), primary monitor only, clipboard is text ≤ 60 KB; the browser web client keeps files received from the remote PC in memory and does not resume them (the app writes to disk and resumes).

## License
MIT — see `LICENSE`. Bundled FFmpeg is GPLv3 (separate program).
