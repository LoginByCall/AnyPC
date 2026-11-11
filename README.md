# AnyPC

AnyPC lets you see and control your computer from another one — even when both are behind routers or mobile networks. No port forwarding, no accounts.
Remote desktop for Windows that works through any NAT — one `AnyPC.exe` for both computers.
Landing page and download: https://www.anypc.org · Описание на русском — `TZ.md`.

**Status: beta.** See *Security* and *Limitations* before relying on it.

## How it works
Both PCs keep a WebSocket connection to the signaling server (`anypc-server`), which only helps them find each other. The session itself is a WebRTC connection: direct (P2P) when the NATs allow it, otherwise relayed through coturn (TURN).
- **Transport:** WebRTC (ICE/STUN/TURN, DTLS-SRTP). Video and input never pass through the signaling server in clear.
- **Controlled side** (`agent/`): screen capture via FFmpeg `ddagrab` (DXGI) → H.264 → Pion WebRTC; input via `SendInput` scancodes; text clipboard sync; file transfer both ways with resume (one data channel per file; to the host's Downloads, or picked on the host via a file dialog; the app writes received files straight to disk).
- **Window** (`app/`): WebView2 + `ui/index.html` (7 languages). FFmpeg is downloaded on first launch (pinned SHA-256, only ffmpeg.exe is read from the gyan.dev zip via HTTP Range) to `%LOCALAPPDATA%\AnyPC`. The browser web client (also for Linux/macOS controllers) runs the same CPace code compiled to WebAssembly (`wasm/`).
- **Linux** (`app/main_linux.go`, `agent/*_linux.go`, beta): `AnyPC-linux-amd64` runs the host and opens the same UI in the browser on `127.0.0.1` (token-protected local API). X11: FFmpeg `x11grab` + XTest; Wayland: xdg-desktop-portal RemoteDesktop/ScreenCast (one-time consent, restore token) + GStreamer `pipewiresrc`. Needs `zenity` (session notice), `ffmpeg` + `xclip` on X11, or `gstreamer1.0-pipewire` + `gstreamer1.0-plugins-ugly` + `wl-clipboard` on Wayland.
- **Server** (`server/`, `hub/`): signaling, time-limited TURN credentials, landing page (`site/`), downloads.

## Build
```sh
./build.sh          # downloads FFmpeg (SHA-256 checked), vet, tests, builds bin/anypc-server and bin/AnyPC.exe
```
Requires Go (toolchain auto-download), `curl`, `unzip`; `node` optional (translation check).

## Your own node (VPS, Ubuntu/Debian)
Hub, relay (TURN) and web client on your server; who connected to whom stays with you.
1. DNS: an A record `my.example.com` → the VPS IP (Cloudflare: grey cloud, DNS only).
2. Open ports: 80, 443/tcp; 3478/tcp+udp; 49152–65535/udp (ufw is opened by the script; a hoster firewall — by you).
3. `curl -fsSL https://raw.githubusercontent.com/LoginByCall/AnyPC/main/deploy/setup.sh | sudo sh -s my.example.com` — downloads `anypc-server`, verifies the release signature on `SHA256SUMS` and the checksum, sets up coturn and a Let's Encrypt certificate. Update: the same command.
   Without `curl | sh`: download `install.sh`, `anypc-server`, `SHA256SUMS` from the release, `sha256sum -c --ignore-missing SHA256SUMS`, `sudo sh install.sh my.example.com`.

In AnyPC: “Own server” = `my.example.com` → Save. The PC re-registers on your node (the ID stays); tick “also stay on the AnyPC network” to be reachable both ways.
A single connection through another node without changing settings: `123456789@my.example.com` in the ID field. Web client: `https://my.example.com/`.

**Docker** (NAS, servers already on Docker): `deploy/docker/compose.yml` — `anypc-server` (image `ghcr.io/loginbycall/anypc-server`, amd64/arm64, published with each release) + coturn, both with `network_mode: host`.
```sh
mkdir anypc && cd anypc
curl -fsSLO https://raw.githubusercontent.com/LoginByCall/AnyPC/main/deploy/docker/compose.yml
printf 'DOMAIN=my.example.com\nPUBLIC_IP=203.0.113.10\nTURN_SECRET=%s\n' "$(openssl rand -base64 32)" > .env
docker compose up -d
```
**Behind your own reverse proxy** (ports 80/443 already taken): run `anypc-server -addr 127.0.0.1:8080` without `-domain` (in compose: replace `"-domain", "${DOMAIN}"` with `"-addr", "127.0.0.1:8080"`) and proxy `my.example.com` to `http://127.0.0.1:8080` with WebSocket — Caddy: `my.example.com { reverse_proxy 127.0.0.1:8080 }`; nginx: `proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection upgrade; proxy_set_header X-Forwarded-For $remote_addr;`. TURN (3478, 49152–65535/udp) stays on the host as is.

**Ansible:** the same script on every host of a group:
```yaml
- hosts: anypc
  become: true
  tasks:
    - ansible.builtin.shell: curl -fsSL https://raw.githubusercontent.com/LoginByCall/AnyPC/main/deploy/setup.sh | sh -s {{ inventory_hostname }}
```

```sh
scp bin/anypc-server deploy/setup.sh root@VPS:/root/anypc-deploy/
ssh root@VPS ANYPC_LOCAL=1 sh /root/anypc-deploy/setup.sh any.example.com www.example.com
scp bin/AnyPC.exe bin/SHA256SUMS root@VPS:/srv/anypc/dl/
```
Later updates: `ANYPC_VPS=root@VPS deploy/publish.sh` (uploads only if `build.sh` passed).
Open ports: 80, 443/tcp, 3478/udp+tcp, 49152–65535/udp. The client's default server is set in `app/config.go`.

## Security
- A password set on the controlled PC is required; only an Argon2id hash is stored.
- **The password never leaves the controller PC:** after the WebRTC/DTLS channel is up, both sides run **CPace** (PAKE, `pake/`, `filippo.io/cpace`) with the input `Argon2id(password, host salt)`, bound to both DTLS certificate fingerprints and the host ID, followed by mutual key confirmation. The signaling server never sees the password or its hash; a server that swaps DTLS certificates (MITM) makes the keys differ and the login fails. Video, input and clipboard start only after that.
- 5 failed logins → temporary lockout. The controlled PC always shows a session notice with a Disconnect button.
- **Host identity:** each host has an Ed25519 key (it never leaves the PC). The server binds the 9-digit ID to that key at first registration (challenge signature), so nobody else can take the ID. After CPace the host also signs both DTLS fingerprints; the client remembers the key fingerprint on first login and warns if it changes (trust on first use).
- **Known gaps:** the stored hash is password-equivalent (OPAQUE would fix it); the CPace implementation follows draft-haase-cpace-01 and has no independent audit; binaries are not code-signed. Review welcome.

## Limitations
No Ctrl+Alt+Del / UAC / lock screen yet (needs service mode); bitrate adapts to packet loss only (RTCP receiver reports; each step restarts the encoder, ~0.5 s pause); monitor switching works on Windows (GPU 0 outputs) and X11, on Wayland the monitor is chosen in the portal dialog; clipboard is text ≤ 60 KB; the browser web client keeps files received from the remote PC in memory and does not resume them (the app writes to disk and resumes).

## Privacy

No accounts, analytics or telemetry; what the servers see and what stays on your PC — [PRIVACY.md](PRIVACY.md) (also at https://www.anypc.org/privacy.html).

## License
MIT — see `LICENSE`. FFmpeg is not bundled: on first launch the Windows app downloads FFmpeg 9.0.2 (GPLv3) from the gyan.dev builds and verifies its SHA-256; on Linux the system ffmpeg is used.

## Verifying downloads

`SHA256SUMS` of every release is signed with the AnyPC release key (Ed25519). Take the key from here, not from a download mirror:

```
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAEtMc223pBHlegIQtFumvKY0PBHohIXYMzwMw8bR9bJs=
-----END PUBLIC KEY-----
```

Save it as `release.pub` next to the downloaded files, `SHA256SUMS` and `SHA256SUMS.sig`, then (OpenSSL 3):

```
openssl pkeyutl -verify -pubin -inkey release.pub -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum -c --ignore-missing SHA256SUMS
```
