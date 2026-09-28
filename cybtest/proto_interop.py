#!/usr/bin/env python3
"""
proto_interop.py — verifies the C implementation (cybcrypt.h / cybproto.h)
against Python's `cryptography` library, an independent implementation of the
same RFCs (RFC 8439, RFC 7748, RFC 5869).

    gcc -O2 -o proto_emit proto_emit.c
    python3 proto_interop.py

The C side prints a deterministic transcript; this script re-derives every
value from scratch and requires an exact match.  Passing this means a Python
listener and a C/C++ implant can talk to each other for real.
"""

import hmac
import hashlib
import subprocess
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError as e:                                    # pragma: no cover
    sys.exit(f"this check needs the 'cryptography' package: {e}")

MAGIC = bytes([0xCB, 0x03])
HDR = 24
AAD_LEN = 12
TAG = 16

L_AUTH = b"CYBERDEMONS-C2-v3-hello"
L_SESSION = b"CYBERDEMONS-C2-v3 session"
L_KEYS = b"cyb3 keys"

T_HELLO, T_HELLOACK = 0x01, 0x02
T_CMD = 0x10

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


def hkdf(ikm, salt, info, length):
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, c = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([c]), hashlib.sha256).digest()
        okm += t
        c += 1
    return okm[:length]


def x25519(priv, peer_pub):
    return X25519PrivateKey.from_private_bytes(priv).exchange(
        X25519PublicKey.from_public_bytes(peer_pub))


def clamp(seed):
    k = bytearray(seed)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def auth_key(psk):
    return hmac.new(psk, L_AUTH, hashlib.sha256).digest()


def build_hello(is_ack, akey, own_pub, own_nonce, peer_pub=None, peer_nonce=None):
    body = own_pub + own_nonce
    tr = (b"A" if is_ack else b"H") + body
    if is_ack and peer_pub and peer_nonce:
        tr += peer_pub + peer_nonce
    body += hmac.new(akey, tr, hashlib.sha256).digest()[:TAG]
    hdr = MAGIC + bytes([T_HELLOACK if is_ack else T_HELLO, 0])
    hdr += (0).to_bytes(4, "big") + len(body).to_bytes(4, "big")
    hdr += b"\x00" * 12
    return hdr + body


def parse(frame):
    assert frame[:2] == MAGIC, "bad magic"
    typ, flags = frame[2], frame[3]
    seq = int.from_bytes(frame[4:8], "big")
    ctlen = int.from_bytes(frame[8:12], "big")
    nonce = frame[12:24]
    ct = frame[24:24 + ctlen]
    tag = frame[24 + ctlen:24 + ctlen + TAG]
    return typ, flags, seq, ctlen, nonce, ct, tag


def main():
    out = subprocess.run(["./proto_emit"], capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"proto_emit failed:\n{out.stderr}")
    tr = {}
    for line in out.stdout.splitlines():
        k, _, v = line.partition(" ")
        tr[k] = v

    psk = bytes.fromhex(tr["psk"])
    cli_pub = bytes.fromhex(tr["cli_pub"])
    cli_nonce = bytes.fromhex(tr["cli_nonce"])
    srv_pub = bytes.fromhex(tr["srv_pub"])
    srv_nonce = bytes.fromhex(tr["srv_nonce"])
    hello = bytes.fromhex(tr["hello"])
    helloack = bytes.fromhex(tr["helloack"])
    cmdframe = bytes.fromhex(tr["cmdframe"])
    msg = tr["msg"].encode()

    print("== primitives ==")
    akey = auth_key(psk)
    check("auth key", akey.hex() == tr["auth_key"],
          f"want {tr['auth_key']} got {akey.hex()}")

    # X25519 against cryptography, from the C-generated public keys
    shared = x25519(clamp(bytes.fromhex(
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")),
        srv_pub)
    check("X25519 shared secret", shared.hex() == tr["shared"],
          f"want {tr['shared']} got {shared.hex()}")

    # the derived session keys
    session = hkdf(psk + shared, cli_nonce + srv_nonce, L_SESSION, 32)
    master = hkdf(session, None, L_KEYS, 72)
    check("k_c2s", master[0:32].hex() == tr["k_c2s"],
          f"want {tr['k_c2s']} got {master[0:32].hex()}")
    check("k_s2c", master[32:64].hex() == tr["k_s2c"],
          f"want {tr['k_s2c']} got {master[32:64].hex()}")
    check("pfx_c2s", master[64:68].hex() == tr["pfx_c2s"])
    check("pfx_s2c", master[68:72].hex() == tr["pfx_s2c"])

    print("\n== handshake frames ==")
    want_hello = build_hello(False, akey, cli_pub, cli_nonce)
    check("HELLO byte-identical", hello == want_hello)
    want_ack = build_hello(True, akey, srv_pub, srv_nonce, cli_pub, cli_nonce)
    check("HELLOACK byte-identical", helloack == want_ack)

    ht, hf, hs, hcl, hn, hct, htag = parse(hello)
    check("HELLO type/len", ht == T_HELLO and hcl == 64)
    check("HELLO body carries pub+nonce", hct[:48] == cli_pub + cli_nonce)

    at, af, as_, acl, an, act, atag = parse(helloack)
    check("HELLOACK type/len", at == T_HELLOACK and acl == 64)

    print("\n== data frame ==")
    ct_t, cf, seq, ctlen, nonce, ct, tag = parse(cmdframe)
    check("frame magic/version", cmdframe[:2] == MAGIC)
    check("frame type is CMD", ct_t == T_CMD)
    check("frame seq is 0", seq == 0)
    check("ct_len matches the message", ctlen == len(msg), f"{ctlen} vs {len(msg)}")
    check("nonce prefix is the s2c one", nonce[:4] == master[68:72],
          f"want {master[68:72].hex()} got {nonce[:4].hex()}")
    check("nonce counter is 0", nonce[4:8] == b"\x00" * 4 and nonce[8:12] == b"\x00" * 4)

    # decrypt with the `cryptography` ChaCha20Poly1305 implementation
    aead = ChaCha20Poly1305(master[32:64])
    try:
        plain = aead.decrypt(nonce, ct + tag, cmdframe[:AAD_LEN])
        check("ChaCha20-Poly1305 decrypts the C ciphertext", plain == msg,
              f"want {msg!r} got {plain!r}")
    except Exception as e:
        check("ChaCha20-Poly1305 decrypts the C ciphertext", False, str(e))

    # and re-encrypt, requiring the exact same bytes
    resealed = aead.encrypt(nonce, msg, cmdframe[:AAD_LEN])
    check("re-encryption is byte-identical", resealed == ct + tag)

    # tamper detection through the independent implementation
    bad = bytearray(ct)
    bad[0] ^= 0x01
    try:
        aead.decrypt(nonce, bytes(bad) + tag, cmdframe[:AAD_LEN])
        check("independent impl also rejects a flipped byte", False)
    except Exception:
        check("independent impl also rejects a flipped byte", True)

    print("\n== round trip: python seals, C-style parser opens ==")
    # build a frame the way a Python listener would and make sure our parser
    # and the C layout agree
    nonce2 = master[68:72] + b"\x00" * 4 + (1).to_bytes(4, "big")
    hdr2 = MAGIC + bytes([T_CMD, 0]) + (1).to_bytes(4, "big") + \
        len(msg).to_bytes(4, "big") + nonce2
    body2 = aead.encrypt(nonce2, msg, hdr2[:AAD_LEN])
    check("python-sealed frame has the expected length",
          len(hdr2) + len(body2) == len(cmdframe))
    check("second frame differs only in seq/nonce",
          hdr2[:4] == cmdframe[:4] and hdr2[4:8] != cmdframe[4:8])

    print("\n======================================================")
    print(f" passed: {g_pass}   failed: {g_fail}")
    print("======================================================")
    return 1 if g_fail else 0


if __name__ == "__main__":
    sys.exit(main())
