/*
 * cybcrypt.h — CYBERDEMONS C2 cryptographic core
 * ---------------------------------------------------------------------------
 * Header-only, dependency-free (no OpenSSL / libsodium / libcrypto).
 *
 * Implements:
 *   SHA-256            FIPS 180-4
 *   HMAC-SHA256        RFC 2104
 *   HKDF-SHA256        RFC 5869
 *   ChaCha20           RFC 8439
 *   Poly1305           RFC 8439
 *   ChaCha20-Poly1305  RFC 8439 (IETF AEAD: 12-byte nonce, 16-byte tag)
 *   X25519             RFC 7748
 *
 * Properties
 * ----------
 *  - No dynamic allocation; callers own every buffer.
 *  - No secret-dependent branches or table indices.
 *  - Nonce layout is the standard IETF split, so a nonce cannot repeat even if
 *    the CSPRNG is compromised:
 *        nonce[0..3]  = per-session random prefix
 *        nonce[4..11] = big-endian message counter
 *    The caller is responsible for refusing to send past counter 2^64-1.
 *
 * Verified against the published test vectors in crypto_selftest.c.
 */

#ifndef CYB_CRYPTO_H
#define CYB_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(_MSC_VER)
#  define CYB_INLINE static __forceinline
#else
#  define CYB_INLINE static inline
#endif

#define CYB_SHA256_LEN 32
#define CYB_BLOCK_LEN  64
#define CYB_TAG_LEN    16
#define CYB_NONCE_LEN  12
#define CYB_KEY_LEN    32

/* ========================================================================== */
/* Constant-time primitives                                                   */
/* ========================================================================== */

CYB_INLINE int cyb_ct_memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    uint8_t acc = 0;
    size_t i;
    for (i = 0; i < n; i++) acc |= (uint8_t)(x[i] ^ y[i]);
    return acc != 0;
}

CYB_INLINE void cyb_secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

CYB_INLINE void cyb_hton32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

CYB_INLINE void cyb_storele32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

CYB_INLINE uint32_t cyb_ntohl32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

/* ========================================================================== */
/* SHA-256                                                                    */
/* ========================================================================== */

typedef struct {
    uint32_t h[8];
    uint64_t total;
    size_t   buflen;
    uint8_t  buf[CYB_BLOCK_LEN];
} cyb_sha256_ctx;

static const uint32_t cyb_k256[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL,
    0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL,
    0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
    0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL, 0xa2bfe8a1UL, 0xa81a664bUL,
    0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL,
    0x5b9cca4fUL, 0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

#define CYB_ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CYB_S0(x)  (CYB_ROR32(x,  2) ^ CYB_ROR32(x, 13) ^ CYB_ROR32(x, 22))
#define CYB_S1(x)  (CYB_ROR32(x,  6) ^ CYB_ROR32(x, 11) ^ CYB_ROR32(x, 25))
#define CYB_s0(x)  (CYB_ROR32(x,  7) ^ CYB_ROR32(x, 18) ^ ((x) >>  3))
#define CYB_s1(x)  (CYB_ROR32(x, 17) ^ CYB_ROR32(x, 19) ^ ((x) >> 10))
#define CYB_ch(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define CYB_maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

CYB_INLINE void cyb_sha256_compress(uint32_t st[8], const uint8_t blk[64])
{
    uint32_t w[64], a, b, c, d, e, f, g, h;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = cyb_ntohl32(blk + i * 4);
    for (i = 16; i < 64; i++)
        w[i] = CYB_s1(w[i - 2]) + w[i - 7] + CYB_s0(w[i - 15]) + w[i - 16];

    a = st[0]; b = st[1]; c = st[2]; d = st[3];
    e = st[4]; f = st[5]; g = st[6]; h = st[7];
    for (i = 0; i < 64; i++) {
        uint32_t t1 = h + CYB_S1(e) + CYB_ch(e, f, g) + cyb_k256[i] + w[i];
        uint32_t t2 = CYB_S0(a) + CYB_maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

CYB_INLINE void cyb_sha256_init(cyb_sha256_ctx *c)
{
    c->h[0] = 0x6a09e667UL; c->h[1] = 0xbb67ae85UL;
    c->h[2] = 0x3c6ef372UL; c->h[3] = 0xa54ff53aUL;
    c->h[4] = 0x510e527fUL; c->h[5] = 0x9b05688cUL;
    c->h[6] = 0x1f83d9abUL; c->h[7] = 0x5be0cd19UL;
    c->total = 0; c->buflen = 0;
}

CYB_INLINE void cyb_sha256_update(cyb_sha256_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    c->total += (uint64_t)len;
    if (c->buflen) {
        size_t need = CYB_BLOCK_LEN - c->buflen;
        size_t take = (len < need) ? len : need;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take; p += take; len -= take;
        if (c->buflen == CYB_BLOCK_LEN) { cyb_sha256_compress(c->h, c->buf); c->buflen = 0; }
    }
    while (len >= CYB_BLOCK_LEN) { cyb_sha256_compress(c->h, p); p += CYB_BLOCK_LEN; len -= CYB_BLOCK_LEN; }
    if (len) { memcpy(c->buf, p, len); c->buflen = len; }
}

CYB_INLINE void cyb_sha256_final(cyb_sha256_ctx *c, uint8_t out[CYB_SHA256_LEN])
{
    uint64_t bits = c->total * 8;
    uint8_t  tail[CYB_BLOCK_LEN * 2];
    size_t   padlen;
    int      i;

    padlen = (c->buflen < 56) ? (56 - c->buflen) : (120 - c->buflen);
    memset(tail, 0, padlen);
    tail[0] = 0x80;
    for (i = 0; i < 8; i++) tail[padlen + i] = (uint8_t)(bits >> (56 - 8 * i));
    cyb_sha256_update(c, tail, padlen + 8);

    for (i = 0; i < 8; i++) cyb_hton32(out + i * 4, c->h[i]);
    cyb_secure_zero(c, sizeof(*c));
}

CYB_INLINE void cyb_sha256(const void *data, size_t len, uint8_t out[CYB_SHA256_LEN])
{
    cyb_sha256_ctx c;
    cyb_sha256_init(&c);
    cyb_sha256_update(&c, data, len);
    cyb_sha256_final(&c, out);
}

/* ========================================================================== */
/* HMAC-SHA256 / HKDF-SHA256                                                   */
/* ========================================================================== */

CYB_INLINE void cyb_hmac_sha256(const uint8_t *key, size_t keylen,
                                const uint8_t *msg, size_t msglen,
                                uint8_t out[CYB_SHA256_LEN])
{
    uint8_t k[CYB_BLOCK_LEN], pad[CYB_BLOCK_LEN], inner[CYB_SHA256_LEN];
    cyb_sha256_ctx h;
    int i;

    memset(k, 0, sizeof(k));
    if (keylen > CYB_BLOCK_LEN) cyb_sha256(key, keylen, k);
    else if (keylen) memcpy(k, key, keylen);

    for (i = 0; i < CYB_BLOCK_LEN; i++) pad[i] = k[i] ^ 0x36;
    cyb_sha256_init(&h);
    cyb_sha256_update(&h, pad, CYB_BLOCK_LEN);
    cyb_sha256_update(&h, msg, msglen);
    cyb_sha256_final(&h, inner);

    for (i = 0; i < CYB_BLOCK_LEN; i++) pad[i] = k[i] ^ 0x5c;
    cyb_sha256_init(&h);
    cyb_sha256_update(&h, pad, CYB_BLOCK_LEN);
    cyb_sha256_update(&h, inner, CYB_SHA256_LEN);
    cyb_sha256_final(&h, out);

    cyb_secure_zero(k, sizeof(k));
    cyb_secure_zero(pad, sizeof(pad));
    cyb_secure_zero(inner, sizeof(inner));
}

CYB_INLINE void cyb_hkdf_extract(uint8_t prk[CYB_SHA256_LEN],
                                 const uint8_t *salt, size_t saltlen,
                                 const uint8_t *ikm, size_t ikmlen)
{
    static const uint8_t zeros[CYB_SHA256_LEN] = { 0 };
    if (!salt || !saltlen) { salt = zeros; saltlen = CYB_SHA256_LEN; }
    cyb_hmac_sha256(salt, saltlen, ikm, ikmlen, prk);
}

CYB_INLINE void cyb_hkdf_expand(uint8_t *okm, size_t okmlen,
                                const uint8_t prk[CYB_SHA256_LEN],
                                const uint8_t *info, size_t infolen)
{
    uint8_t t[CYB_SHA256_LEN], blk[CYB_SHA256_LEN + 512];
    size_t  tlen = 0, done = 0;
    uint8_t ctr = 1;

    while (done < okmlen) {
        size_t blen = tlen + infolen + 1;
        size_t take;

        if (blen > sizeof(blk)) break;          /* info too long for this buffer */
        if (tlen)  memcpy(blk, t, tlen);
        if (infolen) memcpy(blk + tlen, info, infolen);
        blk[tlen + infolen] = ctr;

        cyb_hmac_sha256(prk, CYB_SHA256_LEN, blk, blen, t);
        tlen = CYB_SHA256_LEN;

        take = okmlen - done;
        if (take > tlen) take = tlen;
        memcpy(okm + done, t, take);
        done += take;
        ctr++;
    }
    cyb_secure_zero(t, sizeof(t));
    cyb_secure_zero(blk, sizeof(blk));
}

CYB_INLINE void cyb_hkdf(uint8_t *okm, size_t okmlen,
                         const uint8_t *salt, size_t saltlen,
                         const uint8_t *ikm, size_t ikmlen,
                         const uint8_t *info, size_t infolen)
{
    uint8_t prk[CYB_SHA256_LEN];
    cyb_hkdf_extract(prk, salt, saltlen, ikm, ikmlen);
    cyb_hkdf_expand(okm, okmlen, prk, info, infolen);
    cyb_secure_zero(prk, sizeof(prk));
}

/* ========================================================================== */
/* ChaCha20                                                                   */
/* ========================================================================== */

#define CYB_ROT32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

CYB_INLINE void cyb_chacha_block(const uint32_t in[16], uint8_t out[64])
{
    uint32_t x[16];
    int i;
    memcpy(x, in, sizeof(x));
    for (i = 0; i < 10; i++) {
#define CYB_QR(a, b, c, d)                        \
        x[a] += x[b]; x[d] ^= x[a]; x[d] = CYB_ROT32(x[d], 16); \
        x[c] += x[d]; x[b] ^= x[c]; x[b] = CYB_ROT32(x[b], 12); \
        x[a] += x[b]; x[d] ^= x[a]; x[d] = CYB_ROT32(x[d],  8);  \
        x[c] += x[d]; x[b] ^= x[c]; x[b] = CYB_ROT32(x[b],  7)
        CYB_QR(0, 4,  8, 12); CYB_QR(1, 5,  9, 13);
        CYB_QR(2, 6, 10, 14); CYB_QR(3,  7, 11, 15);
        CYB_QR(0, 5, 10, 15); CYB_QR(1, 6, 11, 12);
        CYB_QR(2, 7,  8, 13); CYB_QR(3, 4,  9, 14);
#undef CYB_QR
    }
    for (i = 0; i < 16; i++) cyb_storele32(out + i * 4, x[i] + in[i]);
    cyb_secure_zero(x, sizeof(x));
}

/* Load 4 little-endian bytes into a 32-bit word (ChaCha state layout). */
CYB_INLINE uint32_t cyb_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

CYB_INLINE void cyb_chacha_set(uint32_t st[16], const uint8_t key[32], const uint8_t nonce[12], uint32_t ctr)
{
    st[0] = 0x61707865UL; st[1] = 0x3320646eUL;
    st[2] = 0x79622d32UL; st[3] = 0x6b206574UL;
    st[4]  = cyb_le32(key +  0); st[5]  = cyb_le32(key +  4);
    st[6]  = cyb_le32(key +  8); st[7]  = cyb_le32(key + 12);
    st[8]  = cyb_le32(key + 16); st[9]  = cyb_le32(key + 20);
    st[10] = cyb_le32(key + 24); st[11] = cyb_le32(key + 28);
    st[12] = ctr;
    st[13] = cyb_le32(nonce + 0); st[14] = cyb_le32(nonce + 4);
    st[15] = cyb_le32(nonce + 8);
}

CYB_INLINE void cyb_chacha20_xor(uint8_t *data, size_t len, const uint8_t key[32],
                                 const uint8_t nonce[12], uint32_t ctr)
{
    uint32_t st[16];
    uint8_t  ks[64];
    size_t   off = 0;
    int      i;

    cyb_chacha_set(st, key, nonce, ctr);
    while (off < len) {
        size_t n = len - off;
        cyb_chacha_block(st, ks);
        st[12]++;
        if (n > 64) n = 64;
        for (i = 0; i < (int)n; i++) data[off + (size_t)i] ^= ks[i];
        off += n;
    }
    cyb_secure_zero(ks, sizeof(ks));
    cyb_secure_zero(st, sizeof(st));
}

/* ========================================================================== */
/* Poly1305                                                                   */
/* ========================================================================== */

typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    uint8_t  buf[16];
    size_t   leftover;
} cyb_poly1305;

CYB_INLINE void cyb_poly1305_blocks(cyb_poly1305 *st, const uint8_t *m, size_t bytes, uint32_t hibit)
{
    const uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    const uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];

    while (bytes >= 16) {
        uint64_t d0, d1, d2, d3, d4;
        uint32_t c;

        h0 += cyb_le32(m + 0)      & 0x3ffffff;
        h1 += (cyb_le32(m + 3) >> 2) & 0x3ffffff;
        h2 += (cyb_le32(m + 6) >> 4) & 0x3ffffff;
        h3 += (cyb_le32(m + 9) >> 6) & 0x3ffffff;
        h4 += (cyb_le32(m + 12) >> 8) | hibit;

        d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;

        m += 16; bytes -= 16;
    }
    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

CYB_INLINE void cyb_poly1305_init(cyb_poly1305 *st, const uint8_t key[32])
{
    st->r[0] = cyb_le32(key + 0)       & 0x3ffffff;
    st->r[1] = (cyb_le32(key + 3) >> 2) & 0x3ffff03;
    st->r[2] = (cyb_le32(key + 6) >> 4) & 0x3ffc0ff;
    st->r[3] = (cyb_le32(key + 9) >> 6) & 0x3f03fff;
    st->r[4] = (cyb_le32(key + 12) >> 8) & 0x00fffff;
    st->pad[0] = cyb_le32(key + 16);
    st->pad[1] = cyb_le32(key + 20);
    st->pad[2] = cyb_le32(key + 24);
    st->pad[3] = cyb_le32(key + 28);
    st->h[0] = st->h[1] = st->h[2] = st->h[3] = st->h[4] = 0;
    st->leftover = 0;
}

CYB_INLINE void cyb_poly1305_update(cyb_poly1305 *st, const uint8_t *m, size_t bytes)
{
    if (st->leftover) {
        size_t want = 16 - st->leftover;
        size_t n = (bytes < want) ? bytes : want;
        memcpy(st->buf + st->leftover, m, n);
        st->leftover += n; m += n; bytes -= n;
        if (st->leftover < 16) return;
        cyb_poly1305_blocks(st, st->buf, 16, 1u << 24);
        st->leftover = 0;
    }
    if (bytes >= 16) {
        size_t want = bytes & ~(size_t)15;
        cyb_poly1305_blocks(st, m, want, 1u << 24);
        m += want; bytes -= want;
    }
    if (bytes) { memcpy(st->buf + st->leftover, m, bytes); st->leftover = bytes; }
}

CYB_INLINE void cyb_poly1305_finish(cyb_poly1305 *st, uint8_t mac[16])
{
    uint32_t h0, h1, h2, h3, h4, c, g0, g1, g2, g3, g4, mask;
    uint64_t f;

    if (st->leftover) {
        size_t i = st->leftover;
        st->buf[i++] = 1;
        for (; i < 16; i++) st->buf[i] = 0;
        st->leftover = 0;
        cyb_poly1305_blocks(st, st->buf, 16, 0);
    }

    h0 = st->h[0]; h1 = st->h[1]; h2 = st->h[2]; h3 = st->h[3]; h4 = st->h[4];

    c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;

    /* g = h + 5; if g does not carry out of the top limb, keep h (fully reduced) */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1UL << 26);

    mask = (g4 >> 31) - 1u;   /* 0xFFFFFFFF if g4's top bit clear, else 0 */
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2; h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    h0 = (h0       ) | (h1 << 26);
    h1 = (h1 >>  6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 <<  8);

    f = (uint64_t)h0 + st->pad[0];             h0 = (uint32_t)f;
    f = (uint64_t)h1 + st->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + st->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + st->pad[3] + (f >> 32); h3 = (uint32_t)f;

    cyb_storele32(mac +  0, h0);
    cyb_storele32(mac +  4, h1);
    cyb_storele32(mac +  8, h2);
    cyb_storele32(mac + 12, h3);
}

/* ========================================================================== */
/* ChaCha20-Poly1305 AEAD (RFC 8439 §2.8)                                      */
/* ========================================================================== */

CYB_INLINE void cyb_poly1305_keygen(const uint8_t key[32], const uint8_t nonce[12], uint8_t otk[32])
{
    uint32_t st[16];
    uint8_t  block[64];
    cyb_chacha_set(st, key, nonce, 0);
    cyb_chacha_block(st, block);
    memcpy(otk, block, 32);
    cyb_secure_zero(block, sizeof(block));
    cyb_secure_zero(st, sizeof(st));
}

CYB_INLINE void cyb_poly1305_mac(const uint8_t otk[32], const uint8_t *aad, size_t aadlen,
                                 const uint8_t *ct, size_t ctlen, uint8_t mac[16])
{
    cyb_poly1305 st;
    uint8_t  blk[16];
    uint64_t al = (uint64_t)aadlen, cl = (uint64_t)ctlen;
    int i;

    cyb_poly1305_init(&st, otk);
    if (aadlen) cyb_poly1305_update(&st, aad, aadlen);
    if (aadlen & 15) { size_t p = 16 - (aadlen & 15); memset(blk, 0, 16); cyb_poly1305_update(&st, blk, p); }
    if (ctlen)  cyb_poly1305_update(&st, ct, ctlen);
    if (ctlen & 15)  { size_t p = 16 - (ctlen & 15);  memset(blk, 0, 16); cyb_poly1305_update(&st, blk, p); }
    for (i = 0; i < 8; i++) blk[i]     = (uint8_t)(al >> (8 * i));
    for (i = 0; i < 8; i++) blk[8 + i] = (uint8_t)(cl >> (8 * i));
    cyb_poly1305_update(&st, blk, 16);
    cyb_poly1305_finish(&st, mac);
    cyb_secure_zero(&st, sizeof(st));
}

/*
 * Seal. `ct` must have room for ptlen + CYB_TAG_LEN bytes.  `ct` and `pt` may
 * alias exactly (in-place operation).
 */
CYB_INLINE void cyb_aead_seal(uint8_t *ct, const uint8_t *pt, size_t ptlen, uint8_t tag[CYB_TAG_LEN],
                              const uint8_t key[32], const uint8_t nonce[12],
                              const uint8_t *aad, size_t aadlen)
{
    uint8_t otk[32], mac[CYB_TAG_LEN];
    cyb_poly1305_keygen(key, nonce, otk);
    if (ptlen) {
        if (ct != pt) memcpy(ct, pt, ptlen);
        cyb_chacha20_xor(ct, ptlen, key, nonce, 1);
    }
    cyb_poly1305_mac(otk, aad, aadlen, ct, ptlen, mac);
    memcpy(tag, mac, CYB_TAG_LEN);
    cyb_secure_zero(otk, sizeof(otk));
    cyb_secure_zero(mac, sizeof(mac));
}

/*
 * Open. Returns 0 on success.  On authentication failure returns -1 and scrubs
 * the output so unauthenticated plaintext is never handed to the caller.
 */
CYB_INLINE int cyb_aead_open(uint8_t *pt, const uint8_t *ct, size_t ctlen,
                             const uint8_t tag[CYB_TAG_LEN],
                             const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *aad, size_t aadlen)
{
    uint8_t otk[32], mac[CYB_TAG_LEN];
    int bad;

    cyb_poly1305_keygen(key, nonce, otk);
    cyb_poly1305_mac(otk, aad, aadlen, ct, ctlen, mac);
    bad = cyb_ct_memcmp(mac, tag, CYB_TAG_LEN);

    if (bad) {
        if (ctlen) memset(pt, 0, ctlen);
        cyb_secure_zero(otk, sizeof(otk));
        cyb_secure_zero(mac, sizeof(mac));
        return -1;
    }
    if (ctlen) {
        if (pt != ct) memcpy(pt, ct, ctlen);
        cyb_chacha20_xor(pt, ctlen, key, nonce, 1);
    }
    cyb_secure_zero(otk, sizeof(otk));
    cyb_secure_zero(mac, sizeof(mac));
    return 0;
}

/* ========================================================================== */
/* CSPRNG                                                                     */
/* ========================================================================== */

#if defined(_WIN32)

/* The Windows branch needs GetModuleHandleA / GetProcAddress.  Including
 * windows.h here keeps this header self-contained; the payloads include it
 * anyway, so the include guard makes it free. */
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>

CYB_INLINE int cyb_random(uint8_t *out, size_t n)
{
    /* BCryptGenRandom is available on Vista+; dynamically loaded so the
     * payload still imports cleanly on older SDK targets.
     *
     * LoadLibraryA, not GetModuleHandleA: GetModuleHandle only finds DLLs the
     * loader has already mapped, and nothing else in this payload pulls in
     * bcrypt.dll. A -DCYB_MINIMAL build has no advapi32 import either, so the
     * SystemFunction036 fallback below also failed to resolve and the implant
     * had no entropy source at all -- do_handshake() bailed on cyb_random()
     * before sending a byte, so a minimal implant connected TCP and then
     * silently failed every handshake. The full build only ever worked by
     * accident: its own ADVAPI32 import happened to map the DLL first. */
    typedef LONG (__stdcall *fn_t)(void *, unsigned char *, unsigned long, unsigned long *);
    static fn_t pfn = NULL;
    static int tried = 0;
    unsigned long got = 0;
    LONG st;

    if (!tried) {
        HMODULE h;
        tried = 1;
        h = LoadLibraryA("bcrypt.dll");
        if (h) pfn = (fn_t)(void *)GetProcAddress(h, "BCryptGenRandom");
    }
    if (pfn) {
        st = pfn(NULL, out, (unsigned long)n, &got);
        if (st == 0 && got == n) return 0;
    }
    /* Fallback: RtlGenRandom (SystemFunction036) via advapi32. LoadLibraryA
     * for the same reason as above -- a minimal build never imports
     * advapi32, so GetModuleHandleA would return NULL and leave this implant
     * with no entropy source and no way to complete a handshake. */
    {
        typedef BOOLEAN (__stdcall *rtl_t)(void *, ULONG);
        static rtl_t prtl = NULL;
        static int t2 = 0;
        size_t off = 0;
        if (!t2) {
            HMODULE h2;
            t2 = 1;
            h2 = LoadLibraryA("advapi32.dll");
            if (h2) prtl = (rtl_t)(void *)GetProcAddress(h2, "SystemFunction036");
        }
        if (!prtl) return -1;
        while (off < n) {
            ULONG chunk = (ULONG)((n - off > 64) ? 64 : (n - off));
            if (!prtl(out + off, chunk)) return -1;
            off += chunk;
        }
        return 0;
    }
}

#else /* POSIX */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#if defined(__linux__)
#  include <sys/syscall.h>
#endif

CYB_INLINE int cyb_random(uint8_t *out, size_t n)
{
    int fd;
    size_t off = 0;

#if defined(__linux__) && defined(SYS_getrandom)
    while (off < n) {
        long r = syscall(SYS_getrandom, out + off, n - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;                       /* fall through to /dev/urandom */
        }
        off += (size_t)r;
    }
    if (off == n) return 0;
#endif

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    while (off < n) {
        ssize_t r = read(fd, out + off, n - off);
        if (r < 0) { if (errno == EINTR) continue; close(fd); return -1; }
        if (r == 0) { close(fd); return -1; }
        off += (size_t)r;
    }
    close(fd);
    return 0;
}

#endif

/* ========================================================================== */
/* X25519 (RFC 7748) — 5x51-bit field arithmetic                             */
/* ========================================================================== */

typedef uint64_t cyb_fe[5];

/*
 * The radix-2^51 representation needs >64-bit accumulators: two limbs of
 * ~2^52 multiply to ~2^104.  Every 64-bit toolchain we target (x86-64 via
 * gcc/clang, x86-64 via mingw-w64, aarch64) provides __uint128_t.
 */
#if !defined(__SIZEOF_INT128__)
#  error "cybcrypt.h: X25519 needs a 64-bit target with __uint128_t (gcc/clang)"
#endif
typedef __uint128_t cyb_fe_acc;

#define CYB_FE_M 0x7ffffffffffffULL            /* 2^51 - 1 */
#define CYB_FE_P2_0 0xFFFFFFFFFFFDAULL          /* 2^52 - 38 */
#define CYB_FE_P2_N 0xFFFFFFFFFFFFEULL          /* 2^52 - 2  */

CYB_INLINE uint64_t cyb_load64le(const uint8_t *p)
{
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

CYB_INLINE void cyb_store64le(uint8_t *p, uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

CYB_INLINE void cyb_fe_0(cyb_fe h) { int i; for (i = 0; i < 5; i++) h[i] = 0; }

CYB_INLINE void cyb_fe_1(cyb_fe h) { h[0] = 1; h[1] = 0; h[2] = 0; h[3] = 0; h[4] = 0; }

/*
 * Propagate carries until every limb is < 2^51.
 *
 * The postcondition (all limbs < 2^51) is load-bearing: cyb_fe_tobytes uses a
 * "does t+19 carry past bit 255" test to decide whether to subtract p, and that
 * test is only valid when the limbs are already in range.  Three full passes
 * are enough for any input below 2^60, which covers every value produced here.
 */
CYB_INLINE void cyb_fe_reduce(cyb_fe h)
{
    int pass;
    for (pass = 0; pass < 3; pass++) {
        uint64_t c;
        c = h[0] >> 51; h[0] &= CYB_FE_M; h[1] += c;
        c = h[1] >> 51; h[1] &= CYB_FE_M; h[2] += c;
        c = h[2] >> 51; h[2] &= CYB_FE_M; h[3] += c;
        c = h[3] >> 51; h[3] &= CYB_FE_M; h[4] += c;
        c = h[4] >> 51; h[4] &= CYB_FE_M; h[0] += c * 19;
    }
}

CYB_INLINE void cyb_fe_add(cyb_fe h, const cyb_fe f, const cyb_fe g)
{
    h[0] = f[0] + g[0]; h[1] = f[1] + g[1]; h[2] = f[2] + g[2];
    h[3] = f[3] + g[3]; h[4] = f[4] + g[4];
}

CYB_INLINE void cyb_fe_sub(cyb_fe h, const cyb_fe f, const cyb_fe g)
{
    /* Add 2p = 2^256-38 so no limb underflows. */
    h[0] = f[0] + CYB_FE_P2_0 - g[0];
    h[1] = f[1] + CYB_FE_P2_N - g[1];
    h[2] = f[2] + CYB_FE_P2_N - g[2];
    h[3] = f[3] + CYB_FE_P2_N - g[3];
    h[4] = f[4] + CYB_FE_P2_N - g[4];
    cyb_fe_reduce(h);
}

CYB_INLINE void cyb_fe_mul(cyb_fe h, const cyb_fe f, const cyb_fe g)
{
    const cyb_fe_acc f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
    const cyb_fe_acc g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];
    cyb_fe_acc r0, r1, r2, r3, r4;
    uint64_t c;

    r0 = f0 * g0 + 19 * (f1 * g4 + f2 * g3 + f3 * g2 + f4 * g1);
    r1 = f0 * g1 + f1 * g0 + 19 * (f2 * g4 + f3 * g3 + f4 * g2);
    r2 = f0 * g2 + f1 * g1 + f2 * g0 + 19 * (f3 * g4 + f4 * g3);
    r3 = f0 * g3 + f1 * g2 + f2 * g1 + f3 * g0 + 19 * (f4 * g4);
    r4 = f0 * g4 + f1 * g3 + f2 * g2 + f3 * g1 + f4 * g0;

    c = (uint64_t)(r0 >> 51); r0 &= CYB_FE_M; r1 += c;
    c = (uint64_t)(r1 >> 51); r1 &= CYB_FE_M; r2 += c;
    c = (uint64_t)(r2 >> 51); r2 &= CYB_FE_M; r3 += c;
    c = (uint64_t)(r3 >> 51); r3 &= CYB_FE_M; r4 += c;
    c = (uint64_t)(r4 >> 51); r4 &= CYB_FE_M; r0 += (cyb_fe_acc)c * 19;
    c = (uint64_t)(r0 >> 51); r0 &= CYB_FE_M; r1 += c;
    /* Fold the wraparound so limb 1 is also back in range. */
    c = (uint64_t)(r1 >> 51); r1 &= CYB_FE_M; r2 += c;

    h[0] = (uint64_t)r0; h[1] = (uint64_t)r1; h[2] = (uint64_t)r2;
    h[3] = (uint64_t)r3; h[4] = (uint64_t)r4;
}

CYB_INLINE void cyb_fe_sq(cyb_fe h, const cyb_fe f) { cyb_fe_mul(h, f, f); }

/* Multiply by a24 = 121665 (RFC 7748 §5).  Not 121666: that is a24+1 and
 * silently produces a different, wrong ladder result. */
CYB_INLINE void cyb_fe_mul_a24(cyb_fe h, const cyb_fe f)
{
    cyb_fe_acc t[5];
    uint64_t c;
    int i;
    /*
     * f[i] can reach ~2^52 and 121665 is ~2^17, so the product needs ~69 bits.
     * The carry chain must therefore run in 128-bit too: storing the raw
     * product into a uint64_t limb would silently truncate it.
     */
    for (i = 0; i < 5; i++) t[i] = (cyb_fe_acc)f[i] * 121665;

    c = (uint64_t)(t[0] >> 51); t[0] &= CYB_FE_M; t[1] += c;
    c = (uint64_t)(t[1] >> 51); t[1] &= CYB_FE_M; t[2] += c;
    c = (uint64_t)(t[2] >> 51); t[2] &= CYB_FE_M; t[3] += c;
    c = (uint64_t)(t[3] >> 51); t[3] &= CYB_FE_M; t[4] += c;
    c = (uint64_t)(t[4] >> 51); t[4] &= CYB_FE_M; t[0] += (cyb_fe_acc)c * 19;
    c = (uint64_t)(t[0] >> 51); t[0] &= CYB_FE_M; t[1] += c;

    for (i = 0; i < 5; i++) h[i] = (uint64_t)t[i];
    cyb_fe_reduce(h);   /* final wraparound so every limb is back < 2^51 */
}

CYB_INLINE void cyb_fe_cswap(cyb_fe a, cyb_fe b, uint64_t bit)
{
    uint64_t mask = 0 - bit;    /* all-ones when bit == 1 */
    int i;
    for (i = 0; i < 5; i++) {
        uint64_t t = mask & (a[i] ^ b[i]);
        a[i] ^= t; b[i] ^= t;
    }
}

CYB_INLINE void cyb_fe_frombytes(cyb_fe h, const uint8_t s[32])
{
    h[0] = cyb_load64le(s)              & CYB_FE_M;
    h[1] = (cyb_load64le(s +  6) >> 3)  & CYB_FE_M;
    h[2] = (cyb_load64le(s + 12) >> 6)  & CYB_FE_M;
    h[3] = (cyb_load64le(s + 19) >> 1)  & CYB_FE_M;
    h[4] = (cyb_load64le(s + 24) >> 12) & CYB_FE_M;
}

CYB_INLINE void cyb_fe_tobytes(uint8_t s[32], const cyb_fe f)
{
    cyb_fe t;
    uint64_t c, q;

    memcpy(t, f, sizeof(t));
    cyb_fe_reduce(t);

    /* Conditionally subtract p: if t+19 carries out of the top limb then t >= p. */
    q = (t[0] + 19) >> 51;
    q = (t[1] + q) >> 51;
    q = (t[2] + q) >> 51;
    q = (t[3] + q) >> 51;
    q = (t[4] + q) >> 51;

    t[0] += 19 * q;
    c = t[0] >> 51; t[0] &= CYB_FE_M; t[1] += c;
    c = t[1] >> 51; t[1] &= CYB_FE_M; t[2] += c;
    c = t[2] >> 51; t[2] &= CYB_FE_M; t[3] += c;
    c = t[3] >> 51; t[3] &= CYB_FE_M; t[4] += c;
    t[4] &= CYB_FE_M;

    /*
     * Pack 5 limbs of radix 2^51 into 32 little-endian bytes.
     * Limb i occupies bits [51i, 51i+50]; bytes straddle limb boundaries at
     * 6, 12, 19 and 25.
     */
    s[ 0] = (uint8_t)(t[0]);
    s[ 1] = (uint8_t)(t[0] >>  8);
    s[ 2] = (uint8_t)(t[0] >> 16);
    s[ 3] = (uint8_t)(t[0] >> 24);
    s[ 4] = (uint8_t)(t[0] >> 32);
    s[ 5] = (uint8_t)(t[0] >> 40);
    s[ 6] = (uint8_t)((t[0] >> 48) | (t[1] <<  3));
    s[ 7] = (uint8_t)(t[1] >>  5);
    s[ 8] = (uint8_t)(t[1] >> 13);
    s[ 9] = (uint8_t)(t[1] >> 21);
    s[10] = (uint8_t)(t[1] >> 29);
    s[11] = (uint8_t)(t[1] >> 37);
    s[12] = (uint8_t)((t[1] >> 45) | (t[2] <<  6));
    s[13] = (uint8_t)(t[2] >>  2);
    s[14] = (uint8_t)(t[2] >> 10);
    s[15] = (uint8_t)(t[2] >> 18);
    s[16] = (uint8_t)(t[2] >> 26);
    s[17] = (uint8_t)(t[2] >> 34);
    s[18] = (uint8_t)(t[2] >> 42);
    s[19] = (uint8_t)((t[2] >> 50) | (t[3] <<  1));
    s[20] = (uint8_t)(t[3] >>  7);
    s[21] = (uint8_t)(t[3] >> 15);
    s[22] = (uint8_t)(t[3] >> 23);
    s[23] = (uint8_t)(t[3] >> 31);
    s[24] = (uint8_t)(t[3] >> 39);
    s[25] = (uint8_t)((t[3] >> 47) | (t[4] <<  4));
    s[26] = (uint8_t)(t[4] >>  4);
    s[27] = (uint8_t)(t[4] >> 12);
    s[28] = (uint8_t)(t[4] >> 20);
    s[29] = (uint8_t)(t[4] >> 28);
    s[30] = (uint8_t)(t[4] >> 36);
    s[31] = (uint8_t)(t[4] >> 44);

    cyb_secure_zero(t, sizeof(t));
}

/* out = z^(p-2) = z^(2^255-21), via the standard addition chain */
CYB_INLINE void cyb_fe_invert(cyb_fe out, const cyb_fe z)
{
    cyb_fe z2, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, z2_250_0, t;
    int i;

    cyb_fe_sq(z2, z);                              /* 2        */
    cyb_fe_sq(t, z2);  cyb_fe_sq(t, t);            /* 2^3 = 8  */
    cyb_fe_mul(z9, t, z);                          /* 9        */
    cyb_fe_mul(z11, z9, z2);                       /* 11       */
    cyb_fe_sq(z2_5_0, z11);                        /* 2^5 = 22 */
    cyb_fe_mul(z2_5_0, z2_5_0, z9);                /* 2^5-2^0  */

    cyb_fe_sq(t, z2_5_0);
    for (i = 0; i < 4; i++) cyb_fe_sq(t, t);       /* 2^5 * 2^5 = 2^10 */
    cyb_fe_mul(z2_10_0, t, z2_5_0);                /* 2^10-2^0 */

    cyb_fe_sq(t, z2_10_0);
    for (i = 0; i < 9; i++) cyb_fe_sq(t, t);       /* 2^20 */
    cyb_fe_mul(z2_20_0, t, z2_10_0);               /* 2^20-2^0 */

    cyb_fe_sq(t, z2_20_0);
    for (i = 0; i < 19; i++) cyb_fe_sq(t, t);      /* 2^40 */
    cyb_fe_mul(t, t, z2_20_0);                     /* 2^40-2^0 */
    cyb_fe_sq(t, t);
    for (i = 0; i < 9; i++) cyb_fe_sq(t, t);       /* 2^50 */
    cyb_fe_mul(z2_50_0, t, z2_10_0);               /* 2^50-2^0 */

    cyb_fe_sq(t, z2_50_0);
    for (i = 0; i < 49; i++) cyb_fe_sq(t, t);      /* 2^99 */
    cyb_fe_mul(z2_100_0, t, z2_50_0);              /* 2^100-2^0 */

    cyb_fe_sq(t, z2_100_0);
    for (i = 0; i < 99; i++) cyb_fe_sq(t, t);      /* 2^199 */
    cyb_fe_mul(t, t, z2_100_0);                    /* 2^200-2^0 */
    cyb_fe_sq(t, t);
    for (i = 0; i < 49; i++) cyb_fe_sq(t, t);      /* 2^250 */
    cyb_fe_mul(z2_250_0, t, z2_50_0);              /* 2^250-2^0 */

    cyb_fe_sq(t, z2_250_0);
    for (i = 0; i < 4; i++) cyb_fe_sq(t, t);       /* 2^255-2^5 */
    cyb_fe_mul(out, t, z11);                       /* 2^255-2^5+11 = 2^255-21 */

    cyb_secure_zero(z2, sizeof(z2));
    cyb_secure_zero(z9, sizeof(z9));
    cyb_secure_zero(z11, sizeof(z11));
    cyb_secure_zero(z2_5_0, sizeof(z2_5_0));
    cyb_secure_zero(z2_10_0, sizeof(z2_10_0));
    cyb_secure_zero(z2_20_0, sizeof(z2_20_0));
    cyb_secure_zero(z2_50_0, sizeof(z2_50_0));
    cyb_secure_zero(z2_100_0, sizeof(z2_100_0));
    cyb_secure_zero(z2_250_0, sizeof(z2_250_0));
    cyb_secure_zero(t, sizeof(t));
}

CYB_INLINE void cyb_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
    uint8_t  k[32];
    cyb_fe   x1, x2, z2, x3, z3, a, aa, b, bb, e, c, d, da, cb, t;
    uint64_t swap = 0;
    int      pos;

    memcpy(k, scalar, 32);
    k[0]  &= 248;
    k[31] &= 127;
    k[31] |= 64;

    cyb_fe_frombytes(x1, point);
    x1[4] &= 0x7ffffffffffffULL;      /* RFC 7748 §5: ignore bit 255 of the u-coordinate */

    cyb_fe_1(x2); cyb_fe_0(z2);
    memcpy(x3, x1, sizeof(x1));
    cyb_fe_1(z3);

    for (pos = 254; pos >= 0; pos--) {
        uint64_t bit = (uint64_t)((k[pos / 8] >> (pos & 7)) & 1);
        swap ^= bit;
        cyb_fe_cswap(x2, x3, swap);
        cyb_fe_cswap(z2, z3, swap);
        swap = bit;

        cyb_fe_add(a, x2, z2);
        cyb_fe_sq(aa, a);
        cyb_fe_sub(b, x2, z2);
        cyb_fe_sq(bb, b);
        cyb_fe_sub(e, aa, bb);
        cyb_fe_add(c, x3, z3);
        cyb_fe_sub(d, x3, z3);
        cyb_fe_mul(da, d, a);
        cyb_fe_mul(cb, c, b);

        cyb_fe_add(t, da, cb);
        cyb_fe_sq(x3, t);
        cyb_fe_sub(t, da, cb);
        cyb_fe_sq(t, t);
        cyb_fe_mul(z3, x1, t);

        cyb_fe_mul(x2, aa, bb);
        cyb_fe_mul_a24(t, e);
        cyb_fe_add(t, t, aa);
        cyb_fe_mul(z2, e, t);
    }
    cyb_fe_cswap(x2, x3, swap);
    cyb_fe_cswap(z2, z3, swap);

    cyb_fe_invert(z2, z2);
    cyb_fe_mul(x2, x2, z2);
    cyb_fe_tobytes(out, x2);

    cyb_secure_zero(k, sizeof(k));
    cyb_secure_zero(x1, sizeof(x1));
    cyb_secure_zero(z2, sizeof(z2));
    cyb_secure_zero(x3, sizeof(x3));
    cyb_secure_zero(z3, sizeof(z3));
}

CYB_INLINE void cyb_x25519_keypair(uint8_t priv[32], uint8_t pub[32], uint8_t seed[32])
{
    static const uint8_t basepoint[32] = { 9 };
    /*
     * A non-NULL seed is used verbatim, which makes key generation
     * deterministic and testable.  A NULL seed draws fresh entropy.  (Do not
     * overwrite a caller-supplied seed here -- that silently makes the
     * function non-deterministic even when a seed was given.)
     */
    if (seed) {
        memcpy(priv, seed, 32);
    } else if (cyb_random(priv, 32) != 0) {
        return;
    }
    priv[0]  &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
    cyb_x25519(pub, priv, basepoint);
}

#endif /* CYB_CRYPTO_H */
