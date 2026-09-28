/*
 * proto_selftest.c — exercises the CYB3 framing, handshake, replay and tamper
 * handling.  Also prints a transcript that proto_interop.py re-derives with
 * Python's `cryptography` library, an independent implementation of the same
 * RFCs, so the C and Python sides are proven to agree.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../cybproto.h"

static int g_pass = 0, g_fail = 0;

static void ok(const char *name, int cond)
{
    if (cond) { printf("  [PASS] %s\n", name); g_pass++; }
    else      { printf("  [FAIL] %s\n", name); g_fail++; }
}

static void hex(const char *label, const uint8_t *b, size_t n)
{
    size_t i;
    printf("    %-14s ", label);
    for (i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

/* ---- a fresh, fully-established client/server pair for each sub-test ---- */

static uint8_t PSK[32];

typedef struct {
    cyb_session s;
} end_t;

static void pair_make(end_t *cli, end_t *srv)
{
    uint8_t cpriv[32], cpub[32], cnonce[16];
    uint8_t spriv[32], spub[32], snonce[16];
    uint8_t k_c2s[32], k_s2c[32], p_c2s[4], p_s2c[4];

    memset(cnonce, 0x11, 16);
    memset(snonce, 0x22, 16);
    cyb_x25519_keypair(cpriv, cpub, NULL);
    cyb_x25519_keypair(spriv, spub, NULL);

    cyb_derive_session(k_c2s, k_s2c, p_c2s, p_s2c, PSK, cpriv, spub, cnonce, snonce, 0);

    cyb_session_init(&cli->s);
    memcpy(cli->s.k_send, k_c2s, 32);  memcpy(cli->s.k_recv, k_s2c, 32);
    memcpy(cli->s.n_send, p_c2s, 4);   memcpy(cli->s.n_recv, p_s2c, 4);
    cli->s.established = 1;

    cyb_session_init(&srv->s);
    memcpy(srv->s.k_send, k_s2c, 32);  memcpy(srv->s.k_recv, k_c2s, 32);
    memcpy(srv->s.n_send, p_s2c, 4);   memcpy(srv->s.n_recv, p_c2s, 4);
    srv->s.established = 1;
}

int main(void)
{
    uint8_t auth[32], wrong_psk[32], wrong_auth[32];
    uint8_t cpub[32], cnonce[16], spub[32], snonce[16];
    uint8_t k_c2s[32], k_s2c[32], p_c2s[4], p_s2c[4];
    uint8_t k_c2s2[32], k_s2c2[32], p_c2s2[4], p_s2c2[4];
    end_t  cli, srv;
    uint8_t *fbuf, *pt;
    size_t  flen, ptlen;
    uint8_t type;
    int     i, r;

    printf("======================================================\n");
    printf(" CYBERDEMONS cybproto.h self-test\n");
    printf("======================================================\n");

    for (i = 0; i < 32; i++) PSK[i] = (uint8_t)(0xA0 + i);
    for (i = 0; i < 32; i++) wrong_psk[i] = (uint8_t)(PSK[i] ^ 0xFF);
    cyb_derive_auth_key(auth, PSK);
    cyb_derive_auth_key(wrong_auth, wrong_psk);

    memset(cnonce, 0x11, 16);
    memset(snonce, 0x22, 16);
    cyb_x25519_keypair((uint8_t[32]){ 0 }, cpub, NULL);
    cyb_x25519_keypair((uint8_t[32]){ 0 }, spub, NULL);

    fbuf = (uint8_t *)malloc(256);
    if (!fbuf) return 1;

    /* ================= handshake ================= */
    printf("\n== handshake ==\n");

    flen = cyb_build_hello(fbuf, 128, 0, auth, cpub, cnonce, NULL, NULL);
    ok("client builds HELLO", flen == CYB_HDR_LEN + CYB_HELLO_FRAME);
    ok("HELLO magic + version", fbuf[0] == CYB_MAGIC0 && fbuf[1] == CYB_MAGIC1);
    ok("HELLO frame type", fbuf[2] == CYB_T_HELLO);
    ok("HELLO length field", cyb_ntohl32(fbuf + 8) == CYB_HELLO_FRAME);
    ok("server accepts a valid HELLO",
       cyb_verify_hello(fbuf + CYB_HDR_LEN, CYB_HELLO_FRAME, 0, auth,
                        NULL, NULL, NULL, NULL) == 0);
    ok("HELLO rejected under the wrong PSK",
       cyb_verify_hello(fbuf + CYB_HDR_LEN, CYB_HELLO_FRAME, 0, wrong_auth,
                        NULL, NULL, NULL, NULL) != 0);
    {
        uint8_t bad[256];
        memcpy(bad, fbuf, CYB_HDR_LEN + CYB_HELLO_FRAME);
        bad[CYB_HDR_LEN + 3] ^= 0x01;
        ok("tampered HELLO pubkey rejected",
           cyb_verify_hello(bad + CYB_HDR_LEN, CYB_HELLO_FRAME, 0, auth,
                            cpub, cnonce, NULL, NULL) != 0);
        memcpy(bad, fbuf, sizeof(bad));
        bad[CYB_HDR_LEN + CYB_HELLO_BODY] ^= 0x80;
        ok("tampered HELLO tag rejected",
           cyb_verify_hello(bad + CYB_HDR_LEN, CYB_HELLO_FRAME, 0, auth,
                            NULL, NULL, NULL, NULL) != 0);
    }
    {
        uint8_t rp[32], rn[16];
        ok("verify returns the sender's key/nonce",
           cyb_verify_hello(fbuf + CYB_HDR_LEN, CYB_HELLO_FRAME, 0, auth,
                            NULL, NULL, rp, rn) == 0 &&
           memcmp(rp, cpub, 32) == 0 && memcmp(rn, cnonce, 16) == 0);
    }
    ok("HELLO with a short body rejected",
       cyb_verify_hello(fbuf + CYB_HDR_LEN, 10, 0, auth, NULL, NULL, NULL, NULL) != 0);

    printf("\n== interop transcript (re-checked by cybtest/proto_interop.py) ==\n");
    hex("psk", PSK, 32);
    hex("cli_pub", cpub, 32);
    hex("cli_nonce", cnonce, 16);
    hex("srv_pub", spub, 32);
    hex("srv_nonce", snonce, 16);

    flen = cyb_build_hello(fbuf, 128, 1, auth, spub, snonce, cpub, cnonce);
    ok("server builds HELLOACK", flen == CYB_HDR_LEN + CYB_HELLO_FRAME);
    ok("HELLOACK frame type", fbuf[2] == CYB_T_HELLOACK);
    ok("client accepts a valid HELLOACK",
       cyb_verify_hello(fbuf + CYB_HDR_LEN, CYB_HELLO_FRAME, 1, auth,
                        cpub, cnonce, NULL, NULL) == 0);
    ok("HELLOACK does not verify against a different client nonce",
       cyb_verify_hello(fbuf + CYB_HDR_LEN, CYB_HELLO_FRAME, 1, auth,
                        cpub, snonce, NULL, NULL) != 0);

    /* ================= key agreement ================= */
    printf("\n== key agreement ==\n");
    {
        uint8_t cpriv[32], spriv[32];
        cyb_x25519_keypair(cpriv, cpub, NULL);
        cyb_x25519_keypair(spriv, spub, NULL);
        cyb_derive_session(k_c2s,  k_s2c,  p_c2s,  p_s2c,  PSK, cpriv, spub, cnonce, snonce, 0);
        cyb_derive_session(k_c2s2, k_s2c2, p_c2s2, p_s2c2, PSK, spriv, cpub, cnonce, snonce, 1);
        ok("client and server agree on k_c2s", memcmp(k_c2s, k_c2s2, 32) == 0);
        ok("client and server agree on k_s2c", memcmp(k_s2c, k_s2c2, 32) == 0);
        ok("client and server agree on the c2s prefix", memcmp(p_c2s, p_c2s2, 4) == 0);
        ok("client and server agree on the s2c prefix", memcmp(p_s2c, p_s2c2, 4) == 0);
        ok("direction keys differ", memcmp(k_c2s, k_s2c, 32) != 0);
        ok("nonce prefixes differ", memcmp(p_c2s, p_s2c, 4) != 0);
        hex("k_c2s", k_c2s, 32);
        hex("k_s2c", k_s2c, 32);
        hex("pfx_c2s", p_c2s, 4);
        hex("pfx_s2c", p_s2c, 4);
    }
    {
        uint8_t a[32], b[32], x[4], y[4], cpriv[32];
        cyb_x25519_keypair(cpriv, cpub, NULL);
        cyb_derive_session(a, b, x, y, wrong_psk, cpriv, spub, cnonce, snonce, 0);
        ok("a different PSK yields different keys", memcmp(a, k_c2s, 32) != 0);
    }
    {
        uint8_t zero[32], a[32], b[32], x[4], y[4], cpriv[32];
        memset(zero, 0, 32);
        cyb_x25519_keypair(cpriv, cpub, NULL);
        cyb_derive_session(a, b, x, y, PSK, cpriv, zero, cnonce, snonce, 0);
        {
            uint8_t z[32];
            memset(z, 0, 32);
            ok("all-zero (low-order) peer key refused", memcmp(a, z, 32) == 0);
        }
    }

    /* ================= data frames ================= */
    printf("\n== data frames ==\n");
    pair_make(&cli, &srv);

    flen = cyb_seal(&srv.s, CYB_T_CMD, (const uint8_t *)"whoami", 6, fbuf);
    ok("seal a CMD", flen == CYB_HDR_LEN + 6 + CYB_TAG_LEN);
    ok("frame type on the wire", fbuf[2] == CYB_T_CMD);
    ok("ct_len on the wire", cyb_ntohl32(fbuf + 8) == 6);
    ok("seq starts at 0", cyb_ntohl32(fbuf + 4) == 0);
    ok("nonce prefix in the frame matches the session", memcmp(fbuf + 12, srv.s.n_send, 4) == 0);
    ok("plaintext is not on the wire", memcmp(fbuf + CYB_HDR_LEN, "whoami", 6) != 0);

    ok("feed accepts bytes", cyb_feed(&cli.s, fbuf, flen) == 0);
    r = cyb_recv_next(&cli.s, &type, &pt, &ptlen);
    ok("recv returns a message", r == 1);
    ok("type is CMD", type == CYB_T_CMD);
    ok("plaintext recovered", ptlen == 6 && memcmp(pt, "whoami", 6) == 0);

    /* byte-at-a-time delivery */
    {
        end_t c2, s2;
        size_t k;
        pair_make(&c2, &s2);
        flen = cyb_seal(&s2.s, CYB_T_RESP, (const uint8_t *)"root\n", 5, fbuf);
        for (k = 0; k < flen; k++) cyb_feed(&c2.s, fbuf + k, 1);
        r = cyb_recv_next(&c2.s, &type, &pt, &ptlen);
        ok("drip-fed frame reassembles",
           r == 1 && type == CYB_T_RESP && ptlen == 5 && memcmp(pt, "root\n", 5) == 0);
        ok("stream fully consumed", c2.s.rx_off == c2.s.rx_len);
        ok("no further frame available", cyb_recv_next(&c2.s, &type, &pt, &ptlen) == 0);
        cyb_session_free(&c2.s); cyb_session_free(&s2.s);
    }

    /* two frames in one segment */
    {
        end_t c2, s2;
        uint8_t *big = (uint8_t *)malloc(2 * (CYB_HDR_LEN + 5 + CYB_TAG_LEN));
        size_t l1, l2;
        int got = 0;
        pair_make(&c2, &s2);
        l1 = cyb_seal(&s2.s, CYB_T_CMD, (const uint8_t *)"aaaaa", 5, big);
        l2 = cyb_seal(&s2.s, CYB_T_CMD, (const uint8_t *)"bbbbb", 5, big + l1);
        cyb_feed(&c2.s, big, l1 + l2);
        while ((r = cyb_recv_next(&c2.s, &type, &pt, &ptlen)) == 1) {
            if (got == 0) ok("coalesced frame 1", ptlen == 5 && memcmp(pt, "aaaaa", 5) == 0);
            if (got == 1) ok("coalesced frame 2", ptlen == 5 && memcmp(pt, "bbbbb", 5) == 0);
            got++;
        }
        ok("both coalesced frames delivered", got == 2);
        cyb_session_free(&c2.s); cyb_session_free(&s2.s);
        free(big);
    }

    /* ================= attacks ================= */
    printf("\n== tamper / replay handling ==\n");

    {   /* flipped ciphertext byte */
        end_t c2, s2;
        pair_make(&c2, &s2);
        flen = cyb_seal(&s2.s, CYB_T_CMD, (const uint8_t *)"whoami", 6, fbuf);
        fbuf[CYB_HDR_LEN + 2] ^= 0x01;
        cyb_feed(&c2.s, fbuf, flen);
        ok("tampered ciphertext rejected", cyb_recv_next(&c2.s, &type, &pt, &ptlen) == -1);
        cyb_session_free(&c2.s); cyb_session_free(&s2.s);
    }
    {   /* flipped tag byte */
        end_t c2, s2;
        pair_make(&c2, &s2);
        flen = cyb_seal(&s2.s, CYB_T_CMD, (const uint8_t *)"whoami", 6, fbuf);
        fbuf[flen - 1] ^= 0x01;
        cyb_feed(&c2.s, fbuf, flen);
        ok("tampered tag rejected", cyb_recv_next(&c2.s, &type, &pt, &ptlen) == -1);
        cyb_session_free(&c2.s); cyb_session_free(&s2.s);
    }
    {   /* replay */
        end_t c2, s2;
        uint8_t *copy = (uint8_t *)malloc(128);
        pair_make(&c2, &s2);
        flen = cyb_seal(&s2.s, CYB_T_CMD, (const uint8_t *)"whoami", 6, fbuf);
        memcpy(copy, fbuf, flen);
        cyb_feed(&c2.s, copy, flen);
        ok("first delivery accepted", cyb_recv_next(&c2.s, &type, &pt, &ptlen) == 1);
        cyb_feed(&c2.s, copy, flen);
        ok("replayed frame rejected", cyb_recv_next(&c2.s, &type, &pt, &ptlen) == -1);
        cyb_session_free(&c2.s); cyb_session_free(&s2.s);
        free(copy);
    }
    {   /* reflection: our own outbound frame fed back to us */
        end_t c2, s2;
        pair_make(&c2, &s2);
        flen = cyb_seal(&c2.s, CYB_T_CMD, (const uint8_t *)"reflect", 7, fbuf);
        cyb_feed(&c2.s, fbuf, flen);
        ok("reflected frame rejected (directional keys)",
           cyb_recv_next(&c2.s, &type, &pt, &ptlen) == -1);
        cyb_session_free(&c2.s); cyb_session_free(&s2.s);
    }
    {   /* retyping a RESP as CMD without recomputing the tag */
        end_t c2, s2;
        pair_make(&c2, &s2);
        flen = cyb_seal(&c2.s, CYB_T_RESP, (const uint8_t *)"spoof", 5, fbuf);
        fbuf[2] = CYB_T_CMD;
        cyb_feed(&c2.s, fbuf, flen);
        ok("retyped frame rejected (type is in the AAD)",
           cyb_recv_next(&c2.s, &type, &pt, &ptlen) == -1);
        cyb_session_free(&c2.s); cyb_session_free(&s2.s);
    }
    {   /* forged frame from a peer holding the wrong key */
        end_t c2, s2;
        pair_make(&c2, &s2);
        memset(s2.s.k_send, 0xEE, 32);
        flen = cyb_seal(&s2.s, CYB_T_CMD, (const uint8_t *)"evil", 4, fbuf);
        cyb_feed(&c2.s, fbuf, flen);
        ok("frame under a wrong key rejected",
           cyb_recv_next(&c2.s, &type, &pt, &ptlen) == -1);
        cyb_session_free(&c2.s); cyb_session_free(&s2.s);
    }
    {   /* absurd declared length */
        end_t c2, s2;
        pair_make(&c2, &s2);
        fbuf[0] = CYB_MAGIC0; fbuf[1] = CYB_MAGIC1; fbuf[2] = CYB_T_CMD; fbuf[3] = 0;
        cyb_hton32(fbuf + 4, 0);
        cyb_hton32(fbuf + 8, 0xFFFFFFF0u);
        cyb_feed(&c2.s, fbuf, CYB_HDR_LEN);
        ok("absurd ct_len rejected without allocating",
           cyb_recv_next(&c2.s, &type, &pt, &ptlen) == -1);
        cyb_session_free(&c2.s); cyb_session_free(&s2.s);
    }
    {   /* bad magic */
        end_t c2, s2;
        pair_make(&c2, &s2);
        fbuf[0] = 0xDE; fbuf[1] = 0xAD; fbuf[2] = CYB_T_CMD; fbuf[3] = 0;
        cyb_feed(&c2.s, fbuf, CYB_HDR_LEN);
        ok("bad magic rejected", cyb_recv_next(&c2.s, &type, &pt, &ptlen) == -1);
        cyb_session_free(&c2.s); cyb_session_free(&s2.s);
    }
    {   /* unknown frame type */
        end_t c2, s2;
        pair_make(&c2, &s2);
        fbuf[0] = CYB_MAGIC0; fbuf[1] = CYB_MAGIC1; fbuf[2] = 0x55; fbuf[3] = 0;
        cyb_feed(&c2.s, fbuf, CYB_HDR_LEN);
        ok("unknown frame type rejected", cyb_recv_next(&c2.s, &type, &pt, &ptlen) == -1);
        cyb_session_free(&c2.s); cyb_session_free(&s2.s);
    }
    {   /* seq gap must not be accepted */
        end_t c2, s2;
        pair_make(&c2, &s2);
        flen = cyb_seal(&s2.s, CYB_T_CMD, (const uint8_t *)"whoami", 6, fbuf);
        cyb_hton32(fbuf + 4, 5);          /* claim seq 5 when 0 is expected */
        cyb_feed(&c2.s, fbuf, flen);
        ok("out-of-order seq rejected", cyb_recv_next(&c2.s, &type, &pt, &ptlen) == -1);
        cyb_session_free(&c2.s); cyb_session_free(&s2.s);
    }

    /* ================= large payload ================= */
    printf("\n== large payload ==\n");
    {
        end_t c2, s2;
        size_t big_n = 4u * 1024u * 1024u;
        uint8_t *big = (uint8_t *)malloc(big_n);
        uint8_t *fbig = (uint8_t *)malloc(CYB_HDR_LEN + big_n + CYB_TAG_LEN);
        int same = 0;
        for (i = 0; i < (int)big_n; i++) big[i] = (uint8_t)(i * 31 + 7);
        pair_make(&c2, &s2);
        flen = cyb_seal(&s2.s, CYB_T_RESP, big, big_n, fbig);
        ok("sealed 4 MB", flen == CYB_HDR_LEN + big_n + CYB_TAG_LEN);
        cyb_feed(&c2.s, fbig, flen);
        r = cyb_recv_next(&c2.s, &type, &pt, &ptlen);
        ok("received 4 MB", r == 1 && ptlen == big_n);
        if (r == 1) same = (memcmp(pt, big, big_n) == 0);
        ok("4 MB round-trips intact", same);
        cyb_session_free(&c2.s); cyb_session_free(&s2.s);
        free(big); free(fbig);
    }
    {
        end_t c2, s2;
        pair_make(&c2, &s2);
        ok("oversized seal refused",
           cyb_seal(&c2.s, CYB_T_RESP, (const uint8_t *)"x", CYB_MAX_PLAINTEXT + 1, fbuf) == 0);
        c2.s.tx_seq = 0xFFFFFFFFFFFFFFFFULL;
        ok("tx counter wrap refused (would reuse a nonce)",
           cyb_seal(&c2.s, CYB_T_CMD, (const uint8_t *)"x", 1, fbuf) == 0);
        cyb_session_free(&c2.s); cyb_session_free(&s2.s);
    }

    cyb_session_free(&cli.s);
    cyb_session_free(&srv.s);
    free(fbuf);

    printf("\n======================================================\n");
    printf(" passed: %d   failed: %d\n", g_pass, g_fail);
    printf("======================================================\n");
    return g_fail ? 1 : 0;
}
