/*
 * proto_emit.c — prints a deterministic CYB3 transcript (fixed keys) for
 * cybtest/proto_interop.py to re-derive with Python's `cryptography` library.
 * If the two agree, the C crypto and protocol are interoperable with a
 * completely independent implementation of the same RFCs.
 */

#include <stdio.h>
#include <string.h>

#include "../cybproto.h"

static const char *PSK_HEX =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
static const char *CLI_SEED_HEX =
    "1f1e1d1c1b1a19181716151413121110" "0f0e0d0c0b0a09080706050403020100";
static const char *SRV_SEED_HEX =
    "202122232425262728292a2b2c2d2e2f" "303132333435363738393a3b3c3d3e3f";

static void unhex(const char *h, uint8_t *o, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) { unsigned v; sscanf(h + i * 2, "%2x", &v); o[i] = (uint8_t)v; }
}

static void ph(const char *label, const uint8_t *b, size_t n)
{
    size_t i;
    printf("%s ", label);
    for (i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(void)
{
    uint8_t psk[32], auth[32];
    uint8_t cseed[32], sseed[32], cpriv[32], cpub[32], spriv[32], spub[32];
    uint8_t cnonce[16], snonce[16];
    uint8_t k_c2s[32], k_s2c[32], p_c2s[4], p_s2c[4], shared[32];
    cyb_session cli, srv;
    uint8_t hello[128], ack[128], cmd[256];
    size_t  n1, n2, n3;
    static const char *MSG = "id && uname -a";

    unhex(PSK_HEX, psk, 32);
    unhex(CLI_SEED_HEX, cseed, 32);
    unhex(SRV_SEED_HEX, sseed, 32);
    memset(cnonce, 0xA1, 16);
    memset(snonce, 0xB2, 16);

    cyb_derive_auth_key(auth, psk);
    cyb_x25519_keypair(cpriv, cpub, cseed);
    cyb_x25519_keypair(spriv, spub, sseed);

    n1 = cyb_build_hello(hello, sizeof(hello), 0, auth, cpub, cnonce, NULL, NULL);
    n2 = cyb_build_hello(ack,   sizeof(ack),   1, auth, spub, snonce, cpub, cnonce);
    cyb_derive_session(k_c2s, k_s2c, p_c2s, p_s2c, psk, cpriv, spub, cnonce, snonce, 0);
    cyb_x25519(shared, cpriv, spub);

    /* client */
    cyb_session_init(&cli);
    memcpy(cli.k_send, k_c2s, 32);  memcpy(cli.k_recv, k_s2c, 32);
    memcpy(cli.n_send, p_c2s, 4);   memcpy(cli.n_recv, p_s2c, 4);
    cli.established = 1;
    /* server */
    cyb_session_init(&srv);
    memcpy(srv.k_send, k_s2c, 32);  memcpy(srv.k_recv, k_c2s, 32);
    memcpy(srv.n_send, p_s2c, 4);   memcpy(srv.n_recv, p_c2s, 4);
    srv.established = 1;

    n3 = cyb_seal(&srv, CYB_T_CMD, (const uint8_t *)MSG, strlen(MSG), cmd);

    printf("psk %s\n", PSK_HEX);
    ph("cli_pub", cpub, 32);
    ph("cli_nonce", cnonce, 16);
    ph("srv_pub", spub, 32);
    ph("srv_nonce", snonce, 16);
    ph("auth_key", auth, 32);
    ph("k_c2s", k_c2s, 32);
    ph("k_s2c", k_s2c, 32);
    ph("pfx_c2s", p_c2s, 4);
    ph("pfx_s2c", p_s2c, 4);
    ph("shared", shared, 32);
    ph("hello", hello, n1);
    ph("helloack", ack, n2);
    ph("cmdframe", cmd, n3);
    printf("msg %s\n", MSG);

    return 0;
}
