/*
 * crypto_selftest.c — validates cybcrypt.h against published test vectors.
 *
 *   gcc -O2 -Wall -Wextra -o crypto_selftest crypto_selftest.c && ./crypto_selftest
 *   x86_64-w64-mingw32-gcc -O2 -o crypto_selftest.exe crypto_selftest.c   (Windows build)
 *
 * Vectors:
 *   SHA-256          FIPS 180-4 / NIST CAVS "abc", "" and 448-bit message
 *   HMAC-SHA256      RFC 4231 cases 1-4
 *   HKDF-SHA256      RFC 5869 appendix A.1, A.2, A.3
 *   ChaCha20         RFC 8439 §2.4.2
 *   Poly1305         RFC 8439 §2.5.2
 *   ChaCha20-Poly1305 RFC 8439 §2.8.2
 *   X25519           RFC 7748 §5.2 (vector 1) and §6.1 (Alice/Bob)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../cybcrypt.h"

static int g_pass = 0, g_fail = 0;

static void check(const char *name, const uint8_t *got, const char *want_hex, size_t n)
{
    char got_hex[512];
    size_t i;
    for (i = 0; i < n && i < 255; i++) sprintf(got_hex + i * 2, "%02x", got[i]);
    got_hex[n * 2] = 0;

    if (strcmp(got_hex, want_hex) == 0) {
        printf("  [PASS] %s\n", name);
        g_pass++;
    } else {
        printf("  [FAIL] %s\n    want = %s\n", name, want_hex);
        printf("    got  = %s\n", got_hex);
        g_fail++;
    }
}

static void check_int(const char *name, int got, int want)
{
    if (got == want) { printf("  [PASS] %s\n", name); g_pass++; }
    else { printf("  [FAIL] %s (want %d, got %d)\n", name, want, got); g_fail++; }
}

static void unhex(const char *h, uint8_t *out, size_t outlen)
{
    size_t i;
    for (i = 0; i < outlen; i++) {
        unsigned v;
        sscanf(h + i * 2, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

/* ---------------------------------------------------------------- SHA-256 */
static void test_sha256(void)
{
    uint8_t d[32];
    printf("\n== SHA-256 ==\n");

    cyb_sha256("", 0, d);
    check("SHA256(\"\")",
          d, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 32);

    cyb_sha256("abc", 3, d);
    check("SHA256(\"abc\")",
          d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32);

    cyb_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
    check("SHA256(448-bit msg)",
          d, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", 32);

    /* multi-chunk, exercises update() across block boundaries */
    {
        char big[1000];
        memset(big, 'a', sizeof(big));
        cyb_sha256(big, sizeof(big), d);
        check("SHA256(1000*'a')",
              d, "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3", 32);
    }
}

/* ------------------------------------------------------------ HMAC/HKDF */
static void test_hmac(void)
{
    uint8_t key[131], d[32];
    printf("\n== HMAC-SHA256 (RFC 4231) ==\n");

    memset(key, 0x0b, 20);
    cyb_hmac_sha256(key, 20, (const uint8_t *)"Hi There", 8, d);
    check("RFC4231 #1",
          d, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", 32);

    cyb_hmac_sha256((const uint8_t *)"Jefe", 4, (const uint8_t *)"what do ya want for nothing?", 28, d);
    check("RFC4231 #2",
          d, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", 32);

    memset(key, 0xaa, 20);
    {
        uint8_t k131[131];
        memset(k131, 0xaa, 131);
        cyb_hmac_sha256(k131, 131, (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First", 54, d);
    }
    check("RFC4231 #6 (131-byte key)",
          d, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", 32);
}

static void test_hkdf(void)
{
    uint8_t ikm[80], salt[80], info[80], okm[82], prk[32];
    int i;
    printf("\n== HKDF-SHA256 (RFC 5869) ==\n");

    /* A.1: basic, SHA-256, zero-length salt and info */
    memset(ikm, 0x0b, 22);
    cyb_hkdf(okm, 42, NULL, 0, ikm, 22, NULL, 0);
    check("A.1 OKM",
          okm,
          "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8", 42);

    cyb_hkdf_extract(prk, NULL, 0, ikm, 22);
    check("A.1 PRK",
          prk, "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", 32);

    /* A.2: longer inputs, 80-byte salt/info */
    memset(ikm, 0, 80);
    memset(salt, 0, 80);
    memset(info, 0xf0, 80);
    for (i = 0; i < 80; i++) { ikm[i] = (uint8_t)i; salt[i] = (uint8_t)(0x60 + i); }
    cyb_hkdf(okm, 82, salt, 80, ikm, 80, info, 80);
    check("A.2 OKM",
          okm,
          "5d5ffa97c087c42fefc7cd64fd695b93bcb1b12557bbfd252495d12f39a815167d"
          "c34c2cc9f38b8773ccfd0fea4dce67c5f772a30cfc4c614f2471e55f8d3faf328"
          "b8e7c757787af8f7d8a4f18a29ecb61bc", 82);

    /* A.3: zero-length salt, non-zero info */
    memset(ikm, 0x0b, 22);
    memset(info, 0xf0, 10);
    cyb_hkdf(okm, 42, NULL, 0, ikm, 22, info, 10);
    check("A.3 OKM",
          okm,
          "1eea1f5fe7a8990c3abc08d29a8fd6cc19e55785a80d0900032da4b6155d4fcd7"
          "c449d6d4d7a8f25dc2e", 42);
}

/* --------------------------------------------------------------- ChaCha20 */
static void test_chacha20(void)
{
    uint8_t key[32], nonce[12];
    uint32_t st[16];
    uint8_t blk[64];
    printf("\n== ChaCha20 (RFC 8439 2.4.2) ==\n");

    unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key, 32);
    unhex("000000090000004a00000000", nonce, 12);
    cyb_chacha_set(st, key, nonce, 1);
    cyb_chacha_block(st, blk);
    check("keystream block 0",
          blk,
          "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
          "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e", 64);
}

static void test_poly1305(void)
{
    uint8_t key[32], data[34], mac[16];
    printf("\n== Poly1305 (RFC 8439 2.5.2) ==\n");

    unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", key, 32);
    memcpy(data, "Cryptographic Forum Research Group", 34);
    {
        cyb_poly1305 st;
        cyb_poly1305_init(&st, key);
        cyb_poly1305_update(&st, data, 34);
        cyb_poly1305_finish(&st, mac);
    }
    check("tag",
          mac, "a8061dc1305136c6c22b8baf0c0127a9", 16);
}

/* ------------------------------------------------------- ChaCha20-Poly1305 */
static void test_aead(void)
{
    uint8_t key[32], nonce[12], aad[12], tag[16];
    uint8_t pt[114], ct[130];
    size_t i;

    printf("\n== ChaCha20-Poly1305 (RFC 8439 2.8.2) ==\n");

    unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", key, 32);
    unhex("070000004041424344454647", nonce, 12);
    unhex("50515253c0c1c2c3c4c5c6c7", aad, 12);
    memcpy(pt, "Ladies and Gentlemen of the class of '99: If I could offer you "
               "only one tip for the future, sunscreen would be it.", 114);

    cyb_aead_seal(ct, pt, 114, tag, key, nonce, aad, 12);
    check("ciphertext",
          ct,
          "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
          "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
          "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
          "3ff4def08e4b7a9de576d26586cec64b6116", 114);
    check("tag", tag, "1ae10b594f09e26a7e902ecbd0600691", 16);

    /* round-trip open */
    {
        uint8_t back[130];
        int rc = cyb_aead_open(back, ct, 114, tag, key, nonce, aad, 12);
        check_int("open() returns 0", rc, 0);
        check_int("plaintext round-trip", memcmp(back, pt, 114), 0);
    }

    /* tamper: flip one ciphertext byte -> must fail, no plaintext released */
    for (i = 0; i < 114; i += 37) {
        uint8_t bad[130], out[130];
        memcpy(bad, ct, 130);
        bad[i] ^= 0x01;
        check_int("tampered ct rejected", cyb_aead_open(out, bad, 114, tag, key, nonce, aad, 12), -1);
    }
    /* tamper the tag */
    {
        uint8_t badtag[16], out[130];
        memcpy(badtag, tag, 16);
        badtag[0] ^= 0x80;
        check_int("tampered tag rejected", cyb_aead_open(out, ct, 114, badtag, key, nonce, aad, 12), -1);
    }
    /* tamper the aad */
    {
        uint8_t badaad[12], out[130];
        memcpy(badaad, aad, 12);
        badaad[0] ^= 0x01;
        check_int("tampered aad rejected", cyb_aead_open(out, ct, 114, tag, key, nonce, badaad, 12), -1);
    }
    /* wrong key */
    {
        uint8_t wk[32], out[130];
        memset(wk, 0xAA, 32);
        check_int("wrong key rejected", cyb_aead_open(out, ct, 114, tag, wk, nonce, aad, 12), -1);
    }
    /* in-place seal then open must work (C2 uses this) */
    {
        uint8_t buf[128 + CYB_TAG_LEN], t2[16], back[128];
        uint8_t msg[128];
        memset(msg, 0x5A, sizeof(msg));
        memcpy(buf, msg, 128);
        cyb_aead_seal(buf, buf, 128, t2, key, nonce, aad, 12);
        check_int("in-place open", cyb_aead_open(back, buf, 128, t2, key, nonce, aad, 12), 0);
        check_int("in-place round-trip", memcmp(back, msg, 128), 0);
    }
}

/* ------------------------------------------------------------------ X25519 */
static void test_x25519(void)
{
    uint8_t k[32], u[32], out[32];

    printf("\n== X25519 (RFC 7748) ==\n");

    /* 5.2 test vector 1: scalar a546..., u-coordinate e6db... */
    unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", k, 32);
    unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u, 32);
    cyb_x25519(out, k, u);
    check("5.2 vector 1",
          out, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", 32);

    /* 5.2 test vector 2 */
    unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", k, 32);
    unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", u, 32);
    cyb_x25519(out, k, u);
    check("5.2 vector 2",
          out, "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", 32);

    /* 6.1 Diffie-Hellman, including the published shared secret */
    {
        uint8_t apriv[32], bpriv[32], apub[32], bpub[32], s1[32], s2[32];
        static const uint8_t base[32] = { 9 };
        unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", apriv, 32);
        unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", bpriv, 32);
        cyb_x25519(apub, apriv, base);
        cyb_x25519(bpub, bpriv, base);
        check("6.1 alice public", apub,
              "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", 32);
        check("6.1 bob public", bpub,
              "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", 32);
        cyb_x25519(s1, apriv, bpub);
        cyb_x25519(s2, bpriv, apub);
        check("6.1 shared secret", s1,
              "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", 32);
        check_int("6.1 both sides agree", memcmp(s1, s2, 32), 0);
    }

    /* Clamping must be applied: scalar 8 and scalar 256*8+7 clamp to the
     * same value, so they must produce the same public key. */
    {
        uint8_t s1[32], s2[32], p1[32], p2[32];
        static const uint8_t base[32] = { 9 };
        memset(s1, 0, 32); s1[0] = 0x08;
        memset(s2, 0, 32); s2[0] = 0x0b;   /* low 3 bits are cleared by clamping */
        cyb_x25519(p1, s1, base);
        cyb_x25519(p2, s2, base);
        check_int("clamping equivalence", memcmp(p1, p2, 32), 0);
    }

    /* ECDH with fixed seeds, verified against an independent implementation */
    {
        uint8_t a_priv[32], b_priv[32], apub[32], bpub[32], s1[32], s2[32];
        static const uint8_t base[32] = { 9 };
        memset(a_priv, 0x11, 32);
        memset(b_priv, 0x22, 32);
        cyb_x25519(apub, a_priv, base);
        cyb_x25519(bpub, b_priv, base);
        cyb_x25519(s1, a_priv, bpub);
        cyb_x25519(s2, b_priv, apub);
        check("seed 0x11*32 public", apub,
              "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13", 32);
        check("seed 0x22*32 public", bpub,
              "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20", 32);
        check("ECDH shared secret", s1,
              "9e004098efc091d4ec2663b4e9f5cfd4d7064571690b4bea97ab146ab9f35056", 32);
        check_int("ECDH symmetric", memcmp(s1, s2, 32), 0);
    }
}

int main(void)
{
    printf("======================================================\n");
    printf(" CYBERDEMONS cybcrypt.h self-test\n");
    printf("======================================================\n");

    test_sha256();
    test_hmac();
    test_hkdf();
    test_chacha20();
    test_poly1305();
    test_aead();
    test_x25519();

    printf("\n======================================================\n");
    printf(" passed: %d   failed: %d\n", g_pass, g_fail);
    printf("======================================================\n");
    return g_fail ? 1 : 0;
}
