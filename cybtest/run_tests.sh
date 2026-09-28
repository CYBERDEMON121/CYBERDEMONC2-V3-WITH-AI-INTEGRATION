#!/usr/bin/env bash
#
# run_tests.sh — full verification for the CYB3 crypto, protocol and implants.
#
#   ./cybtest/run_tests.sh
#
# Layers, cheapest first:
#   1. crypto vectors   RFC test vectors for every primitive
#   2. protocol        framing, handshake, replay and tamper handling
#   3. interop         C output vs Python `cryptography` (independent impl)
#   4. backend parity  `cryptography` path vs the pure-Python fallback
#   5. implant         a real compiled implant against a real Python listener
#   6. panel           the real Flask panel driving a real compiled implant
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
cd "$ROOT"

FAIL=0
run() {
    local name="$1"; shift
    echo
    echo "=============================================================="
    echo "  $name"
    echo "=============================================================="
    if "$@"; then
        echo "--> $name OK"
    else
        echo "--> $name FAILED"
        FAIL=1
    fi
}

echo "CYBERDEMONS C2 - verification suite"
echo "gcc:      $(gcc --version | head -1)"
echo "python:   $(python3 --version)"
echo "mingw:    $(x86_64-w64-mingw32-g++ --version 2>/dev/null | head -1 || echo 'not installed')"

# ---------------------------------------------------------------- 1. crypto
build_and_run_crypto() {
    gcc -O2 -Wall -Wextra -o /tmp/cyb_crypto_selftest cybtest/crypto_selftest.c || return 1
    /tmp/cyb_crypto_selftest
}

# ------------------------------------------------------------- 2. protocol
build_and_run_proto() {
    gcc -O2 -Wall -Wextra -o /tmp/cyb_proto_selftest cybtest/proto_selftest.c || return 1
    /tmp/cyb_proto_selftest
}

# --------------------------------------------------------------- 3. interop
build_and_run_interop() {
    python3 -c "import cryptography" 2>/dev/null || {
        echo "  (skipped: the 'cryptography' package is not installed)"
        return 0
    }
    # Build the emitter next to the script that runs it, so there is no copy
    # step that can fail silently.
    gcc -O2 -Wall -Wextra -I "$ROOT" -o "$HERE/proto_emit" "$HERE/proto_emit.c" || return 1
    ( cd "$HERE" && python3 proto_interop.py )
}

# ------------------------------------------------------- 4. backend parity
backend_parity() {
    python3 - <<'PY'
import os, sys
sys.path.insert(0, ".")
import cybc2

if not cybc2.HAVE_CRYPTOGRAPHY:
    print("  (skipped: only the pure-Python backend is available)")
    sys.exit(0)

fails = 0

# Force the pure-Python backend by hiding the accelerated one.
_fast = cybc2._CCP
cybc2._CCP = None
try:
    for i in range(48):
        key, nonce = os.urandom(32), os.urandom(12)
        aad = os.urandom(i % 48)
        pt = os.urandom((i * 41) % 3000)

        slow_ct, slow_tag = cybc2.aead_seal(key, nonce, aad, pt)
        fast_ct, fast_tag = cybc2._fast_seal(key, nonce, aad, pt)
        if slow_ct != fast_ct or slow_tag != fast_tag:
            print(f"  [FAIL] seal mismatch at i={i} (len={len(pt)}, aad={len(aad)})")
            fails += 1
            continue
        if cybc2.aead_open(key, nonce, aad, slow_ct, slow_tag) != pt:
            print(f"  [FAIL] pure-python open mismatch at i={i}")
            fails += 1

        # a single flipped bit anywhere must be rejected on the slow path
        if pt:
            bad = bytearray(slow_ct)
            bad[i % len(bad)] ^= 0x01
            try:
                cybc2.aead_open(key, nonce, aad, bytes(bad), slow_tag)
                print(f"  [FAIL] pure-python accepted a flipped ciphertext bit at i={i}")
                fails += 1
            except Exception:
                pass
        badtag = bytearray(slow_tag)
        badtag[3] ^= 0x80
        try:
            cybc2.aead_open(key, nonce, aad, slow_ct, bytes(badtag))
            print(f"  [FAIL] pure-python accepted a flipped tag bit at i={i}")
            fails += 1
        except Exception:
            pass
finally:
    cybc2._CCP = _fast

# X25519: the pure-Python ladder must agree with the library on the RFC vector.
RFC_A = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
RFC_B = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
WANT = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
got = cybc2._x25519_python(RFC_A, RFC_B).hex()
if got != WANT:
    print(f"  [FAIL] pure-python x25519 RFC 7748 vector: {got}")
    fails += 1

print(f"  [FAIL] {fails} mismatches" if fails
      else "  [PASS] both AEAD backends agree, and the pure-Python x25519 matches RFC 7748")
sys.exit(1 if fails else 0)
PY
}

# --------------------------------------------------------------- 5. implant
implant_e2e() {
    gcc -O2 -o /tmp/cyb_implant pay_linux.c -lX11 -lpthread -lcrypt -ldl -lm || return 1
    python3 cybtest/implant_test.py /tmp/cyb_implant
}

# ----------------------------------------------------------------- 6. panel
panel_e2e() {
    python3 cybtest/panel_test.py
}

# ------------------------------------------------------- payload build check
payload_builds() {
    local ok=1
    gcc -O2 -Wall -Wextra -o /tmp/cyb_pay_linux pay_linux.c \
        -lX11 -lpthread -lcrypt -ldl -lm || ok=0
    gcc -O2 -Wall -Wextra -DNO_X11 -o /tmp/cyb_pay_linux_nox11 pay_linux.c \
        -lpthread -lcrypt -ldl -lm || ok=0
    if command -v x86_64-w64-mingw32-g++ >/dev/null; then
        x86_64-w64-mingw32-windres resources.rc -o /tmp/cyb_res.o || ok=0
        x86_64-w64-mingw32-g++ -Wall -Wextra -o /tmp/cyb_pay.exe pay.cpp /tmp/cyb_res.o \
            -lws2_32 -liphlpapi -lcrypt32 -lpsapi -lgdi32 -luser32 -s -O2 -mwindows || ok=0
    fi
    [ "$ok" = 1 ] && echo "  [PASS] all payload variants build clean with -Wall -Wextra"
    return $((1 - ok))
}

run "payload build (gcc + mingw, -Wall -Wextra)"  payload_builds
run "crypto vectors (RFC 180-4/2104/4231/5869/8439/7748)" build_and_run_crypto
run "CYB3 protocol (framing, replay, tamper)"      build_and_run_proto
run "interop vs cryptography"                      build_and_run_interop
run "AEAD backend parity"                          backend_parity
run "implant end-to-end"                           implant_e2e
run "panel end-to-end"                             panel_e2e

echo
echo "=============================================================="
if [ "$FAIL" = 0 ]; then
    echo "  ALL SUITES PASSED"
else
    echo "  SOME SUITES FAILED"
fi
echo "=============================================================="
exit $FAIL
