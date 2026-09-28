/*
 * cybbuf.h — growable output buffer for implant command results.
 * ---------------------------------------------------------------------------
 * The previous payloads accumulated output with
 *
 *     pos += snprintf(out + pos, sizeof(out) - pos, ...);
 *
 * which is unsafe: snprintf returns the length it *would* have written, so a
 * truncated result makes `pos` run past the end of the buffer and the
 * subsequent `out[pos] = 0` is a heap overflow.  This type removes that entire
 * class of bug by never trusting a return value.
 *
 * Hard cap: a runaway command cannot make the implant allocate without bound.
 */

#ifndef CYB_BUF_H
#define CYB_BUF_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cybcrypt.h"

#ifndef CYB_OB_MAX
#  define CYB_OB_MAX (16u * 1024u * 1024u)
#endif

typedef struct {
    char  *p;
    size_t len;
    size_t cap;
    int    oom;      /* sticky: allocation failed or the cap was hit */
} cyb_ob;

CYB_INLINE void ob_init(cyb_ob *b)
{
    b->p = NULL;
    b->len = 0;
    b->cap = 0;
    b->oom = 0;
}

CYB_INLINE void ob_free(cyb_ob *b)
{
    if (b->p) {
        cyb_secure_zero(b->p, b->cap);
        free(b->p);
    }
    ob_init(b);
}

CYB_INLINE void ob_reset(cyb_ob *b)
{
    if (b->p && b->cap) b->p[0] = 0;
    b->len = 0;
    b->oom = 0;
}

CYB_INLINE int ob_reserve(cyb_ob *b, size_t extra)
{
    size_t need, ncap;
    char  *np;

    if (b->oom) return -1;
    if (extra > CYB_OB_MAX || b->len > CYB_OB_MAX - extra - 1) {
        b->oom = 1;
        return -1;
    }
    need = b->len + extra + 1;
    if (need <= b->cap) return 0;

    ncap = b->cap ? b->cap : 4096;
    while (ncap < need) {
        if (ncap > CYB_OB_MAX) { ncap = CYB_OB_MAX; break; }
        ncap *= 2;
    }
    np = (char *)realloc(b->p, ncap);
    if (!np) { b->oom = 1; return -1; }
    b->p = np;
    b->cap = ncap;
    return 0;
}

CYB_INLINE void ob_add(cyb_ob *b, const void *data, size_t n)
{
    if (n == 0) { if (ob_reserve(b, 0) == 0 && b->p) b->p[b->len] = 0; return; }
    if (ob_reserve(b, n) != 0) return;
    memcpy(b->p + b->len, data, n);
    b->len += n;
    b->p[b->len] = 0;
}

CYB_INLINE void ob_puts(cyb_ob *b, const char *s)
{
    if (s) ob_add(b, s, strlen(s));
}

CYB_INLINE void ob_putc(cyb_ob *b, char c)
{
    ob_add(b, &c, 1);
}

CYB_INLINE void ob_repeat(cyb_ob *b, char c, size_t n)
{
    if (ob_reserve(b, n) != 0) return;
    memset(b->p + b->len, c, n);
    b->len += n;
    b->p[b->len] = 0;
}

/* printf into the buffer; the result is truncated rather than overflowing. */
CYB_INLINE void ob_printf(cyb_ob *b, const char *fmt, ...)
{
    va_list ap;
    int     n;
    size_t  avail;

    if (b->oom) return;
    if (!b->p && ob_reserve(b, 256) != 0) return;

    for (;;) {
        avail = b->cap - b->len;
        va_start(ap, fmt);
        n = vsnprintf(b->p + b->len, avail, fmt, ap);
        va_end(ap);
        if (n < 0) { b->oom = 1; return; }
        if ((size_t)n < avail) { b->len += (size_t)n; return; }
        if (ob_reserve(b, (size_t)n + 1) != 0) return;
    }
}

/* Hand the bytes to the transport.  NUL-terminated for convenience, but the
 * length is authoritative. */
CYB_INLINE const char *ob_data(cyb_ob *b, size_t *len)
{
    if (!b->p) {
        static const char empty[1] = { 0 };
        if (len) *len = 0;
        return empty;
    }
    if (len) *len = b->len;
    return b->p;
}

#endif /* CYB_BUF_H */
