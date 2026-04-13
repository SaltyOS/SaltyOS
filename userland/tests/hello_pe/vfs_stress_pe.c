/* Dedicated Win32 PE fixture for VFS stress tests.
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Keeps enough deterministic work to overlap parent-side VFS activity, while
 * avoiding heavy console/csrss churn so failures stay attributable to the
 * VFS/exec/load side of the system.
 */

typedef unsigned int DWORD;
typedef int BOOL;
typedef long long HANDLE;

#define TRUE  1
#define FALSE 0
#define STD_OUTPUT_HANDLE 0xFFFFFFF5u
#define ERROR_INVALID_HANDLE 6u
#define INVALID_HANDLE_VALUE ((HANDLE)-1)

__declspec(dllimport) HANDLE  GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) BOOL    WriteConsoleA(HANDLE hOut, const void *buf,
                                            DWORD nChars, DWORD *written,
                                            const void *reserved);
__declspec(dllimport) DWORD   GetCurrentProcessId(void);
__declspec(dllimport) DWORD   GetLastError(void);
__declspec(dllimport) void    SetLastError(DWORD dwErrCode);
__declspec(dllimport) void    ExitProcess(unsigned int uExitCode);

static void print(HANDLE h, const char *s) {
    DWORD len = 0;
    const char *p = s;
    while (*p++) len++;
    WriteConsoleA(h, s, len, (DWORD *)0, (DWORD *)0);
}

static void print_dec(HANDLE h, DWORD val) {
    char buf[12];
    int i = 0;
    int j;
    if (val == 0) {
        print(h, "0");
        return;
    }
    while (val > 0) {
        buf[i++] = (char)('0' + (val % 10));
        val /= 10;
    }
    for (j = 0; j < i / 2; j++) {
        char tmp = buf[j];
        buf[j] = buf[i - 1 - j];
        buf[i - 1 - j] = tmp;
    }
    buf[i] = 0;
    print(h, buf);
}

static void print_hex(HANDLE h, DWORD val) {
    char buf[11];
    int i;
    buf[0] = '0';
    buf[1] = 'x';
    for (i = 0; i < 8; i++) {
        unsigned int nibble = (val >> (28 - i * 4)) & 0xF;
        buf[2 + i] = nibble < 10 ? (char)('0' + nibble) : (char)('a' + nibble - 10);
    }
    buf[10] = 0;
    print(h, buf);
}

static DWORD mix_round(DWORD acc, DWORD x) {
    acc ^= x + 0x9e3779b9u + (acc << 6) + (acc >> 2);
    acc = (acc << 7) | (acc >> 25);
    return acc ^ 0x85ebca6bu;
}

void mainCRTStartup(void) {
    HANDLE stdout_h;
    DWORD pid;
    volatile DWORD checksum = 0;
    volatile DWORD rolling = 0x2468ace1u;
    DWORD i;

    stdout_h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (stdout_h == INVALID_HANDLE_VALUE) {
        ExitProcess(1);
    }

    print(stdout_h, "[VFS_STRESS_PE] start\n");

    pid = GetCurrentProcessId();
    print(stdout_h, "[VFS_STRESS_PE] PID=");
    print_dec(stdout_h, pid);
    print(stdout_h, "\n");

    for (i = 0; i < 32768; i++) {
        DWORD val = (i * 2654435761u) ^ pid;
        SetLastError(val);
        checksum ^= GetLastError();
        rolling = mix_round(rolling, val ^ checksum);
    }

    SetLastError(0);
    if (GetStdHandle(999) != INVALID_HANDLE_VALUE || GetLastError() != ERROR_INVALID_HANDLE) {
        ExitProcess(2);
    }

    for (i = 0; i < 32768; i++) {
        DWORD val = rolling ^ (i * 2246822519u) ^ pid;
        SetLastError(val);
        if (GetLastError() != val) {
            ExitProcess(3);
        }
        rolling = mix_round(rolling, val + checksum + i);
        if ((i & 4095u) == 0) {
            checksum ^= rolling ^ i;
        }
    }

    checksum ^= rolling;

    print(stdout_h, "[VFS_STRESS_PE] checksum=");
    print_hex(stdout_h, checksum);
    print(stdout_h, "\n");
    print(stdout_h, "[VFS_STRESS_PE] PASS\n");
    ExitProcess(0);
}
