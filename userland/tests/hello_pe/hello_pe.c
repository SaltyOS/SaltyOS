/* SaltyOS Win32 PE subsystem test program
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Exercises the full Win32 pipeline: PE loader -> kernel32.dll import
 * resolution -> Win32 API calls -> win32_csrss IPC -> console output.
 *
 * Entry point: mainCRTStartup (lld-link default, no CRT).
 * Imports: kernel32.dll only.
 */

typedef unsigned int DWORD;
typedef int BOOL;
typedef long long HANDLE;
typedef unsigned long long size_t;

#define TRUE  1
#define FALSE 0
#define STD_OUTPUT_HANDLE 0xFFFFFFF5u
#define STD_INPUT_HANDLE  0xFFFFFFF6u
#define ERROR_INVALID_HANDLE 6u
#define INVALID_HANDLE_VALUE ((HANDLE)-1)

/* kernel32.dll imports */
__declspec(dllimport) HANDLE  GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) BOOL    WriteConsoleA(HANDLE hOut, const void *buf,
                                            DWORD nChars, DWORD *written,
                                            const void *reserved);
__declspec(dllimport) DWORD   GetCurrentProcessId(void);
__declspec(dllimport) BOOL    GetConsoleMode(HANDLE hConsole, DWORD *lpMode);
__declspec(dllimport) BOOL    SetConsoleMode(HANDLE hConsole, DWORD dwMode);
__declspec(dllimport) DWORD   GetLastError(void);
__declspec(dllimport) void    SetLastError(DWORD dwErrCode);
__declspec(dllimport) void    ExitProcess(unsigned int uExitCode);

static void print(HANDLE h, const char *s) {
    DWORD len = 0;
    const char *p = s;
    while (*p++) len++;
    WriteConsoleA(h, s, len, (DWORD *)0, (DWORD *)0);
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

static void print_dec(HANDLE h, DWORD val) {
    char buf[12];
    int i = 0, j;
    if (val == 0) {
        print(h, "0");
        return;
    }
    while (val > 0) {
        buf[i++] = (char)('0' + val % 10);
        val /= 10;
    }
    /* reverse */
    for (j = 0; j < i / 2; j++) {
        char tmp = buf[j];
        buf[j] = buf[i - 1 - j];
        buf[i - 1 - j] = tmp;
    }
    buf[i] = 0;
    print(h, buf);
}

void mainCRTStartup(void) {
    HANDLE stdout_h;
    DWORD mode = 0;
    DWORD pid;
    int pass = 1;

    /* 1. GetStdHandle */
    stdout_h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (stdout_h == INVALID_HANDLE_VALUE) {
        ExitProcess(1);
    }

    print(stdout_h, "[HELLO_PE] Hello from Win32 PE!\n");

    /* 2. GetCurrentProcessId */
    pid = GetCurrentProcessId();
    print(stdout_h, "[HELLO_PE] PID=");
    print_dec(stdout_h, pid);
    print(stdout_h, "\n");

    /* 3. GetConsoleMode */
    if (GetConsoleMode(stdout_h, &mode)) {
        print(stdout_h, "[HELLO_PE] stdout mode: ");
        print_hex(stdout_h, mode);
        print(stdout_h, "\n");
    } else {
        print(stdout_h, "[HELLO_PE] FAIL GetConsoleMode\n");
        pass = 0;
    }

    /* 4. SetConsoleMode / round-trip */
    if (SetConsoleMode(stdout_h, mode)) {
        DWORD mode2 = 0;
        if (GetConsoleMode(stdout_h, &mode2) && mode2 == mode) {
            print(stdout_h, "[HELLO_PE] SetConsoleMode round-trip OK\n");
        } else {
            print(stdout_h, "[HELLO_PE] FAIL SetConsoleMode round-trip\n");
            pass = 0;
        }
    } else {
        print(stdout_h, "[HELLO_PE] FAIL SetConsoleMode\n");
        pass = 0;
    }

    /* 5. GetLastError / SetLastError */
    SetLastError(42);
    if (GetLastError() == 42) {
        print(stdout_h, "[HELLO_PE] LastError round-trip OK\n");
    } else {
        print(stdout_h, "[HELLO_PE] FAIL LastError\n");
        pass = 0;
    }

    /* 6. Invalid handle test */
    {
        SetLastError(0);
        HANDLE bad = GetStdHandle(999);
        if (bad == INVALID_HANDLE_VALUE && GetLastError() == ERROR_INVALID_HANDLE) {
            print(stdout_h, "[HELLO_PE] Invalid handle detection OK\n");
        } else {
            print(stdout_h, "[HELLO_PE] FAIL invalid handle\n");
            pass = 0;
        }
    }

    if (pass) {
        print(stdout_h, "[HELLO_PE] PASS\n");
    } else {
        print(stdout_h, "[HELLO_PE] FAIL\n");
    }

    ExitProcess(pass ? 0 : 1);
}
