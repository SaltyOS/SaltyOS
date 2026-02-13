/* FreeBSD compat — libxo text-mode stub for ported FreeBSD utilities */
/* xo_stub.c — Minimal libxo stub for SaltyOS (text display only)
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Implements a subset of FreeBSD's libxo sufficient for utilities
 * like wc that use xo_emit() for output. Only text display mode
 * is supported (no JSON/XML).
 *
 * Handle support: xo_create_to_file() stores a FILE* as the handle.
 * xo_emit_h() outputs to that FILE* instead of stdout when non-NULL.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <err.h>

/* The handle is just a FILE* cast to void* */

/*
 * xo_emit_core — extract printf formats from xo field specs and vfprintf.
 *
 * XO format: literal text mixed with {[role]:name[/printf-format]} fields.
 * For text display, we output literal text as-is and for fields that
 * have a /format, we output using that printf format with the corresponding
 * vararg. Fields without /format are skipped (they're structural-only).
 */
static int
xo_emit_core(FILE *fp, const char *fmt, va_list ap)
{
    char pfmt[2048];
    int pi = 0;
    const char *p = fmt;

    while (*p && pi < (int)sizeof(pfmt) - 2) {
        if (*p == '{') {
            p++; /* skip '{' */
            /* Find '/' and '}' */
            const char *slash = NULL;
            const char *end = p;
            while (*end && *end != '}') {
                if (*end == '/' && !slash)
                    slash = end;
                end++;
            }
            if (slash) {
                /* Copy printf format between '/' and '}' */
                const char *f = slash + 1;
                while (f < end && pi < (int)sizeof(pfmt) - 2)
                    pfmt[pi++] = *f++;
            }
            /* else: field without format, skip (no vararg consumed) */
            p = (*end == '}') ? end + 1 : end;
        } else {
            pfmt[pi++] = *p++;
        }
    }
    pfmt[pi] = '\0';

    return vfprintf(fp, pfmt, ap);
}

/* Structural functions — no-ops for text mode */
int xo_parse_args(int argc, char **argv) {
    (void)argv;
    return argc;
}

void xo_open_list(const char *name) { (void)name; }
void xo_close_list(const char *name) { (void)name; }
void xo_open_instance(const char *name) { (void)name; }
void xo_close_instance(const char *name) { (void)name; }
void xo_open_container(const char *name) { (void)name; }
void xo_close_container(const char *name) { (void)name; }
int xo_finish(void) { return fflush(stdout); }
void xo_set_flags(void *xop, int flags) { (void)xop; (void)flags; }
void xo_no_setlocale(void) {}
void xo_set_version(const char *ver) { (void)ver; }
void xo_set_program(const char *prog) { (void)prog; }

/* Handle-based structural functions — delegate to non-handle versions */
void xo_open_list_h(void *xop, const char *name)
{ (void)xop; xo_open_list(name); }
void xo_close_list_h(void *xop, const char *name)
{ (void)xop; xo_close_list(name); }
void xo_open_instance_h(void *xop, const char *name)
{ (void)xop; xo_open_instance(name); }
void xo_close_instance_h(void *xop, const char *name)
{ (void)xop; xo_close_instance(name); }
void xo_open_container_h(void *xop, const char *name)
{ (void)xop; xo_open_container(name); }
void xo_close_container_h(void *xop, const char *name)
{ (void)xop; xo_close_container(name); }

/* Handle management */
void *xo_create_to_file(FILE *fp, int style, int flags)
{
    (void)style;
    (void)flags;
    return (void *)fp;
}

void xo_destroy(void *xop)
{
    (void)xop;
}

int xo_finish_h(void *xop)
{
    if (xop != NULL)
        return fflush((FILE *)xop);
    return fflush(stdout);
}

/* xo_emit — output to stdout */
int xo_emit(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int ret = xo_emit_core(stdout, fmt, ap);
    va_end(ap);
    return ret;
}

/* xo_emit_h — output to handle's FILE* if non-NULL, else stdout */
int xo_emit_h(void *xop, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    FILE *fp = xop ? (FILE *)xop : stdout;
    int ret = xo_emit_core(fp, fmt, ap);
    va_end(ap);
    return ret;
}

/* xo_error — output to stderr */
void xo_error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

/* Error/warning wrappers — forward to standard err(3)/warn(3) functions */
void xo_err(int eval, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    verr(eval, fmt, ap);
    /* verr does not return */
    va_end(ap);
}

void xo_errx(int eval, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    verrx(eval, fmt, ap);
    va_end(ap);
}

void xo_warn(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vwarn(fmt, ap);
    va_end(ap);
}

void xo_warnx(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vwarnx(fmt, ap);
    va_end(ap);
}
