/* SPDX-License-Identifier: GPL-2.0-only */
/* libxo text-mode stub declarations for SaltyOS */
#ifndef __LIBXO_XO_H__
#define __LIBXO_XO_H__

#include <stdio.h>

/* XO handle type */
typedef void *xo_handle_t;

/* Style constants (text mode only) */
#define XO_STYLE_TEXT   0
#define XO_STYLE_XML    1
#define XO_STYLE_JSON   2

/* Flag constants */
#define XOF_WARN        0x0001
#define XOF_XPATH       0x0002
#define XOF_INFO        0x0004
#define XOF_DTRT        0x0008
#define XOF_KEYS        0x0010
#define XOF_UNITS       0x0020
#define XOF_FLUSH       0x0040
#define XOF_COLUMNS     0x0080

/* Core emit functions */
int xo_emit(const char *fmt, ...);
int xo_emit_h(xo_handle_t *xop, const char *fmt, ...);

/* Handle management */
xo_handle_t *xo_create_to_file(FILE *fp, int style, int flags);
void xo_destroy(xo_handle_t *xop);
int xo_finish(void);
int xo_finish_h(xo_handle_t *xop);

/* Structural functions */
int xo_parse_args(int argc, char **argv);
void xo_open_list(const char *name);
void xo_close_list(const char *name);
void xo_open_instance(const char *name);
void xo_close_instance(const char *name);
void xo_open_container(const char *name);
void xo_close_container(const char *name);

/* Handle-based structural functions */
void xo_open_list_h(xo_handle_t *xop, const char *name);
void xo_close_list_h(xo_handle_t *xop, const char *name);
void xo_open_instance_h(xo_handle_t *xop, const char *name);
void xo_close_instance_h(xo_handle_t *xop, const char *name);
void xo_open_container_h(xo_handle_t *xop, const char *name);
void xo_close_container_h(xo_handle_t *xop, const char *name);

/* Configuration */
void xo_set_flags(xo_handle_t *xop, int flags);
void xo_no_setlocale(void);
void xo_set_version(const char *ver);
void xo_set_program(const char *prog);

/* Error/warning wrappers */
void xo_err(int eval, const char *fmt, ...) __attribute__((noreturn));
void xo_errx(int eval, const char *fmt, ...) __attribute__((noreturn));
void xo_warn(const char *fmt, ...);
void xo_warnx(const char *fmt, ...);
void xo_error(const char *fmt, ...);

#endif /* __LIBXO_XO_H__ */
