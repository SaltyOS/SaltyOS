/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __TERMCAP_H__
#define __TERMCAP_H__

extern int   tgetent(char *bp, const char *name);
extern int   tgetnum(const char *id);
extern int   tgetflag(const char *id);
extern char *tgetstr(const char *id, char **area);
extern char *tgoto(const char *cm, int col, int row);
extern int   tputs(const char *str, int affcnt, int (*putc_fn)(int));

extern char *BC;
extern char *UP;
extern char  PC;

#endif /* __TERMCAP_H__ */
