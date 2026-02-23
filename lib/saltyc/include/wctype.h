/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __WCTYPE_H__
#define __WCTYPE_H__

typedef unsigned long wctype_t;
typedef unsigned long wctrans_t;
typedef unsigned int  wint_t;

extern int iswalpha(wint_t wc);
extern int iswdigit(wint_t wc);
extern int iswalnum(wint_t wc);
extern int iswspace(wint_t wc);
extern int iswupper(wint_t wc);
extern int iswlower(wint_t wc);
extern int iswprint(wint_t wc);
extern int iswcntrl(wint_t wc);
extern int iswpunct(wint_t wc);
extern int iswblank(wint_t wc);
extern int iswxdigit(wint_t wc);
extern int iswgraph(wint_t wc);

extern wint_t towupper(wint_t wc);
extern wint_t towlower(wint_t wc);

extern wctype_t  wctype(const char *name);
extern int       iswctype(wint_t wc, wctype_t desc);
extern wint_t    nextwctype(wint_t wc, wctype_t desc);
extern wctrans_t wctrans(const char *name);
extern wint_t    towctrans(wint_t wc, wctrans_t desc);

#endif /* __WCTYPE_H__ */
