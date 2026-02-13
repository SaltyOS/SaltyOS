/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __LOCALE_H__
#define __LOCALE_H__

#define LC_CTYPE    0
#define LC_NUMERIC  1
#define LC_TIME     2
#define LC_COLLATE  3
#define LC_MONETARY 4
#define LC_MESSAGES 5
#define LC_ALL      6

struct lconv {
    char *decimal_point;
    char *thousands_sep;
    char *grouping;
    char *int_curr_symbol;
    char *currency_symbol;
    char *mon_decimal_point;
    char *mon_thousands_sep;
    char *mon_grouping;
    char *positive_sign;
    char *negative_sign;
    char  int_frac_digits;
    char  frac_digits;
    char  p_cs_precedes;
    char  p_sep_by_space;
    char  n_cs_precedes;
    char  n_sep_by_space;
    char  p_sign_posn;
    char  n_sign_posn;
};

extern char        *setlocale(int category, const char *locale);
extern struct lconv *localeconv(void);

/* gettext stubs */
extern char *textdomain(const char *domainname);
extern char *bindtextdomain(const char *domainname, const char *dirname);
extern char *gettext(const char *msgid);
extern char *dgettext(const char *domainname, const char *msgid);
extern char *dcgettext(const char *domainname, const char *msgid, int category);
extern char *ngettext(const char *msgid1, const char *msgid2, unsigned long n);
extern char *dngettext(const char *domainname, const char *msgid1,
                       const char *msgid2, unsigned long n);

#endif /* __LOCALE_H__ */
