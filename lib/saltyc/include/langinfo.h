/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __LANGINFO_H__
#define __LANGINFO_H__

typedef int nl_item;

#define CODESET     14
#define D_T_FMT     0
#define D_FMT       1
#define T_FMT       2
#define T_FMT_AMPM  3
#define AM_STR      4
#define PM_STR      5
#define DAY_1       6
#define DAY_2       7
#define DAY_3       8
#define DAY_4       9
#define DAY_5       10
#define DAY_6       11
#define DAY_7       12
#define ABDAY_1     13
#define MON_1       21
#define ABMON_1     33
#define RADIXCHAR   45
#define THOUSEP     46
#define YESEXPR     47
#define NOEXPR      48
#define CRNCYSTR    49
#define ERA         50

extern char *nl_langinfo(nl_item item);

#endif /* __LANGINFO_H__ */
