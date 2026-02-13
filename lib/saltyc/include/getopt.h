/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __GETOPT_H__
#define __GETOPT_H__

extern char *optarg;
extern int   optind;
extern int   opterr;
extern int   optopt;

extern int getopt(int argc, char * const argv[], const char *optstring);

struct option {
    const char *name;
    int         has_arg;
    int        *flag;
    int         val;
};

#define no_argument       0
#define required_argument 1
#define optional_argument 2

extern int getopt_long(int argc, char * const argv[],
                       const char *optstring,
                       const struct option *longopts, int *longindex);
extern int getopt_long_only(int argc, char * const argv[],
                            const char *optstring,
                            const struct option *longopts, int *longindex);

#endif /* __GETOPT_H__ */
