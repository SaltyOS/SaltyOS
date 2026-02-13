/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * getopt.c — POSIX getopt + GNU getopt_long for SaltyOS
 *
 * Implements POSIX.1-2008 getopt() and GNU getopt_long()/getopt_long_only().
 * Based on the POSIX specification with GNU extensions.
 */

#include <getopt.h>
#include <string.h>
#include <stdio.h>

char *optarg = NULL;
int   optind = 1;
int   opterr = 1;
int   optopt = '?';

/* Internal state */
static const char *nextchar = NULL;   /* next option char to process */
static int posixly_correct = 0;       /* stop at first non-option */
static int return_nonopts = 0;        /* return non-options as '\1' */

static void
permute(char *const argv[], int from, int to)
{
    char *tmp = argv[from];
    int i;
    for (i = from; i > to; i--)
        ((char **)argv)[i] = argv[i - 1];
    ((char **)argv)[to] = tmp;
}

/*
 * Parse optstring prefix characters:
 *   '+' → POSIXLY_CORRECT (stop at first non-option)
 *   '-' → return non-option args as '\1'
 *   ':' → return ':' instead of '?' for missing arg
 */
static const char *
parse_prefix(const char *optstring, int *colon_mode)
{
    posixly_correct = 0;
    return_nonopts = 0;
    *colon_mode = 0;

    while (*optstring) {
        if (*optstring == '+') {
            posixly_correct = 1;
            optstring++;
        } else if (*optstring == '-') {
            return_nonopts = 1;
            optstring++;
        } else if (*optstring == ':') {
            *colon_mode = 1;
            optstring++;
        } else {
            break;
        }
    }
    return optstring;
}

int
getopt(int argc, char * const argv[], const char *optstring)
{
    int colon_mode;
    const char *opts;
    const char *p;

    if (optind <= 0) {
        optind = 1;
        nextchar = NULL;
    }

    optarg = NULL;

    opts = parse_prefix(optstring, &colon_mode);

    /* If no more chars in current arg, advance to next */
    if (nextchar == NULL || *nextchar == '\0') {
    restart:
        if (optind >= argc)
            return -1;

        /* Check for "--" end-of-options marker */
        if (argv[optind][0] == '-' && argv[optind][1] == '-' &&
            argv[optind][2] == '\0') {
            optind++;
            return -1;
        }

        /* Not an option? */
        if (argv[optind][0] != '-' || argv[optind][1] == '\0') {
            if (posixly_correct)
                return -1;
            if (return_nonopts) {
                optarg = argv[optind++];
                return 1;  /* '\1' — non-option argument */
            }
            /* Default: permute non-options to end (simplified: stop) */
            return -1;
        }

        nextchar = &argv[optind][1];
    }

    /* Current option character */
    int c = *nextchar++;
    optopt = c;

    /* Look up in optstring */
    p = strchr(opts, c);
    if (p == NULL || c == ':') {
        if (opterr && !colon_mode)
            fprintf(stderr, "%s: invalid option -- '%c'\n",
                    argv[0] ? argv[0] : "", c);
        if (*nextchar == '\0') {
            optind++;
            nextchar = NULL;
        }
        return '?';
    }

    /* Does this option take an argument? */
    if (p[1] == ':') {
        if (p[2] == ':') {
            /* Optional argument (::) — must be in same argv element */
            if (*nextchar != '\0') {
                optarg = (char *)nextchar;
                nextchar = NULL;
            } else {
                optarg = NULL;
            }
            optind++;
            nextchar = NULL;
        } else {
            /* Required argument */
            if (*nextchar != '\0') {
                optarg = (char *)nextchar;
                nextchar = NULL;
                optind++;
            } else if (optind + 1 < argc) {
                optind++;
                optarg = argv[optind];
                optind++;
            } else {
                /* Missing argument */
                optind++;
                nextchar = NULL;
                if (colon_mode) return ':';
                if (opterr)
                    fprintf(stderr,
                            "%s: option requires an argument -- '%c'\n",
                            argv[0] ? argv[0] : "", c);
                return '?';
            }
        }
    } else {
        /* No argument */
        if (*nextchar == '\0') {
            optind++;
            nextchar = NULL;
        }
    }

    return c;
}

/*
 * Match a long option name. Returns index into longopts or -1.
 * Sets *exact to 1 if exact match, 0 if prefix match.
 * Sets *ambig to 1 if ambiguous prefix match.
 */
static int
match_long(const char *arg, const struct option *longopts,
           int *exact, int *ambig)
{
    size_t arglen;
    int match = -1;
    int nmatches = 0;
    int i;
    const char *eq;

    *exact = 0;
    *ambig = 0;

    eq = strchr(arg, '=');
    arglen = eq ? (size_t)(eq - arg) : strlen(arg);

    for (i = 0; longopts[i].name != NULL; i++) {
        if (strncmp(arg, longopts[i].name, arglen) == 0) {
            if (strlen(longopts[i].name) == arglen) {
                /* Exact match */
                *exact = 1;
                return i;
            }
            /* Prefix match */
            match = i;
            nmatches++;
        }
    }

    if (nmatches == 1)
        return match;
    if (nmatches > 1)
        *ambig = 1;
    return -1;
}

static int
getopt_long_internal(int argc, char * const argv[],
                     const char *optstring,
                     const struct option *longopts, int *longindex,
                     int long_only)
{
    int colon_mode;
    const char *opts;
    int exact, ambig;
    int match;

    if (optind <= 0) {
        optind = 1;
        nextchar = NULL;
    }

    optarg = NULL;

    opts = parse_prefix(optstring, &colon_mode);

    /* If no more chars in current arg, advance */
    if (nextchar == NULL || *nextchar == '\0') {
        if (optind >= argc)
            return -1;

        /* "--" end marker */
        if (argv[optind][0] == '-' && argv[optind][1] == '-' &&
            argv[optind][2] == '\0') {
            optind++;
            return -1;
        }

        /* Not an option? */
        if (argv[optind][0] != '-' || argv[optind][1] == '\0') {
            if (posixly_correct)
                return -1;
            if (return_nonopts) {
                optarg = argv[optind++];
                return 1;
            }
            return -1;
        }

        nextchar = NULL;

        /* Try long option first: "--foo" or (long_only) "-foo" */
        if (longopts != NULL) {
            int is_long = (argv[optind][0] == '-' && argv[optind][1] == '-');
            int try_long = is_long ||
                          (long_only && argv[optind][0] == '-' &&
                           argv[optind][2] != '\0');

            if (try_long) {
                const char *longarg = argv[optind] + (is_long ? 2 : 1);
                match = match_long(longarg, longopts, &exact, &ambig);

                if (ambig) {
                    if (opterr)
                        fprintf(stderr,
                                "%s: option '%s' is ambiguous\n",
                                argv[0] ? argv[0] : "", argv[optind]);
                    optind++;
                    return '?';
                }

                if (match >= 0) {
                    const struct option *o = &longopts[match];
                    const char *eq = strchr(longarg, '=');

                    if (longindex)
                        *longindex = match;

                    if (o->has_arg == no_argument) {
                        if (eq) {
                            if (opterr)
                                fprintf(stderr,
                                    "%s: option '--%s' doesn't allow "
                                    "an argument\n",
                                    argv[0] ? argv[0] : "", o->name);
                            optind++;
                            return '?';
                        }
                        optind++;
                    } else if (o->has_arg == required_argument) {
                        if (eq) {
                            optarg = (char *)(eq + 1);
                            optind++;
                        } else if (optind + 1 < argc) {
                            optind++;
                            optarg = argv[optind];
                            optind++;
                        } else {
                            if (opterr)
                                fprintf(stderr,
                                    "%s: option '--%s' requires an "
                                    "argument\n",
                                    argv[0] ? argv[0] : "", o->name);
                            optind++;
                            return colon_mode ? ':' : '?';
                        }
                    } else { /* optional_argument */
                        if (eq) {
                            optarg = (char *)(eq + 1);
                        }
                        optind++;
                    }

                    if (o->flag) {
                        *o->flag = o->val;
                        return 0;
                    }
                    return o->val;
                }

                /* No long match for "--xxx": error */
                if (is_long) {
                    if (opterr)
                        fprintf(stderr,
                                "%s: unrecognized option '%s'\n",
                                argv[0] ? argv[0] : "", argv[optind]);
                    optind++;
                    return '?';
                }
                /* long_only with no match: fall through to short opt */
            }
        }

        /* Set up for short option processing */
        nextchar = &argv[optind][1];
    }

    /* Short option processing — delegate to getopt logic */
    {
        int c = *nextchar++;
        const char *p;

        optopt = c;
        p = strchr(opts, c);
        if (p == NULL || c == ':') {
            if (opterr && !colon_mode)
                fprintf(stderr, "%s: invalid option -- '%c'\n",
                        argv[0] ? argv[0] : "", c);
            if (*nextchar == '\0') {
                optind++;
                nextchar = NULL;
            }
            return '?';
        }

        if (p[1] == ':') {
            if (p[2] == ':') {
                /* Optional argument */
                if (*nextchar != '\0') {
                    optarg = (char *)nextchar;
                    nextchar = NULL;
                } else {
                    optarg = NULL;
                }
                optind++;
                nextchar = NULL;
            } else {
                /* Required argument */
                if (*nextchar != '\0') {
                    optarg = (char *)nextchar;
                    nextchar = NULL;
                    optind++;
                } else if (optind + 1 < argc) {
                    optind++;
                    optarg = argv[optind];
                    optind++;
                } else {
                    optind++;
                    nextchar = NULL;
                    if (colon_mode) return ':';
                    if (opterr)
                        fprintf(stderr,
                            "%s: option requires an argument -- '%c'\n",
                            argv[0] ? argv[0] : "", c);
                    return '?';
                }
            }
        } else {
            if (*nextchar == '\0') {
                optind++;
                nextchar = NULL;
            }
        }

        return c;
    }
}

int
getopt_long(int argc, char * const argv[],
            const char *optstring,
            const struct option *longopts, int *longindex)
{
    return getopt_long_internal(argc, argv, optstring, longopts, longindex, 0);
}

int
getopt_long_only(int argc, char * const argv[],
                 const char *optstring,
                 const struct option *longopts, int *longindex)
{
    return getopt_long_internal(argc, argv, optstring, longopts, longindex, 1);
}
