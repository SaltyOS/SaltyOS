/* SPDX-License-Identifier: GPL-2.0-only */
/* File tree stream — BSD fts(3) interface */
#ifndef __FTS_H__
#define __FTS_H__

#include <sys/types.h>
#include <sys/stat.h>

typedef struct _ftsent {
    unsigned short  fts_info;       /* flags for FTSENT structure */
    char           *fts_accpath;    /* access path */
    char           *fts_path;       /* root path */
    unsigned short  fts_pathlen;    /* strlen(fts_path) */
    char           *fts_name;       /* filename */
    unsigned short  fts_namelen;    /* strlen(fts_name) */
    long            fts_level;      /* depth (-1 to N) */
    int             fts_errno;      /* file errno */
    long long       fts_number;     /* local numeric value */
    void           *fts_pointer;    /* local address value */
    struct _ftsent *fts_parent;     /* parent directory */
    struct _ftsent *fts_link;       /* next file structure */
    struct _ftsent *fts_cycle;      /* cycle structure */
    struct stat    *fts_statp;      /* stat(2) information */
} FTSENT;

typedef struct {
    FTSENT         *fts_cur;        /* current node */
    FTSENT         *fts_child;      /* linked list of children */
    FTSENT        **fts_array;      /* sort array */
    int             fts_nitems;     /* elements in array */
    int             fts_options;    /* fts_open options */
    char           *fts_path;      /* path buffer */
    int             fts_pathlen;   /* sizeof(path) */
    /* internal state */
    char          **fts_argv;       /* copy of argv */
    int             fts_argc;       /* number of root paths */
    int             fts_arg_idx;    /* current root index */
    int             fts_state;      /* internal state machine */
    dev_t           fts_dev;        /* starting device # */
    int           (*fts_compar)(const FTSENT **, const FTSENT **);
} FTS;

/* fts_open options */
#define FTS_COMFOLLOW   0x001       /* follow command line symlinks */
#define FTS_LOGICAL     0x002       /* logical walk */
#define FTS_NOCHDIR     0x004       /* don't change directories */
#define FTS_NOSTAT      0x008       /* don't get stat info */
#define FTS_PHYSICAL    0x010       /* physical walk */
#define FTS_SEEDOT      0x020       /* return dot and dot-dot */
#define FTS_XDEV        0x040       /* don't cross devices */

/* fts_info values */
#define FTS_D           1           /* preorder directory */
#define FTS_DC          2           /* directory that causes cycles */
#define FTS_DEFAULT     3           /* none of the above */
#define FTS_DNR         4           /* unreadable directory */
#define FTS_DOT         5           /* dot or dot-dot */
#define FTS_DP          6           /* postorder directory */
#define FTS_ERR         7           /* error; errno is set */
#define FTS_F           8           /* regular file */
#define FTS_INIT        9           /* initialized only */
#define FTS_NS         10           /* stat(2) failed */
#define FTS_NSOK       11           /* no stat(2) requested */
#define FTS_SL         12           /* symbolic link */
#define FTS_SLNONE     13           /* symbolic link without target */
#define FTS_W          14           /* whiteout object */

/* fts_set instructions */
#define FTS_AGAIN       1           /* read node again */
#define FTS_FOLLOW      2           /* follow symbolic link */
#define FTS_NOINSTR     3           /* no instructions */
#define FTS_SKIP        4           /* discard node */

FTS    *fts_open(char * const *, int, int (*)(const FTSENT **, const FTSENT **));
FTSENT *fts_read(FTS *);
FTSENT *fts_children(FTS *, int);
int     fts_set(FTS *, FTSENT *, int);
int     fts_close(FTS *);

#endif /* __FTS_H__ */
