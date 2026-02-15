/* SPDX-License-Identifier: GPL-2.0-only */
/* File tree stream — FreeBSD-compatible fts(3) ABI */
#ifndef __FTS_H__
#define __FTS_H__

#include <sys/types.h>
#include <sys/stat.h>

typedef struct _ftsent FTSENT;
typedef struct _fts FTS;

struct _fts {
    FTSENT  *fts_cur;       /* current node */
    FTSENT  *fts_child;     /* linked list of children */
    FTSENT **fts_array;     /* sort array */
    dev_t    fts_dev;       /* starting device # */
    char    *fts_path;      /* path for this descent */
    int      fts_rfd;       /* fd for root */
    size_t   fts_pathlen;   /* sizeof(path) */
    size_t   fts_nitems;    /* elements in sort array */
    int    (*fts_compar)(const FTSENT * const *, const FTSENT * const *);
    int      fts_options;   /* fts_open options, global flags */
    void    *fts_clientptr; /* private caller/library data */
};

struct _ftsent {
    FTSENT      *fts_cycle;     /* cycle node */
    FTSENT      *fts_parent;    /* parent directory */
    FTSENT      *fts_link;      /* next file in directory */
    long long    fts_number;    /* local numeric value */
    void        *fts_pointer;   /* local address value */
    char        *fts_accpath;   /* access path */
    char        *fts_path;      /* root path */
    int          fts_errno;     /* errno for this node */
    int          fts_symfd;     /* fd for symlink */
    size_t       fts_pathlen;   /* strlen(fts_path) */
    size_t       fts_namelen;   /* strlen(fts_name) */
    ino_t        fts_ino;       /* inode */
    dev_t        fts_dev;       /* device */
    nlink_t      fts_nlink;     /* link count */
    long         fts_level;     /* depth (-1 to N) */
    int          fts_info;      /* user status for FTSENT */
    unsigned int fts_flags;     /* private flags for FTSENT */
    int          fts_instr;     /* fts_set() instructions */
    struct stat *fts_statp;     /* stat(2) information */
    char        *fts_name;      /* file name */
    FTS         *fts_fts;       /* back pointer to stream */
};

/* fts_open options */
#define FTS_COMFOLLOW   0x001       /* follow command line symlinks */
#define FTS_LOGICAL     0x002       /* logical walk */
#define FTS_NOCHDIR     0x004       /* don't change directories */
#define FTS_NOSTAT      0x008       /* don't get stat info */
#define FTS_PHYSICAL    0x010       /* physical walk */
#define FTS_SEEDOT      0x020       /* return dot and dot-dot */
#define FTS_XDEV        0x040       /* don't cross devices */
#define FTS_WHITEOUT    0x080       /* return whiteout information */
#define FTS_OPTIONMASK  0x0ff       /* valid user option mask */
#define FTS_NAMEONLY    0x100       /* private: child names only */
#define FTS_STOP        0x200       /* private: unrecoverable error */

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

#define FTS_DONTCHDIR   0x01
#define FTS_SYMFOLLOW   0x02
#define FTS_ISW         0x04

#define FTS_ROOTPARENTLEVEL -1
#define FTS_ROOTLEVEL       0

/* fts_set instructions */
#define FTS_AGAIN       1           /* read node again */
#define FTS_FOLLOW      2           /* follow symbolic link */
#define FTS_NOINSTR     3           /* no instructions */
#define FTS_SKIP        4           /* discard node */

FTS    *fts_open(char * const *, int,
                 int (*)(const FTSENT * const *, const FTSENT * const *));
FTSENT *fts_read(FTS *);
FTSENT *fts_children(FTS *, int);
int     fts_set(FTS *, FTSENT *, int);
int     fts_close(FTS *);

#define fts_get_clientptr(fts) ((fts)->fts_clientptr)
#define fts_set_clientptr(fts, p) ((fts)->fts_clientptr = (p))
#define fts_get_stream(ftsent) ((ftsent)->fts_fts)

#endif /* __FTS_H__ */
