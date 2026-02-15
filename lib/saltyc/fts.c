/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * fts.c — Minimal BSD fts(3) file tree stream for SaltyOS
 *
 * Simplified single-pass traversal with NOCHDIR behavior.
 * Sufficient for ls, cp -r, rm -r, chmod -R, find, etc.
 */

#include <fts.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

/* Internal traversal states */
#define STATE_ROOTS     0   /* returning root entries from argv */
#define STATE_CHILDREN  1   /* descending into directory children */
#define STATE_POSTORDER 2   /* returning FTS_DP for completed directory */
#define STATE_DONE      3   /* traversal finished */

/* Maximum path length we support */
#define FTS_MAXPATH 4096

typedef struct {
    char **argv;            /* owned argv copy */
    int argc;               /* number of roots */
    int arg_idx;            /* current root index */
    int state;              /* traversal state */
} FTS_PRIV;

/* Saved comparator for qsort wrapper (single-threaded, no reentrancy issue) */
static int (*fts_saved_compar)(const FTSENT * const *, const FTSENT * const *);

static FTS_PRIV *fts_priv(FTS *sp)
{
    return (FTS_PRIV *)sp->fts_clientptr;
}

static int fts_qsort_wrapper(const void *a, const void *b)
{
    return fts_saved_compar((const FTSENT * const *)a,
                            (const FTSENT * const *)b);
}

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

/*
 * Allocate an FTSENT with stat buffer, path string, and name string
 * packed into a single allocation.
 */
static FTSENT *fts_alloc(FTS *sp, const char *name, size_t namelen,
                         const char *path, size_t pathlen)
{
    size_t total = sizeof(FTSENT) + sizeof(struct stat)
                   + pathlen + 1 + namelen + 1;
    FTSENT *p = calloc(1, total);
    if (!p)
        return NULL;

    p->fts_statp = (struct stat *)((char *)p + sizeof(FTSENT));
    p->fts_path  = (char *)p->fts_statp + sizeof(struct stat);
    memcpy(p->fts_path, path, pathlen);
    p->fts_path[pathlen] = '\0';
    p->fts_pathlen = pathlen;

    p->fts_name = p->fts_path + pathlen + 1;
    memcpy(p->fts_name, name, namelen);
    p->fts_name[namelen] = '\0';
    p->fts_namelen = namelen;

    /* NOCHDIR mode: access path is the full path */
    p->fts_accpath = p->fts_path;
    p->fts_info = FTS_INIT;
    p->fts_flags = 0;
    p->fts_instr = FTS_NOINSTR;
    p->fts_link = NULL;
    p->fts_parent = NULL;
    p->fts_cycle = NULL;
    p->fts_number = 0;
    p->fts_pointer = NULL;
    p->fts_errno = 0;
    p->fts_symfd = -1;
    p->fts_ino = 0;
    p->fts_dev = 0;
    p->fts_nlink = 0;
    p->fts_fts = sp;

    (void)sp;
    return p;
}

/*
 * Free a linked list of FTSENT nodes (following fts_link).
 */
static void fts_free_list(FTSENT *head)
{
    while (head) {
        FTSENT *next = head->fts_link;
        free(head);
        head = next;
    }
}

/*
 * Extract the basename from a path string.
 * Returns pointer into the path buffer (does not allocate).
 */
static const char *fts_basename(const char *path)
{
    const char *base = strrchr(path, '/');
    return base ? base + 1 : path;
}

/*
 * Build a child path: parent/name. Writes into buf[bufsz].
 * Returns length on success, 0 on overflow.
 */
static size_t fts_build_path(char *buf, size_t bufsz,
                             const char *parent, size_t plen,
                             const char *name, size_t nlen)
{
    int need_sep = (plen > 0 && parent[plen - 1] != '/');
    size_t total = plen + (need_sep ? 1 : 0) + nlen;

    if (total >= bufsz)
        return 0;

    memcpy(buf, parent, plen);
    if (need_sep)
        buf[plen++] = '/';
    memcpy(buf + plen, name, nlen);
    buf[plen + nlen] = '\0';
    return plen + nlen;
}

/*
 * Perform stat or lstat on an entry, set fts_info accordingly.
 * Returns 0 on success, -1 on stat failure (fts_info set to FTS_NS).
 */
static int fts_stat_entry(FTS *sp, FTSENT *ent)
{
    int opts = sp->fts_options;
    int rc;

    if ((opts & FTS_LOGICAL)
        || ((opts & FTS_COMFOLLOW) && ent->fts_level == FTS_ROOTLEVEL)) {
        rc = stat(ent->fts_path, ent->fts_statp);
    } else {
        /* FTS_PHYSICAL: use lstat to not follow symlinks */
        rc = lstat(ent->fts_path, ent->fts_statp);
    }

    if (rc != 0) {
        ent->fts_errno = errno;
        ent->fts_info = FTS_NS;
        return -1;
    }

    ent->fts_ino = ent->fts_statp->st_ino;
    ent->fts_dev = ent->fts_statp->st_dev;
    ent->fts_nlink = ent->fts_statp->st_nlink;

    unsigned int mode = ent->fts_statp->st_mode;

    if (S_ISDIR(mode)) {
        ent->fts_info = FTS_D;
    } else if (S_ISREG(mode)) {
        ent->fts_info = FTS_F;
    } else if (S_ISLNK(mode)) {
        /*
         * For FTS_PHYSICAL we got lstat, so S_ISLNK is possible.
         * Check if the target exists; if not, FTS_SLNONE.
         */
        struct stat target;
        if (stat(ent->fts_path, &target) != 0) {
            ent->fts_info = FTS_SLNONE;
        } else {
            ent->fts_info = FTS_SL;
        }
    } else {
        ent->fts_info = FTS_DEFAULT;
    }

    return 0;
}

/*
 * Read directory contents and build a linked list of child FTSENT nodes.
 * Returns the head of the list, or NULL on error/empty.
 */
static FTSENT *fts_build_children(FTS *sp, FTSENT *parent, int nameonly)
{
    DIR *dirp = opendir(parent->fts_path);
    if (!dirp) {
        parent->fts_info = FTS_DNR;
        parent->fts_errno = errno;
        return NULL;
    }

    char pathbuf[FTS_MAXPATH];
    FTSENT *head = NULL;
    FTSENT *tail = NULL;
    struct dirent *de;

    while ((de = readdir(dirp)) != NULL) {
        /* Skip . and .. unless FTS_SEEDOT is set */
        if (de->d_name[0] == '.') {
            if (de->d_name[1] == '\0')
                goto skip_dot;
            if (de->d_name[1] == '.' && de->d_name[2] == '\0')
                goto skip_dot;
        }
        goto not_dot;

    skip_dot:
        if (!(sp->fts_options & FTS_SEEDOT))
            continue;
        /* Fall through: include dot entry */

    not_dot:;
        size_t nlen = strlen(de->d_name);
        size_t plen = fts_build_path(pathbuf, sizeof(pathbuf),
                                     parent->fts_path,
                                     parent->fts_pathlen,
                                     de->d_name, nlen);
        if (plen == 0)
            continue; /* path too long, skip */

        FTSENT *child = fts_alloc(sp, de->d_name, nlen, pathbuf, plen);
        if (!child)
            continue; /* allocation failure, skip entry */

        child->fts_level = parent->fts_level + 1;
        child->fts_parent = parent;

        if (nameonly) {
            child->fts_info = FTS_NSOK;
        } else {
            fts_stat_entry(sp, child);
        }

        /* Check FTS_XDEV: skip entries on different device */
        if (!nameonly && (sp->fts_options & FTS_XDEV) && child->fts_info != FTS_NS
            && child->fts_info != FTS_NSOK) {
            if (child->fts_statp->st_dev != sp->fts_dev) {
                free(child);
                continue;
            }
        }

        /* Append to list */
        child->fts_link = NULL;
        if (!head) {
            head = child;
            tail = child;
        } else {
            tail->fts_link = child;
            tail = child;
        }
    }

    closedir(dirp);

    /* Sort children if a comparator was provided */
    if (head && sp->fts_compar) {
        /* Count entries */
        int n = 0;
        for (FTSENT *p = head; p; p = p->fts_link)
            n++;

        if (n > 1) {
            FTSENT **arr = malloc((size_t)n * sizeof(FTSENT *));
            if (arr) {
                int i = 0;
                for (FTSENT *p = head; p; p = p->fts_link)
                    arr[i++] = p;

                fts_saved_compar = sp->fts_compar;
                qsort(arr, (size_t)n, sizeof(FTSENT *), fts_qsort_wrapper);

                /* Rebuild linked list in sorted order */
                for (i = 0; i < n - 1; i++)
                    arr[i]->fts_link = arr[i + 1];
                arr[n - 1]->fts_link = NULL;
                head = arr[0];

                free(arr);
            }
        }
    }

    return head;
}

/*
 * Build an FTSENT list for the original argv root paths.
 * Used by callers that query fts_children() before the first fts_read().
 */
static FTSENT *fts_build_roots(FTS *sp, int nameonly)
{
    FTS_PRIV *priv = fts_priv(sp);
    if (!priv)
        return NULL;

    FTSENT *head = NULL;
    FTSENT *tail = NULL;

    for (int i = 0; i < priv->argc; i++) {
        const char *root = priv->argv[i];
        size_t rlen = strlen(root);
        while (rlen > 1 && root[rlen - 1] == '/')
            rlen--;

        const char *name = fts_basename(root);
        size_t nlen = strlen(name);
        FTSENT *ent = fts_alloc(sp, name, nlen, root, rlen);
        if (!ent)
            continue;

        ent->fts_level = FTS_ROOTLEVEL;
        ent->fts_parent = NULL;

        if (nameonly) {
            ent->fts_info = FTS_NSOK;
        } else {
            fts_stat_entry(sp, ent);
        }

        ent->fts_link = NULL;
        if (!head) {
            head = ent;
            tail = ent;
        } else {
            tail->fts_link = ent;
            tail = ent;
        }
    }

    if (head && sp->fts_compar) {
        int n = 0;
        for (FTSENT *p = head; p; p = p->fts_link)
            n++;

        if (n > 1) {
            FTSENT **arr = malloc((size_t)n * sizeof(FTSENT *));
            if (arr) {
                int i = 0;
                for (FTSENT *p = head; p; p = p->fts_link)
                    arr[i++] = p;

                fts_saved_compar = sp->fts_compar;
                qsort(arr, (size_t)n, sizeof(FTSENT *), fts_qsort_wrapper);

                for (i = 0; i < n - 1; i++)
                    arr[i]->fts_link = arr[i + 1];
                arr[n - 1]->fts_link = NULL;
                head = arr[0];

                free(arr);
            }
        }
    }

    return head;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

FTS *fts_open(char * const *argv, int options,
              int (*compar)(const FTSENT * const *,
                            const FTSENT * const *))
{
    if (!argv || !*argv) {
        errno = EINVAL;
        return NULL;
    }

    FTS *sp = calloc(1, sizeof(FTS));
    if (!sp)
        return NULL;
    FTS_PRIV *priv = calloc(1, sizeof(FTS_PRIV));
    if (!priv) {
        free(sp);
        return NULL;
    }

    sp->fts_options = options | FTS_NOCHDIR; /* always nochdir */
    sp->fts_compar = compar;
    sp->fts_clientptr = priv;
    sp->fts_rfd = -1;

    /* Count argv entries */
    int argc = 0;
    for (char * const *p = argv; *p; p++)
        argc++;

    if (argc == 0) {
        free(priv);
        free(sp);
        errno = EINVAL;
        return NULL;
    }

    /* Copy argv */
    priv->argv = malloc(((size_t)argc + 1) * sizeof(char *));
    if (!priv->argv) {
        free(priv);
        free(sp);
        return NULL;
    }
    for (int i = 0; i < argc; i++) {
        priv->argv[i] = strdup(argv[i]);
        if (!priv->argv[i]) {
            for (int j = 0; j < i; j++)
                free(priv->argv[j]);
            free(priv->argv);
            free(priv);
            free(sp);
            return NULL;
        }
    }
    priv->argv[argc] = NULL;
    priv->argc = argc;
    priv->arg_idx = 0;
    priv->state = STATE_ROOTS;
    sp->fts_cur = NULL;
    sp->fts_child = NULL;
    sp->fts_array = NULL;
    sp->fts_nitems = 0;
    sp->fts_dev = 0;
    sp->fts_path = NULL;
    sp->fts_pathlen = 0;

    return sp;
}

FTSENT *fts_read(FTS *sp)
{
    if (!sp) {
        errno = EINVAL;
        return NULL;
    }
    FTS_PRIV *priv = fts_priv(sp);
    if (!priv) {
        errno = EINVAL;
        return NULL;
    }

    for (;;) {
        switch (priv->state) {

        case STATE_ROOTS: {
            /* Return root entries one at a time from argv */
            if (priv->arg_idx >= priv->argc) {
                priv->state = STATE_DONE;
                return NULL;
            }

            char *root = priv->argv[priv->arg_idx++];
            size_t rlen = strlen(root);

            /* Strip trailing slashes for consistent paths */
            while (rlen > 1 && root[rlen - 1] == '/')
                rlen--;

            const char *name = fts_basename(root);
            size_t nlen = strlen(name);

            FTSENT *ent = fts_alloc(sp, name, nlen, root, rlen);
            if (!ent) {
                errno = ENOMEM;
                return NULL;
            }

            ent->fts_level = 0;
            ent->fts_parent = NULL;

            fts_stat_entry(sp, ent);

            /* Record starting device for FTS_XDEV */
            if (priv->arg_idx == 1 && ent->fts_info != FTS_NS
                && ent->fts_info != FTS_NSOK) {
                sp->fts_dev = ent->fts_statp->st_dev;
            }

            sp->fts_cur = ent;

            /* If it is a directory, push to children state */
            if (ent->fts_info == FTS_D) {
                priv->state = STATE_CHILDREN;
                /* Build child list and chain onto entry */
                sp->fts_child = fts_build_children(sp, ent, 0);
            }
            /* If more roots remain and this isn't a directory, stay in ROOTS */

            return ent;
        }

        case STATE_CHILDREN: {
            /* Pop next child from the child list */
            if (sp->fts_child) {
                FTSENT *child = sp->fts_child;
                sp->fts_child = child->fts_link;
                child->fts_link = NULL;

                sp->fts_cur = child;

                if (child->fts_info == FTS_D) {
                    /*
                     * Push: save current child list on the parent's
                     * fts_link chain, then descend into this directory.
                     * We use the directory's fts_link to store the
                     * remaining siblings so we can resume after
                     * postorder.
                     */
                    child->fts_link = sp->fts_child;
                    sp->fts_child = fts_build_children(sp, child, 0);
                }

                return child;
            }

            /*
             * No more children — return postorder (FTS_DP) for the
             * current directory, then resume its parent's sibling list.
             */
            priv->state = STATE_POSTORDER;
            continue;
        }

        case STATE_POSTORDER: {
            /*
             * Walk up the tree returning FTS_DP entries for each
             * completed directory.
             */
            FTSENT *cur = sp->fts_cur;
            if (!cur) {
                priv->state = STATE_ROOTS;
                continue;
            }

            /*
             * Find the directory that just finished. Walk up through
             * parents to find the innermost directory that hasn't
             * been postorder-returned yet.
             */
            FTSENT *dir = NULL;

            /* If cur itself is a preorder directory, return its DP */
            if (cur->fts_info == FTS_D) {
                dir = cur;
            } else {
                /* Walk up to find enclosing directory */
                dir = cur->fts_parent;
            }

            if (!dir) {
                /* Back at root level, continue to next root */
                priv->state = STATE_ROOTS;
                continue;
            }

            /* Create the postorder entry for this directory */
            FTSENT *dp = fts_alloc(sp, dir->fts_name, dir->fts_namelen,
                                   dir->fts_path, dir->fts_pathlen);
            if (!dp) {
                priv->state = STATE_ROOTS;
                continue;
            }
            dp->fts_info = FTS_DP;
            dp->fts_level = dir->fts_level;
            dp->fts_parent = dir->fts_parent;
            /* Copy stat data */
            memcpy(dp->fts_statp, dir->fts_statp, sizeof(struct stat));

            sp->fts_cur = dp;

            /* Resume siblings that were saved on the directory's fts_link */
            sp->fts_child = dir->fts_link;
            dir->fts_link = NULL;

            if (sp->fts_child) {
                priv->state = STATE_CHILDREN;
            } else if (dir->fts_parent) {
                /*
                 * The parent directory may also be done.
                 * Set cur to parent so next postorder iteration
                 * handles it.
                 */
                sp->fts_cur = dir->fts_parent;
                priv->state = STATE_POSTORDER;

                /* Only emit DP if the parent is itself a directory */
                if (dir->fts_parent->fts_info != FTS_D) {
                    priv->state = STATE_ROOTS;
                }
            } else {
                /* Root directory finished, return to roots */
                priv->state = STATE_ROOTS;
            }

            return dp;
        }

        case STATE_DONE:
        default:
            return NULL;
        }
    }
}

FTSENT *fts_children(FTS *sp, int instr)
{
    if (!sp) {
        errno = EINVAL;
        return NULL;
    }
    FTS_PRIV *priv = fts_priv(sp);
    if (!priv) {
        errno = EINVAL;
        return NULL;
    }

    if (sp->fts_cur == NULL) {
        /*
         * BSD fts allows querying children right after fts_open():
         * this returns the root argument list.
         */
        if (priv->arg_idx == 0 && priv->state == STATE_ROOTS)
            return fts_build_roots(sp, (instr & FTS_NAMEONLY) != 0);
        return NULL;
    }

    FTSENT *cur = sp->fts_cur;

    /* Only meaningful for directories in preorder */
    if (cur->fts_info != FTS_D)
        return NULL;

    /*
     * Build a fresh child list. This is separate from the traversal
     * child list — callers use fts_children() to peek at children
     * without advancing the traversal.
     */
    return fts_build_children(sp, cur, (instr & FTS_NAMEONLY) != 0);
}

int fts_set(FTS *sp, FTSENT *ent, int instr)
{
    if (!sp || !ent) {
        errno = EINVAL;
        return -1;
    }

    switch (instr) {
    case FTS_SKIP:
        /*
         * Mark this entry to be skipped. If it's a preorder directory,
         * discard its children so fts_read will move to postorder.
         */
        if (ent == sp->fts_cur && ent->fts_info == FTS_D) {
            fts_free_list(sp->fts_child);
            sp->fts_child = NULL;
        }
        break;

    case FTS_FOLLOW:
        /*
         * Re-stat this entry following symlinks.
         * Only meaningful for FTS_SL/FTS_SLNONE entries.
         */
        if (ent->fts_info == FTS_SL || ent->fts_info == FTS_SLNONE) {
            if (stat(ent->fts_path, ent->fts_statp) == 0) {
                if (S_ISDIR(ent->fts_statp->st_mode))
                    ent->fts_info = FTS_D;
                else if (S_ISREG(ent->fts_statp->st_mode))
                    ent->fts_info = FTS_F;
                else
                    ent->fts_info = FTS_DEFAULT;
            }
        }
        break;

    case FTS_AGAIN:
    case FTS_NOINSTR:
        /* No-op in this simplified implementation */
        break;

    default:
        errno = EINVAL;
        return -1;
    }

    return 0;
}

int fts_close(FTS *sp)
{
    if (!sp)
        return 0;
    FTS_PRIV *priv = fts_priv(sp);

    /* Free remaining child list */
    fts_free_list(sp->fts_child);
    sp->fts_child = NULL;

    /* Free current entry (if any) */
    /* Note: callers own previously returned entries; we only free
     * the internal current pointer. In a full implementation we'd
     * track all allocations, but for this minimal version callers
     * should not use entries after fts_close(). */

    /* Free private argv copy and state */
    if (priv) {
        if (priv->argv) {
            for (int i = 0; i < priv->argc; i++)
                free(priv->argv[i]);
            free(priv->argv);
        }
        free(priv);
    }

    /* Free sort array if allocated */
    if (sp->fts_array)
        free(sp->fts_array);

    /* Free path buffer if allocated */
    if (sp->fts_path)
        free(sp->fts_path);

    free(sp);
    return 0;
}
