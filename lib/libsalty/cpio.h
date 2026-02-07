/* CPIO newc Archive Parser
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Minimal read-only parser for CPIO newc format archives.
 * Userland port of kernel/src/cpio.rs.
 */

#ifndef LIBSALTY_CPIO_H
#define LIBSALTY_CPIO_H

#include <stdint.h>
#include <stddef.h>

/* CPIO newc header size: 6 magic + 13*8 hex fields = 110 bytes */
#define CPIO_HEADER_SIZE  110

/* A file entry found in a CPIO archive */
struct cpio_entry {
    const char *name;
    size_t      name_len;
    const uint8_t *data;
    size_t      data_len;
};

/* Parse an 8-character hex ASCII field */
static inline size_t cpio_parse_hex8(const uint8_t *bytes) {
    size_t val = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t b = bytes[i];
        size_t digit;
        if (b >= '0' && b <= '9')      digit = b - '0';
        else if (b >= 'a' && b <= 'f') digit = b - 'a' + 10;
        else if (b >= 'A' && b <= 'F') digit = b - 'A' + 10;
        else return 0;
        val = (val << 4) | digit;
    }
    return val;
}

/* Align up to 4-byte boundary */
static inline size_t cpio_align4(size_t n) {
    return (n + 3) & ~(size_t)3;
}

/* Compare two byte strings of given lengths */
static inline int cpio_namecmp(const uint8_t *a, size_t alen,
                                const char *b, size_t blen) {
    if (alen != blen) return 1;
    for (size_t i = 0; i < alen; i++) {
        if (a[i] != (uint8_t)b[i]) return 1;
    }
    return 0;
}

/* Find a file by name in a CPIO newc archive.
 * Returns 1 if found (entry populated), 0 if not found.
 */
static inline int cpio_find_file(const uint8_t *archive, size_t archive_len,
                                  const char *name, struct cpio_entry *entry) {
    size_t name_len = 0;
    while (name[name_len]) name_len++;

    size_t offset = 0;

    for (;;) {
        /* Need at least a header */
        if (offset + CPIO_HEADER_SIZE > archive_len)
            return 0;

        const uint8_t *header = archive + offset;

        /* Verify magic "070701" */
        if (header[0] != '0' || header[1] != '7' || header[2] != '0' ||
            header[3] != '7' || header[4] != '0' || header[5] != '1')
            return 0;

        /* Parse namesize (offset 94) and filesize (offset 54) */
        size_t namesize = cpio_parse_hex8(header + 94);
        size_t filesize = cpio_parse_hex8(header + 54);

        /* Filename starts after header */
        size_t name_start = offset + CPIO_HEADER_SIZE;
        if (name_start + namesize > archive_len)
            return 0;

        /* Name includes NUL terminator; compare without it */
        const uint8_t *entry_name = archive + name_start;
        size_t entry_name_len = namesize;
        if (entry_name_len > 0 && entry_name[entry_name_len - 1] == 0)
            entry_name_len--;

        /* Check for trailer */
        if (entry_name_len == 10 &&
            entry_name[0] == 'T' && entry_name[1] == 'R' &&
            entry_name[2] == 'A' && entry_name[3] == 'I' &&
            entry_name[4] == 'L' && entry_name[5] == 'E' &&
            entry_name[6] == 'R' && entry_name[7] == '!' &&
            entry_name[8] == '!' && entry_name[9] == '!')
            return 0;

        /* Data starts after name, aligned to 4 bytes */
        size_t data_start = cpio_align4(offset + CPIO_HEADER_SIZE + namesize);
        size_t data_end = data_start + filesize;

        if (data_end > archive_len)
            return 0;

        /* Check if this is the file we're looking for */
        if (cpio_namecmp(entry_name, entry_name_len, name, name_len) == 0) {
            entry->name = (const char *)entry_name;
            entry->name_len = entry_name_len;
            entry->data = archive + data_start;
            entry->data_len = filesize;
            return 1;
        }

        /* Move to next entry */
        offset = cpio_align4(data_end);
    }
}

/* Iterator: find the next entry after a given offset.
 * Pass *offset = 0 to start. Returns 1 if found, 0 if done.
 */
static inline int cpio_next(const uint8_t *archive, size_t archive_len,
                             size_t *offset, struct cpio_entry *entry) {
    if (*offset + CPIO_HEADER_SIZE > archive_len)
        return 0;

    const uint8_t *header = archive + *offset;

    if (header[0] != '0' || header[1] != '7' || header[2] != '0' ||
        header[3] != '7' || header[4] != '0' || header[5] != '1')
        return 0;

    size_t namesize = cpio_parse_hex8(header + 94);
    size_t filesize = cpio_parse_hex8(header + 54);

    size_t name_start = *offset + CPIO_HEADER_SIZE;
    if (name_start + namesize > archive_len)
        return 0;

    const uint8_t *entry_name = archive + name_start;
    size_t entry_name_len = namesize;
    if (entry_name_len > 0 && entry_name[entry_name_len - 1] == 0)
        entry_name_len--;

    /* Check for trailer */
    if (entry_name_len == 10 &&
        entry_name[0] == 'T' && entry_name[1] == 'R' &&
        entry_name[2] == 'A' && entry_name[3] == 'I' &&
        entry_name[4] == 'L' && entry_name[5] == 'E' &&
        entry_name[6] == 'R' && entry_name[7] == '!' &&
        entry_name[8] == '!' && entry_name[9] == '!')
        return 0;

    size_t data_start = cpio_align4(*offset + CPIO_HEADER_SIZE + namesize);
    size_t data_end = data_start + filesize;

    if (data_end > archive_len)
        return 0;

    entry->name = (const char *)entry_name;
    entry->name_len = entry_name_len;
    entry->data = archive + data_start;
    entry->data_len = filesize;

    *offset = cpio_align4(data_end);
    return 1;
}

/* Compute the total size of a CPIO archive (up to and including TRAILER!!!).
 * max_len is the maximum number of bytes to scan.
 * Returns the archive size in bytes, or max_len if no trailer is found.
 */
static inline size_t cpio_archive_size(const uint8_t *archive, size_t max_len) {
    size_t offset = 0;

    for (;;) {
        if (offset + CPIO_HEADER_SIZE > max_len)
            return max_len;

        const uint8_t *header = archive + offset;

        if (header[0] != '0' || header[1] != '7' || header[2] != '0' ||
            header[3] != '7' || header[4] != '0' || header[5] != '1')
            return offset;  /* not a valid header, archive ends here */

        size_t namesize = cpio_parse_hex8(header + 94);
        size_t filesize = cpio_parse_hex8(header + 54);

        size_t name_start = offset + CPIO_HEADER_SIZE;
        if (name_start + namesize > max_len)
            return max_len;

        const uint8_t *entry_name = archive + name_start;
        size_t entry_name_len = namesize;
        if (entry_name_len > 0 && entry_name[entry_name_len - 1] == 0)
            entry_name_len--;

        size_t data_start = cpio_align4(offset + CPIO_HEADER_SIZE + namesize);
        size_t data_end = data_start + filesize;
        size_t next_offset = cpio_align4(data_end);

        /* Check for TRAILER!!! — include it in the size */
        if (entry_name_len == 10 &&
            entry_name[0] == 'T' && entry_name[1] == 'R' &&
            entry_name[2] == 'A' && entry_name[3] == 'I' &&
            entry_name[4] == 'L' && entry_name[5] == 'E' &&
            entry_name[6] == 'R' && entry_name[7] == '!' &&
            entry_name[8] == '!' && entry_name[9] == '!')
            return next_offset;

        if (data_end > max_len)
            return max_len;

        offset = next_offset;
    }
}

/* Extended CPIO entry with full metadata */
struct cpio_entry_ext {
    const char    *name;
    size_t         name_len;
    const uint8_t *data;
    size_t         data_len;
    uint32_t       mode;    /* file mode (offset 14 in header) */
    uint32_t       nlink;   /* number of links (offset 38) */
    uint32_t       mtime;   /* modification time (offset 46) */
    uint32_t       ino;     /* inode number (offset 6) */
};

/* Iterator with extended metadata.
 * Pass *offset = 0 to start. Returns 1 if found, 0 if done.
 *
 * CPIO newc header layout (110 bytes, hex ASCII):
 *   0: magic (6)   "070701"
 *   6: ino (8)
 *  14: mode (8)
 *  22: uid (8)
 *  30: gid (8)
 *  38: nlink (8)
 *  46: mtime (8)
 *  54: filesize (8)
 *  62: devmajor (8)
 *  70: devminor (8)
 *  78: rdevmajor (8)
 *  86: rdevminor (8)
 *  94: namesize (8)
 * 102: check (8)
 */
static inline int cpio_next_ext(const uint8_t *archive, size_t archive_len,
                                 size_t *offset, struct cpio_entry_ext *entry) {
    if (*offset + CPIO_HEADER_SIZE > archive_len)
        return 0;

    const uint8_t *header = archive + *offset;

    if (header[0] != '0' || header[1] != '7' || header[2] != '0' ||
        header[3] != '7' || header[4] != '0' || header[5] != '1')
        return 0;

    size_t namesize = cpio_parse_hex8(header + 94);
    size_t filesize = cpio_parse_hex8(header + 54);

    size_t name_start = *offset + CPIO_HEADER_SIZE;
    if (name_start + namesize > archive_len)
        return 0;

    const uint8_t *entry_name = archive + name_start;
    size_t entry_name_len = namesize;
    if (entry_name_len > 0 && entry_name[entry_name_len - 1] == 0)
        entry_name_len--;

    /* Check for trailer */
    if (entry_name_len == 10 &&
        entry_name[0] == 'T' && entry_name[1] == 'R' &&
        entry_name[2] == 'A' && entry_name[3] == 'I' &&
        entry_name[4] == 'L' && entry_name[5] == 'E' &&
        entry_name[6] == 'R' && entry_name[7] == '!' &&
        entry_name[8] == '!' && entry_name[9] == '!')
        return 0;

    size_t data_start = cpio_align4(*offset + CPIO_HEADER_SIZE + namesize);
    size_t data_end = data_start + filesize;

    if (data_end > archive_len)
        return 0;

    entry->name = (const char *)entry_name;
    entry->name_len = entry_name_len;
    entry->data = archive + data_start;
    entry->data_len = filesize;
    entry->ino = (uint32_t)cpio_parse_hex8(header + 6);
    entry->mode = (uint32_t)cpio_parse_hex8(header + 14);
    entry->nlink = (uint32_t)cpio_parse_hex8(header + 38);
    entry->mtime = (uint32_t)cpio_parse_hex8(header + 46);

    *offset = cpio_align4(data_end);
    return 1;
}

#endif /* LIBSALTY_CPIO_H */
