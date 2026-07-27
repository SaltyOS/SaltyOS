/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * IPC buffer layout + MessagePipe / DataPipe wire formats.
 *
 * Every TCB has a 4 KiB IpcBuffer page mapped into its VSpace; the
 * kernel reads/writes the buffer to stage syscall payloads that don't
 * fit in registers. MessagePipe records (KERNITE_INV_MP_*) carry
 * label + 32 message words + 4 cap-transfer slots.
 */

#ifndef KERNITE_UAPI_IPC_H
#define KERNITE_UAPI_IPC_H

#include <stdint.h>

#define KERNITE_IPC_MSG_REGS    32
#define KERNITE_IPC_MAX_CAPS    4
#define KERNITE_IPC_BUFFER_SIZE 4096

/*
 * Per-thread IPC buffer mapped into userland. Layout is fixed by the
 * kernel; userland MUST treat unknown trailing reserved words as
 * opaque.
 *
 * Total size: 4096 bytes (one page). Layout is exhaustive — the
 * trailing reserved[] is sized so the struct sums to exactly
 * KERNITE_IPC_BUFFER_SIZE.
 */
struct kernite_ipc_buffer {
    /* trona_msg overlay: [label, length, regs[0..31]] */
    uint64_t msg[2 + KERNITE_IPC_MSG_REGS]; /* 0x000: 272 bytes */

    /* Badge received from sender. */
    uint64_t badge;                         /* 0x110: 8 */

    /* MP record flags surfaced from the inbound `kernite_mp_record`
     * (KERNITE_MP_FLAG_*). Distinct from `badge` so the sender's tag
     * is not entangled with the kernel-set call/reply bits. */
    uint64_t mp_flags;                      /* 0x118: 8 */

    /* Capability slots staged for transfer (sender's CSpace indices). */
    uint64_t caps[KERNITE_IPC_MAX_CAPS];    /* 0x120: 32 */

    /* Receive-side cap install target. */
    uint64_t receive_cnode;                 /* 0x140: 8 */
    uint64_t receive_index;                 /* 0x148: 8 */
    uint64_t receive_depth;                 /* 0x150: 8 */

    /* MessagePipe call transaction id. The kernel writes this on
     * inbound MP_READ records and MP_CALL replies. Servers copy it
     * into reply-marked MP_WRITE records so the kernel can complete
     * the matching blocked caller instead of exposing replies through
     * the normal FIFO stream. */
    uint64_t mp_txid;                       /* 0x158: 8 */

    /* Reserved / extended payload area. Well-known indices below;
     * userland MUST treat unknown indices as opaque so the kernel can
     * claim them later.
     *
     *   reserved[KERNITE_IPC_RESERVED_RECEIVE_SLOT_DEPTH]
     *       Nested receive-slot depth for chained cap delivery.
     *
     *   reserved[KERNITE_IPC_RESERVED_EVENT_RECORD_BASE
     *            .. +sizeof(kernite_event_record)/8]
     *       The kernel publishes one `kernite_event_record` here on
     *       every successful EQ_WAIT / EQ_POLL invocation. Userland
     *       casts this slice to `struct kernite_event_record` for
     *       typed access.
     */
    uint64_t reserved[468];                 /* 0x160: 3744 */
};

/* Well-known indices into `kernite_ipc_buffer.reserved[]`. Adding a
 * new index is an ABI change; never reuse an index for a new purpose.
 *
 *   reserved[KERNITE_IPC_RESERVED_RECEIVE_SLOT_DEPTH] (u64)
 *       Nested receive-slot depth for chained cap delivery.
 *
 *   reserved[KERNITE_IPC_RESERVED_RECEIVED_CAP_COUNT] (u64)
 *       Number of caps the kernel installed into `caps[]` on the
 *       most recent inbound IPC. Receivers inspect `caps[..cap_count]`;
 *       the trailing slots are sentinel-filled.
 *
 *   reserved[KERNITE_IPC_RESERVED_EVENT_RECORD_BASE
 *            .. +sizeof(kernite_event_record)/8] (8 u64 words)
 *       The kernel publishes one `kernite_event_record` here on
 *       every successful EQ_WAIT / EQ_POLL invocation.
 */
#define KERNITE_IPC_RESERVED_RECEIVE_SLOT_DEPTH 0u
#define KERNITE_IPC_RESERVED_RECEIVED_CAP_COUNT 1u
#define KERNITE_IPC_RESERVED_EVENT_RECORD_BASE  2u

/* ---- MessagePipe record wire format. ---- */

#define KERNITE_MP_RECORD_WORDS 32
#define KERNITE_MP_RECORD_CAPS  4

/*
 * Fixed-layout record carried over MessagePipe. The kernel bounds
 * the in-pipe queue depth at retype time; readers consume one record
 * per MP_READ.
 *
 * Cap-transfer caps are NOT in this wire struct — they are carried
 * out-of-band in a kernel-internal carrier array attached to each
 * record. Senders pass `cap_count` plus the source CSpace indices in
 * their IpcBuffer's caps[] area; the kernel mints those into hidden
 * carriers under the core lock at MP_WRITE time. Receivers see the
 * installed receive-side slot indices in their own IpcBuffer's caps[]
 * area at MP_READ time, sourced from receive_cnode/index/depth.
 */
struct kernite_mp_record {
    uint64_t label;                                /* 0x000: 8 */
    uint64_t length;                               /* 0x008: 8 — valid words[] count */
    uint64_t cap_count;                            /* 0x010: 8 — count of carrier caps */
    uint64_t flags;                                /* 0x018: 8 — KERNITE_MP_FLAG_* */
    uint64_t badge;                                /* 0x020: 8 — sender opaque tag */
    uint64_t txid;                                 /* 0x028: 8 — MP_CALL correlation id */
    uint64_t words[KERNITE_MP_RECORD_WORDS];       /* 0x030: 256 */
};

/* MP record flags. */
#define KERNITE_MP_FLAG_NONE  0ULL
#define KERNITE_MP_FLAG_CALL  (1ULL << 0) /* Sender expects reply. */
#define KERNITE_MP_FLAG_REPLY (1ULL << 1) /* This is a reply. */
#define KERNITE_MP_FLAG_FAULT (1ULL << 2) /* Kernel-injected fault. */

/*
 * MP transaction-id range split. The kernel generates sync MP_CALL txids
 * with this high bit SET (see next_mp_call_txid); userspace async
 * request/reply writes MUST keep txids in the low range (bit clear) so a
 * user write can never forge a reply that completes a parked sync caller.
 * txid == 0 is the "no correlation" sentinel (also used by fault delivery).
 *
 * The *bit position* (63) is the bindgen-bridged value, because a bit-63
 * *mask* exceeds i64::MAX and current bindgen cannot fold it to a u64 const
 * (rust-bindgen #2618, fixed only in unreleased git). C consumers use the
 * mask macro directly; Rust shifts the bridged position.
 */
#define KERNITE_MP_TXID_KERNEL_BIT_SHIFT 63
#define KERNITE_MP_TXID_KERNEL_BIT (1ULL << KERNITE_MP_TXID_KERNEL_BIT_SHIFT)

#endif /* KERNITE_UAPI_IPC_H */
