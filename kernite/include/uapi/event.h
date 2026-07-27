/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Watchable state flags + EventQueue wire format.
 *
 * Every state-bearing kernel object (MessagePipe, DataPipe,
 * EventQueue, Timer, IrqHandler) carries an AtomicU64 state_flags
 * field. Userland-visible bits are below; kernel-private bits live in
 * the upper half and are never surfaced.
 *
 * Watch registrations on a state-bearing object enqueue an event
 * record into the bound EventQueue when watched bits become set.
 */

#ifndef KERNITE_UAPI_EVENT_H
#define KERNITE_UAPI_EVENT_H

#include <stdint.h>

/* ---- Watchable state bits (low 32 bits, ABI-stable). ---- */

#define KERNITE_STATE_NONE        0ULL
#define KERNITE_STATE_READABLE    (1ULL << 0)
#define KERNITE_STATE_WRITABLE    (1ULL << 1)
#define KERNITE_STATE_PEER_CLOSED (1ULL << 2)
#define KERNITE_STATE_CLOSED      (1ULL << 3)
#define KERNITE_STATE_ERROR       (1ULL << 4)
#define KERNITE_STATE_HANGUP      (1ULL << 5)
#define KERNITE_STATE_OVERRUN     (1ULL << 6)
#define KERNITE_STATE_SIGNALED    (1ULL << 7)
#define KERNITE_STATE_TIMED_OUT   (1ULL << 8)
#define KERNITE_STATE_READ_THRESHOLD  (1ULL << 9)  /* DataPipe RX bytes >= rx_threshold */
#define KERNITE_STATE_WRITE_THRESHOLD (1ULL << 10) /* DataPipe TX free  >= tx_threshold */

/* ---- EventRecord wire (delivered through EventQueue). ---- */

#define KERNITE_EVENT_TYPE_NONE     0u
#define KERNITE_EVENT_TYPE_STATE    1u  /* state_flags transition */
#define KERNITE_EVENT_TYPE_IRQ      2u
#define KERNITE_EVENT_TYPE_TIMER    3u
#define KERNITE_EVENT_TYPE_PIPE     4u  /* MP/DP record arrival */
#define KERNITE_EVENT_TYPE_USER     5u  /* userland-pushed record */
#define KERNITE_EVENT_TYPE_OVERFLOW     6u  /* dropped-event marker */
#define KERNITE_EVENT_TYPE_PAGER_REQUEST 7u  /* file-backed page fault — vfs supplies */

#define KERNITE_EVENT_STATUS_OK            0u
#define KERNITE_EVENT_STATUS_CANCELLED     1u
#define KERNITE_EVENT_STATUS_PEER_CLOSE    2u
#define KERNITE_EVENT_STATUS_OBJECT_CLOSED 3u
#define KERNITE_EVENT_STATUS_DROPPED       4u

/*
 * Fixed-layout event record. Userland reads via EQ_WAIT/POLL;
 * the kernel writes from the producer side under the EQ lock.
 *
 * Layout chosen for natural alignment + amenability to bindgen.
 */
struct kernite_event_record {
    uint32_t kind;       /* KERNITE_EVENT_TYPE_* */
    uint32_t status;     /* KERNITE_EVENT_STATUS_* */
    uint64_t cookie;     /* opaque caller-supplied tag */
    uint64_t object_id;  /* watched-object identity (Watch arms) */
    uint64_t state_set;  /* STATE_* bits asserted */
    uint64_t state_seen; /* STATE_* bits userland already knows about */
    uint64_t payload0;
    uint64_t payload1;
    uint64_t payload2;
};

#endif /* KERNITE_UAPI_EVENT_H */
