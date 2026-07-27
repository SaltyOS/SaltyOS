// SPDX-License-Identifier: GPL-2.0-only
//
//! Wire-level constants for rsrcsrv.

use trona_protocol::rsrcsrv::RSRC_ALLOC as RSRC_ALLOC_PROTOCOL;

/// `RSRC_*` label set. The block is 0x300..=0x3FF; rsrcsrv only owns
/// the contiguous prefix within that block — the rest is reserved for
/// future expansion.
pub const LABEL_ALLOC: u64 = RSRC_ALLOC_PROTOCOL;
pub const LABEL_FREE: u64 = 0x301;
pub const LABEL_BATCH_ALLOC: u64 = 0x302;
pub const LABEL_GET_QUOTA: u64 = 0x303;
pub const LABEL_SET_QUOTA: u64 = 0x304;
pub const LABEL_OWNER_EXITED: u64 = 0x305;
pub const LABEL_DUMP_STATS: u64 = 0x306;
pub const LABEL_ADOPT_UNTYPED: u64 = 0x307;
pub const LABEL_PROVISION_CLIENT: u64 = 0x308;
pub const LABEL_REBIND_FAULT_PIPE: u64 = 0x309;
pub const LABEL_ALLOC_MP_PAIR: u64 = 0x30A;
pub const LABEL_ALLOC_DP_PAIR: u64 = 0x30B;

/// Per-message wire offsets.
pub const REQ_TYPE_WORD: usize = 0;
pub const REQ_SIZE_BITS_WORD: usize = 1;
pub const REQ_FLAGS_WORD: usize = 2;
pub const REQ_BATCH_COUNT_WORD: usize = 0;
pub const REQ_BATCH_TYPES_BASE: usize = 1;
pub const REQ_BATCH_SIZE_BITS_BASE: usize = 9;
pub const REQ_FREE_RECORD_ID_WORD: usize = 0;

pub const REPLY_RECORD_ID_WORD: usize = 0;

/// Aggregate-class id used by SET_QUOTA when the caller wants to set
/// the per-owner byte cap rather than a single per-class count.
pub const RSRC_TYPE_AGGREGATE: u64 = 0xFF;
