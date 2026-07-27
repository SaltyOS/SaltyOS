// SPDX-License-Identifier: GPL-2.0-only
//
//! Wire-level constants for the namesrv master MP. Includes sub-op
//! packing and the protocol mirror of the labels POSIX wrappers send.

use trona_protocol::namesrv::{
    NAMESRV_GRANT_PUBLISHER, NAMESRV_LIST, NAMESRV_LIST_BY_PREFIX, NAMESRV_LOOKUP,
    NAMESRV_LOOKUP_NONBLOCK, NAMESRV_LOOKUP_TIMEOUT, NAMESRV_OWNER_EXITED, NAMESRV_REGISTER,
    NAMESRV_REGISTER_EVENT, NAMESRV_SUBSCRIBE, NAMESRV_SUBSCRIBE_REGISTER, NAMESRV_UNREGISTER,
    NAMESRV_UNSUBSCRIBE,
};

pub const LABEL_REGISTER: u64 = NAMESRV_REGISTER;
pub const LABEL_UNREGISTER: u64 = NAMESRV_UNREGISTER;
pub const LABEL_LOOKUP: u64 = NAMESRV_LOOKUP;
pub const LABEL_LOOKUP_NONBLOCK: u64 = NAMESRV_LOOKUP_NONBLOCK;
pub const LABEL_LOOKUP_TIMEOUT: u64 = NAMESRV_LOOKUP_TIMEOUT;
pub const LABEL_SUBSCRIBE: u64 = NAMESRV_SUBSCRIBE;
pub const LABEL_UNSUBSCRIBE: u64 = NAMESRV_UNSUBSCRIBE;
pub const LABEL_LIST: u64 = NAMESRV_LIST;
pub const LABEL_LIST_BY_PREFIX: u64 = NAMESRV_LIST_BY_PREFIX;
pub const LABEL_GRANT_PUBLISHER: u64 = NAMESRV_GRANT_PUBLISHER;
pub const LABEL_OWNER_EXITED: u64 = NAMESRV_OWNER_EXITED;
pub const LABEL_SUBSCRIBE_REGISTER: u64 = NAMESRV_SUBSCRIBE_REGISTER;
pub const LABEL_REGISTER_EVENT: u64 = NAMESRV_REGISTER_EVENT;

/// Maximum byte length of a registered name (header + body).
pub const MAX_NAME_BYTES: usize = 64;

/// Maximum byte length of a publisher prefix.
pub const MAX_PREFIX_BYTES: usize = 32;

/// Word offset within `TronaMsg.regs[]` where REGISTER / LOOKUP /
/// UNREGISTER labels begin packing the requested name. The first word
/// (`regs[0]`) carries the byte length; subsequent words carry the
/// name's bytes packed 8-per-word, little-endian.
pub const NAME_PACK_BASE: usize = 1;

/// Reply payload word offsets — REGISTER / LOOKUP success replies pack
/// the entry id at `regs[0]`, optional flags at `regs[1]`, and (for
/// LOOKUP) the registered cap is delivered via cap-transfer slot 0.
pub const REPLY_REGS_ENTRY_ID: usize = 0;
pub const REPLY_REGS_FLAGS: usize = 1;

/// Sub-op for SUBSCRIBE: the caller passes a 64-bit cookie at
/// `regs[NAME_PACK_BASE + ceil(name_len / 8)]` so namesrv can echo it
/// back in the eventual notification record.
pub const SUBSCRIBE_COOKIE_TAIL_OFFSET: usize = 0;

/// `NameEntry::flags` bit 0 — when set, namesrv mints a per-caller
/// badged copy on `LOOKUP` instead of `cnode_copy`-ing the registered
/// cap verbatim. The badge value is the lookup caller's `client_id`
/// (extracted from the request record badge). Used by per-client
/// servers (rsrcsrv, mmsrv, vfs, console, win32srv) so each caller
/// receives a uniquely badged send and the server's dispatcher can
/// demultiplex by badge.
pub const ENTRY_FLAG_BADGE_AS_CALLER: u32 = 1 << 0;

/// Word offset of the optional flags byte in `NAMESRV_REGISTER`.
/// Layout after the packed name:
///   regs[NAME_PACK_BASE - 1] = name_len
///   regs[NAME_PACK_BASE..NAME_PACK_BASE + ceil(name_len/8)] = name bytes
///   regs[REGISTER_FLAGS_REG] = flags (or 0 when caller wants default)
pub const REGISTER_FLAGS_REG: usize = 31;
