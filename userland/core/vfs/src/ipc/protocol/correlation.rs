// SPDX-License-Identifier: GPL-2.0-only
//
//! Correlation header — 4-word `regs[]` stamp every backend RPC
//! and its reply carries to identify the originating `PendingOp`.
//!
//! The wire types and constants are defined in `trona_protocol`
//! so the saltyfs daemon (and any future backend driver) can share
//! the same encoding without depending on this crate. This module
//! re-exports the substrate-owned definitions for the rest of vfs
//! to consume.

pub(crate) use trona_protocol::posix::{
    CORRELATION_BACKEND_DISPDRV, CORRELATION_BACKEND_NETSRV, CORRELATION_BACKEND_POSIX_TTYSRV,
    CORRELATION_BACKEND_SALTYFS, CORRELATION_CLASS_DEV, CORRELATION_CLASS_FS,
    CORRELATION_CLASS_NET, CORRELATION_CLASS_PAGER, CORRELATION_CLASS_PTY,
    CORRELATION_F_LOOKUP_PARENT, CORRELATION_HEADER_REG_COUNT, CORRELATION_HEADER_REG_START,
    CORRELATION_KIND_COMPLETION, CORRELATION_KIND_REQUEST, CorrelationHeader,
    ensure_correlation_wire_length,
};
