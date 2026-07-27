// SPDX-License-Identifier: GPL-2.0-only
//
//! Owner-reactor IPC plumbing. Cookie encoding, label namespaces,
//! and the dispatcher that fan-outs over the four cookie kinds.

pub(crate) mod cookie;
pub(crate) mod dispatch;
pub(crate) mod protocol;
