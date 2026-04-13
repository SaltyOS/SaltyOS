// SPDX-License-Identifier: GPL-2.0-only
//! AF_INET socket implementation (TCP/UDP via netsrv).
pub(crate) mod callback;
pub(crate) mod control;
pub(crate) mod io;
pub(crate) mod lifecycle;
pub(crate) use callback::*;
pub(crate) use control::*;
pub(crate) use io::*;
pub(crate) use lifecycle::*;
