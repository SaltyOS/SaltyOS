// SPDX-License-Identifier: GPL-2.0-only
//! Stateful socket management — connection pools, rx buffering, completions.

pub(crate) mod options;
pub(crate) mod raw_ipv4;
pub(crate) mod tcp;
pub(crate) mod udp;
