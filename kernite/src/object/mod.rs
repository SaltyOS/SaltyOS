// SPDX-License-Identifier: GPL-2.0-only
//! Kernel object lifetime helpers.

mod reaper;

pub(crate) use reaper::{drain_reaper, enqueue_reap};
