// SPDX-License-Identifier: GPL-2.0-only
//! Async event plane.
//!
//! Hosts watchable kernel objects (`EventQueue`, `Watch`, `Timer`,
//! `IrqHandler`), the per-object `WatcherList` + `state_flags`
//! publication path, and the `EventRecord` wire format consumed
//! through `EventQueue::dequeue`.

pub mod event_queue;
pub mod irq;
pub mod record;
pub mod source;
pub mod state;
pub mod timer;
pub mod watch;
pub mod watcher_list;
