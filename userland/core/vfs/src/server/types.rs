// SPDX-License-Identifier: GPL-2.0-only
//
//! Personality-neutral handle aliases used across the `server::*`
//! and `posix::*` layers. The naming is `OpenObject` /
//! `OpenObjectHandle` / `ObjectSlot` — never `OpenFile` or
//! `FdEntry` — so server-side code stays free of POSIX-specific
//! vocabulary. POSIX-side `fd` projection lives in
//! `personality::posix`.

use crate::arena::handle::Handle;
use crate::owner::clients::ClientState;
use crate::server::open_object::OpenObject;

pub(crate) type OpenObjectHandle = Handle<OpenObject>;
pub(crate) type ClientHandle = Handle<ClientState>;

/// Generic 32-bit slot index used inside `SegmentedSlotTable` for
/// fd → handle resolution. The personality layer maps its local
/// integer (POSIX fd, Win32 HANDLE table index) onto this.
pub(crate) type ObjectSlot = u32;
