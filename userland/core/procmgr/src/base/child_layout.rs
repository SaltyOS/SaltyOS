//! procmgr-private per-child CSpace offsets.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Where `spawn_tx` temporarily realizes newly allocated kernel objects
//! inside procmgr's own CSpace before copying / minting them into the
//! child's CNode. These are spawner-private and have nothing to do with
//! where the child sees the caps in its own CSpace — that layout is
//! `trona_runtime::spawn::layout::ChildCapLayout`, and is communicated to the child via
//! `SaltyOSStartupLayoutV1.cap_table_ptr`.

pub const COFF_TCB: usize = 0;
pub const COFF_VSPACE: usize = 1;
pub const COFF_CNODE: usize = 2;
pub const COFF_SC: usize = 3;
pub const COFF_SIGNAL_NTFN: usize = 6;
pub const COFF_READY_NTFN: usize = 7;
