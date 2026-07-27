// SPDX-License-Identifier: GPL-2.0-only
//
//! Lifecycle observer fan-out. POSIX wrappers and debug agents call
//! `INIT_LIFECYCLE_SUBSCRIBE(mask, hint_pid; cap[0]=subscriber MP recv)`
//! to register interest in spawn/exit/exec events. init owns the send
//! sides and writes one record per matching event.
//!
//! Observers live in an arena [`TrackedSlab`] — there is no fixed
//! subscriber ceiling; the slab grows on demand through init's
//! [`InitSelfVm`](crate::supervisor::self_vm::InitSelfVm) backing.
//!
//! Wire layout for an event published into a subscriber MP:
//!
//! ```text
//!   regs[0] = event_kind  (EVT_SPAWN | EVT_EXIT | EVT_EXEC | EVT_SIGNAL)
//!   regs[1] = pid
//!   regs[2] = ppid
//!   regs[3] = aux  (exit status / signal number / spawn service idx)
//!   regs[4] = monotonic_ns_low32
//!   regs[5] = monotonic_ns_high32
//! ```

use trona_kernel::core_types::{IpcContext, TronaMsg};
use trona_kernel::ipc;
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_server::slab::{PageBacking, TrackedSlab};

pub const EVT_SPAWN: u64 = 1;
pub const EVT_EXIT: u64 = 2;
pub const EVT_EXEC: u64 = 3;
pub const EVT_SIGNAL: u64 = 4;

pub const MASK_SPAWN: u32 = 1 << 0;
pub const MASK_EXIT: u32 = 1 << 1;
pub const MASK_EXEC: u32 = 1 << 2;
pub const MASK_SIGNAL: u32 = 1 << 3;

pub struct Observer {
    /// Send side of the subscriber's MP — owned by init, written one
    /// record per matching event. Dropped (cap deleted + slot freed)
    /// when the slab slot is freed.
    pub mp_send: OwnedCap,
    /// Bitset of `MASK_*` flags the subscriber wants.
    pub mask: u32,
    /// `0` = system-wide, otherwise filter to a single pid.
    pub hint_pid: u32,
    /// PID of the observer process (used to evict on observer exit).
    pub owner_pid: u32,
}

pub struct LifecycleStreams {
    /// Arena of live observers. Grows on demand; freed slots are
    /// recycled, so there is no fixed subscriber cap. `slot_free`
    /// calls `drop_in_place` on the entry, which runs `OwnedCap::drop`
    /// on `mp_send` and releases the capability automatically.
    observers: TrackedSlab<Observer>,
}

impl LifecycleStreams {
    pub const fn new() -> Self {
        Self {
            observers: TrackedSlab::empty(),
        }
    }

    /// Register an observer. Returns `false` on arena exhaustion.
    ///
    /// # Safety
    /// `backing` must be live; single-threaded owner.
    pub unsafe fn subscribe(
        &mut self,
        mp_send: OwnedCap,
        mask: u32,
        hint_pid: u32,
        owner_pid: u32,
        backing: &mut impl PageBacking,
    ) -> bool {
        unsafe {
            self.observers
                .slot_alloc(
                    Observer {
                        mp_send,
                        mask,
                        hint_pid,
                        owner_pid,
                    },
                    backing,
                )
                .is_some()
        }
    }

    /// Drop the observer matching `(owner_pid, mp_send_addr)`. The
    /// underlying `OwnedCap` is released automatically when the slab
    /// slot is freed. Returns `true` if an observer was found.
    pub fn unsubscribe(&mut self, owner_pid: u32, mp_send_addr: u64) -> bool {
        // SAFETY: single-threaded owner.
        unsafe {
            let id = self
                .observers
                .iter()
                .find(|(_, o)| {
                    o.mp_send.borrow().addr() == mp_send_addr && o.owner_pid == owner_pid
                })
                .map(|(id, _)| id);
            match id {
                Some(id) => {
                    self.observers.slot_free(id);
                    true
                }
                None => false,
            }
        }
    }

    /// Drop every observer owned by `pid`. The `OwnedCap` in each
    /// freed entry drops automatically — no external `drop_slot`
    /// callback needed.
    pub fn evict_by_pid(&mut self, pid: u32) -> usize {
        let mut n = 0;
        loop {
            // SAFETY: single-threaded owner.
            let found = unsafe {
                self.observers
                    .iter()
                    .find(|(_, o)| o.owner_pid == pid)
                    .map(|(id, _)| id)
            };
            match found {
                Some(id) => {
                    // SAFETY: single-threaded owner; id from the scan above.
                    unsafe { self.observers.slot_free(id) };
                    n += 1;
                }
                None => break,
            }
        }
        n
    }

    pub fn publish(
        &self,
        ipc_ctx: *mut IpcContext,
        event_kind: u64,
        pid: u32,
        ppid: u32,
        aux: u64,
        now_ns: u64,
    ) {
        let needed_mask = match event_kind {
            EVT_SPAWN => MASK_SPAWN,
            EVT_EXIT => MASK_EXIT,
            EVT_EXEC => MASK_EXEC,
            EVT_SIGNAL => MASK_SIGNAL,
            _ => 0,
        };
        let mut msg = TronaMsg::zeroed();
        msg.length = 6;
        msg.regs[0] = event_kind;
        msg.regs[1] = pid as u64;
        msg.regs[2] = ppid as u64;
        msg.regs[3] = aux;
        msg.regs[4] = now_ns & 0xFFFF_FFFF;
        msg.regs[5] = now_ns >> 32;

        // SAFETY: single-threaded owner.
        for (_, o) in unsafe { self.observers.iter() } {
            if needed_mask != 0 && (o.mask & needed_mask) == 0 {
                continue;
            }
            if o.hint_pid != 0 && o.hint_pid != pid {
                continue;
            }
            // Best-effort: drop on PEER_CLOSED / queue-full. The observer
            // is responsible for keeping their MP drained.
            let _ =
                unsafe { mp_write_best_effort(ipc_ctx, o.mp_send.borrow().addr(), &raw const msg) };
        }
    }
}

unsafe fn mp_write_best_effort(ipc_ctx: *mut IpcContext, mp: u64, msg: *const TronaMsg) -> i32 {
    unsafe { ipc::mp_write_ctx(ipc_ctx, mp, msg) }
}
