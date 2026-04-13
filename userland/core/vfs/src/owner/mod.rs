// SPDX-License-Identifier: GPL-2.0-only
//! `VfsState` — the single owner of all mutable VFS state.
//!
//! Every `static mut` global from the old `server/state.rs` is absorbed
//! into this struct. The VFS main loop holds the sole `&mut VfsState`
//! reference. Workers never touch it.

pub(crate) mod dispatch;
pub(crate) mod loop_;
pub(crate) mod reclaim;
pub(crate) mod worker;

use crate::arena::{Arena, BadgeMap};
use crate::personality::posix::consts::*;
use crate::personality::posix::types::*;
use crate::server::consts::*;
use crate::server::types::*;
use crate::vfs_core::mount::Mount;
use crate::vfs_core::mount_ns::MountNamespace;
use crate::vfs_core::vnode::Vnode;

use crate::vfs_core::mount::MountHandle;
use crate::vfs_core::mount_ns::MountNsHandle;

use worker::{CompletionQueue, WorkQueue};

// =========================================================================
// VfsState
// =========================================================================

/// All mutable VFS state, owned exclusively by the main loop.
///
/// Replaces every `static mut` global from the old pool-based architecture.
/// No global mutable statics remain after this struct is introduced.
pub(crate) struct VfsState {
    // -----------------------------------------------------------------
    // Core arenas
    // -----------------------------------------------------------------
    pub(crate) vnodes: Arena<Vnode>,
    pub(crate) mounts: Arena<Mount>,
    pub(crate) clients: Arena<ClientState>,
    pub(crate) mount_ns: Arena<MountNamespace>,

    // -----------------------------------------------------------------
    // Subsystem arenas (were global pools)
    // -----------------------------------------------------------------
    pub(crate) sockets: Arena<SocketState>,
    pub(crate) pipes: Arena<PipeState>,
    pub(crate) poll_waiters: Arena<PollWaiter>,
    pub(crate) epolls: Arena<EpollInstance>,
    pub(crate) shm_data: Arena<ShmData>,

    // -----------------------------------------------------------------
    // Mount tree
    // -----------------------------------------------------------------
    /// Root mount of the VFS namespace. Set during bootstrap.
    pub(crate) root_mount: MountHandle,
    /// Default mount namespace shared by all processes.
    pub(crate) global_ns: MountNsHandle,

    // -----------------------------------------------------------------
    // Client lookup
    // -----------------------------------------------------------------
    /// O(1) badge → ClientHandle hash map.
    pub(crate) badge_map: BadgeMap,

    // -----------------------------------------------------------------
    // Worker dispatch
    // -----------------------------------------------------------------
    pub(crate) work_queue: WorkQueue,
    pub(crate) completion_queue: CompletionQueue,

    // -----------------------------------------------------------------
    // ID counters
    // -----------------------------------------------------------------
    pub(crate) next_sock_id: u32,

    // -----------------------------------------------------------------
    // Deferred reply slot allocator
    // -----------------------------------------------------------------
    pub(crate) next_reply_slot: u64,

    // -----------------------------------------------------------------
    // PTY pending readers
    // -----------------------------------------------------------------
    pub(crate) pty_pending: [[PtyPendingReader; MAX_PTY_WAITERS]; MAX_PTYS],
    pub(crate) pty_pending_count: [usize; MAX_PTYS],

    // -----------------------------------------------------------------
    // Urandom CSPRNG state
    // -----------------------------------------------------------------
    pub(crate) urandom_key: [u8; 32],
    pub(crate) urandom_ctr: u64,
    pub(crate) urandom_buf: [u8; 64],
    pub(crate) urandom_buf_pos: usize,
    pub(crate) urandom_counter: u64,

    // -----------------------------------------------------------------
    // Framebuffer info
    // -----------------------------------------------------------------
    pub(crate) fb_width: u32,
    pub(crate) fb_height: u32,
    pub(crate) fb_pitch: u32,
    pub(crate) fb_bpp: u8,
    pub(crate) fb_red_pos: u8,
    pub(crate) fb_red_size: u8,
    pub(crate) fb_green_pos: u8,
    pub(crate) fb_green_size: u8,
    pub(crate) fb_blue_pos: u8,
    pub(crate) fb_blue_size: u8,

    // -----------------------------------------------------------------
    // Misc
    // -----------------------------------------------------------------
    /// Procfs root inode id.
    pub(crate) proc_root_ino: u32,
    /// Dispatch cycle counter (for periodic sweep).
    pub(crate) dispatch_count: u64,

    // -----------------------------------------------------------------
    // Receive slot tracking
    // -----------------------------------------------------------------
    pub(crate) current_recv_slot: u64,
    pub(crate) worker_recv_slots: [u64; MAX_VFS_WORKERS],
    pub(crate) worker_recv_slot_count: usize,
}

const MAX_VFS_WORKERS: usize = 32;

impl VfsState {
    /// Create and initialize a new VfsState. Allocates all arenas.
    /// Returns `None` if any arena allocation fails.
    pub(crate) fn new() -> Option<Self> {
        Some(VfsState {
            vnodes: Arena::new(256)?,
            mounts: Arena::new(16)?,
            clients: Arena::new(INITIAL_CLIENTS as u32)?,
            mount_ns: Arena::new(8)?,

            sockets: Arena::new(INITIAL_SOCKETS as u32)?,
            pipes: Arena::new(INITIAL_PIPES as u32)?,
            poll_waiters: Arena::new(INITIAL_POLL_WAITERS as u32)?,
            epolls: Arena::new(INITIAL_EPOLLS as u32)?,
            shm_data: Arena::new(INITIAL_SHM as u32)?,

            root_mount: MountHandle::INVALID,
            global_ns: MountNsHandle::INVALID,

            badge_map: BadgeMap::new(256)?,

            work_queue: WorkQueue::new(),
            completion_queue: CompletionQueue::new(),

            next_sock_id: 1,

            next_reply_slot: CAP_REPLY_BASE,

            pty_pending: [[PtyPendingReader::zeroed(); MAX_PTY_WAITERS]; MAX_PTYS],
            pty_pending_count: [0; MAX_PTYS],

            urandom_key: [0; 32],
            urandom_ctr: 0,
            urandom_buf: [0; 64],
            urandom_buf_pos: 64,
            urandom_counter: 0,

            fb_width: 0,
            fb_height: 0,
            fb_pitch: 0,
            fb_bpp: 0,
            fb_red_pos: 0,
            fb_red_size: 0,
            fb_green_pos: 0,
            fb_green_size: 0,
            fb_blue_pos: 0,
            fb_blue_size: 0,

            proc_root_ino: 0,
            dispatch_count: 0,

            current_recv_slot: 0,
            worker_recv_slots: [0; MAX_VFS_WORKERS],
            worker_recv_slot_count: 1,
        })
    }

    /// Allocate a deferred reply slot (wraps around at CAP_REPLY_LIMIT).
    pub(crate) fn alloc_reply_slot(&mut self) -> u64 {
        let slot = self.next_reply_slot;
        self.next_reply_slot += 1;
        if self.next_reply_slot >= CAP_REPLY_LIMIT {
            self.next_reply_slot = CAP_REPLY_BASE;
        }
        slot
    }
}
