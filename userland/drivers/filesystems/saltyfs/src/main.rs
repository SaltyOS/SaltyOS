//! SaltyOS SaltyFS Server
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Mounts a SaltyFS partition from blkdrv and serves file read/directory
//! traversal requests over IPC.
//!
//! On-disk format follows docs/design/saltyfs.md exactly.
//! Data transfer to/from blkdrv uses mmsrv SHM.
//!
//! IPC protocol:
//!   Label 1 = SALTYFS_MOUNT:   mount the filesystem
//!   Label 2 = SALTYFS_LOOKUP:  MR0=parent_ino, MR1..=name -> MR0=child_ino
//!   Label 3 = SALTYFS_READ:    MR0=ino, MR1=offset, MR2=count, MR3=shm_offset
//!   Label 4 = SALTYFS_READDIR: MR0=dir_ino, MR1=cursor -> entries
//!   Label 5 = SALTYFS_STAT:    MR0=ino -> stat info
//!   Label 6 = SALTYFS_GETINFO: -> total/free blocks, label
//!
//! Cap layout:
//!   0  = self TCB
//!   1  = self VSpace
//!   2  = self CSpace
//!   68 = server endpoint (pre-created service EP)
//!   14 = readiness notification
//!   64 = blkdrv endpoint
//!   5  = namesrv endpoint
//!   7  = mmsrv endpoint

#![no_std]
#![no_main]

extern crate trona;
extern crate trona_posix;

mod consts;
mod types;
mod crc;
mod block;
mod alloc;
mod btree;
mod handlers;

use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;

use consts::*;
use types::Superblock;

// ======================================================================
// Global state
// ======================================================================

static mut MOUNTED: bool = false;
static mut SB: Superblock = unsafe { core::mem::zeroed() };
static mut BLOCK_SIZE: u64 = DEFAULT_BLOCK_SIZE;
static mut BLK_SHM_ID: u64 = 0;

/// Block cache: LRU-ish (just track block numbers, evict oldest)
static mut CACHE_BLOCK_NR: [u64; CACHE_SLOTS] = [u64::MAX; CACHE_SLOTS];
static mut CACHE_AGE: [u32; CACHE_SLOTS] = [0; CACHE_SLOTS];
static mut CACHE_TICK: u32 = 0;
static mut CACHE_DIRTY: [bool; CACHE_SLOTS] = [false; CACHE_SLOTS];

/// Next inode number to allocate
static mut NEXT_INO: u64 = 2;

/// Bitmap block allocator
static mut BITMAP_CACHE: [[u8; 4096]; BITMAP_CACHE_SLOTS] = [[0; 4096]; BITMAP_CACHE_SLOTS];
static mut BITMAP_CACHE_BLOCK: [u64; BITMAP_CACHE_SLOTS] = [u64::MAX; BITMAP_CACHE_SLOTS];
static mut BITMAP_CACHE_DIRTY: [bool; BITMAP_CACHE_SLOTS] = [false; BITMAP_CACHE_SLOTS];
static mut BITMAP_BLOCK_COUNT: u64 = 0;
static mut ALLOC_HINT: u64 = 0;

/// VFS-SaltyFS shared memory state
static mut VFS_SHM_MAPPED: bool = false;

fn ipc_ctx() -> *mut IpcContext {
    trona_posix::tls::current_ipc_ctx()
}

fn signal_ready() {
    let _ = trona::syscall::syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

// ======================================================================
// Name service registration
// ======================================================================

fn register_namesrv() {
    let name = b"saltyfs";
    let mut msg = TronaMsg::zeroed();
    msg.label = NS_REGISTER;
    msg.regs[0] = name.len() as u64;
    msg.length = 1 + (name.len() as u64 + 7) / 8;
    unsafe {
        let dst = &raw mut msg.regs[1] as *mut u8;
        for i in 0..name.len() {
            *dst.add(i) = name[i];
        }
        ipc::set_send_cap_ctx(ipc_ctx(), 0, CAP_SERVER_EP);
        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), CAP_NAMESRV_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            trona::uerror!(|_lb| { _lb.str(b"[saltyfs] namesrv registration failed\n"); });
        }
    }
}

// ======================================================================
// Server main loop
// ======================================================================

fn server_loop() -> ! {
    trona::uinfo!(|_lb| { _lb.str(b"[saltyfs] Entering server loop\n"); });

    let ctx = ipc_ctx();
    let mut msg = TronaMsg::zeroed();
    let mut badge: u64 = 0;
    unsafe { ipc::recv_ctx(ctx, CAP_SERVER_EP, &raw mut msg, &raw mut badge); }

    loop {
        let label = msg.label;
        let reply = match label {
            SALTYFS_MOUNT => handlers::handle_mount(),
            SALTYFS_LOOKUP => handlers::handle_lookup(&msg),
            SALTYFS_READ => handlers::handle_read(&msg),
            SALTYFS_READDIR => handlers::handle_readdir(&msg),
            SALTYFS_STAT => handlers::handle_stat(&msg),
            SALTYFS_GETINFO => handlers::handle_getinfo(),
            SALTYFS_READ_INLINE => handlers::handle_read_inline(&msg),
            SALTYFS_WRITE_INLINE => handlers::handle_write_inline(&msg),
            SALTYFS_CREATE => handlers::handle_create(&msg),
            SALTYFS_MKDIR => handlers::handle_mkdir_fs(&msg),
            SALTYFS_UNLINK => handlers::handle_unlink_fs(&msg),
            SALTYFS_RMDIR => handlers::handle_rmdir_fs(&msg),
            SALTYFS_RENAME => handlers::handle_rename_fs(&msg),
            SALTYFS_TRUNCATE => handlers::handle_truncate_fs(&msg),
            SALTYFS_SHM_SETUP => handlers::handle_shm_setup(&msg),
            SALTYFS_WRITE => handlers::handle_write_shm(&msg),
            SALTYFS_SYMLINK => handlers::handle_symlink(&msg),
            SALTYFS_READLINK => handlers::handle_readlink(&msg),
            SALTYFS_LINK => handlers::handle_link(&msg),
            SALTYFS_GETPARENT => handlers::handle_getparent(&msg),
            _ => {
                let mut r = TronaMsg::zeroed();
                r.label = TRONA_INVALID_OPERATION;
                r
            }
        };

        // Flush dirty cache blocks after mutating operations
        if label == SALTYFS_WRITE_INLINE
            || label == SALTYFS_WRITE
            || label == SALTYFS_CREATE
            || label == SALTYFS_MKDIR
            || label == SALTYFS_UNLINK
            || label == SALTYFS_RMDIR
            || label == SALTYFS_RENAME
            || label == SALTYFS_TRUNCATE
            || label == SALTYFS_SYMLINK
            || label == SALTYFS_LINK
        {
            block::cache_flush_all();
        }

        msg = TronaMsg::zeroed();
        badge = 0;
        unsafe {
            ipc::reply_recv_ctx(
                ctx, CAP_SERVER_EP, &raw const reply, &raw mut msg, &raw mut badge,
            );
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    trona::uinfo!(|_lb| { _lb.str(b"[saltyfs] SaltyFS Server starting\n"); });

    // Set up SHM from blkdrv
    if !block::setup_blk_shm() {
        trona::uerror!(|_lb| { _lb.str(b"[saltyfs] Failed to set up blkdrv SHM -- cannot operate\n"); });
    }

    // Set up block cache
    if !block::setup_cache() {
        trona::uerror!(|_lb| { _lb.str(b"[saltyfs] Failed to set up block cache\n"); });
    }

    // Auto-mount on startup
    if !block::read_superblock() {
        trona::uwarn!(|_lb| { _lb.str(b"[saltyfs] No SaltyFS partition found -- running without mount\n"); });
    } else {
        unsafe { *(&raw mut MOUNTED) = true; }
        alloc::init_bitmap();

        // Bitmap consistency check: verify used_blocks matches actual bitmap
        let actual_used = alloc::count_used_blocks();
        let sb_used = unsafe { (*(&raw const SB)).used_blocks };
        if actual_used != sb_used {
            trona::uwarn!(|_lb| {
                _lb.str(b"[saltyfs] WARN: bitmap mismatch: sb.used_blocks=");
                _lb.dec(sb_used);
                _lb.str(b" actual=");
                _lb.dec(actual_used);
                _lb.str(b" (correcting)\n");
            });
            unsafe { (*(&raw mut SB)).used_blocks = actual_used; }
            block::write_superblock();
        }

        block::discover_max_inode();
    }

    // Register with name service
    register_namesrv();

    // Signal readiness
    signal_ready();

    // Enter server loop
    server_loop()
}
