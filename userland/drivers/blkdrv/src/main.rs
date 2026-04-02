//! SaltyOS virtio-blk Block Device Driver
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Discovers virtio-blk-pci device via pcidrv, initializes the virtio
//! transport (legacy PCI), and serves block read/write requests over IPC.
//!
//! Data is transferred via mmsrv shared memory (SHM). Clients map the same
//! SHM region and specify offsets in IPC requests.
//!
//! IPC protocol:
//!   Label 1 = BLK_READ:     MR0=start_sector, MR1=count, MR2=shm_offset
//!   Label 2 = BLK_WRITE:    MR0=start_sector, MR1=count, MR2=shm_offset
//!   Label 3 = BLK_GET_INFO: -> MR0=capacity_sectors, MR1=sector_size
//!   Label 4 = BLK_FLUSH:    flush disk cache
//!   Label 5 = BLK_GET_SHM_ID: -> MR0=shm_id
//!
//! Cap layout:
//!   0  = self TCB
//!   1  = self VSpace
//!   2  = self CSpace
//!   68 = server endpoint (pre-created service EP)
//!   14 = readiness notification
//!   64 = pcidrv endpoint
//!   5  = namesrv endpoint
//!   7  = mmsrv endpoint

#![no_std]
#![no_main]

extern crate trona;
extern crate trona_posix;

mod virtio;
mod virtio_modern;
mod handlers;

use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;

const CAP_SERVER_EP: u64 = 68;
const CAP_READINESS_NTFN: u64 = 14;
const CAP_NAMESRV_EP: u64 = 5;
const CAP_MMSRV_EP: u64 = 7;

pub(crate) const SECTOR_SIZE: u32 = 512;

/// SHM ID for block device data transfer
pub(crate) const BLK_SHM_ID: u64 = 0x424C4B00; // "BLK\0"
const BLK_SHM_PAGES: u64 = 64; // 256KB
pub(crate) const SHM_SIZE: u64 = BLK_SHM_PAGES * 4096;

/// Virtual address for SHM buffer
pub(crate) const SHM_VADDR: u64 = 0x0000_0000_4200_0000;

/// Device state
static mut CAPACITY_SECTORS: u64 = 0;
static mut BAR0_IS_IO: bool = false;
static mut PCI_IOPORT_CAP: u64 = 0;
static mut VIRTIO_INITIALIZED: bool = false;
static mut USING_MODERN_TRANSPORT: bool = false;
static mut VQUEUE_BASE: u64 = virtio::VQUEUE_HINT_VADDR;

/// Virtqueue state
static mut QUEUE_SIZE: u16 = 0;
static mut QUEUE_PHYS: u64 = 0;
static mut AVAIL_IDX: u16 = 0;
static mut LAST_USED_IDX: u16 = 0;
static mut QUEUE_AVAIL_OFF: u64 = 0;
static mut QUEUE_USED_OFF: u64 = 0;
static mut QUEUE_EVENT_IDX: bool = false;

fn ipc_ctx() -> *mut IpcContext {
    trona_posix::tls::current_ipc_ctx()
}

fn signal_ready() {
    let _ = trona::syscall::syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

/// Create SHM for data transfer.
fn setup_shm() -> bool {
    let ctx = ipc_ctx();

    let mut msg = TronaMsg::zeroed();
    msg.label = MM_SHM_CREATE;
    msg.length = 2;
    msg.regs[0] = BLK_SHM_ID;
    msg.regs[1] = BLK_SHM_PAGES;

    let mut reply = TronaMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || (reply.label != 0 && reply.label != TRONA_ALREADY_EXISTS) {
        trona::uerror!(|_lb| {
            _lb.str(b"[blkdrv] SHM create failed: ");
            _lb.dec(if err != 0 { err as u64 } else { reply.label });
            _lb.putc(b'\n');
        });
        return false;
    }

    let mut msg = TronaMsg::zeroed();
    msg.label = MM_SHM_MAP;
    msg.length = 4;
    msg.regs[0] = BLK_SHM_ID;
    msg.regs[1] = 0;
    msg.regs[2] = SHM_VADDR;
    msg.regs[3] = 0x3; // RW

    let mut reply = TronaMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != 0 {
        trona::uerror!(|_lb| {
            _lb.str(b"[blkdrv] SHM map failed: ");
            _lb.dec(if err != 0 { err as u64 } else { reply.label });
            _lb.putc(b'\n');
        });
        return false;
    }

    trona::uinfo!(|_lb| { _lb.str(b"[blkdrv] SHM region mapped\n"); });
    true
}

/// Register with name service.
fn register_namesrv() {
    let name = b"blkdrv";
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
            trona::uerror!(|_lb| { _lb.str(b"[blkdrv] namesrv registration failed\n"); });
        }
    }
}

/// Server main loop.
fn server_loop() -> ! {
    trona::uinfo!(|_lb| { _lb.str(b"[blkdrv] Entering server loop\n"); });

    let ctx = ipc_ctx();
    let mut msg = TronaMsg::zeroed();
    let mut badge: u64 = 0;
    unsafe { ipc::recv_ctx(ctx, CAP_SERVER_EP, &raw mut msg, &raw mut badge); }

    loop {
        let reply = match msg.label {
            BLK_READ => handlers::handle_read(&msg),
            BLK_WRITE => handlers::handle_write(&msg),
            BLK_GET_INFO => handlers::handle_get_info(),
            BLK_FLUSH => {
                let mut r = TronaMsg::zeroed();
                r.label = 0;
                r
            }
            BLK_GET_SHM_ID => handlers::handle_get_shm_id(),
            _ => {
                let mut r = TronaMsg::zeroed();
                r.label = TRONA_INVALID_OPERATION;
                r
            }
        };

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
    trona::uinfo!(|_lb| { _lb.str(b"[blkdrv] virtio-blk Block Device Driver starting\n"); });

    // Try modern virtio (device ID 0x1042) first
    let mut initialized = false;
    if let Some((bus, dev, func)) = virtio_modern::find_virtio_blk_modern() {
        trona::uinfo!(|_lb| { _lb.str(b"[blkdrv] Found modern virtio-blk device\n"); });
        if virtio_modern::init_virtio_modern(bus, dev, func) {
            unsafe { *(&raw mut USING_MODERN_TRANSPORT) = true; }
            initialized = true;
        }
    }

    // Fall back to legacy virtio (device ID 0x1001)
    if !initialized {
        match virtio::find_virtio_blk() {
            Some((bus, dev, func, bar0, _bar0_full)) => {
                trona::uinfo!(|_lb| {
                    _lb.str(b"[blkdrv] Found virtio-blk at ");
                    _lb.dec(bus as u64);
                    _lb.putc(b':');
                    _lb.dec(dev as u64);
                    _lb.str(b" BAR0=");
                    _lb.hex(bar0 as u64);
                    _lb.putc(b'\n');
                });

                let Some((_bar_phys, _bar_bits, bar_size, irq, _bar_is_io)) = virtio::get_device_caps(bus, dev, func) else {
                    trona::uerror!(|_lb| { _lb.str(b"[blkdrv] Failed to get PCI caps from pcidrv\n"); });
                    register_namesrv();
                    signal_ready();
                    server_loop()
                };
                trona::uinfo!(|_lb| {
                    _lb.str(b"[blkdrv] IRQ=");
                    _lb.dec(irq as u64);
                    _lb.putc(b'\n');
                });

                // Transitional device (0x1001): try modern transport first.
                // Modern transport handles non-contiguous virtqueue memory
                // by passing separate physical addresses for desc/avail/used.
                if virtio_modern::init_virtio_modern(bus, dev, func) {
                    unsafe { *(&raw mut USING_MODERN_TRANSPORT) = true; }
                    handlers::clear_pending_irq();
                } else if !virtio::init_virtio(bar0, bar_size) {
                    trona::uerror!(|_lb| { _lb.str(b"[blkdrv] Failed to init virtio transport\n"); });
                    trona::uwarn!(|_lb| { _lb.str(b"[blkdrv] Running in stub mode -- no actual I/O\n"); });
                } else {
                    handlers::clear_pending_irq();
                }
            }
            None => {
                trona::uwarn!(|_lb| { _lb.str(b"[blkdrv] No virtio-blk device found -- running in stub mode\n"); });
            }
        }
    }

    if !setup_shm() {
        trona::uwarn!(|_lb| { _lb.str(b"[blkdrv] SHM setup failed -- continuing without SHM\n"); });
    }

    register_namesrv();
    signal_ready();
    server_loop()
}
