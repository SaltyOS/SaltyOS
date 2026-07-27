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
//!   Label 5 = BLK_GET_SHM_ID: -> MR0=mmsrv_shm_idx, caps[0]=shm_mo_cap
//!
//! Startup caps are role-based. System caps come from `trona_runtime::client::caps::*()`,
//! and the service-local `pcidrv_ep` dependency is resolved through the
//! `trona_runtime::local_cap!` macro declared below.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_posix;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;

mod handlers;
mod virtio;
mod virtio_modern;

use trona_kernel::core_types::*;
use trona_kernel::invoke;
use trona_kernel::ipc;
use trona_protocol::blk::*;
use trona_protocol::common::{TRONA_INVALID_OPERATION, TRONA_OK};
use trona_protocol::namesrv::NAMESRV_REGISTER;
use trona_runtime::core::slot_alloc::{OwnedCap, TransferCap};

// Service-local cap: `Require=pcidrv-ep.socket` (Provider=pcidrv,
// Alias=pcidrv_ep) in `blkdrv.service`. Init hashes the key
// `"blkdrv:pcidrv_ep"` into a LOCAL_ROLE id when building the
// startup cap_table; the macro below resolves that same role at runtime.
trona_runtime::local_cap!(pub(crate) pcidrv_ep = "blkdrv:pcidrv_ep");

// All cross-service caps flow through the role-based startup cap_table.
// System roles (`namesrv`, `mmsrv`) come from `trona_runtime::client::caps::*`; the
// service-local `pcidrv_ep` getter is declared above.

pub(crate) const SECTOR_SIZE: u32 = 512;

/// SHM ID for block device data transfer
pub(crate) const BLK_SHM_ID: u64 = 0x424C4B00; // "BLK\0"
const BLK_SHM_PAGES: u64 = 64; // 256KB
pub(crate) const SHM_SIZE: u64 = BLK_SHM_PAGES * 4096;

/// Virtual address for SHM buffer
pub(crate) const SHM_VADDR: u64 = 0x0000_0000_2200_0000;

/// Device state
static mut CAPACITY_SECTORS: u64 = 0;
pub(crate) static mut BLK_SHM_IDX: u64 = 0;
static mut BLK_SHM_CAP: Option<OwnedCap> = None;
static mut BAR0_IS_IO: bool = false;
static mut PCI_IOPORT_CAP: Option<OwnedCap> = None;
static mut PCI_IOPORT_BASE: u64 = 0;
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

const CAP_SELF_CSPACE: u64 = trona_kernel::uapi::KERNITE_CAP_SELF_CSPACE as u64;

fn copy_cap_to_temp(src: &OwnedCap, label: &'static [u8]) -> Option<OwnedCap> {
    let temp = trona_runtime::core::slot_alloc::alloc_slot_or_idle(label);
    let src_slot = src.as_raw();
    let err = invoke::cnode_copy_ref(
        trona_kernel::core_types::CapRef::flat(CAP_SELF_CSPACE),
        trona_runtime::core::slot_alloc::resolved_cap_ref(src_slot),
        trona_kernel::core_types::CapRef::flat(CAP_SELF_CSPACE),
        trona_runtime::core::slot_alloc::resolved_cap_ref(temp.addr()),
        trona_kernel::uapi::KERNITE_RIGHT_ALL as u64,
    );
    if err != 0 {
        // copy failed: `temp` (OwnedSlot) Drop frees the empty slot.
        return None;
    }
    // The copy landed a cap; adopt the slot as an OwnedCap.
    Some(temp.assume_filled())
}

/// Stage a copy of the SHM MO cap for IPC transfer to a client.
///
/// The returned [`TransferCap`] must be kept alive until after the IPC send
/// completes — dropping it frees the temporary slot and kernel cap.
pub(crate) fn stage_shm_cap_for_reply() -> Option<TransferCap> {
    let shm_cap = unsafe { (&*(&raw const BLK_SHM_CAP)).as_ref()? };
    let temp = copy_cap_to_temp(shm_cap, b"blkdrv shm reply cap")?;
    let tc = temp.into_transfer();
    unsafe {
        ipc::set_send_cap_ctx(ipc_ctx(), 0, tc.slot());
    }
    Some(tc)
}

/// Create SHM for data transfer.
fn setup_shm() -> bool {
    // Create the SHM region. blkdrv retains the MO cap (BLK_SHM_CAP) to hand
    // copies to consumers (e.g. saltyfs) via `stage_shm_cap_for_reply`.
    let (shm_idx, shm_cap) = match trona_runtime::client::mm::shm_create(BLK_SHM_ID, SHM_SIZE) {
        Ok(v) => v,
        Err(label) => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[blkdrv] SHM create failed: ");
                _lb.dec(label);
                _lb.putc(b'\n');
            });
            return false;
        }
    };

    // Duplicate the cap for the map call; shm_map takes ownership via TransferCap.
    // Keep `shm_cap` in BLK_SHM_CAP for consumer handoff.
    let Some(map_copy) = copy_cap_to_temp(&shm_cap, b"blkdrv shm map cap") else {
        // shm_cap drops here, releasing the MO cap.
        return false;
    };
    let va = match trona_runtime::client::mm::shm_map(
        shm_idx,
        map_copy.into_transfer(),
        SHM_VADDR,
        SHM_SIZE,
        0x3,
    ) {
        Ok(va) => va,
        Err(label) => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[blkdrv] SHM map failed: ");
                _lb.dec(label);
                _lb.putc(b'\n');
            });
            // shm_cap drops here.
            return false;
        }
    };
    if va != SHM_VADDR {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] SHM mapped at unexpected VA ");
            _lb.hex(va);
            _lb.putc(b'\n');
        });
        // shm_cap drops here.
        return false;
    }
    unsafe {
        *(&raw mut BLK_SHM_IDX) = shm_idx;
        *(&raw mut BLK_SHM_CAP) = Some(shm_cap);
    }

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[blkdrv] SHM region mapped\n");
    });
    true
}

/// Register with name service.
fn register_namesrv() {
    const ENTRY_FLAG_BADGE_AS_CALLER: u64 = 1 << 0;
    const REGISTER_FLAGS_REG: usize = 31;

    let name = b"blkdrv";
    let mut msg = TronaMsg::zeroed();
    msg.label = NAMESRV_REGISTER;
    msg.regs[0] = name.len() as u64;
    let Some(publish_tc) = trona_runtime::client::caps::service_client_ep_for_transfer() else {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] No service client ep to publish\n");
        });
        return;
    };
    unsafe {
        let dst = &raw mut msg.regs[1] as *mut u8;
        for i in 0..name.len() {
            *dst.add(i) = name[i];
        }
        ipc::set_send_cap_ctx(ipc_ctx(), 0, publish_tc.slot());
    }
    msg.regs[REGISTER_FLAGS_REG] = ENTRY_FLAG_BADGE_AS_CALLER;
    msg.length = (REGISTER_FLAGS_REG + 1) as u64;
    unsafe {
        let mut reply = TronaMsg::zeroed();
        let err = ipc::mp_call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::namesrv_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        drop(publish_tc);
        if err != 0 || reply.label != TRONA_OK {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[blkdrv] namesrv registration failed\n");
            });
        }
    }
}

/// Cookie for the single service-pipe `STATE_READABLE` Watch (kind 0, slot 0,
/// generation 1). blkdrv has one event source, so the cookie is constant.
const BLKDRV_SERVICE_COOKIE: u64 = trona_server::event_loop::encode_cookie(0, 0, 1);

/// Single-source reactor dispatcher. The only armed event is `STATE_READABLE`
/// on the service pipe; each inbound record is routed by block label and the
/// reply rides back on the same pipe (txid-correlated).
struct BlkdrvDispatcher {
    recv_ep: Cap,
    watch_cap: Cap,
    eq_cap: Cap,
    scratch: Cap,
}

impl trona_server::event_loop::EqDispatcher for BlkdrvDispatcher {
    fn resolve_mp_recv(&self, _cookie: u64) -> Option<Cap> {
        Some(self.recv_ep)
    }

    fn dispatch_state(
        &mut self,
        _cookie: u64,
        msg: &TronaMsg,
        _meta: trona_server::event_loop::MpReadMeta,
    ) -> i32 {
        let (reply, reply_tc) = match msg.label {
            BLK_READ => (handlers::handle_read(msg), None),
            BLK_WRITE => (handlers::handle_write(msg), None),
            BLK_GET_INFO => (handlers::handle_get_info(), None),
            BLK_FLUSH => {
                let mut r = TronaMsg::zeroed();
                r.label = 0;
                (r, None)
            }
            BLK_GET_SHM_ID => handlers::handle_get_shm_id(),
            _ => {
                let mut r = TronaMsg::zeroed();
                r.label = TRONA_INVALID_OPERATION;
                (r, None)
            }
        };
        // SAFETY: `ipc_ctx()` is this thread's IPC context; the reply rides
        // the service pipe correlated to the just-read request's txid.
        let _ = unsafe { ipc::mp_write_reply_ctx(ipc_ctx(), self.recv_ep, &raw const reply) };
        // Drop the TransferCap after the IPC send completes.
        drop(reply_tc);
        0
    }

    fn prepare_mp_read(&mut self, _cookie: u64) -> bool {
        // SAFETY: re-arm the sticky cap-receive scratch before each MP_READ.
        unsafe {
            trona_runtime::core::ipc_ext::set_receive_slot_ctx(
                ipc_ctx(),
                CAP_SELF_CSPACE,
                self.scratch,
                0,
            );
        }
        true
    }

    fn rearm_state_source(&mut self, _cookie: u64) -> i32 {
        // One-shot Watch is consumed on fire; re-arm the service pipe's
        // READABLE edge onto the reactor EQ.
        trona_kernel::invoke::watch_register(
            trona_kernel::core_types::CapRef::flat(self.watch_cap),
            trona_kernel::core_types::CapRef::flat(self.recv_ep),
            trona_kernel::core_types::CapRef::flat(self.eq_cap),
            trona_kernel::uapi::KERNITE_STATE_READABLE as u64,
            BLKDRV_SERVICE_COOKIE,
        )
    }

    fn handle_overflow(&mut self, _dropped: u64) {}

    fn handle_timer(&mut self, _cookie: u64) {}
}

fn idle() -> ! {
    loop {
        let _ = trona_kernel::syscall::yield_now();
    }
}

/// Server main loop: a single-source `EventLoop` reactor. Blocks on the reactor
/// `EventQueue` (`EQ_WAIT`), drains the service pipe when it becomes readable,
/// dispatches by label, and replies. Replaces the former `mp_write_reply_read`
/// tight loop, which spun on `WOULD_BLOCK` once `MP_READ` became non-blocking.
fn server_loop() -> ! {
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[blkdrv] Entering server loop\n");
    });

    let ctx = ipc_ctx();
    let recv_ep = trona_runtime::client::caps::service_recv_ep().addr();

    // Self-provision the reactor's EventQueue + Watch from rsrcsrv (general
    // services spawn after rsrcsrv is live, so no init pre-provisioning).
    let eq = trona_runtime::core::slot_alloc::rsrc_alloc_object(
        trona_kernel::uapi::KERNITE_OBJ_EVENT_QUEUE as u64,
        4,
    );
    let watch = trona_runtime::core::slot_alloc::rsrc_alloc_object(
        trona_kernel::uapi::KERNITE_OBJ_WATCH as u64,
        0,
    );
    let (eq, watch) = match (eq, watch) {
        (Some(eq), Some(watch)) => (eq, watch),
        _ => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[blkdrv] reactor EventQueue/Watch alloc failed\n");
            });
            idle();
        }
    };
    let eq_cap = eq.borrow().addr();
    let watch_cap = watch.borrow().addr();
    let scratch =
        trona_runtime::core::ipc_ext::arm_mp_write_reply_read_slot_ctx(ctx, b"blkdrv reply recv");

    // Arm the service pipe's READABLE edge onto the reactor EQ.
    let _ = trona_kernel::invoke::watch_register(
        trona_kernel::core_types::CapRef::flat(watch_cap),
        trona_kernel::core_types::CapRef::flat(recv_ep),
        trona_kernel::core_types::CapRef::flat(eq_cap),
        trona_kernel::uapi::KERNITE_STATE_READABLE as u64,
        BLKDRV_SERVICE_COOKIE,
    );

    // The EQ / Watch live for the process lifetime; suppress their OwnedCap
    // drop so the caps are never torn down under the running reactor.
    core::mem::forget(eq);
    core::mem::forget(watch);

    let dispatcher = BlkdrvDispatcher {
        recv_ep,
        watch_cap,
        eq_cap,
        scratch,
    };
    let mut reactor = trona_server::event_loop::EventLoop::new(eq_cap, dispatcher);

    loop {
        // SAFETY: `ctx` is this thread's IPC context; arm the cap-receive
        // scratch, then block on the EQ and dispatch one ready event.
        unsafe {
            trona_runtime::core::ipc_ext::set_receive_slot_ctx(ctx, CAP_SELF_CSPACE, scratch, 0);
            let _ = reactor.run_iteration(ctx);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[blkdrv] virtio-blk Block Device Driver starting\n");
    });

    // Try modern virtio (device ID 0x1042) first
    let mut initialized = false;
    if let Some((bus, dev, func)) = virtio_modern::find_virtio_blk_modern() {
        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[blkdrv] Found modern virtio-blk device\n");
        });
        if virtio_modern::init_virtio_modern(bus, dev, func) {
            unsafe {
                *(&raw mut USING_MODERN_TRANSPORT) = true;
            }
            initialized = true;
        }
    }

    // Fall back to legacy virtio (device ID 0x1001)
    if !initialized {
        match virtio::find_virtio_blk() {
            Some((bus, dev, func, bar0, _bar0_full)) => {
                trona_runtime::uinfo!(|_lb| {
                    _lb.str(b"[blkdrv] Found virtio-blk at ");
                    _lb.dec(bus as u64);
                    _lb.putc(b':');
                    _lb.dec(dev as u64);
                    _lb.str(b" BAR0=");
                    _lb.hex(bar0 as u64);
                    _lb.putc(b'\n');
                });

                let Some((_bar_phys, _bar_bits, bar_size, irq, _bar_is_io)) =
                    virtio::get_device_caps(bus, dev, func)
                else {
                    trona_runtime::uerror!(|_lb| {
                        _lb.str(b"[blkdrv] Failed to get PCI caps from pcidrv\n");
                    });
                    return 1;
                };
                trona_runtime::uinfo!(|_lb| {
                    _lb.str(b"[blkdrv] IRQ=");
                    _lb.dec(irq as u64);
                    _lb.putc(b'\n');
                });

                // Transitional device (0x1001): try modern transport first.
                // Modern transport handles non-contiguous virtqueue memory
                // by passing separate physical addresses for desc/avail/used.
                if virtio_modern::init_virtio_modern(bus, dev, func) {
                    unsafe {
                        *(&raw mut USING_MODERN_TRANSPORT) = true;
                    }
                    handlers::clear_pending_irq();
                } else if !virtio::init_virtio(bar0, bar_size) {
                    trona_runtime::uerror!(|_lb| {
                        _lb.str(b"[blkdrv] Failed to init virtio transport\n");
                    });
                    return 1;
                } else {
                    handlers::clear_pending_irq();
                }
            }
            None => {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[blkdrv] No virtio-blk device found\n");
                });
                return 1;
            }
        }
    }

    if !setup_shm() {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[blkdrv] SHM setup failed -- continuing without SHM\n");
        });
    }

    register_namesrv();
    server_loop()
}
