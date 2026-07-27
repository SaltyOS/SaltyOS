// SPDX-License-Identifier: GPL-2.0-only
//! VirtIO block device transport layer.

use trona_kernel::core_types::*;
use trona_kernel::invoke;
use trona_kernel::ipc;
use trona_protocol::common::{TRONA_NOT_FOUND, TRONA_OK};
use trona_protocol::mm::{MM_MMAP, MMAP_KIND_ANON};
use trona_protocol::pci::{PCI_FIND_DEVICE, PCI_GET_CAPS};
use trona_runtime::core::slot_alloc::OwnedCap;

use crate::ipc_ctx;
use crate::{
    BAR0_IS_IO, CAPACITY_SECTORS, PCI_IOPORT_BASE, PCI_IOPORT_CAP, VIRTIO_INITIALIZED, VQUEUE_BASE,
};
use crate::{QUEUE_AVAIL_OFF, QUEUE_EVENT_IDX, QUEUE_PHYS, QUEUE_SIZE, QUEUE_USED_OFF};

const CAP_SELF_VSPACE: u64 = 1;
const CAP_SELF_CSPACE: u64 = 2;

// Service-local role: `Require=pcidrv-ep.socket` resolved via
// `trona_runtime::local_cap!` in `main.rs` (see `crate::pcidrv_ep`).

/// Scratch range for the BAR cap plus the optional IRQ handler cap that
/// pcidrv may attach as `extra_caps[1]`.
static mut LEGACY_CAP_SCRATCH_BASE: u64 = 0;
/// Persistent slot holding the MMIO BAR cap when BAR0 is memory-mapped.
static mut LEGACY_MMIO_CAP_SLOT: u64 = 0;

/// virtio-blk PCI vendor/device IDs
const VIRTIO_VENDOR: u16 = 0x1AF4;
const VIRTIO_BLK_DEVICE: u16 = 0x1001;

/// virtio legacy PCI I/O space register offsets
const VIRTIO_DEV_FEATURES: u64 = 0x00;
const VIRTIO_GUEST_FEATURES: u64 = 0x04;
const VIRTIO_QUEUE_ADDR: u64 = 0x08;
const VIRTIO_QUEUE_SIZE: u64 = 0x0C;
const VIRTIO_QUEUE_SELECT: u64 = 0x0E;
pub(crate) const VIRTIO_QUEUE_NOTIFY: u64 = 0x10;
const VIRTIO_DEVICE_STATUS: u64 = 0x12;
pub(crate) const VIRTIO_ISR_STATUS: u64 = 0x13;
const VIRTIO_BLK_CAPACITY: u64 = 0x14;

const VIRTIO_STATUS_ACK: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTQ_AVAIL_F_NO_INTERRUPT: u16 = 1;
// Ring feature bits (virtio 1.0+ legacy transport feature map)
const VIRTIO_RING_F_INDIRECT_DESC: u32 = 1 << 28;
const VIRTIO_RING_F_EVENT_IDX: u32 = 1 << 29;

/// Virtual address for BAR0 MMIO mapping
const BAR0_VADDR: u64 = 0x0000_0000_4000_0000;

/// Ask mmsrv to auto-place virtqueue memory inside the client's
/// registered mmap window. The old fixed-ish hint lived above the
/// default service mmap limit and made `MM_MMAP` fail before DMA
/// setup could start.
pub(crate) const VQUEUE_HINT_VADDR: u64 = 0;

/// Virtio descriptor table entry
#[repr(C)]
pub(crate) struct VirtqDesc {
    pub(crate) addr: u64,
    pub(crate) len: u32,
    pub(crate) flags: u16,
    pub(crate) next: u16,
}

pub(crate) const VRING_DESC_F_NEXT: u16 = 1;
pub(crate) const VRING_DESC_F_WRITE: u16 = 2;

/// Virtio block request header
#[repr(C)]
pub(crate) struct VirtioBlkReqHeader {
    pub(crate) req_type: u32,
    pub(crate) reserved: u32,
    pub(crate) sector: u64,
}

/// Static request header and status byte for DMA
pub(crate) static mut REQ_HEADER: VirtioBlkReqHeader = VirtioBlkReqHeader {
    req_type: 0,
    reserved: 0,
    sector: 0,
};
pub(crate) static mut REQ_STATUS: u8 = 0xFF;

#[derive(Clone, Copy)]
struct VirtqLayout {
    avail_off: u64,
    used_off: u64,
    total_bytes: u64,
}

fn align_up(value: u64, align: u64) -> u64 {
    (value + (align - 1)) & !(align - 1)
}

fn virtq_layout(qsz: u16, event_idx: bool) -> Option<VirtqLayout> {
    if qsz < 3 {
        return None;
    }
    // Virtio split ring queue size must be a power-of-two.
    if (qsz & (qsz - 1)) != 0 {
        return None;
    }

    let q = qsz as u64;
    let desc_bytes = 16 * q;
    let avail_off = desc_bytes;
    let avail_bytes = 4 + 2 * q + if event_idx { 2 } else { 0 };
    let used_off = align_up(avail_off + avail_bytes, 4096);
    let used_bytes = 4 + 8 * q + if event_idx { 2 } else { 0 };
    let total_bytes = used_off + used_bytes;

    Some(VirtqLayout {
        avail_off,
        used_off,
        total_bytes,
    })
}

/// Resolve exactly one present user mapping for DMA.
pub(crate) fn vaddr_to_phys(vaddr: u64) -> u64 {
    let (err, phys) = invoke::vspace_resolve_page(
        trona_kernel::core_types::CapRef::flat(CAP_SELF_VSPACE),
        vaddr,
    );
    if err != 0 {
        return 0;
    }
    phys
}

#[cold]
fn log_ioport_err(op: &[u8], port: u64, err: i32) {
    trona_runtime::uerror!(|_lb| {
        _lb.str(b"[blkdrv] BAR ioport ");
        _lb.bytes(op);
        _lb.str(b" port=");
        _lb.hex(port);
        _lb.str(b" err=");
        _lb.dec(err as u64);
        _lb.putc(b'\n');
    });
}

#[inline]
fn bar_io_port(offset: u64) -> (CapRef, u64) {
    // SAFETY: PCI_IOPORT_CAP is written once during get_device_caps and never
    // mutated after init; reading it here is safe under single-threaded execution.
    let cap_ref = unsafe {
        (&*(&raw const PCI_IOPORT_CAP))
            .as_ref()
            .map_or(CapRef::flat(0), |c| c.borrow())
    };
    let port = unsafe { *(&raw const PCI_IOPORT_BASE) } + offset;
    (cap_ref, port)
}

/// Read a byte from BAR0.
pub(crate) fn bar_read8(offset: u64) -> u8 {
    unsafe {
        if *(&raw const BAR0_IS_IO) {
            let (cap, port) = bar_io_port(offset);
            invoke::ioport_in8(cap, port).unwrap_or_else(|err| {
                log_ioport_err(b"read8", port, err);
                0xFF
            })
        } else {
            let ptr = (BAR0_VADDR + offset) as *const u8;
            ptr.read_volatile()
        }
    }
}

pub(crate) fn bar_read16(offset: u64) -> u16 {
    unsafe {
        if *(&raw const BAR0_IS_IO) {
            let (cap, port) = bar_io_port(offset);
            invoke::ioport_in16(cap, port).unwrap_or_else(|err| {
                log_ioport_err(b"read16", port, err);
                0xFFFF
            })
        } else {
            let ptr = (BAR0_VADDR + offset) as *const u16;
            ptr.read_volatile()
        }
    }
}

pub(crate) fn bar_read32(offset: u64) -> u32 {
    unsafe {
        if *(&raw const BAR0_IS_IO) {
            let (cap, port) = bar_io_port(offset);
            invoke::ioport_in32(cap, port).unwrap_or_else(|err| {
                log_ioport_err(b"read32", port, err);
                0xFFFF_FFFF
            })
        } else {
            let ptr = (BAR0_VADDR + offset) as *const u32;
            ptr.read_volatile()
        }
    }
}

pub(crate) fn bar_write8(offset: u64, val: u8) {
    unsafe {
        if *(&raw const BAR0_IS_IO) {
            let (cap, port) = bar_io_port(offset);
            if let Err(err) = invoke::ioport_out8(cap, port, val) {
                log_ioport_err(b"write8", port, err);
            }
        } else {
            let ptr = (BAR0_VADDR + offset) as *mut u8;
            ptr.write_volatile(val);
        }
    }
}

pub(crate) fn bar_write16(offset: u64, val: u16) {
    unsafe {
        if *(&raw const BAR0_IS_IO) {
            let (cap, port) = bar_io_port(offset);
            if let Err(err) = invoke::ioport_out16(cap, port, val) {
                log_ioport_err(b"write16", port, err);
            }
        } else {
            let ptr = (BAR0_VADDR + offset) as *mut u16;
            ptr.write_volatile(val);
        }
    }
}

pub(crate) fn bar_write32(offset: u64, val: u32) {
    unsafe {
        if *(&raw const BAR0_IS_IO) {
            let (cap, port) = bar_io_port(offset);
            if let Err(err) = invoke::ioport_out32(cap, port, val) {
                log_ioport_err(b"write32", port, err);
            }
        } else {
            let ptr = (BAR0_VADDR + offset) as *mut u32;
            ptr.write_volatile(val);
        }
    }
}

fn ensure_legacy_cap_scratch() -> Option<u64> {
    unsafe {
        let base = *(&raw const LEGACY_CAP_SCRATCH_BASE);
        if base != 0 {
            return Some(base);
        }
        let base = trona_runtime::core::slot_alloc::slot_alloc_consecutive(2)?;
        *(&raw mut LEGACY_CAP_SCRATCH_BASE) = base;
        Some(base)
    }
}

fn legacy_mmio_cap_slot() -> u64 {
    unsafe { *(&raw const LEGACY_MMIO_CAP_SLOT) }
}

/// Query pcidrv for virtio-blk device.
pub(crate) fn find_virtio_blk() -> Option<(u8, u8, u8, u32, u64)> {
    let ep = crate::pcidrv_ep();
    if ep.is_null() {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] Missing pcidrv_ep capability\n");
        });
        return None;
    }

    let mut msg = TronaMsg::zeroed();
    msg.label = PCI_FIND_DEVICE;
    msg.length = 2;
    msg.regs[0] = VIRTIO_VENDOR as u64;
    msg.regs[1] = VIRTIO_BLK_DEVICE as u64;

    let mut reply = TronaMsg::zeroed();
    let err = unsafe {
        ipc::mp_call_ctx(
            ipc_ctx(),
            ep.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] PCI_FIND_DEVICE IPC failed ep=");
            _lb.hex(ep.addr());
            _lb.str(b" err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
        return None;
    }
    if reply.label == TRONA_NOT_FOUND {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] pcidrv did not report legacy virtio-blk\n");
        });
        return None;
    }
    if reply.label != TRONA_OK {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] PCI_FIND_DEVICE failed label=");
            _lb.hex(reply.label);
            _lb.str(b"\n");
        });
        return None;
    }

    let bus = reply.regs[0] as u8;
    let dev = reply.regs[1] as u8;
    let func = reply.regs[2] as u8;
    let bar0 = reply.regs[4];

    Some((bus, dev, func, bar0 as u32, bar0))
}

/// Get BAR/IRQ info from pcidrv. Returns (bar_base, bar_bits, bar_size, irq, bar_is_io).
pub(crate) fn get_device_caps(bus: u8, dev: u8, func: u8) -> Option<(u64, u64, u32, u8, bool)> {
    let ep = crate::pcidrv_ep();
    if ep.is_null() {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] Missing pcidrv_ep capability\n");
        });
        return None;
    }

    let mut msg = TronaMsg::zeroed();
    msg.label = PCI_GET_CAPS;
    msg.length = 3;
    msg.regs[0] = bus as u64;
    msg.regs[1] = dev as u64;
    msg.regs[2] = func as u64;

    let recv_base = ensure_legacy_cap_scratch()?;

    // Receive the BAR cap at `recv_base`; pcidrv may place an optional IRQ
    // handler in the next consecutive slot, so reserve both.
    unsafe {
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(
            ipc_ctx(),
            CAP_SELF_CSPACE,
            recv_base,
            0,
        );
    }

    let mut reply = TronaMsg::zeroed();
    let err = unsafe {
        ipc::mp_call_ctx(
            ipc_ctx(),
            ep.addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] PCI_GET_CAPS IPC failed ep=");
            _lb.hex(ep.addr());
            _lb.str(b" err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
        return None;
    }
    if reply.label != TRONA_OK {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] PCI_GET_CAPS failed label=");
            _lb.hex(reply.label);
            _lb.str(b" bus=");
            _lb.dec(bus as u64);
            _lb.putc(b':');
            _lb.dec(dev as u64);
            _lb.putc(b':');
            _lb.dec(func as u64);
            _lb.str(b"\n");
        });
        return None;
    }
    let bar_is_io = reply.regs[4] != 0;

    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[blkdrv] GET_CAPS reply ");
        _lb.dec(bus as u64);
        _lb.putc(b':');
        _lb.dec(dev as u64);
        _lb.putc(b':');
        _lb.dec(func as u64);
        _lb.str(b" base=");
        _lb.hex(reply.regs[0]);
        _lb.str(b" bits=");
        _lb.hex(reply.regs[1]);
        _lb.str(b" size=");
        _lb.hex(reply.regs[2]);
        _lb.str(b" irq=");
        _lb.dec(reply.regs[3]);
        _lb.str(b" is_io=");
        _lb.dec(bar_is_io as u64);
        _lb.str(b" recv_slot=");
        _lb.hex(recv_base);
        _lb.putc(b'\n');
    });

    if bar_is_io {
        unsafe {
            // SAFETY: recv_base was just populated by pcidrv via IPC cap transfer;
            // we take sole ownership of that slot here.
            *(&raw mut PCI_IOPORT_CAP) = Some(OwnedCap::adopt_received(recv_base));
            *(&raw mut PCI_IOPORT_BASE) = reply.regs[0];
            *(&raw mut LEGACY_MMIO_CAP_SLOT) = 0;
        }
    } else {
        unsafe {
            *(&raw mut LEGACY_MMIO_CAP_SLOT) = recv_base;
        }
    }

    Some((
        reply.regs[0],
        reply.regs[1],
        reply.regs[2] as u32,
        reply.regs[3] as u8,
        bar_is_io,
    ))
}

/// Set up the virtio-blk device (legacy PCI transport).
pub(crate) fn init_virtio(bar0_raw: u32, bar_size: u32) -> bool {
    unsafe {
        if bar0_raw == 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[blkdrv] Invalid BAR0 (0)\n");
            });
            return false;
        }
        *(&raw mut BAR0_IS_IO) = (bar0_raw & 1) != 0;

        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[blkdrv] init_virtio bar0_raw=");
            _lb.hex(bar0_raw as u64);
            _lb.str(b" bar_size=");
            _lb.hex(bar_size as u64);
            _lb.str(b" bar0_is_io=");
            _lb.dec((*(&raw const BAR0_IS_IO)) as u64);
            _lb.str(b" ioport_cap=");
            _lb.hex(
                (&*(&raw const PCI_IOPORT_CAP))
                    .as_ref()
                    .map_or(0, |c| c.as_raw()),
            );
            _lb.str(b" mmio_cap=");
            _lb.hex(*(&raw const LEGACY_MMIO_CAP_SLOT));
            _lb.putc(b'\n');
        });

        if *(&raw const BAR0_IS_IO) {
            if (&*(&raw const PCI_IOPORT_CAP)).is_none() {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[blkdrv] BAR0 is I/O space -- no IoPort cap available\n");
                });
                return false;
            }
            trona_runtime::uinfo!(|_lb| {
                _lb.str(b"[blkdrv] BAR0 is I/O space -- using IoPort cap\n");
            });
            return virtio_negotiate();
        }

        // MMIO BAR: map device untyped into our VSpace
        let num_pages = ((bar_size as u64) + 4095) / 4096;
        if num_pages == 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[blkdrv] Invalid MMIO BAR size\n");
            });
            return false;
        }
        let mmio_cap = legacy_mmio_cap_slot();
        if mmio_cap == 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[blkdrv] Missing MMIO BAR cap\n");
            });
            return false;
        }
        // MMIO must be uncacheable.
        let map_flags = (trona_kernel::uapi::KERNITE_PAGE_FLAG_WRITABLE
            | trona_kernel::uapi::KERNITE_PAGE_FLAG_USER
            | trona_kernel::uapi::KERNITE_PAGE_FLAG_NOCACHE) as u64;
        let (err, mapped) = invoke::vspace_map_device_range(
            trona_kernel::core_types::CapRef::flat(CAP_SELF_VSPACE),
            trona_runtime::core::slot_alloc::resolved_cap_ref(mmio_cap),
            0,
            BAR0_VADDR,
            num_pages,
            map_flags,
        );
        if err != 0 || mapped != num_pages {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[blkdrv] MMIO BAR mapping failed err=");
                _lb.hex(err as u64);
                _lb.str(b" mapped=");
                _lb.hex(mapped);
                _lb.putc(b'/');
                _lb.hex(num_pages);
                _lb.putc(b'\n');
            });
            return false;
        }
        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[blkdrv] BAR0 MMIO mapped\n");
        });
        virtio_negotiate()
    }
}

/// Initialize virtio device (protocol negotiation + virtqueue setup).
fn virtio_negotiate() -> bool {
    let status0 = bar_read8(VIRTIO_DEVICE_STATUS);
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[blkdrv] legacy status initial=");
        _lb.hex(status0 as u64);
        _lb.putc(b'\n');
    });

    // Reset device
    bar_write8(VIRTIO_DEVICE_STATUS, 0);
    let status_reset = bar_read8(VIRTIO_DEVICE_STATUS);
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[blkdrv] legacy status after reset=");
        _lb.hex(status_reset as u64);
        _lb.putc(b'\n');
    });
    bar_write8(VIRTIO_DEVICE_STATUS, VIRTIO_STATUS_ACK);
    let status_ack = bar_read8(VIRTIO_DEVICE_STATUS);
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[blkdrv] legacy status after ACK=");
        _lb.hex(status_ack as u64);
        _lb.putc(b'\n');
    });
    bar_write8(
        VIRTIO_DEVICE_STATUS,
        VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER,
    );
    let status_driver = bar_read8(VIRTIO_DEVICE_STATUS);
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[blkdrv] legacy status after DRIVER=");
        _lb.hex(status_driver as u64);
        _lb.putc(b'\n');
    });

    // Feature negotiation
    let dev_features = bar_read32(VIRTIO_DEV_FEATURES);
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[blkdrv] legacy dev_features=");
        _lb.hex(dev_features as u64);
        _lb.putc(b'\n');
    });
    let negotiated_features: u32 = 0;

    // Keep minimal baseline semantics for now. We only expose layout branching
    // for EVENT_IDX, but intentionally avoid enabling it until interrupt/event
    // handling uses it.
    if (dev_features & VIRTIO_RING_F_EVENT_IDX) != 0 {
        let _ = VIRTIO_RING_F_EVENT_IDX;
    }
    if (dev_features & VIRTIO_RING_F_INDIRECT_DESC) != 0 {
        let _ = VIRTIO_RING_F_INDIRECT_DESC;
    }
    bar_write32(VIRTIO_GUEST_FEATURES, negotiated_features);

    // Read capacity
    let cap_lo = bar_read32(VIRTIO_BLK_CAPACITY);
    let cap_hi = bar_read32(VIRTIO_BLK_CAPACITY + 4);
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[blkdrv] legacy capacity regs lo=");
        _lb.hex(cap_lo as u64);
        _lb.str(b" hi=");
        _lb.hex(cap_hi as u64);
        _lb.putc(b'\n');
    });
    unsafe {
        *(&raw mut CAPACITY_SECTORS) = ((cap_hi as u64) << 32) | (cap_lo as u64);
    }

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[blkdrv] Capacity: ");
        _lb.dec(unsafe { *(&raw const CAPACITY_SECTORS) });
        _lb.str(b" sectors (");
        _lb.dec(unsafe { *(&raw const CAPACITY_SECTORS) } * 512 / 1024 / 1024);
        _lb.str(b" MB)\n");
    });

    // Select and read queue 0 size
    bar_write16(VIRTIO_QUEUE_SELECT, 0);
    let qsize = bar_read16(VIRTIO_QUEUE_SIZE);
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[blkdrv] legacy queue0 size=");
        _lb.hex(qsize as u64);
        _lb.putc(b'\n');
    });
    if qsize == 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] Queue 0 unavailable\n");
        });
        return false;
    }
    let event_idx = (negotiated_features & VIRTIO_RING_F_EVENT_IDX) != 0;
    let layout = match virtq_layout(qsize, event_idx) {
        Some(v) => v,
        None => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[blkdrv] Invalid virtqueue size/layout\n");
            });
            return false;
        }
    };

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[blkdrv] Queue 0 size: ");
        _lb.dec(qsize as u64);
        _lb.putc(b'\n');
    });

    unsafe {
        *(&raw mut QUEUE_SIZE) = qsize;
    }
    unsafe {
        *(&raw mut QUEUE_AVAIL_OFF) = layout.avail_off;
    }
    unsafe {
        *(&raw mut QUEUE_USED_OFF) = layout.used_off;
    }
    unsafe {
        *(&raw mut QUEUE_EVENT_IDX) = event_idx;
    }

    // Allocate virtqueue memory via mmsrv mmap.
    // Size depends on queue size and negotiated layout flags (e.g. EVENT_IDX).
    let vq_bytes = layout.total_bytes;
    let vq_pages = (vq_bytes + 4095) / 4096;
    let ctx = ipc_ctx();
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_MMAP;
    msg.length = 5;
    msg.regs[0] = MMAP_KIND_ANON;
    msg.regs[1] = VQUEUE_HINT_VADDR;
    msg.regs[2] = vq_pages * 4096;
    msg.regs[3] = 0x3; // PROT_READ | PROT_WRITE
    msg.regs[4] = 0; // mmsrv wire flags: auto-place, eager anon mapping
    let mut reply = TronaMsg::zeroed();
    let err = unsafe {
        ipc::mp_call_ctx(
            ctx,
            trona_runtime::client::caps::mmsrv_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 || reply.label != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] Failed to allocate virtqueue memory err=");
            _lb.hex(err as u64);
            _lb.str(b" label=");
            _lb.hex(reply.label);
            _lb.str(b"\n");
        });
        return false;
    }
    let vq_base = reply.regs[0];
    unsafe {
        *(&raw mut VQUEUE_BASE) = vq_base;
    }

    // Zero virtqueue memory
    unsafe {
        let vq_ptr = vq_base as *mut u8;
        for i in 0..(vq_pages * 4096) as usize {
            *vq_ptr.add(i) = 0;
        }
    }

    // Get physical address of virtqueue page
    let vq_phys = vaddr_to_phys(vq_base);
    if vq_phys == 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] Failed to get virtqueue phys addr\n");
        });
        return false;
    }

    unsafe {
        *(&raw mut QUEUE_PHYS) = vq_phys;
    }

    // Set queue address (legacy: PFN = phys / 4096)
    bar_write32(VIRTIO_QUEUE_ADDR, (vq_phys / 4096) as u32);

    // blkdrv completes requests synchronously by polling used.idx, so device
    // interrupts on queue completions are pure shared-IRQ noise.
    unsafe {
        let avail_base = (vq_base + layout.avail_off) as *mut u16;
        core::ptr::write_volatile(avail_base, VIRTQ_AVAIL_F_NO_INTERRUPT);
    }
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[blkdrv] Queue interrupts suppressed (polling mode)\n");
    });

    // Now set DRIVER_OK
    bar_write8(
        VIRTIO_DEVICE_STATUS,
        VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_DRIVER_OK,
    );

    unsafe {
        *(&raw mut VIRTIO_INITIALIZED) = true;
    }
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[blkdrv] virtio initialized OK\n");
    });
    true
}
