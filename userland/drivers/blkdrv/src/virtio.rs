// SPDX-License-Identifier: GPL-2.0-only
//! VirtIO block device transport layer.

use trona::consts::*;
use trona::ipc;
use trona::invoke;
use trona::types::*;

use crate::ipc_ctx;
use crate::{CAPACITY_SECTORS, BAR0_IS_IO, PCI_IOPORT_CAP, VIRTIO_INITIALIZED, VQUEUE_BASE};
use crate::{QUEUE_SIZE, QUEUE_PHYS, QUEUE_AVAIL_OFF, QUEUE_USED_OFF, QUEUE_EVENT_IDX};

const CAP_SELF_VSPACE: u64 = 1;
const CAP_SELF_CSPACE: u64 = 2;
const CAP_PCISRV_EP: u64 = 64;
const CAP_MMSRV_EP: u64 = 7;

/// Slot for dynamically received IoPort cap from pcisrv
const CAP_RECEIVED_IOPORT: u64 = 80;
/// Slot for dynamically received device untyped cap from pcisrv (MMIO BAR)
const CAP_RECEIVED_DEVUT: u64 = 81;

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

/// Hint VA for virtqueue memory; mmsrv may choose another base.
pub(crate) const VQUEUE_HINT_VADDR: u64 = 0x0000_0000_4100_0000;

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
pub(crate) static mut REQ_HEADER: VirtioBlkReqHeader = VirtioBlkReqHeader { req_type: 0, reserved: 0, sector: 0 };
pub(crate) static mut REQ_STATUS: u8 = 0xFF;

#[derive(Clone, Copy)]
struct VirtqLayout {
    desc_off: u64,
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
    let desc_off = 0u64;
    let desc_bytes = 16 * q;
    let avail_off = desc_off + desc_bytes;
    let avail_bytes = 4 + 2 * q + if event_idx { 2 } else { 0 };
    let used_off = align_up(avail_off + avail_bytes, 4096);
    let used_bytes = 4 + 8 * q + if event_idx { 2 } else { 0 };
    let total_bytes = used_off + used_bytes;

    Some(VirtqLayout {
        desc_off,
        avail_off,
        used_off,
        total_bytes,
    })
}

/// Compute physical address via vspace_walk for a given virtual address.
pub(crate) fn vaddr_to_phys(vaddr: u64) -> u64 {
    let err = invoke::vspace_walk(CAP_SELF_VSPACE, vaddr, 1);
    if err != 0 {
        return 0;
    }
    match invoke::vspace_walk_result_entry(0) {
        Some((_v, phys, _flags)) => phys + (vaddr & 0xFFF),
        None => 0,
    }
}

/// Read a byte from BAR0.
pub(crate) fn bar_read8(offset: u64) -> u8 {
    unsafe {
        if *(&raw const BAR0_IS_IO) {
            invoke::ioport_in8(PCI_IOPORT_CAP, offset)
        } else {
            let ptr = (BAR0_VADDR + offset) as *const u8;
            ptr.read_volatile()
        }
    }
}

pub(crate) fn bar_read16(offset: u64) -> u16 {
    unsafe {
        if *(&raw const BAR0_IS_IO) {
            invoke::ioport_in16(PCI_IOPORT_CAP, offset)
        } else {
            let ptr = (BAR0_VADDR + offset) as *const u16;
            ptr.read_volatile()
        }
    }
}

pub(crate) fn bar_read32(offset: u64) -> u32 {
    unsafe {
        if *(&raw const BAR0_IS_IO) {
            invoke::ioport_in32(PCI_IOPORT_CAP, offset)
        } else {
            let ptr = (BAR0_VADDR + offset) as *const u32;
            ptr.read_volatile()
        }
    }
}

pub(crate) fn bar_write8(offset: u64, val: u8) {
    unsafe {
        if *(&raw const BAR0_IS_IO) {
            invoke::ioport_out8(PCI_IOPORT_CAP, offset, val);
        } else {
            let ptr = (BAR0_VADDR + offset) as *mut u8;
            ptr.write_volatile(val);
        }
    }
}

pub(crate) fn bar_write16(offset: u64, val: u16) {
    unsafe {
        if *(&raw const BAR0_IS_IO) {
            invoke::ioport_out16(PCI_IOPORT_CAP, offset, val);
        } else {
            let ptr = (BAR0_VADDR + offset) as *mut u16;
            ptr.write_volatile(val);
        }
    }
}

pub(crate) fn bar_write32(offset: u64, val: u32) {
    unsafe {
        if *(&raw const BAR0_IS_IO) {
            invoke::ioport_out32(PCI_IOPORT_CAP, offset, val);
        } else {
            let ptr = (BAR0_VADDR + offset) as *mut u32;
            ptr.write_volatile(val);
        }
    }
}

/// Query pcisrv for virtio-blk device.
pub(crate) fn find_virtio_blk() -> Option<(u8, u8, u8, u32, u64)> {
    let mut msg = TronaMsg::zeroed();
    msg.label = PCI_FIND_DEVICE;
    msg.length = 2;
    msg.regs[0] = VIRTIO_VENDOR as u64;
    msg.regs[1] = VIRTIO_BLK_DEVICE as u64;

    let mut reply = TronaMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ipc_ctx(), CAP_PCISRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != 0 {
        return None;
    }

    let bus = reply.regs[0] as u8;
    let dev = reply.regs[1] as u8;
    let func = reply.regs[2] as u8;
    let bar0 = reply.regs[4];

    Some((bus, dev, func, bar0 as u32, bar0))
}

/// Get BAR/IRQ info from pcisrv. Returns (bar_base, bar_bits, bar_size, irq, bar_is_io).
pub(crate) fn get_device_caps(bus: u8, dev: u8, func: u8) -> Option<(u64, u64, u32, u8, bool)> {
    let mut msg = TronaMsg::zeroed();
    msg.label = PCI_GET_CAPS;
    msg.length = 3;
    msg.regs[0] = bus as u64;
    msg.regs[1] = dev as u64;
    msg.regs[2] = func as u64;

    // Set up receive slot for IoPort or device untyped cap transfer
    unsafe {
        ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, CAP_RECEIVED_IOPORT, 0);
    }

    let mut reply = TronaMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ipc_ctx(), CAP_PCISRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != 0 {
        return None;
    }
    let bar_is_io = reply.regs[4] != 0;

    if bar_is_io {
        // Received an IoPort cap
        unsafe { *(&raw mut PCI_IOPORT_CAP) = CAP_RECEIVED_IOPORT; }
    } else {
        // Received a device untyped cap for MMIO — move to DEVUT slot
        let _ = invoke::cnode_move(
            CAP_SELF_CSPACE, CAP_RECEIVED_DEVUT,
            CAP_SELF_CSPACE, CAP_RECEIVED_IOPORT,
        );
    }

    Some((reply.regs[0], reply.regs[1], reply.regs[2] as u32, reply.regs[3] as u8, bar_is_io))
}

/// Set up the virtio-blk device (legacy PCI transport).
pub(crate) fn init_virtio(bar0_raw: u32, bar_size: u32) -> bool {
    unsafe {
        if bar0_raw == 0 {
            trona::uerror!(|_lb| { _lb.str(b"[blkdrv] Invalid BAR0 (0)\n"); });
            return false;
        }
        *(&raw mut BAR0_IS_IO) = (bar0_raw & 1) != 0;

        if *(&raw const BAR0_IS_IO) {
            let cap = *(&raw const PCI_IOPORT_CAP);
            if cap == 0 {
                trona::uerror!(|_lb| { _lb.str(b"[blkdrv] BAR0 is I/O space -- no IoPort cap available\n"); });
                return false;
            }
            trona::uinfo!(|_lb| { _lb.str(b"[blkdrv] BAR0 is I/O space -- using IoPort cap\n"); });
            return virtio_negotiate();
        }

        // MMIO BAR: map device untyped into our VSpace
        let num_pages = ((bar_size as u64) + 4095) / 4096;
        if num_pages == 0 {
            trona::uerror!(|_lb| { _lb.str(b"[blkdrv] Invalid MMIO BAR size\n"); });
            return false;
        }
        let (err, _mapped) = invoke::vspace_map_device_range(
            CAP_SELF_VSPACE,
            CAP_RECEIVED_DEVUT,
            0,
            BAR0_VADDR,
            num_pages,
            0x3, // RW
        );
        if err != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[blkdrv] MMIO BAR mapping failed\n"); });
            return false;
        }
        trona::uinfo!(|_lb| { _lb.str(b"[blkdrv] BAR0 MMIO mapped\n"); });
        virtio_negotiate()
    }
}

/// Initialize virtio device (protocol negotiation + virtqueue setup).
fn virtio_negotiate() -> bool {
    // Reset device
    bar_write8(VIRTIO_DEVICE_STATUS, 0);
    bar_write8(VIRTIO_DEVICE_STATUS, VIRTIO_STATUS_ACK);
    bar_write8(VIRTIO_DEVICE_STATUS, VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER);

    // Feature negotiation
    let dev_features = bar_read32(VIRTIO_DEV_FEATURES);
    let mut negotiated_features: u32 = 0;

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
    unsafe {
        *(&raw mut CAPACITY_SECTORS) = ((cap_hi as u64) << 32) | (cap_lo as u64);
    }

    trona::uinfo!(|_lb| {
        _lb.str(b"[blkdrv] Capacity: ");
        _lb.dec(unsafe { *(&raw const CAPACITY_SECTORS) });
        _lb.str(b" sectors (");
        _lb.dec(unsafe { *(&raw const CAPACITY_SECTORS) } * 512 / 1024 / 1024);
        _lb.str(b" MB)\n");
    });

    // Select and read queue 0 size
    bar_write16(VIRTIO_QUEUE_SELECT, 0);
    let qsize = bar_read16(VIRTIO_QUEUE_SIZE);
    if qsize == 0 {
        trona::uerror!(|_lb| { _lb.str(b"[blkdrv] Queue 0 unavailable\n"); });
        return false;
    }
    let event_idx = (negotiated_features & VIRTIO_RING_F_EVENT_IDX) != 0;
    let layout = match virtq_layout(qsize, event_idx) {
        Some(v) => v,
        None => {
            trona::uerror!(|_lb| { _lb.str(b"[blkdrv] Invalid virtqueue size/layout\n"); });
            return false;
        }
    };

    trona::uinfo!(|_lb| {
        _lb.str(b"[blkdrv] Queue 0 size: ");
        _lb.dec(qsize as u64);
        _lb.putc(b'\n');
    });

    unsafe { *(&raw mut QUEUE_SIZE) = qsize; }
    unsafe { *(&raw mut QUEUE_AVAIL_OFF) = layout.avail_off; }
    unsafe { *(&raw mut QUEUE_USED_OFF) = layout.used_off; }
    unsafe { *(&raw mut QUEUE_EVENT_IDX) = event_idx; }

    // Allocate virtqueue memory via mmsrv mmap.
    // Size depends on queue size and negotiated layout flags (e.g. EVENT_IDX).
    let vq_bytes = layout.total_bytes;
    let vq_pages = (vq_bytes + 4095) / 4096;
    let ctx = ipc_ctx();
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_MMAP;
    msg.length = 4;
    msg.regs[0] = VQUEUE_HINT_VADDR;
    msg.regs[1] = vq_pages * 4096;
    msg.regs[2] = 0x3; // PROT_READ | PROT_WRITE
    msg.regs[3] = 0x22; // MAP_PRIVATE | MAP_ANONYMOUS
    let mut reply = TronaMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != 0 {
        trona::uerror!(|_lb| { _lb.str(b"[blkdrv] Failed to allocate virtqueue memory\n"); });
        return false;
    }
    let vq_base = reply.regs[0];
    unsafe { *(&raw mut VQUEUE_BASE) = vq_base; }

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
        trona::uerror!(|_lb| { _lb.str(b"[blkdrv] Failed to get virtqueue phys addr\n"); });
        return false;
    }

    unsafe { *(&raw mut QUEUE_PHYS) = vq_phys; }

    // Set queue address (legacy: PFN = phys / 4096)
    bar_write32(VIRTIO_QUEUE_ADDR, (vq_phys / 4096) as u32);

    // blkdrv completes requests synchronously by polling used.idx, so device
    // interrupts on queue completions are pure shared-IRQ noise.
    unsafe {
        let avail_base = (vq_base + layout.avail_off) as *mut u16;
        core::ptr::write_volatile(avail_base, VIRTQ_AVAIL_F_NO_INTERRUPT);
    }
    trona::udebug!(|_lb| { _lb.str(b"[blkdrv] Queue interrupts suppressed (polling mode)\n"); });

    // Now set DRIVER_OK
    bar_write8(
        VIRTIO_DEVICE_STATUS,
        VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_DRIVER_OK,
    );

    unsafe { *(&raw mut VIRTIO_INITIALIZED) = true; }
    trona::uinfo!(|_lb| { _lb.str(b"[blkdrv] virtio initialized OK\n"); });
    true
}
