//! SaltyOS virtio-blk Block Device Driver
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Discovers virtio-blk-pci device via pcisrv, initializes the virtio
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
//!   64 = pcisrv endpoint
//!   5  = nameserv endpoint
//!   7  = mmsrv endpoint

#![no_std]
#![no_main]

extern crate salty;

use salty::consts::*;
use salty::ipc;
use salty::invoke;
use salty::serial;
use salty::serial::LineBuf;
use salty::types::*;

const CAP_SELF_TCB: u64 = 0;
const CAP_SELF_VSPACE: u64 = 1;
const CAP_SELF_CSPACE: u64 = 2;
const CAP_SERVER_EP: u64 = 68;
const CAP_READINESS_NTFN: u64 = 14;
const CAP_PCISRV_EP: u64 = 64;
const CAP_NAMESERV_EP: u64 = 5;
const CAP_MMSRV_EP: u64 = 7;

/// Slot for dynamically received IoPort cap from pcisrv
const CAP_RECEIVED_IOPORT: u64 = 80;
/// Slot for dynamically received device untyped cap from pcisrv (MMIO BAR)
const CAP_RECEIVED_DEVUT: u64 = 81;

const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

/// virtio-blk PCI vendor/device IDs
const VIRTIO_VENDOR: u16 = 0x1AF4;
const VIRTIO_BLK_DEVICE: u16 = 0x1001;

/// virtio legacy PCI I/O space register offsets
const VIRTIO_DEV_FEATURES: u64 = 0x00;
const VIRTIO_GUEST_FEATURES: u64 = 0x04;
const VIRTIO_QUEUE_ADDR: u64 = 0x08;
const VIRTIO_QUEUE_SIZE: u64 = 0x0C;
const VIRTIO_QUEUE_SELECT: u64 = 0x0E;
const VIRTIO_QUEUE_NOTIFY: u64 = 0x10;
const VIRTIO_DEVICE_STATUS: u64 = 0x12;
const VIRTIO_ISR_STATUS: u64 = 0x13;
const VIRTIO_BLK_CAPACITY: u64 = 0x14;

const VIRTIO_STATUS_ACK: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
// Ring feature bits (virtio 1.0+ legacy transport feature map)
const VIRTIO_RING_F_INDIRECT_DESC: u32 = 1 << 28;
const VIRTIO_RING_F_EVENT_IDX: u32 = 1 << 29;

const SECTOR_SIZE: u32 = 512;

/// SHM ID for block device data transfer
const BLK_SHM_ID: u64 = 0x424C4B00; // "BLK\0"
const BLK_SHM_PAGES: u64 = 64; // 256KB
const SHM_SIZE: u64 = BLK_SHM_PAGES * 4096;

/// Virtual address for BAR0 MMIO mapping
const BAR0_VADDR: u64 = 0x0000_0000_4000_0000;
/// Virtual address for SHM buffer
const SHM_VADDR: u64 = 0x0000_0000_4200_0000;

/// Hint VA for virtqueue memory; mmsrv may choose another base.
const VQUEUE_HINT_VADDR: u64 = 0x0000_0000_4100_0000;

/// Device state
static mut CAPACITY_SECTORS: u64 = 0;
static mut BAR0_IS_IO: bool = false;
static mut PCI_IOPORT_CAP: u64 = 0;
static mut VIRTIO_INITIALIZED: bool = false;
static mut VQUEUE_BASE: u64 = VQUEUE_HINT_VADDR;

/// Virtqueue state
static mut QUEUE_SIZE: u16 = 0;
static mut QUEUE_PHYS: u64 = 0;
static mut AVAIL_IDX: u16 = 0;
static mut LAST_USED_IDX: u16 = 0;
static mut QUEUE_AVAIL_OFF: u64 = 0;
static mut QUEUE_USED_OFF: u64 = 0;
static mut QUEUE_EVENT_IDX: bool = false;

/// Virtio descriptor table entry
#[repr(C)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

/// Virtio block request header
#[repr(C)]
struct VirtioBlkReqHeader {
    req_type: u32,
    reserved: u32,
    sector: u64,
}

/// Static request header and status byte for DMA
static mut REQ_HEADER: VirtioBlkReqHeader = VirtioBlkReqHeader { req_type: 0, reserved: 0, sector: 0 };
static mut REQ_STATUS: u8 = 0xFF;

/// Compute physical address via vspace_walk for a given virtual address.
fn vaddr_to_phys(vaddr: u64) -> u64 {
    let err = invoke::vspace_walk(CAP_SELF_VSPACE, vaddr, 1);
    if err != 0 {
        return 0;
    }
    match invoke::vspace_walk_result_entry(0) {
        Some((_v, phys, _flags)) => phys + (vaddr & 0xFFF),
        None => 0,
    }
}

/// Virtqueue layout helpers for legacy virtio.
/// Descriptor table starts at offset 0.
/// Available ring at offset: queue_size * 16 (sizeof VirtqDesc).
/// Used ring at offset: aligned_up(desc_size + avail_size, 4096).

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

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn ipc_ctx() -> *mut IpcContext {
    &raw mut salty::__salty_ipc_ctx
}

fn signal_ready() {
    let _ = salty::syscall::syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

/// Read a byte from BAR0.
fn bar_read8(offset: u64) -> u8 {
    unsafe {
        if *(&raw const BAR0_IS_IO) {
            invoke::ioport_in8(PCI_IOPORT_CAP, offset)
        } else {
            let ptr = (BAR0_VADDR + offset) as *const u8;
            ptr.read_volatile()
        }
    }
}

fn bar_read16(offset: u64) -> u16 {
    unsafe {
        if *(&raw const BAR0_IS_IO) {
            invoke::ioport_in16(PCI_IOPORT_CAP, offset)
        } else {
            let ptr = (BAR0_VADDR + offset) as *const u16;
            ptr.read_volatile()
        }
    }
}

fn bar_read32(offset: u64) -> u32 {
    unsafe {
        if *(&raw const BAR0_IS_IO) {
            invoke::ioport_in32(PCI_IOPORT_CAP, offset)
        } else {
            let ptr = (BAR0_VADDR + offset) as *const u32;
            ptr.read_volatile()
        }
    }
}

fn bar_write8(offset: u64, val: u8) {
    unsafe {
        if *(&raw const BAR0_IS_IO) {
            invoke::ioport_out8(PCI_IOPORT_CAP, offset, val);
        } else {
            let ptr = (BAR0_VADDR + offset) as *mut u8;
            ptr.write_volatile(val);
        }
    }
}

fn bar_write16(offset: u64, val: u16) {
    unsafe {
        if *(&raw const BAR0_IS_IO) {
            invoke::ioport_out16(PCI_IOPORT_CAP, offset, val);
        } else {
            let ptr = (BAR0_VADDR + offset) as *mut u16;
            ptr.write_volatile(val);
        }
    }
}

fn bar_write32(offset: u64, val: u32) {
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
fn find_virtio_blk() -> Option<(u8, u8, u8, u32, u64)> {
    let mut msg = SaltyMsg::zeroed();
    msg.label = PCI_FIND_DEVICE;
    msg.length = 2;
    msg.regs[0] = VIRTIO_VENDOR as u64;
    msg.regs[1] = VIRTIO_BLK_DEVICE as u64;

    let mut reply = SaltyMsg::zeroed();
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
fn get_device_caps(bus: u8, dev: u8, func: u8) -> Option<(u64, u64, u32, u8, bool)> {
    let mut msg = SaltyMsg::zeroed();
    msg.label = PCI_GET_CAPS;
    msg.length = 3;
    msg.regs[0] = bus as u64;
    msg.regs[1] = dev as u64;
    msg.regs[2] = func as u64;

    // Set up receive slot for IoPort or device untyped cap transfer
    unsafe {
        ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, CAP_RECEIVED_IOPORT, 0);
    }

    let mut reply = SaltyMsg::zeroed();
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
fn init_virtio(bar0_raw: u32, bar_size: u32) -> bool {
    unsafe {
        if bar0_raw == 0 {
            puts(b"[blkdrv] Invalid BAR0 (0)\n");
            return false;
        }
        *(&raw mut BAR0_IS_IO) = (bar0_raw & 1) != 0;

        if *(&raw const BAR0_IS_IO) {
            let cap = *(&raw const PCI_IOPORT_CAP);
            if cap == 0 {
                puts(b"[blkdrv] BAR0 is I/O space -- no IoPort cap available\n");
                return false;
            }
            puts(b"[blkdrv] BAR0 is I/O space -- using IoPort cap\n");
            return virtio_negotiate();
        }

        // MMIO BAR: map device untyped into our VSpace
        let num_pages = ((bar_size as u64) + 4095) / 4096;
        if num_pages == 0 {
            puts(b"[blkdrv] Invalid MMIO BAR size\n");
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
            puts(b"[blkdrv] MMIO BAR mapping failed\n");
            return false;
        }
        puts(b"[blkdrv] BAR0 MMIO mapped\n");
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

    {
        let mut lb = LineBuf::new();
        lb.str(b"[blkdrv] Capacity: ");
        lb.dec(unsafe { *(&raw const CAPACITY_SECTORS) });
        lb.str(b" sectors (");
        lb.dec(unsafe { *(&raw const CAPACITY_SECTORS) } * 512 / 1024 / 1024);
        lb.str(b" MB)\n");
        lb.flush();
    }

    // Select and read queue 0 size
    bar_write16(VIRTIO_QUEUE_SELECT, 0);
    let qsize = bar_read16(VIRTIO_QUEUE_SIZE);
    if qsize == 0 {
        puts(b"[blkdrv] Queue 0 unavailable\n");
        return false;
    }
    let event_idx = (negotiated_features & VIRTIO_RING_F_EVENT_IDX) != 0;
    let layout = match virtq_layout(qsize, event_idx) {
        Some(v) => v,
        None => {
            puts(b"[blkdrv] Invalid virtqueue size/layout\n");
            return false;
        }
    };

    {
        let mut lb = LineBuf::new();
        lb.str(b"[blkdrv] Queue 0 size: ");
        lb.dec(qsize as u64);
        lb.putc(b'\n');
        lb.flush();
    }

    unsafe { *(&raw mut QUEUE_SIZE) = qsize; }
    unsafe { *(&raw mut QUEUE_AVAIL_OFF) = layout.avail_off; }
    unsafe { *(&raw mut QUEUE_USED_OFF) = layout.used_off; }
    unsafe { *(&raw mut QUEUE_EVENT_IDX) = event_idx; }

    // Allocate virtqueue memory via mmsrv mmap.
    // Size depends on queue size and negotiated layout flags (e.g. EVENT_IDX).
    let vq_bytes = layout.total_bytes;
    let vq_pages = (vq_bytes + 4095) / 4096;
    let ctx = ipc_ctx();
    let mut msg = SaltyMsg::zeroed();
    msg.label = MM_MMAP;
    msg.length = 4;
    msg.regs[0] = VQUEUE_HINT_VADDR;
    msg.regs[1] = vq_pages * 4096;
    msg.regs[2] = 0x3; // PROT_READ | PROT_WRITE
    msg.regs[3] = 0x22; // MAP_PRIVATE | MAP_ANONYMOUS
    let mut reply = SaltyMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != 0 {
        puts(b"[blkdrv] Failed to allocate virtqueue memory\n");
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
        puts(b"[blkdrv] Failed to get virtqueue phys addr\n");
        return false;
    }

    unsafe { *(&raw mut QUEUE_PHYS) = vq_phys; }

    // Set queue address (legacy: PFN = phys / 4096)
    bar_write32(VIRTIO_QUEUE_ADDR, (vq_phys / 4096) as u32);

    // Now set DRIVER_OK
    bar_write8(
        VIRTIO_DEVICE_STATUS,
        VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_DRIVER_OK,
    );

    unsafe { *(&raw mut VIRTIO_INITIALIZED) = true; }
    puts(b"[blkdrv] virtio initialized OK\n");
    true
}

/// Create SHM for data transfer.
fn setup_shm() -> bool {
    let ctx = ipc_ctx();

    let mut msg = SaltyMsg::zeroed();
    msg.label = MM_SHM_CREATE;
    msg.length = 2;
    msg.regs[0] = BLK_SHM_ID;
    msg.regs[1] = BLK_SHM_PAGES;

    let mut reply = SaltyMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || (reply.label != 0 && reply.label != SALTY_ALREADY_EXISTS) {
        let mut lb = LineBuf::new();
        lb.str(b"[blkdrv] SHM create failed: ");
        lb.dec(if err != 0 { err as u64 } else { reply.label });
        lb.putc(b'\n');
        lb.flush();
        return false;
    }

    let mut msg = SaltyMsg::zeroed();
    msg.label = MM_SHM_MAP;
    msg.length = 4;
    msg.regs[0] = BLK_SHM_ID;
    msg.regs[1] = 0;
    msg.regs[2] = SHM_VADDR;
    msg.regs[3] = 0x3; // RW

    let mut reply = SaltyMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != 0 {
        let mut lb = LineBuf::new();
        lb.str(b"[blkdrv] SHM map failed: ");
        lb.dec(if err != 0 { err as u64 } else { reply.label });
        lb.putc(b'\n');
        lb.flush();
        return false;
    }

    puts(b"[blkdrv] SHM region mapped\n");
    true
}

/// Register with name service.
fn register_nameserv() {
    let name = b"blkdrv";
    let mut msg = SaltyMsg::zeroed();
    msg.label = POSIX_NS_REGISTER;
    msg.regs[0] = name.len() as u64;
    msg.length = 1 + (name.len() as u64 + 7) / 8;
    unsafe {
        let dst = &raw mut msg.regs[1] as *mut u8;
        for i in 0..name.len() {
            *dst.add(i) = name[i];
        }
        ipc::set_send_cap_ctx(ipc_ctx(), 0, CAP_SERVER_EP);
        let mut reply = SaltyMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), CAP_NAMESERV_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != SALTY_OK {
            puts(b"[blkdrv] nameserv registration failed\n");
        }
    }
}

fn handle_read(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();

    if !unsafe { *(&raw const VIRTIO_INITIALIZED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    let start_sector = msg.regs[0];
    let count = msg.regs[1];
    let shm_offset = msg.regs[2];

    // Limit to 8 sectors (4KB) per request
    let actual_count = if count > 8 { 8 } else { count };
    let byte_count = actual_count * 512;

    if shm_offset + byte_count > SHM_SIZE {
        reply.label = SALTY_OUT_OF_RANGE;
        return reply;
    }

    unsafe {
        let qsz = *(&raw const QUEUE_SIZE);
        let vq_base = *(&raw const VQUEUE_BASE);
        let avail_off = *(&raw const QUEUE_AVAIL_OFF);
        let used_off = *(&raw const QUEUE_USED_OFF);

        // Get physical addresses for DMA
        let data_vaddr = SHM_VADDR + shm_offset;
        let data_phys = vaddr_to_phys(data_vaddr);
        if data_phys == 0 {
            reply.label = SALTY_BAD_ADDRESS;
            return reply;
        }

        // Set up request header
        let hdr = &raw mut REQ_HEADER;
        (*hdr).req_type = 0; // VIRTIO_BLK_T_IN (read)
        (*hdr).reserved = 0;
        (*hdr).sector = start_sector;
        let hdr_phys = vaddr_to_phys(hdr as u64);
        if hdr_phys == 0 {
            reply.label = SALTY_BAD_ADDRESS;
            return reply;
        }

        // Set up status byte
        *(&raw mut REQ_STATUS) = 0xFF;
        let status_phys = vaddr_to_phys(&raw const REQ_STATUS as u64);
        if status_phys == 0 {
            reply.label = SALTY_BAD_ADDRESS;
            return reply;
        }

        // Set up 3 descriptors
        let desc_base = vq_base as *mut VirtqDesc;

        // Desc 0: request header (device-readable)
        (*desc_base.add(0)).addr = hdr_phys;
        (*desc_base.add(0)).len = 16; // sizeof VirtioBlkReqHeader
        (*desc_base.add(0)).flags = VRING_DESC_F_NEXT;
        (*desc_base.add(0)).next = 1;

        // Desc 1: data buffer (device-writable)
        (*desc_base.add(1)).addr = data_phys;
        (*desc_base.add(1)).len = byte_count as u32;
        (*desc_base.add(1)).flags = VRING_DESC_F_NEXT | VRING_DESC_F_WRITE;
        (*desc_base.add(1)).next = 2;

        // Desc 2: status byte (device-writable)
        (*desc_base.add(2)).addr = status_phys;
        (*desc_base.add(2)).len = 1;
        (*desc_base.add(2)).flags = VRING_DESC_F_WRITE;
        (*desc_base.add(2)).next = 0;

        // Add to available ring
        let avail_base = (vq_base + avail_off) as *mut u16;
        // avail.flags at offset 0
        // avail.idx at offset 1
        // avail.ring[i] at offset 2+i
        let avail_idx = *(&raw const AVAIL_IDX);
        let ring_idx = (avail_idx % qsz) as usize;
        *avail_base.add(2 + ring_idx) = 0; // descriptor chain head = 0
        // Memory barrier (compiler fence)
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        *avail_base.add(1) = avail_idx.wrapping_add(1);
        *(&raw mut AVAIL_IDX) = avail_idx.wrapping_add(1);

        // Kick the device
        bar_write16(VIRTIO_QUEUE_NOTIFY, 0);

        // Poll for completion
        let used_base = (vq_base + used_off) as *const u16;
        // used.flags at offset 0
        // used.idx at offset 1
        let last_used = *(&raw const LAST_USED_IDX);
        let mut spin_count = 0u32;
        loop {
            let used_idx = core::ptr::read_volatile(used_base.add(1));
            if used_idx != last_used {
                *(&raw mut LAST_USED_IDX) = used_idx;
                break;
            }
            spin_count += 1;
            if spin_count > 10_000_000 {
                puts(b"[blkdrv] virtio read timeout\n");
                reply.label = SALTY_BUSY;
                return reply;
            }
        }

        // Check status
        let status = *(&raw const REQ_STATUS);
        if status != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[blkdrv] read error status=");
            lb.dec(status as u64);
            lb.putc(b'\n');
            lb.flush();
            reply.label = SALTY_INVALID_OPERATION;
            return reply;
        }
    }

    reply.label = 0;
    reply.length = 1;
    reply.regs[0] = byte_count;
    reply
}

fn handle_write(msg: &SaltyMsg) -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();

    if !unsafe { *(&raw const VIRTIO_INITIALIZED) } {
        reply.label = SALTY_INVALID_OPERATION;
        return reply;
    }

    let start_sector = msg.regs[0];
    let count = msg.regs[1];
    let shm_offset = msg.regs[2];

    // Limit to 8 sectors (4KB) per request
    let actual_count = if count > 8 { 8 } else { count };
    let byte_count = actual_count * 512;

    if shm_offset + byte_count > SHM_SIZE {
        reply.label = SALTY_OUT_OF_RANGE;
        return reply;
    }

    unsafe {
        let qsz = *(&raw const QUEUE_SIZE);
        let vq_base = *(&raw const VQUEUE_BASE);
        let avail_off = *(&raw const QUEUE_AVAIL_OFF);
        let used_off = *(&raw const QUEUE_USED_OFF);

        // Get physical addresses for DMA
        let data_vaddr = SHM_VADDR + shm_offset;
        let data_phys = vaddr_to_phys(data_vaddr);
        if data_phys == 0 {
            reply.label = SALTY_BAD_ADDRESS;
            return reply;
        }

        // Set up request header
        let hdr = &raw mut REQ_HEADER;
        (*hdr).req_type = 1; // VIRTIO_BLK_T_OUT (write)
        (*hdr).reserved = 0;
        (*hdr).sector = start_sector;
        let hdr_phys = vaddr_to_phys(hdr as u64);
        if hdr_phys == 0 {
            reply.label = SALTY_BAD_ADDRESS;
            return reply;
        }

        // Set up status byte
        *(&raw mut REQ_STATUS) = 0xFF;
        let status_phys = vaddr_to_phys(&raw const REQ_STATUS as u64);
        if status_phys == 0 {
            reply.label = SALTY_BAD_ADDRESS;
            return reply;
        }

        // Set up 3 descriptors
        let desc_base = vq_base as *mut VirtqDesc;

        // Desc 0: request header (device-readable)
        (*desc_base.add(0)).addr = hdr_phys;
        (*desc_base.add(0)).len = 16; // sizeof VirtioBlkReqHeader
        (*desc_base.add(0)).flags = VRING_DESC_F_NEXT;
        (*desc_base.add(0)).next = 1;

        // Desc 1: data buffer (device-readable for write — NO VRING_DESC_F_WRITE)
        (*desc_base.add(1)).addr = data_phys;
        (*desc_base.add(1)).len = byte_count as u32;
        (*desc_base.add(1)).flags = VRING_DESC_F_NEXT;
        (*desc_base.add(1)).next = 2;

        // Desc 2: status byte (device-writable)
        (*desc_base.add(2)).addr = status_phys;
        (*desc_base.add(2)).len = 1;
        (*desc_base.add(2)).flags = VRING_DESC_F_WRITE;
        (*desc_base.add(2)).next = 0;

        // Add to available ring
        let avail_base = (vq_base + avail_off) as *mut u16;
        let avail_idx = *(&raw const AVAIL_IDX);
        let ring_idx = (avail_idx % qsz) as usize;
        *avail_base.add(2 + ring_idx) = 0; // descriptor chain head = 0
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        *avail_base.add(1) = avail_idx.wrapping_add(1);
        *(&raw mut AVAIL_IDX) = avail_idx.wrapping_add(1);

        // Kick the device
        bar_write16(VIRTIO_QUEUE_NOTIFY, 0);

        // Poll for completion
        let used_base = (vq_base + used_off) as *const u16;
        let last_used = *(&raw const LAST_USED_IDX);
        let mut spin_count = 0u32;
        loop {
            let used_idx = core::ptr::read_volatile(used_base.add(1));
            if used_idx != last_used {
                *(&raw mut LAST_USED_IDX) = used_idx;
                break;
            }
            spin_count += 1;
            if spin_count > 10_000_000 {
                puts(b"[blkdrv] virtio write timeout\n");
                reply.label = SALTY_BUSY;
                return reply;
            }
        }

        // Check status
        let status = *(&raw const REQ_STATUS);
        if status != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[blkdrv] write error status=");
            lb.dec(status as u64);
            lb.putc(b'\n');
            lb.flush();
            reply.label = SALTY_INVALID_OPERATION;
            return reply;
        }
    }

    reply.label = 0;
    reply.length = 1;
    reply.regs[0] = byte_count;
    reply
}

fn handle_get_info() -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();
    reply.label = 0;
    reply.length = 2;
    reply.regs[0] = unsafe { *(&raw const CAPACITY_SECTORS) };
    reply.regs[1] = SECTOR_SIZE as u64;
    reply
}

fn handle_get_shm_id() -> SaltyMsg {
    let mut reply = SaltyMsg::zeroed();
    reply.label = 0;
    reply.length = 1;
    reply.regs[0] = BLK_SHM_ID;
    reply
}

/// Server main loop.
fn server_loop() -> ! {
    puts(b"[blkdrv] Entering server loop\n");

    let ctx = ipc_ctx();
    let mut msg = SaltyMsg::zeroed();
    let mut badge: u64 = 0;
    unsafe { ipc::recv_ctx(ctx, CAP_SERVER_EP, &raw mut msg, &raw mut badge); }

    loop {
        let reply = match msg.label {
            BLK_READ => handle_read(&msg),
            BLK_WRITE => handle_write(&msg),
            BLK_GET_INFO => handle_get_info(),
            BLK_FLUSH => {
                let mut r = SaltyMsg::zeroed();
                r.label = 0;
                r
            }
            BLK_GET_SHM_ID => handle_get_shm_id(),
            _ => {
                let mut r = SaltyMsg::zeroed();
                r.label = SALTY_INVALID_OPERATION;
                r
            }
        };

        msg = SaltyMsg::zeroed();
        badge = 0;
        unsafe {
            ipc::reply_recv_ctx(
                ctx, CAP_SERVER_EP, &raw const reply, &raw mut msg, &raw mut badge,
            );
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    puts(b"[blkdrv] virtio-blk Block Device Driver starting\n");

    let _ = invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
    unsafe {
        (*ipc_ctx()).ipc_buffer = IPC_BUF_VADDR as *mut IpcBuffer;
    }

    match find_virtio_blk() {
        Some((bus, dev, func, bar0, _bar0_full)) => {
            {
                let mut lb = LineBuf::new();
                lb.str(b"[blkdrv] Found virtio-blk at ");
                lb.dec(bus as u64);
                lb.putc(b':');
                lb.dec(dev as u64);
                lb.str(b" BAR0=");
                lb.hex(bar0 as u64);
                lb.putc(b'\n');
                lb.flush();
            }

            let Some((_bar_phys, _bar_bits, bar_size, irq, _bar_is_io)) = get_device_caps(bus, dev, func) else {
                puts(b"[blkdrv] Failed to get PCI caps from pcisrv\n");
                register_nameserv();
                signal_ready();
                server_loop()
            };
            {
                let mut lb = LineBuf::new();
                lb.str(b"[blkdrv] IRQ=");
                lb.dec(irq as u64);
                lb.putc(b'\n');
                lb.flush();
            }

            if !init_virtio(bar0, bar_size) {
                puts(b"[blkdrv] Failed to init virtio transport (IoPort cap needed)\n");
                puts(b"[blkdrv] Running in stub mode -- no actual I/O\n");
            }
        }
        None => {
            puts(b"[blkdrv] No virtio-blk device found -- running in stub mode\n");
        }
    }

    if !setup_shm() {
        puts(b"[blkdrv] SHM setup failed -- continuing without SHM\n");
    }

    register_nameserv();
    signal_ready();
    server_loop()
}
