// SPDX-License-Identifier: GPL-2.0-only
//! VirtIO network device transport layer (legacy PCI).
//!
//! Manages two virtqueues: RX (queue 0) for receiving packets and TX (queue 1)
//! for transmitting packets. DMA buffers are allocated via mmsrv.

use salty::consts::*;
use salty::ipc;
use salty::invoke;
use salty::serial::LineBuf;
use salty::types::*;

use crate::{ipc_ctx, puts};

const CAP_SELF_VSPACE: u64 = 1;
const CAP_SELF_CSPACE: u64 = 2;
const CAP_PCISRV_EP: u64 = 64;
const CAP_MMSRV_EP: u64 = 7;

/// Slot for dynamically received BAR cap from pcisrv (IoPort or device untyped)
const CAP_RECEIVED_BAR: u64 = 80;

/// virtio-net PCI vendor/device IDs (legacy transitional)
const VIRTIO_VENDOR: u16 = 0x1AF4;
const VIRTIO_NET_DEVICE: u16 = 0x1000;

/// virtio legacy PCI I/O space register offsets
const VIRTIO_DEV_FEATURES: u64 = 0x00;
const VIRTIO_GUEST_FEATURES: u64 = 0x04;
const VIRTIO_QUEUE_ADDR: u64 = 0x08;
const VIRTIO_QUEUE_SIZE: u64 = 0x0C;
const VIRTIO_QUEUE_SELECT: u64 = 0x0E;
const VIRTIO_QUEUE_NOTIFY: u64 = 0x10;
const VIRTIO_DEVICE_STATUS: u64 = 0x12;
const VIRTIO_ISR_STATUS: u64 = 0x13;

/// Network device config space starts at offset 0x14 (after common virtio header)
const VIRTIO_NET_MAC_OFFSET: u64 = 0x14;

const VIRTIO_STATUS_ACK: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;

/// Feature bits
const VIRTIO_NET_F_MAC: u32 = 1 << 5;
const VIRTIO_RING_F_EVENT_IDX: u32 = 1 << 29;

/// Virtual address for BAR0 MMIO mapping
const BAR0_VADDR: u64 = 0x0000_0000_4000_0000;

/// Hint VA for virtqueue memory
const RX_VQUEUE_HINT: u64 = 0x0000_0000_4100_0000;
const TX_VQUEUE_HINT: u64 = 0x0000_0000_4180_0000;
const DMA_BUF_HINT: u64 = 0x0000_0000_4200_0000;

/// VirtIO network header (10 bytes, prepended to every packet)
#[repr(C)]
pub(crate) struct VirtioNetHdr {
    pub(crate) flags: u8,
    pub(crate) gso_type: u8,
    pub(crate) hdr_len: u16,
    pub(crate) gso_size: u16,
    pub(crate) csum_start: u16,
    pub(crate) csum_offset: u16,
}

pub(crate) const VIRTIO_NET_HDR_SIZE: usize = 10;

/// Virtio descriptor table entry
#[repr(C)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

const VRING_DESC_F_WRITE: u16 = 2;

/// DMA buffer configuration
const RX_BUF_COUNT: usize = 64;
const TX_BUF_COUNT: usize = 32;
const BUF_SIZE: usize = 2048;

// --- Module state ---
pub(crate) static mut MAC_ADDR: [u8; 6] = [0; 6];
static mut BAR0_IS_IO: bool = false;
static mut PCI_IOPORT_CAP: u64 = 0;
static mut VIRTIO_INITIALIZED: bool = false;

// RX queue state (queue 0)
static mut RX_QUEUE_SIZE: u16 = 0;
static mut RX_QUEUE_BASE: u64 = 0;
static mut RX_AVAIL_OFF: u64 = 0;
static mut RX_USED_OFF: u64 = 0;
static mut RX_AVAIL_IDX: u16 = 0;
static mut RX_LAST_USED_IDX: u16 = 0;

// TX queue state (queue 1)
static mut TX_QUEUE_SIZE: u16 = 0;
static mut TX_QUEUE_BASE: u64 = 0;
static mut TX_AVAIL_OFF: u64 = 0;
static mut TX_USED_OFF: u64 = 0;
static mut TX_AVAIL_IDX: u16 = 0;
static mut TX_LAST_USED_IDX: u16 = 0;

// DMA buffer pools
static mut RX_BUF_BASE: u64 = 0;
static mut TX_BUF_BASE: u64 = 0;
static mut RX_BUF_PHYS: [u64; RX_BUF_COUNT] = [0; RX_BUF_COUNT];
static mut TX_BUF_PHYS: [u64; TX_BUF_COUNT] = [0; TX_BUF_COUNT];

// --- Virtqueue layout ---

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

fn virtq_layout(qsz: u16) -> Option<VirtqLayout> {
    if qsz < 3 || (qsz & (qsz - 1)) != 0 {
        return None;
    }
    let q = qsz as u64;
    let desc_off = 0u64;
    let desc_bytes = 16 * q;
    let avail_off = desc_off + desc_bytes;
    let avail_bytes = 4 + 2 * q;
    let used_off = align_up(avail_off + avail_bytes, 4096);
    let used_bytes = 4 + 8 * q;
    let total_bytes = used_off + used_bytes;
    Some(VirtqLayout { desc_off, avail_off, used_off, total_bytes })
}

/// Format a byte as two hex digits (no "0x" prefix) into a LineBuf.
fn format_hex_byte(lb: &mut LineBuf, val: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    lb.putc(HEX[(val >> 4) as usize]);
    lb.putc(HEX[(val & 0x0F) as usize]);
}

// --- BAR I/O ---

fn bar_read8(offset: u64) -> u8 {
    // SAFETY: BAR0_IS_IO and PCI_IOPORT_CAP are set during init before any
    // bar_read/write calls. Single-threaded driver.
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
    // SAFETY: See bar_read8.
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
    // SAFETY: See bar_read8.
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
    // SAFETY: See bar_read8.
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
    // SAFETY: See bar_read8.
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
    // SAFETY: See bar_read8.
    unsafe {
        if *(&raw const BAR0_IS_IO) {
            invoke::ioport_out32(PCI_IOPORT_CAP, offset, val);
        } else {
            let ptr = (BAR0_VADDR + offset) as *mut u32;
            ptr.write_volatile(val);
        }
    }
}

/// Compute physical address via vspace_walk for a given virtual address.
fn vaddr_to_phys(vaddr: u64) -> u64 {
    let err = invoke::vspace_walk(CAP_SELF_VSPACE, vaddr, 1);
    if err != 0 {
        let mut lb = LineBuf::new();
        lb.str(b"[netdrv] vspace_walk failed: ");
        lb.dec(err as u64);
        lb.putc(b'\n');
        lb.flush();
        return 0;
    }
    match invoke::vspace_walk_result_entry(0) {
        Some((_v, phys, _flags)) => phys + (vaddr & 0xFFF),
        None => 0,
    }
}

// --- PCI discovery ---

/// Query pcisrv for virtio-net device.
/// Returns (bus, dev, func, bar0_raw, bar0_full).
pub(crate) fn find_virtio_net() -> Option<(u8, u8, u8, u32, u64)> {
    let mut msg = SaltyMsg::zeroed();
    msg.label = PCI_FIND_DEVICE;
    msg.length = 2;
    msg.regs[0] = VIRTIO_VENDOR as u64;
    msg.regs[1] = VIRTIO_NET_DEVICE as u64;

    let mut reply = SaltyMsg::zeroed();
    // SAFETY: ipc_ctx() returns a valid pointer to our thread-local IPC context.
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

/// Get BAR/IRQ info from pcisrv.
/// Returns (bar_base, bar_bits, bar_size, irq, bar_is_io, has_irq_handler).
pub(crate) fn get_device_caps(bus: u8, dev: u8, func: u8) -> Option<(u64, u64, u32, u8, bool, bool)> {
    let mut msg = SaltyMsg::zeroed();
    msg.label = PCI_GET_CAPS;
    msg.length = 3;
    msg.regs[0] = bus as u64;
    msg.regs[1] = dev as u64;
    msg.regs[2] = func as u64;

    // SAFETY: Set up receive slot for BAR cap (IoPort or device untyped) transfer.
    unsafe {
        ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, CAP_RECEIVED_BAR, 0);
    }

    let mut reply = SaltyMsg::zeroed();
    // SAFETY: ipc_ctx() returns a valid pointer.
    let err = unsafe { ipc::call_ctx(ipc_ctx(), CAP_PCISRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != 0 {
        return None;
    }
    let bar_is_io = reply.regs[4] != 0;
    let has_irq_handler = reply.regs[5] != 0;

    if bar_is_io {
        // Received an IoPort cap at slot 80
        // SAFETY: Single-threaded init path; PCI_IOPORT_CAP written once.
        unsafe { *(&raw mut PCI_IOPORT_CAP) = CAP_RECEIVED_BAR; }
    }
    // For MMIO BAR, the device untyped cap stays at slot 80 (CAP_RECEIVED_BAR).
    // IRQ handler cap from pcisrv (extra cap #1) is at slot 81.

    Some((reply.regs[0], reply.regs[1], reply.regs[2] as u32, reply.regs[3] as u8, bar_is_io, has_irq_handler))
}

// --- Virtio init ---

/// Set up the virtio-net device (legacy PCI transport).
pub(crate) fn init_virtio(bar0_raw: u32, bar_size: u32) -> bool {
    // SAFETY: Single-threaded init path.
    unsafe {
        if bar0_raw == 0 {
            puts(b"[netdrv] Invalid BAR0 (0)\n");
            return false;
        }
        *(&raw mut BAR0_IS_IO) = (bar0_raw & 1) != 0;

        if *(&raw const BAR0_IS_IO) {
            let cap = *(&raw const PCI_IOPORT_CAP);
            if cap == 0 {
                puts(b"[netdrv] BAR0 is I/O space -- no IoPort cap\n");
                return false;
            }
            puts(b"[netdrv] BAR0 is I/O space -- using IoPort cap\n");
            return virtio_negotiate();
        }

        // MMIO BAR: map device untyped into our VSpace
        let num_pages = ((bar_size as u64) + 4095) / 4096;
        if num_pages == 0 {
            puts(b"[netdrv] Invalid MMIO BAR size\n");
            return false;
        }
        let (err, _mapped) = invoke::vspace_map_device_range(
            CAP_SELF_VSPACE,
            CAP_RECEIVED_BAR,
            0,
            BAR0_VADDR,
            num_pages,
            0x3, // RW
        );
        if err != 0 {
            puts(b"[netdrv] MMIO BAR mapping failed\n");
            bar_write8(VIRTIO_DEVICE_STATUS, 0);
            return false;
        }
        puts(b"[netdrv] BAR0 MMIO mapped\n");
        virtio_negotiate()
    }
}

/// Allocate memory via mmsrv MM_MMAP.
fn mmap_alloc(hint_vaddr: u64, num_pages: u64) -> Option<u64> {
    let ctx = ipc_ctx();
    let mut msg = SaltyMsg::zeroed();
    msg.label = MM_MMAP;
    msg.length = 4;
    msg.regs[0] = hint_vaddr;
    msg.regs[1] = num_pages * 4096;
    msg.regs[2] = 0x3; // PROT_READ | PROT_WRITE
    msg.regs[3] = 0x22; // MAP_PRIVATE | MAP_ANONYMOUS
    let mut reply = SaltyMsg::zeroed();
    // SAFETY: ipc_ctx() is valid.
    let err = unsafe { ipc::call_ctx(ctx, CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != 0 {
        return None;
    }
    Some(reply.regs[0])
}

/// Set up a single virtqueue. Returns (queue_base, avail_off, used_off, queue_size).
fn setup_queue(queue_idx: u16, hint_vaddr: u64) -> Option<(u64, u64, u64, u16)> {
    bar_write16(VIRTIO_QUEUE_SELECT, queue_idx);
    let qsize = bar_read16(VIRTIO_QUEUE_SIZE);
    if qsize == 0 {
        return None;
    }
    let layout = virtq_layout(qsize)?;

    let vq_pages = (layout.total_bytes + 4095) / 4096;
    let vq_base = mmap_alloc(hint_vaddr, vq_pages)?;

    // Zero virtqueue memory
    // SAFETY: vq_base was just allocated and mapped; zeroing it is valid.
    unsafe {
        core::ptr::write_bytes(vq_base as *mut u8, 0, (vq_pages * 4096) as usize);
    }

    // Get physical address
    let vq_phys = vaddr_to_phys(vq_base);
    if vq_phys == 0 {
        puts(b"[netdrv] Failed to get virtqueue phys addr\n");
        return None;
    }

    // Set queue address (legacy: PFN = phys / 4096)
    bar_write32(VIRTIO_QUEUE_ADDR, (vq_phys / 4096) as u32);

    Some((vq_base, layout.avail_off, layout.used_off, qsize))
}

/// Initialize virtio-net device: negotiate features, set up queues, read MAC.
fn virtio_negotiate() -> bool {
    // Reset device
    bar_write8(VIRTIO_DEVICE_STATUS, 0);
    bar_write8(VIRTIO_DEVICE_STATUS, VIRTIO_STATUS_ACK);
    bar_write8(VIRTIO_DEVICE_STATUS, VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER);

    // Feature negotiation: only request MAC feature
    let dev_features = bar_read32(VIRTIO_DEV_FEATURES);
    let mut negotiated: u32 = 0;
    if (dev_features & VIRTIO_NET_F_MAC) != 0 {
        negotiated |= VIRTIO_NET_F_MAC;
    }
    bar_write32(VIRTIO_GUEST_FEATURES, negotiated);

    // Read MAC address from config space (6 bytes at offset 0x14)
    // SAFETY: Single-threaded init; MAC_ADDR written once.
    unsafe {
        let mac = &mut *(&raw mut MAC_ADDR);
        for i in 0..6 {
            mac[i] = bar_read8(VIRTIO_NET_MAC_OFFSET + i as u64);
        }
        let mut lb = LineBuf::new();
        lb.str(b"[netdrv] MAC: ");
        for i in 0..6 {
            if i > 0 {
                lb.putc(b':');
            }
            format_hex_byte(&mut lb, mac[i]);
        }
        lb.putc(b'\n');
        lb.flush();
    }

    // Set up RX queue (queue 0)
    let (rx_base, rx_avail, rx_used, rx_qsz) = match setup_queue(0, RX_VQUEUE_HINT) {
        Some(v) => v,
        None => {
            puts(b"[netdrv] Failed to set up RX queue\n");
            bar_write8(VIRTIO_DEVICE_STATUS, 0);
            return false;
        }
    };
    {
        let mut lb = LineBuf::new();
        lb.str(b"[netdrv] RX queue size: ");
        lb.dec(rx_qsz as u64);
        lb.putc(b'\n');
        lb.flush();
    }

    // Set up TX queue (queue 1)
    let (tx_base, tx_avail, tx_used, tx_qsz) = match setup_queue(1, TX_VQUEUE_HINT) {
        Some(v) => v,
        None => {
            puts(b"[netdrv] Failed to set up TX queue\n");
            bar_write8(VIRTIO_DEVICE_STATUS, 0);
            return false;
        }
    };
    {
        let mut lb = LineBuf::new();
        lb.str(b"[netdrv] TX queue size: ");
        lb.dec(tx_qsz as u64);
        lb.putc(b'\n');
        lb.flush();
    }

    // Store queue state
    // SAFETY: Single-threaded init path.
    unsafe {
        *(&raw mut RX_QUEUE_SIZE) = rx_qsz;
        *(&raw mut RX_QUEUE_BASE) = rx_base;
        *(&raw mut RX_AVAIL_OFF) = rx_avail;
        *(&raw mut RX_USED_OFF) = rx_used;
        *(&raw mut RX_AVAIL_IDX) = 0;
        *(&raw mut RX_LAST_USED_IDX) = 0;

        *(&raw mut TX_QUEUE_SIZE) = tx_qsz;
        *(&raw mut TX_QUEUE_BASE) = tx_base;
        *(&raw mut TX_AVAIL_OFF) = tx_avail;
        *(&raw mut TX_USED_OFF) = tx_used;
        *(&raw mut TX_AVAIL_IDX) = 0;
    }

    // Allocate DMA buffer pools
    if !alloc_dma_buffers() {
        puts(b"[netdrv] Failed to allocate DMA buffers\n");
        bar_write8(VIRTIO_DEVICE_STATUS, 0);
        return false;
    }

    // Set DRIVER_OK
    bar_write8(
        VIRTIO_DEVICE_STATUS,
        VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_DRIVER_OK,
    );

    // Pre-fill RX ring with buffers
    prefill_rx_ring();

    // SAFETY: Single-threaded init.
    unsafe { *(&raw mut VIRTIO_INITIALIZED) = true; }
    puts(b"[netdrv] virtio-net initialized OK\n");
    true
}

/// Allocate DMA buffer memory for RX and TX pools.
fn alloc_dma_buffers() -> bool {
    let rx_total_bytes = (RX_BUF_COUNT * BUF_SIZE) as u64;
    let rx_pages = (rx_total_bytes + 4095) / 4096;
    let tx_total_bytes = (TX_BUF_COUNT * BUF_SIZE) as u64;
    let tx_pages = (tx_total_bytes + 4095) / 4096;

    let rx_base = match mmap_alloc(DMA_BUF_HINT, rx_pages) {
        Some(v) => v,
        None => {
            puts(b"[netdrv] Failed to alloc RX DMA buffers\n");
            return false;
        }
    };
    let tx_base = match mmap_alloc(DMA_BUF_HINT + rx_pages * 4096, tx_pages) {
        Some(v) => v,
        None => {
            puts(b"[netdrv] Failed to alloc TX DMA buffers\n");
            return false;
        }
    };

    // Zero buffer memory
    // SAFETY: Memory was just allocated and mapped.
    unsafe {
        core::ptr::write_bytes(rx_base as *mut u8, 0, (rx_pages * 4096) as usize);
        core::ptr::write_bytes(tx_base as *mut u8, 0, (tx_pages * 4096) as usize);
    }

    // Compute physical addresses for each buffer
    // SAFETY: Single-threaded init.
    unsafe {
        *(&raw mut RX_BUF_BASE) = rx_base;
        *(&raw mut TX_BUF_BASE) = tx_base;

        let rx_phys = &mut *(&raw mut RX_BUF_PHYS);
        for i in 0..RX_BUF_COUNT {
            let vaddr = rx_base + (i * BUF_SIZE) as u64;
            rx_phys[i] = vaddr_to_phys(vaddr);
            if rx_phys[i] == 0 {
                puts(b"[netdrv] Failed to get RX buf phys addr\n");
                return false;
            }
        }

        let tx_phys = &mut *(&raw mut TX_BUF_PHYS);
        for i in 0..TX_BUF_COUNT {
            let vaddr = tx_base + (i * BUF_SIZE) as u64;
            tx_phys[i] = vaddr_to_phys(vaddr);
            if tx_phys[i] == 0 {
                puts(b"[netdrv] Failed to get TX buf phys addr\n");
                return false;
            }
        }
    }

    true
}

/// Pre-fill the RX ring with receive buffers.
fn prefill_rx_ring() {
    // SAFETY: Single-threaded init; queue state set up above.
    unsafe {
        let qsz = *(&raw const RX_QUEUE_SIZE) as usize;
        let base = *(&raw const RX_QUEUE_BASE);
        let avail_off = *(&raw const RX_AVAIL_OFF);
        let rx_phys = &*(&raw const RX_BUF_PHYS);

        // Only fill up to min(RX_BUF_COUNT, queue_size)
        let fill_count = core::cmp::min(RX_BUF_COUNT, qsz);

        for i in 0..fill_count {
            // Write descriptor: addr, len, flags=WRITE (device writes to it), next=0
            let desc_ptr = (base + (i * 16) as u64) as *mut VirtqDesc;
            (*desc_ptr).addr = rx_phys[i];
            (*desc_ptr).len = BUF_SIZE as u32;
            (*desc_ptr).flags = VRING_DESC_F_WRITE;
            (*desc_ptr).next = 0;

            // Write available ring entry
            let avail_ring = (base + avail_off + 4 + (i * 2) as u64) as *mut u16;
            *avail_ring = i as u16;
        }

        // Update available ring index
        let avail_idx_ptr = (base + avail_off + 2) as *mut u16;
        *avail_idx_ptr = fill_count as u16;
        *(&raw mut RX_AVAIL_IDX) = fill_count as u16;

        // Notify device about RX queue (queue 0)
        bar_write16(VIRTIO_QUEUE_NOTIFY, 0);
    }
}

// --- Runtime operations ---

/// Read the ISR status register (clears on read).
pub(crate) fn read_isr() -> u8 {
    bar_read8(VIRTIO_ISR_STATUS)
}

/// Reclaim completed TX buffers by updating our local used index.
fn tx_reclaim() {
    // SAFETY: Single-threaded driver.
    unsafe {
        let base = *(&raw const TX_QUEUE_BASE);
        let used_off = *(&raw const TX_USED_OFF);
        let used_idx_ptr = (base + used_off + 2) as *const u16;
        *(&raw mut TX_LAST_USED_IDX) = used_idx_ptr.read_volatile();
    }
}

/// Transmit a packet. `data` is the raw Ethernet frame (no VirtioNetHdr).
///
/// Prepends a zeroed VirtioNetHdr and submits the buffer to the TX ring.
/// Returns false if the packet is too large or all TX buffers are in-flight.
pub(crate) fn tx_packet(data: &[u8]) -> bool {
    let total_len = VIRTIO_NET_HDR_SIZE + data.len();
    if total_len > BUF_SIZE {
        return false;
    }

    // SAFETY: Single-threaded driver. TX queue state is consistent.
    unsafe {
        let qsz = *(&raw const TX_QUEUE_SIZE) as usize;
        if qsz == 0 {
            return false;
        }
        let avail_idx = *(&raw const TX_AVAIL_IDX);

        // Check that we have a free TX buffer before overwriting
        let inflight = avail_idx.wrapping_sub(*(&raw const TX_LAST_USED_IDX));
        if inflight as usize >= TX_BUF_COUNT {
            tx_reclaim();
            let inflight = (*(&raw const TX_AVAIL_IDX)).wrapping_sub(*(&raw const TX_LAST_USED_IDX));
            if inflight as usize >= TX_BUF_COUNT {
                return false;
            }
        }

        // Use avail_idx mod TX_BUF_COUNT as the buffer index
        let buf_idx = (avail_idx as usize) % TX_BUF_COUNT;
        let tx_base_val = *(&raw const TX_BUF_BASE);
        let tx_phys = &*(&raw const TX_BUF_PHYS);

        // Write VirtioNetHdr (zeroed) + data into the TX buffer
        let buf_vaddr = tx_base_val + (buf_idx * BUF_SIZE) as u64;
        let buf_ptr = buf_vaddr as *mut u8;

        // Zero the VirtioNetHdr
        core::ptr::write_bytes(buf_ptr, 0, VIRTIO_NET_HDR_SIZE);
        // Copy packet data
        for i in 0..data.len() {
            *buf_ptr.add(VIRTIO_NET_HDR_SIZE + i) = data[i];
        }

        // Write descriptor
        let base = *(&raw const TX_QUEUE_BASE);
        let desc_idx = (avail_idx as usize) % qsz;
        let desc_ptr = (base + (desc_idx * 16) as u64) as *mut VirtqDesc;
        (*desc_ptr).addr = tx_phys[buf_idx];
        (*desc_ptr).len = total_len as u32;
        (*desc_ptr).flags = 0; // Device reads from this buffer
        (*desc_ptr).next = 0;

        // Add to available ring
        let avail_off = *(&raw const TX_AVAIL_OFF);
        let ring_entry = (base + avail_off + 4 + (desc_idx * 2) as u64) as *mut u16;
        *ring_entry = desc_idx as u16;

        // Memory barrier (compiler fence)
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        // Update available index
        let new_avail = avail_idx.wrapping_add(1);
        let avail_idx_ptr = (base + avail_off + 2) as *mut u16;
        *avail_idx_ptr = new_avail;
        *(&raw mut TX_AVAIL_IDX) = new_avail;

        // Notify device (TX queue = queue 1)
        bar_write16(VIRTIO_QUEUE_NOTIFY, 1);
    }

    true
}

/// Poll the RX used ring for a completed receive.
/// Returns (descriptor_index, total_byte_length) if a packet is available.
pub(crate) fn rx_poll() -> Option<(usize, usize)> {
    // SAFETY: Single-threaded driver.
    unsafe {
        let base = *(&raw const RX_QUEUE_BASE);
        let used_off = *(&raw const RX_USED_OFF);
        let qsz = *(&raw const RX_QUEUE_SIZE) as usize;
        let last_used = *(&raw const RX_LAST_USED_IDX);

        // Read used ring index
        let used_idx_ptr = (base + used_off + 2) as *const u16;
        let used_idx = used_idx_ptr.read_volatile();

        if last_used == used_idx {
            return None;
        }

        // Read the used ring entry with volatile reads (device-written memory)
        let entry_off = used_off + 4 + ((last_used as usize % qsz) * 8) as u64;
        let used_entry = (base + entry_off) as *const u32;
        let desc_id = used_entry.read_volatile() as usize;
        let byte_len = used_entry.add(1).read_volatile() as usize;

        // Validate descriptor index from device
        if desc_id >= qsz {
            return None;
        }

        *(&raw mut RX_LAST_USED_IDX) = last_used.wrapping_add(1);

        Some((desc_id, byte_len))
    }
}

/// Get a slice to the received packet data for the given buffer index.
///
/// The returned slice includes the VirtioNetHdr prefix. Callers should skip
/// the first `VIRTIO_NET_HDR_SIZE` bytes for the actual Ethernet frame.
///
/// Callers must process the returned data before calling `rx_repost()` for
/// the same `buf_idx`, as reposting makes the buffer writable by the device.
pub(crate) fn rx_get_data(buf_idx: usize, len: usize) -> &'static [u8] {
    if buf_idx >= RX_BUF_COUNT {
        return &[];
    }
    // SAFETY: buf_idx < RX_BUF_COUNT (checked above), memory is allocated and
    // mapped during init. Single-threaded driver; caller processes data before
    // calling rx_repost() which re-posts the buffer to the device.
    unsafe {
        let rx_base_val = *(&raw const RX_BUF_BASE);
        let buf_vaddr = rx_base_val + (buf_idx * BUF_SIZE) as u64;
        let actual_len = core::cmp::min(len, BUF_SIZE);
        core::slice::from_raw_parts(buf_vaddr as *const u8, actual_len)
    }
}

/// Re-post a receive buffer back to the RX available ring.
pub(crate) fn rx_repost(buf_idx: usize) {
    if buf_idx >= RX_BUF_COUNT {
        return;
    }
    // SAFETY: Single-threaded driver. buf_idx validated above.
    unsafe {
        let base = *(&raw const RX_QUEUE_BASE);
        let avail_off = *(&raw const RX_AVAIL_OFF);
        let qsz = *(&raw const RX_QUEUE_SIZE) as usize;
        let rx_phys = &*(&raw const RX_BUF_PHYS);
        let avail_idx = *(&raw const RX_AVAIL_IDX);

        // Re-initialize the descriptor
        let desc_ptr = (base + (buf_idx * 16) as u64) as *mut VirtqDesc;
        (*desc_ptr).addr = rx_phys[buf_idx];
        (*desc_ptr).len = BUF_SIZE as u32;
        (*desc_ptr).flags = VRING_DESC_F_WRITE;
        (*desc_ptr).next = 0;

        // Add to available ring
        let ring_entry = (base + avail_off + 4 + ((avail_idx as usize % qsz) * 2) as u64) as *mut u16;
        *ring_entry = buf_idx as u16;

        // Memory barrier
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        // Update available index
        let new_avail = avail_idx.wrapping_add(1);
        let avail_idx_ptr = (base + avail_off + 2) as *mut u16;
        *avail_idx_ptr = new_avail;
        *(&raw mut RX_AVAIL_IDX) = new_avail;

        // Notify device (RX queue = queue 0)
        bar_write16(VIRTIO_QUEUE_NOTIFY, 0);
    }
}
