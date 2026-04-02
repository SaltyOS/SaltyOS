// SPDX-License-Identifier: GPL-2.0-only
//! VirtIO 1.0+ (modern) PCI transport for virtio-net.
//!
//! Discovers modern virtio-net devices (device ID 0x1041) and locates register
//! regions via PCI vendor-specific capabilities.

use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::invoke;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;

use crate::ipc_ctx;

const CAP_SELF_VSPACE: u64 = 1;
const CAP_SELF_CSPACE: u64 = 2;
const CAP_PCIDRV_EP: u64 = 64;
const CAP_MMSRV_EP: u64 = 7;

/// Modern virtio-net PCI device ID (non-transitional)
const VIRTIO_NET_MODERN_DEVICE: u16 = 0x1041;
const VIRTIO_VENDOR: u16 = 0x1AF4;

/// PCI capability IDs
const PCI_CAP_ID_VENDOR: u8 = 0x09;

/// Virtio PCI capability types
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

/// Virtual addresses for BAR MMIO mappings
const BAR_VADDR_BASE: u64 = 0x0000_0000_4000_0000;
const BAR_VADDR_STRIDE: u64 = 0x0000_0000_0020_0000;

/// Slot allocation for receiving BAR device untyped caps
const CAP_BAR_SLOT_BASE: u64 = 90;

/// Virtio 1.0 status bits
const VIRTIO_STATUS_ACK: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;

/// Feature bits
const VIRTIO_NET_F_MAC: u32 = 1 << 5;
const VIRTIO_NET_F_MRG_RXBUF: u32 = 1 << 15;

// Common config register offsets (virtio 1.0 spec §4.1.4.3)
const CC_DEVICE_FEATURE_SELECT: u32 = 0x00;
const CC_DEVICE_FEATURE: u32 = 0x04;
const CC_DRIVER_FEATURE_SELECT: u32 = 0x08;
const CC_DRIVER_FEATURE: u32 = 0x0C;
const CC_NUM_QUEUES: u32 = 0x12;
const CC_DEVICE_STATUS: u32 = 0x14;
const CC_QUEUE_SELECT: u32 = 0x16;
const CC_QUEUE_SIZE: u32 = 0x18;
const CC_QUEUE_ENABLE: u32 = 0x1C;
const CC_QUEUE_NOTIFY_OFF: u32 = 0x1E;
const CC_QUEUE_DESC_LO: u32 = 0x20;
const CC_QUEUE_DESC_HI: u32 = 0x24;
const CC_QUEUE_AVAIL_LO: u32 = 0x28;
const CC_QUEUE_AVAIL_HI: u32 = 0x2C;
const CC_QUEUE_USED_LO: u32 = 0x30;
const CC_QUEUE_USED_HI: u32 = 0x34;

/// Discovered modern virtio register layout
pub(crate) struct VirtioModernLayout {
    common_cfg_base: u64,
    common_cfg_offset: u32,
    notify_base: u64,
    notify_offset: u32,
    notify_off_multiplier: u32,
    isr_base: u64,
    isr_offset: u32,
    device_cfg_base: u64,
    device_cfg_offset: u32,
}

/// Mapped BAR virtual addresses (indexed by BAR number 0-5)
static mut BAR_VADDRS: [u64; 6] = [0; 6];

/// Stored layout for runtime access from event loop.
pub(crate) static mut MODERN_LAYOUT: Option<VirtioModernLayout> = None;
/// Per-queue notify offsets (RX=0, TX=1)
static mut QUEUE_NOTIFY_OFFS: [u16; 2] = [0; 2];

// ---------------------------------------------------------------------------
// PCI config space read via pcidrv IPC
// ---------------------------------------------------------------------------

fn pci_config_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let mut msg = TronaMsg::zeroed();
    msg.label = PCI_READ_CONFIG32;
    msg.length = 4;
    msg.regs[0] = bus as u64;
    msg.regs[1] = dev as u64;
    msg.regs[2] = func as u64;
    msg.regs[3] = offset as u64;

    let mut reply = TronaMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ipc_ctx(), CAP_PCIDRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != 0 {
        return 0xFFFF_FFFF;
    }
    reply.regs[0] as u32
}

// ---------------------------------------------------------------------------
// Device discovery
// ---------------------------------------------------------------------------

/// Query pcidrv for modern virtio-net device (device ID 0x1041).
pub(crate) fn find_virtio_net_modern() -> Option<(u8, u8, u8)> {
    let mut msg = TronaMsg::zeroed();
    msg.label = PCI_FIND_DEVICE;
    msg.length = 2;
    msg.regs[0] = VIRTIO_VENDOR as u64;
    msg.regs[1] = VIRTIO_NET_MODERN_DEVICE as u64;

    let mut reply = TronaMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ipc_ctx(), CAP_PCIDRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != 0 {
        return None;
    }

    Some((reply.regs[0] as u8, reply.regs[1] as u8, reply.regs[2] as u8))
}

// ---------------------------------------------------------------------------
// BAR mapping
// ---------------------------------------------------------------------------

fn map_bar(bus: u8, dev: u8, func: u8, bar_idx: u8) -> Option<(u64, u32)> {
    let recv_slot = CAP_BAR_SLOT_BASE + bar_idx as u64;

    let mut msg = TronaMsg::zeroed();
    msg.label = PCI_GET_BAR_CAP;
    msg.length = 4;
    msg.regs[0] = bus as u64;
    msg.regs[1] = dev as u64;
    msg.regs[2] = func as u64;
    msg.regs[3] = bar_idx as u64;

    unsafe {
        ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, recv_slot, 0);
    }

    let mut reply = TronaMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ipc_ctx(), CAP_PCIDRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != 0 {
        return None;
    }

    let bar_size = reply.regs[1] as u32;
    let is_io = reply.regs[2] != 0;
    if bar_size == 0 || is_io {
        return None;
    }

    let num_pages = ((bar_size as u64) + 4095) / 4096;
    let vaddr = BAR_VADDR_BASE + (bar_idx as u64) * BAR_VADDR_STRIDE;

    let (map_err, _mapped) = invoke::vspace_map_device_range(
        CAP_SELF_VSPACE,
        recv_slot,
        0,
        vaddr,
        num_pages,
        0x3 | 0x8, // RW + cache_disable (MMIO must be uncacheable)
    );
    if map_err != 0 {
        return None;
    }

    unsafe { *(&raw mut BAR_VADDRS[bar_idx as usize]) = vaddr; }
    Some((vaddr, bar_size))
}

// ---------------------------------------------------------------------------
// PCI capability scanning
// ---------------------------------------------------------------------------

fn scan_virtio_caps(bus: u8, dev: u8, func: u8) -> Option<VirtioModernLayout> {
    let cap_ptr_raw = pci_config_read32(bus, dev, func, 0x34);
    let mut cap_offset = (cap_ptr_raw & 0xFF) as u8;

    let mut common_bar: u8 = 0xFF;
    let mut common_offset: u32 = 0;
    let mut notify_bar: u8 = 0xFF;
    let mut notify_offset: u32 = 0;
    let mut notify_off_multiplier: u32 = 0;
    let mut isr_bar: u8 = 0xFF;
    let mut isr_offset: u32 = 0;
    let mut device_bar: u8 = 0xFF;
    let mut device_offset: u32 = 0;

    while cap_offset != 0 {
        let cap_header = pci_config_read32(bus, dev, func, cap_offset);
        let cap_id = (cap_header & 0xFF) as u8;
        let next = ((cap_header >> 8) & 0xFF) as u8;

        if cap_id == PCI_CAP_ID_VENDOR {
            let type_len = (cap_header >> 16) as u16;
            let cfg_type = ((type_len >> 8) & 0xFF) as u8;
            let bar_word = pci_config_read32(bus, dev, func, cap_offset + 4);
            let bar_num = (bar_word & 0xFF) as u8;
            let off = pci_config_read32(bus, dev, func, cap_offset + 8);

            match cfg_type {
                VIRTIO_PCI_CAP_COMMON_CFG => {
                    common_bar = bar_num;
                    common_offset = off;
                }
                VIRTIO_PCI_CAP_NOTIFY_CFG => {
                    notify_bar = bar_num;
                    notify_offset = off;
                    notify_off_multiplier = pci_config_read32(bus, dev, func, cap_offset + 16);
                }
                VIRTIO_PCI_CAP_ISR_CFG => {
                    isr_bar = bar_num;
                    isr_offset = off;
                }
                VIRTIO_PCI_CAP_DEVICE_CFG => {
                    device_bar = bar_num;
                    device_offset = off;
                }
                _ => {}
            }
        }

        cap_offset = next;
    }

    if common_bar == 0xFF || notify_bar == 0xFF || device_bar == 0xFF {
        trona::uerror!(|_lb| { _lb.str(b"[netdrv] Missing required virtio PCI capabilities\n"); });
        return None;
    }

    let bars_needed = [common_bar, notify_bar, isr_bar, device_bar];
    for &b in &bars_needed {
        if b == 0xFF {
            continue;
        }
        let vaddr = unsafe { *(&raw const BAR_VADDRS[b as usize]) };
        if vaddr == 0 {
            if map_bar(bus, dev, func, b).is_none() {
                trona::uerror!(|_lb| {
                    _lb.str(b"[netdrv] Failed to map BAR ");
                    _lb.dec(b as u64);
                    _lb.putc(b'\n');
                });
                return None;
            }
        }
    }

    let common_base = unsafe { *(&raw const BAR_VADDRS[common_bar as usize]) };
    let notify_base = unsafe { *(&raw const BAR_VADDRS[notify_bar as usize]) };
    let isr_base = if isr_bar != 0xFF {
        unsafe { *(&raw const BAR_VADDRS[isr_bar as usize]) }
    } else {
        0
    };
    let device_base = unsafe { *(&raw const BAR_VADDRS[device_bar as usize]) };

    Some(VirtioModernLayout {
        common_cfg_base: common_base,
        common_cfg_offset: common_offset,
        notify_base,
        notify_offset,
        notify_off_multiplier,
        isr_base,
        isr_offset,
        device_cfg_base: device_base,
        device_cfg_offset: device_offset,
    })
}

// ---------------------------------------------------------------------------
// Modern register accessors
// ---------------------------------------------------------------------------

impl VirtioModernLayout {
    fn common_read8(&self, off: u32) -> u8 {
        let addr = self.common_cfg_base + self.common_cfg_offset as u64 + off as u64;
        unsafe { core::ptr::read_volatile(addr as *const u8) }
    }
    fn common_write8(&self, off: u32, val: u8) {
        let addr = self.common_cfg_base + self.common_cfg_offset as u64 + off as u64;
        unsafe { core::ptr::write_volatile(addr as *mut u8, val); }
    }
    fn common_read16(&self, off: u32) -> u16 {
        let addr = self.common_cfg_base + self.common_cfg_offset as u64 + off as u64;
        unsafe { core::ptr::read_volatile(addr as *const u16) }
    }
    fn common_write16(&self, off: u32, val: u16) {
        let addr = self.common_cfg_base + self.common_cfg_offset as u64 + off as u64;
        unsafe { core::ptr::write_volatile(addr as *mut u16, val); }
    }
    fn common_read32(&self, off: u32) -> u32 {
        let addr = self.common_cfg_base + self.common_cfg_offset as u64 + off as u64;
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }
    fn common_write32(&self, off: u32, val: u32) {
        let addr = self.common_cfg_base + self.common_cfg_offset as u64 + off as u64;
        unsafe { core::ptr::write_volatile(addr as *mut u32, val); }
    }
    fn device_read8(&self, off: u32) -> u8 {
        let addr = self.device_cfg_base + self.device_cfg_offset as u64 + off as u64;
        unsafe { core::ptr::read_volatile(addr as *const u8) }
    }
    pub(crate) fn notify_queue(&self, queue_notify_off: u16, queue_idx: u16) {
        let addr = self.notify_base
            + self.notify_offset as u64
            + (queue_notify_off as u64) * (self.notify_off_multiplier as u64);
        unsafe { core::ptr::write_volatile(addr as *mut u16, queue_idx); }
    }
    pub(crate) fn isr_read(&self) -> u8 {
        if self.isr_base == 0 {
            return 0;
        }
        let addr = self.isr_base + self.isr_offset as u64;
        unsafe { core::ptr::read_volatile(addr as *const u8) }
    }
}

// ---------------------------------------------------------------------------
// Modern virtio-net initialization
// ---------------------------------------------------------------------------

fn align_up(value: u64, align: u64) -> u64 {
    (value + (align - 1)) & !(align - 1)
}

/// Initialize virtio-net via modern (1.0+) PCI transport.
///
/// Sets up the same global state as `virtio::init_virtio` so the legacy
/// RX/TX ring code in virtio.rs can be reused.
pub(crate) fn init_virtio_modern(bus: u8, dev: u8, func: u8) -> bool {
    trona::uinfo!(|_lb| { _lb.str(b"[netdrv] Probing modern virtio transport\n"); });

    let layout = match scan_virtio_caps(bus, dev, func) {
        Some(l) => l,
        None => return false,
    };

    trona::uinfo!(|_lb| { _lb.str(b"[netdrv] Modern virtio caps discovered\n"); });

    // Reset
    layout.common_write8(CC_DEVICE_STATUS, 0);
    layout.common_write8(CC_DEVICE_STATUS, VIRTIO_STATUS_ACK);
    layout.common_write8(CC_DEVICE_STATUS, VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER);

    // Feature negotiation
    // Page 0 (bits 0-31): device-specific features
    layout.common_write32(CC_DEVICE_FEATURE_SELECT, 0);
    let dev_features0 = layout.common_read32(CC_DEVICE_FEATURE);
    let mut driver_features0: u32 = 0;
    if (dev_features0 & VIRTIO_NET_F_MAC) != 0 {
        driver_features0 |= VIRTIO_NET_F_MAC;
    }
    let use_mrg_rxbuf = (dev_features0 & VIRTIO_NET_F_MRG_RXBUF) != 0;
    if use_mrg_rxbuf {
        driver_features0 |= VIRTIO_NET_F_MRG_RXBUF;
    }
    layout.common_write32(CC_DRIVER_FEATURE_SELECT, 0);
    layout.common_write32(CC_DRIVER_FEATURE, driver_features0);

    // Page 1 (bits 32-63): transport features — VIRTIO_F_VERSION_1 is mandatory
    layout.common_write32(CC_DEVICE_FEATURE_SELECT, 1);
    let dev_features1 = layout.common_read32(CC_DEVICE_FEATURE);
    let mut driver_features1: u32 = 0;
    if (dev_features1 & 1) != 0 {
        // VIRTIO_F_VERSION_1 = bit 32 = bit 0 of page 1
        driver_features1 |= 1;
    }
    layout.common_write32(CC_DRIVER_FEATURE_SELECT, 1);
    layout.common_write32(CC_DRIVER_FEATURE, driver_features1);

    // FEATURES_OK
    layout.common_write8(
        CC_DEVICE_STATUS,
        VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK,
    );
    let status = layout.common_read8(CC_DEVICE_STATUS);
    if (status & VIRTIO_STATUS_FEATURES_OK) == 0 {
        trona::uerror!(|_lb| { _lb.str(b"[netdrv] Device did not accept features\n"); });
        return false;
    }

    // Read MAC address from device config
    if (driver_features0 & VIRTIO_NET_F_MAC) != 0 {
        let mut mac = [0u8; 6];
        for i in 0..6 {
            mac[i] = layout.device_read8(i as u32);
        }
        unsafe { *(&raw mut crate::virtio::MAC_ADDR) = mac; }

        trona::uinfo!(|_lb| {
            _lb.str(b"[netdrv] MAC: ");
            for i in 0..6 {
                if i > 0 { _lb.putc(b':'); }
                let hi = b"0123456789abcdef"[(mac[i] >> 4) as usize];
                let lo = b"0123456789abcdef"[(mac[i] & 0xF) as usize];
                _lb.putc(hi);
                _lb.putc(lo);
            }
            _lb.putc(b'\n');
        });
    }

    // Set up RX queue (queue 0) and TX queue (queue 1)
    let num_queues = layout.common_read16(CC_NUM_QUEUES);
    if num_queues < 2 {
        trona::uerror!(|_lb| { _lb.str(b"[netdrv] Device has fewer than 2 queues\n"); });
        return false;
    }

    // Use the legacy virtio.rs queue setup infrastructure by setting global state
    // and delegating DMA allocation to the existing init_virtio path.
    // Instead, we do a minimal modern queue setup here.
    for qi in 0u16..2 {
        layout.common_write16(CC_QUEUE_SELECT, qi);
        let qsize = layout.common_read16(CC_QUEUE_SIZE);
        if qsize == 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[netdrv] Queue ");
                _lb.dec(qi as u64);
                _lb.str(b" unavailable\n");
            });
            return false;
        }

        // Compute virtqueue layout
        let q = qsize as u64;
        let desc_bytes = 16 * q;
        let avail_off = desc_bytes;
        let avail_bytes = 4 + 2 * q;
        let used_off = align_up(avail_off + avail_bytes, 4096);
        let used_bytes = 4 + 8 * q;
        let total_bytes = used_off + used_bytes;
        let vq_pages = (total_bytes + 4095) / 4096;

        // Allocate virtqueue memory via mmsrv
        let hint_vaddr: u64 = if qi == 0 { 0x4100_0000 } else { 0x4180_0000 };
        let mut msg = TronaMsg::zeroed();
        msg.label = MM_MMAP;
        msg.length = 4;
        msg.regs[0] = hint_vaddr;
        msg.regs[1] = vq_pages * 4096;
        msg.regs[2] = 0x3;
        msg.regs[3] = 0x22;
        let mut reply = TronaMsg::zeroed();
        let err = unsafe { ipc::call_ctx(ipc_ctx(), CAP_MMSRV_EP, &raw const msg, &raw mut reply) };
        if err != 0 || reply.label != 0 {
            trona::uerror!(|_lb| { _lb.str(b"[netdrv] Failed to allocate virtqueue memory\n"); });
            return false;
        }
        let vq_base = reply.regs[0];

        // Zero memory
        unsafe {
            let ptr = vq_base as *mut u8;
            for i in 0..(vq_pages * 4096) as usize {
                *ptr.add(i) = 0;
            }
        }

        // Get physical addresses per-region (pages may not be contiguous)
        let desc_phys = crate::virtio::vaddr_to_phys(vq_base);
        let avail_phys = crate::virtio::vaddr_to_phys(vq_base + avail_off);
        let used_phys = crate::virtio::vaddr_to_phys(vq_base + used_off);
        if desc_phys == 0 || avail_phys == 0 || used_phys == 0 {
            trona::uerror!(|_lb| { _lb.str(b"[netdrv] Failed to get virtqueue phys addr\n"); });
            return false;
        }

        layout.common_write32(CC_QUEUE_DESC_LO, desc_phys as u32);
        layout.common_write32(CC_QUEUE_DESC_HI, (desc_phys >> 32) as u32);
        layout.common_write32(CC_QUEUE_AVAIL_LO, avail_phys as u32);
        layout.common_write32(CC_QUEUE_AVAIL_HI, (avail_phys >> 32) as u32);
        layout.common_write32(CC_QUEUE_USED_LO, used_phys as u32);
        layout.common_write32(CC_QUEUE_USED_HI, (used_phys >> 32) as u32);

        // Save notify offset
        let queue_notify_off = layout.common_read16(CC_QUEUE_NOTIFY_OFF);
        unsafe { *(&raw mut QUEUE_NOTIFY_OFFS[qi as usize]) = queue_notify_off; }

        // Enable queue
        layout.common_write16(CC_QUEUE_ENABLE, 1);

        // Diagnostic: log queue physical addresses
        // Store queue state in legacy globals for reuse
        unsafe {
            if qi == 0 {
                *(&raw mut crate::virtio::RX_QUEUE_SIZE) = qsize;
                *(&raw mut crate::virtio::RX_QUEUE_BASE) = vq_base;
                *(&raw mut crate::virtio::RX_AVAIL_OFF) = avail_off;
                *(&raw mut crate::virtio::RX_USED_OFF) = used_off;
            } else {
                *(&raw mut crate::virtio::TX_QUEUE_SIZE) = qsize;
                *(&raw mut crate::virtio::TX_QUEUE_BASE) = vq_base;
                *(&raw mut crate::virtio::TX_AVAIL_OFF) = avail_off;
                *(&raw mut crate::virtio::TX_USED_OFF) = used_off;
                *(&raw mut crate::virtio::TX_INFLIGHT_LIMIT) =
                    core::cmp::min(32usize, qsize as usize);
            }
        }

        trona::uinfo!(|_lb| {
            _lb.str(b"[netdrv] Queue ");
            _lb.dec(qi as u64);
            _lb.str(b" size: ");
            _lb.dec(qsize as u64);
            _lb.putc(b'\n');
        });
    }

    // Allocate DMA buffers (reuse legacy allocation logic)
    if !crate::virtio::alloc_dma_buffers() {
        trona::uerror!(|_lb| { _lb.str(b"[netdrv] Failed to allocate DMA buffers\n"); });
        return false;
    }

    // Store layout so transport_notify_rx() uses modern path
    unsafe {
        *(&raw mut MODERN_LAYOUT) = Some(layout);
        *(&raw mut crate::USING_MODERN_TRANSPORT) = true;
        *(&raw mut crate::virtio::USE_FLEX_LAYOUT) = true;
        crate::virtio::set_net_hdr_size(if use_mrg_rxbuf { 12 } else { 10 });
    }

    trona::udebug!(|_lb| {
        _lb.str(b"[netdrv] modern net hdr size=");
        _lb.dec(if use_mrg_rxbuf { 12 } else { 10 });
        _lb.str(b" mrg_rxbuf=");
        _lb.dec(use_mrg_rxbuf as u64);
        _lb.putc(b'\n');
    });

    // DRIVER_OK must be set BEFORE prefill_rx_ring: the device ignores
    // queue notifications until DRIVER_OK is active (virtio 1.0 §3.1.1).
    unsafe {
        if let Some(ref l) = *(&raw const MODERN_LAYOUT) {
            l.common_write8(
                CC_DEVICE_STATUS,
                VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK,
            );
        }
    }

    // Pre-fill RX ring with receive buffers (calls transport_notify_rx internally)
    crate::virtio::prefill_rx_ring();

    // SAFETY: Single-threaded init path.
    unsafe {
        *(&raw mut crate::virtio::VIRTIO_INITIALIZED) = true;
    }

    trona::uinfo!(|_lb| { _lb.str(b"[netdrv] Modern virtio-net initialized OK\n"); });
    true
}

// ---------------------------------------------------------------------------
// Runtime transport helpers (called from event loop / virtio.rs)
// ---------------------------------------------------------------------------

/// Read ISR status (modern transport).
pub(crate) fn modern_isr_read() -> u8 {
    unsafe {
        if let Some(ref layout) = *(&raw const MODERN_LAYOUT) {
            layout.isr_read()
        } else {
            0
        }
    }
}

/// Notify RX queue (modern transport).
pub(crate) fn modern_notify_rx() {
    unsafe {
        if let Some(ref layout) = *(&raw const MODERN_LAYOUT) {
            layout.notify_queue(*(&raw const QUEUE_NOTIFY_OFFS[0]), 0);
        }
    }
}

/// Notify TX queue (modern transport).
pub(crate) fn modern_notify_tx() {
    unsafe {
        if let Some(ref layout) = *(&raw const MODERN_LAYOUT) {
            layout.notify_queue(*(&raw const QUEUE_NOTIFY_OFFS[1]), 1);
        }
    }
}
