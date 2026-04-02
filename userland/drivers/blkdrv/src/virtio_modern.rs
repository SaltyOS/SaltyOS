// SPDX-License-Identifier: GPL-2.0-only
//! VirtIO 1.0+ (modern) PCI transport for virtio-blk.
//!
//! Discovers modern virtio devices (device ID 0x1042) and locates register
//! regions via PCI vendor-specific capabilities.  Falls back to legacy
//! transport when the device is transitional (0x1001).

use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::invoke;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;

use crate::ipc_ctx;
use crate::{CAPACITY_SECTORS, VIRTIO_INITIALIZED, VQUEUE_BASE};
use crate::{QUEUE_SIZE, QUEUE_PHYS, QUEUE_AVAIL_OFF, QUEUE_USED_OFF, QUEUE_EVENT_IDX};

const CAP_SELF_VSPACE: u64 = 1;
const CAP_SELF_CSPACE: u64 = 2;
const CAP_PCIDRV_EP: u64 = 64;
const CAP_MMSRV_EP: u64 = 7;

/// Slot for dynamically received device untyped cap from pcidrv (MMIO BAR)
const CAP_RECEIVED_DEVUT: u64 = 81;

/// Modern virtio-blk PCI device ID (non-transitional)
const VIRTIO_BLK_MODERN_DEVICE: u16 = 0x1042;
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
const BAR_VADDR_STRIDE: u64 = 0x0000_0000_0020_0000; // 2 MB per BAR

/// Hint VA for virtqueue memory
const VQUEUE_HINT_VADDR: u64 = 0x0000_0000_4100_0000;

/// Virtio 1.0 status bits
const VIRTIO_STATUS_ACK: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTQ_AVAIL_F_NO_INTERRUPT: u16 = 1;

/// Discovered modern virtio register layout
struct VirtioModernLayout {
    /// BAR virtual address for common config
    common_cfg_base: u64,
    common_cfg_offset: u32,
    /// BAR virtual address for notifications
    notify_base: u64,
    notify_offset: u32,
    notify_off_multiplier: u32,
    /// BAR virtual address for ISR
    isr_base: u64,
    isr_offset: u32,
    /// BAR virtual address for device config
    device_cfg_base: u64,
    device_cfg_offset: u32,
}

/// Mapped BAR virtual addresses (indexed by BAR number 0-5)
static mut BAR_VADDRS: [u64; 6] = [0; 6];

/// Read 32-bit PCI config via pcidrv IPC
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

/// Query pcidrv for modern virtio-blk device (device ID 0x1042).
pub(crate) fn find_virtio_blk_modern() -> Option<(u8, u8, u8)> {
    let mut msg = TronaMsg::zeroed();
    msg.label = PCI_FIND_DEVICE;
    msg.length = 2;
    msg.regs[0] = VIRTIO_VENDOR as u64;
    msg.regs[1] = VIRTIO_BLK_MODERN_DEVICE as u64;

    let mut reply = TronaMsg::zeroed();
    let err = unsafe { ipc::call_ctx(ipc_ctx(), CAP_PCIDRV_EP, &raw const msg, &raw mut reply) };
    if err != 0 || reply.label != 0 {
        return None;
    }

    let bus = reply.regs[0] as u8;
    let dev = reply.regs[1] as u8;
    let func = reply.regs[2] as u8;
    Some((bus, dev, func))
}

/// Slot allocation for receiving BAR device untyped caps.
/// Each BAR gets its own slot so multiple BARs can be mapped simultaneously.
const CAP_BAR_SLOT_BASE: u64 = 82;

/// Map a PCI BAR into our address space via pcidrv PCI_GET_BAR_CAP.
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

    // Map device untyped
    let num_pages = ((bar_size as u64) + 4095) / 4096;
    let vaddr = BAR_VADDR_BASE + (bar_idx as u64) * BAR_VADDR_STRIDE;

    let (map_err, _mapped) = invoke::vspace_map_device_range(
        CAP_SELF_VSPACE,
        recv_slot,
        0,
        vaddr,
        num_pages,
        0x3, // RW
    );
    if map_err != 0 {
        return None;
    }

    unsafe { *(&raw mut BAR_VADDRS[bar_idx as usize]) = vaddr; }
    Some((vaddr, bar_size))
}

/// Walk PCI capability list and find virtio capabilities.
fn scan_virtio_caps(bus: u8, dev: u8, func: u8) -> Option<VirtioModernLayout> {
    // Read capabilities pointer from PCI config offset 0x34
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
        // Read capability header: [cap_id (8), next (8), ...]
        let cap_header = pci_config_read32(bus, dev, func, cap_offset);
        let cap_id = (cap_header & 0xFF) as u8;
        let next = ((cap_header >> 8) & 0xFF) as u8;

        if cap_id == PCI_CAP_ID_VENDOR {
            // Virtio PCI capability structure:
            //   +0: cap_id, next
            //   +2: cap_len, cfg_type
            //   +4: bar
            //   +8: offset (32-bit)
            //   +12: length (32-bit)
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
                    // Notify off multiplier is at cap_offset + 16
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
        trona::uerror!(|_lb| { _lb.str(b"[blkdrv] Missing required virtio PCI capabilities\n"); });
        return None;
    }

    // Map required BARs
    let bars_needed = [common_bar, notify_bar, isr_bar, device_bar];
    for &b in &bars_needed {
        if b == 0xFF {
            continue;
        }
        let vaddr = unsafe { *(&raw const BAR_VADDRS[b as usize]) };
        if vaddr == 0 {
            if map_bar(bus, dev, func, b).is_none() {
                trona::uerror!(|_lb| {
                    _lb.str(b"[blkdrv] Failed to map BAR ");
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
    fn device_read32(&self, off: u32) -> u32 {
        let addr = self.device_cfg_base + self.device_cfg_offset as u64 + off as u64;
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }
    fn notify_queue(&self, queue_notify_off: u16) {
        let addr = self.notify_base
            + self.notify_offset as u64
            + (queue_notify_off as u64) * (self.notify_off_multiplier as u64);
        unsafe { core::ptr::write_volatile(addr as *mut u16, 0); }
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
// Common config register offsets (virtio 1.0 spec §4.1.4.3)
// ---------------------------------------------------------------------------
const CC_DEVICE_FEATURE_SELECT: u32 = 0x00;
const CC_DEVICE_FEATURE: u32 = 0x04;
const CC_DRIVER_FEATURE_SELECT: u32 = 0x08;
const CC_DRIVER_FEATURE: u32 = 0x0C;
const CC_MSIX_CONFIG: u32 = 0x10;
const CC_NUM_QUEUES: u32 = 0x12;
const CC_DEVICE_STATUS: u32 = 0x14;
const CC_CONFIG_GENERATION: u32 = 0x15;
const CC_QUEUE_SELECT: u32 = 0x16;
const CC_QUEUE_SIZE: u32 = 0x18;
const CC_QUEUE_MSIX_VECTOR: u32 = 0x1A;
const CC_QUEUE_ENABLE: u32 = 0x1C;
const CC_QUEUE_NOTIFY_OFF: u32 = 0x1E;
const CC_QUEUE_DESC_LO: u32 = 0x20;
const CC_QUEUE_DESC_HI: u32 = 0x24;
const CC_QUEUE_AVAIL_LO: u32 = 0x28;
const CC_QUEUE_AVAIL_HI: u32 = 0x2C;
const CC_QUEUE_USED_LO: u32 = 0x30;
const CC_QUEUE_USED_HI: u32 = 0x34;

/// Modern virtio notify offset for queue 0 (stored after init).
static mut MODERN_QUEUE_NOTIFY_OFF: u16 = 0;
/// Stored layout for notify/ISR access from handlers.
static mut MODERN_LAYOUT: Option<VirtioModernLayout> = None;

fn align_up(value: u64, align: u64) -> u64 {
    (value + (align - 1)) & !(align - 1)
}

/// Initialize virtio-blk device via modern (1.0+) PCI transport.
pub(crate) fn init_virtio_modern(bus: u8, dev: u8, func: u8) -> bool {
    trona::uinfo!(|_lb| { _lb.str(b"[blkdrv] Probing modern virtio transport\n"); });

    let layout = match scan_virtio_caps(bus, dev, func) {
        Some(l) => l,
        None => return false,
    };

    trona::uinfo!(|_lb| { _lb.str(b"[blkdrv] Modern virtio caps discovered\n"); });

    // 1. Reset device
    layout.common_write8(CC_DEVICE_STATUS, 0);
    // 2. Acknowledge
    layout.common_write8(CC_DEVICE_STATUS, VIRTIO_STATUS_ACK);
    // 3. Driver
    layout.common_write8(CC_DEVICE_STATUS, VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER);

    // 4. Feature negotiation (accept defaults, no extra features)
    layout.common_write32(CC_DEVICE_FEATURE_SELECT, 0);
    let _dev_features_lo = layout.common_read32(CC_DEVICE_FEATURE);
    layout.common_write32(CC_DRIVER_FEATURE_SELECT, 0);
    layout.common_write32(CC_DRIVER_FEATURE, 0); // no features requested

    // 5. FEATURES_OK
    layout.common_write8(
        CC_DEVICE_STATUS,
        VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK,
    );
    let status = layout.common_read8(CC_DEVICE_STATUS);
    if (status & VIRTIO_STATUS_FEATURES_OK) == 0 {
        trona::uerror!(|_lb| { _lb.str(b"[blkdrv] Device did not accept features\n"); });
        return false;
    }

    // Read capacity from device config (offset 0 = capacity u64)
    let cap_lo = layout.device_read32(0);
    let cap_hi = layout.device_read32(4);
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

    // 6. Queue setup
    layout.common_write16(CC_QUEUE_SELECT, 0);
    let qsize = layout.common_read16(CC_QUEUE_SIZE);
    if qsize == 0 {
        trona::uerror!(|_lb| { _lb.str(b"[blkdrv] Queue 0 unavailable\n"); });
        return false;
    }

    {
        trona::uinfo!(|_lb| {
            _lb.str(b"[blkdrv] Queue 0 size: ");
            _lb.dec(qsize as u64);
            _lb.putc(b'\n');
        });
    }

    // Compute virtqueue layout (split ring)
    let q = qsize as u64;
    let desc_bytes = 16 * q;
    let avail_off = desc_bytes;
    let avail_bytes = 4 + 2 * q;
    let used_off = align_up(avail_off + avail_bytes, 4096);
    let used_bytes = 4 + 8 * q;
    let total_bytes = used_off + used_bytes;

    unsafe {
        *(&raw mut QUEUE_SIZE) = qsize;
        *(&raw mut QUEUE_AVAIL_OFF) = avail_off;
        *(&raw mut QUEUE_USED_OFF) = used_off;
        *(&raw mut QUEUE_EVENT_IDX) = false;
    }

    // Allocate virtqueue memory via mmsrv mmap
    let vq_pages = (total_bytes + 4095) / 4096;
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

    // Get physical addresses per-region (pages may not be contiguous)
    let desc_phys = crate::virtio::vaddr_to_phys(vq_base);
    let avail_phys = crate::virtio::vaddr_to_phys(vq_base + avail_off);
    let used_phys = crate::virtio::vaddr_to_phys(vq_base + used_off);
    if desc_phys == 0 || avail_phys == 0 || used_phys == 0 {
        trona::uerror!(|_lb| { _lb.str(b"[blkdrv] Failed to translate virtqueue ring addresses\n"); });
        return false;
    }
    unsafe { *(&raw mut QUEUE_PHYS) = desc_phys; }

    layout.common_write32(CC_QUEUE_DESC_LO, desc_phys as u32);
    layout.common_write32(CC_QUEUE_DESC_HI, (desc_phys >> 32) as u32);
    layout.common_write32(CC_QUEUE_AVAIL_LO, avail_phys as u32);
    layout.common_write32(CC_QUEUE_AVAIL_HI, (avail_phys >> 32) as u32);
    layout.common_write32(CC_QUEUE_USED_LO, used_phys as u32);
    layout.common_write32(CC_QUEUE_USED_HI, (used_phys >> 32) as u32);

    // Save notify offset for this queue
    let queue_notify_off = layout.common_read16(CC_QUEUE_NOTIFY_OFF);
    unsafe { *(&raw mut MODERN_QUEUE_NOTIFY_OFF) = queue_notify_off; }

    // blkdrv uses synchronous used.idx polling, so queue-completion interrupts
    // only create shared-IRQ churn with no forward progress.
    unsafe {
        let avail_base = (vq_base + avail_off) as *mut u16;
        core::ptr::write_volatile(avail_base, VIRTQ_AVAIL_F_NO_INTERRUPT);
    }
    trona::udebug!(|_lb| { _lb.str(b"[blkdrv] Queue interrupts suppressed (polling mode)\n"); });

    // Enable queue
    layout.common_write16(CC_QUEUE_ENABLE, 1);

    // 7. DRIVER_OK
    layout.common_write8(
        CC_DEVICE_STATUS,
        VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK,
    );

    // Store layout for runtime use
    unsafe { *(&raw mut MODERN_LAYOUT) = Some(layout); }
    unsafe { *(&raw mut VIRTIO_INITIALIZED) = true; }

    trona::uinfo!(|_lb| { _lb.str(b"[blkdrv] Modern virtio initialized OK\n"); });
    true
}

/// Notify queue 0 (modern transport).
pub(crate) fn modern_notify_queue() {
    unsafe {
        if let Some(ref layout) = *(&raw const MODERN_LAYOUT) {
            layout.notify_queue(*(&raw const MODERN_QUEUE_NOTIFY_OFF));
        }
    }
}

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
