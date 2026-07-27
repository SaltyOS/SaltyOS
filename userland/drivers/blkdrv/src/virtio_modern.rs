// SPDX-License-Identifier: GPL-2.0-only
//! VirtIO 1.0+ (modern) PCI transport for virtio-blk.
//!
//! Discovers modern virtio devices (device ID 0x1042) and locates register
//! regions via PCI vendor-specific capabilities.  Falls back to legacy
//! transport when the device is transitional (0x1001).

use trona_kernel::core_types::*;
use trona_kernel::invoke;
use trona_kernel::ipc;
use trona_protocol::common::{TRONA_NOT_FOUND, TRONA_OK};
use trona_protocol::mm::{MM_MMAP, MMAP_KIND_ANON};
use trona_protocol::pci::{PCI_FIND_DEVICE, PCI_GET_BAR_CAP, PCI_READ_CONFIG32};

use crate::ipc_ctx;
use crate::{CAPACITY_SECTORS, VIRTIO_INITIALIZED, VQUEUE_BASE};
use crate::{QUEUE_AVAIL_OFF, QUEUE_EVENT_IDX, QUEUE_PHYS, QUEUE_SIZE, QUEUE_USED_OFF};

const CAP_SELF_VSPACE: u64 = 1;
const CAP_SELF_CSPACE: u64 = 2;

// Service-local role: `Require=pcidrv-ep.socket` resolved via
// `trona_runtime::local_cap!` in `main.rs` (see `crate::pcidrv_ep`).

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

/// Ask mmsrv to auto-place virtqueue memory inside the client's
/// registered mmap window.
const VQUEUE_HINT_VADDR: u64 = 0;

/// Virtio 1.0 status bits
const VIRTIO_STATUS_ACK: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTQ_AVAIL_F_NO_INTERRUPT: u16 = 1;
/// Feature bit 32, exposed as bit 0 when DEVICE_FEATURE_SELECT=1.
const VIRTIO_F_VERSION_1_HI: u32 = 1 << 0;

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
/// Persistent BAR-cap slots matched to `BAR_VADDRS`.
static mut BAR_CAP_SLOTS: [u64; 6] = [0; 6];

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
    let err = unsafe {
        ipc::mp_call_ctx(
            ipc_ctx(),
            crate::pcidrv_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[blkdrv] pci_config_read32 off=");
        _lb.hex(offset as u64);
        _lb.str(b" err=");
        _lb.hex(err as u64);
        _lb.str(b" label=");
        _lb.hex(reply.label);
        _lb.str(b" val=");
        _lb.hex(reply.regs[0]);
        _lb.putc(b'\n');
    });
    if err != 0 || reply.label != 0 {
        return 0xFFFF_FFFF;
    }
    reply.regs[0] as u32
}

/// Query pcidrv for modern virtio-blk device (device ID 0x1042).
pub(crate) fn find_virtio_blk_modern() -> Option<(u8, u8, u8)> {
    let ep = crate::pcidrv_ep().addr();
    if ep == 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] Missing pcidrv_ep capability\n");
        });
        return None;
    }

    let mut msg = TronaMsg::zeroed();
    msg.label = PCI_FIND_DEVICE;
    msg.length = 2;
    msg.regs[0] = VIRTIO_VENDOR as u64;
    msg.regs[1] = VIRTIO_BLK_MODERN_DEVICE as u64;

    let mut reply = TronaMsg::zeroed();
    let err = unsafe {
        ipc::mp_call_ctx(
            ipc_ctx(),
            ep,
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] PCI_FIND_DEVICE(modern) IPC failed ep=");
            _lb.hex(ep);
            _lb.str(b" err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
        return None;
    }
    if reply.label == TRONA_NOT_FOUND {
        return None;
    }
    if reply.label != TRONA_OK {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] PCI_FIND_DEVICE(modern) failed label=");
            _lb.hex(reply.label);
            _lb.str(b"\n");
        });
        return None;
    }

    let bus = reply.regs[0] as u8;
    let dev = reply.regs[1] as u8;
    let func = reply.regs[2] as u8;
    Some((bus, dev, func))
}

fn clear_bar_cap_slot(bar_idx: u8) {
    unsafe {
        let slot = *(&raw const BAR_CAP_SLOTS[bar_idx as usize]);
        if slot == 0 {
            return;
        }
        trona_runtime::core::slot_alloc::delete_and_free(slot);
        *(&raw mut BAR_CAP_SLOTS[bar_idx as usize]) = 0;
    }
}

fn ensure_bar_cap_slot(bar_idx: u8) -> Option<u64> {
    unsafe {
        let slot = *(&raw const BAR_CAP_SLOTS[bar_idx as usize]);
        if slot != 0 {
            return Some(slot);
        }
        let slot = trona_runtime::core::slot_alloc::slot_alloc()?;
        *(&raw mut BAR_CAP_SLOTS[bar_idx as usize]) = slot;
        Some(slot)
    }
}

/// Map a PCI BAR into our address space via pcidrv PCI_GET_BAR_CAP.
fn map_bar(bus: u8, dev: u8, func: u8, bar_idx: u8) -> Option<(u64, u32)> {
    let recv_slot = ensure_bar_cap_slot(bar_idx)?;

    let mut msg = TronaMsg::zeroed();
    msg.label = PCI_GET_BAR_CAP;
    msg.length = 4;
    msg.regs[0] = bus as u64;
    msg.regs[1] = dev as u64;
    msg.regs[2] = func as u64;
    msg.regs[3] = bar_idx as u64;

    unsafe {
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(
            ipc_ctx(),
            CAP_SELF_CSPACE,
            recv_slot,
            0,
        );
    }

    let mut reply = TronaMsg::zeroed();
    let err = unsafe {
        ipc::mp_call_ctx(
            ipc_ctx(),
            crate::pcidrv_ep().addr(),
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    if err != 0 || reply.label != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] PCI_GET_BAR_CAP failed bar=");
            _lb.dec(bar_idx as u64);
            _lb.str(b" recv_slot=");
            _lb.hex(recv_slot);
            _lb.str(b" err=");
            _lb.hex(err as u64);
            _lb.str(b" label=");
            _lb.hex(reply.label);
            _lb.putc(b'\n');
        });
        clear_bar_cap_slot(bar_idx);
        return None;
    }

    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[blkdrv] PCI_GET_BAR_CAP ok bar=");
        _lb.dec(bar_idx as u64);
        _lb.str(b" recv_slot=");
        _lb.hex(recv_slot);
        _lb.str(b" phys=");
        _lb.hex(reply.regs[0]);
        _lb.str(b" size=");
        _lb.hex(reply.regs[1]);
        _lb.str(b" is_io=");
        _lb.dec((reply.regs[2] != 0) as u64);
        _lb.putc(b'\n');
    });

    let bar_size = reply.regs[1] as u32;
    let is_io = reply.regs[2] != 0;
    if bar_size == 0 || is_io {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] Rejecting BAR mapping bar=");
            _lb.dec(bar_idx as u64);
            _lb.str(b" size=");
            _lb.hex(bar_size as u64);
            _lb.str(b" is_io=");
            _lb.dec(is_io as u64);
            _lb.putc(b'\n');
        });
        clear_bar_cap_slot(bar_idx);
        return None;
    }

    // Map device untyped
    let num_pages = ((bar_size as u64) + 4095) / 4096;
    let vaddr = BAR_VADDR_BASE + (bar_idx as u64) * BAR_VADDR_STRIDE;

    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[blkdrv] Mapping BAR ");
        _lb.dec(bar_idx as u64);
        _lb.str(b" phys=");
        _lb.hex(reply.regs[0]);
        _lb.str(b" size=");
        _lb.hex(bar_size as u64);
        _lb.str(b" pages=");
        _lb.hex(num_pages);
        _lb.str(b" vaddr=");
        _lb.hex(vaddr);
        _lb.str(b" slot=");
        _lb.hex(recv_slot);
        _lb.putc(b'\n');
    });

    // MMIO must be uncacheable; write-back caching corrupts device-register
    // access on real hardware.
    let map_flags = (trona_kernel::uapi::KERNITE_PAGE_FLAG_WRITABLE
        | trona_kernel::uapi::KERNITE_PAGE_FLAG_USER
        | trona_kernel::uapi::KERNITE_PAGE_FLAG_NOCACHE) as u64;
    let (map_err, mapped) = invoke::vspace_map_device_range(
        trona_kernel::core_types::CapRef::flat(CAP_SELF_VSPACE),
        trona_runtime::core::slot_alloc::resolved_cap_ref(recv_slot),
        0,
        vaddr,
        num_pages,
        map_flags,
    );
    if map_err != 0 || mapped != num_pages {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] vspace_map_device_range failed bar=");
            _lb.dec(bar_idx as u64);
            _lb.str(b" err=");
            _lb.hex(map_err as u64);
            _lb.str(b" mapped=");
            _lb.hex(mapped);
            _lb.putc(b'/');
            _lb.hex(num_pages);
            _lb.str(b" phys=");
            _lb.hex(reply.regs[0]);
            _lb.str(b" size=");
            _lb.hex(bar_size as u64);
            _lb.str(b" vaddr=");
            _lb.hex(vaddr);
            _lb.putc(b'\n');
        });
        clear_bar_cap_slot(bar_idx);
        return None;
    }

    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[blkdrv] BAR mapped bar=");
        _lb.dec(bar_idx as u64);
        _lb.str(b" vaddr=");
        _lb.hex(vaddr);
        _lb.str(b" size=");
        _lb.hex(bar_size as u64);
        _lb.putc(b'\n');
    });

    unsafe {
        *(&raw mut BAR_VADDRS[bar_idx as usize]) = vaddr;
    }
    Some((vaddr, bar_size))
}

/// Walk PCI capability list and find virtio capabilities.
fn scan_virtio_caps(bus: u8, dev: u8, func: u8) -> Option<VirtioModernLayout> {
    // Read capabilities pointer from PCI config offset 0x34
    let cap_ptr_raw = pci_config_read32(bus, dev, func, 0x34);
    let mut cap_offset = (cap_ptr_raw & 0xFF) as u8;

    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[blkdrv] scan_virtio_caps ");
        _lb.dec(bus as u64);
        _lb.putc(b':');
        _lb.dec(dev as u64);
        _lb.putc(b':');
        _lb.dec(func as u64);
        _lb.str(b" cap_ptr=");
        _lb.hex(cap_offset as u64);
        _lb.putc(b'\n');
    });

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
            let len = pci_config_read32(bus, dev, func, cap_offset + 12);

            trona_runtime::udebug!(|_lb| {
                _lb.str(b"[blkdrv] virtio cap off=");
                _lb.hex(cap_offset as u64);
                _lb.str(b" type=");
                _lb.hex(cfg_type as u64);
                _lb.str(b" bar=");
                _lb.dec(bar_num as u64);
                _lb.str(b" off=");
                _lb.hex(off as u64);
                _lb.str(b" len=");
                _lb.hex(len as u64);
                _lb.putc(b'\n');
            });

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
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] Missing required virtio PCI capabilities\n");
        });
        return None;
    }

    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[blkdrv] modern layout common=");
        _lb.dec(common_bar as u64);
        _lb.str(b"@");
        _lb.hex(common_offset as u64);
        _lb.str(b" notify=");
        _lb.dec(notify_bar as u64);
        _lb.str(b"@");
        _lb.hex(notify_offset as u64);
        _lb.str(b" mult=");
        _lb.hex(notify_off_multiplier as u64);
        _lb.str(b" isr=");
        _lb.dec(isr_bar as u64);
        _lb.str(b"@");
        _lb.hex(isr_offset as u64);
        _lb.str(b" device=");
        _lb.dec(device_bar as u64);
        _lb.str(b"@");
        _lb.hex(device_offset as u64);
        _lb.putc(b'\n');
    });

    // Map required BARs
    let bars_needed = [common_bar, notify_bar, isr_bar, device_bar];
    for &b in &bars_needed {
        if b == 0xFF {
            continue;
        }
        let vaddr = unsafe { *(&raw const BAR_VADDRS[b as usize]) };
        if vaddr == 0 {
            if map_bar(bus, dev, func, b).is_none() {
                trona_runtime::uerror!(|_lb| {
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
        unsafe {
            core::ptr::write_volatile(addr as *mut u8, val);
        }
    }
    fn common_read16(&self, off: u32) -> u16 {
        let addr = self.common_cfg_base + self.common_cfg_offset as u64 + off as u64;
        unsafe { core::ptr::read_volatile(addr as *const u16) }
    }
    fn common_write16(&self, off: u32, val: u16) {
        let addr = self.common_cfg_base + self.common_cfg_offset as u64 + off as u64;
        unsafe {
            core::ptr::write_volatile(addr as *mut u16, val);
        }
    }
    fn common_read32(&self, off: u32) -> u32 {
        let addr = self.common_cfg_base + self.common_cfg_offset as u64 + off as u64;
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }
    fn common_write32(&self, off: u32, val: u32) {
        let addr = self.common_cfg_base + self.common_cfg_offset as u64 + off as u64;
        unsafe {
            core::ptr::write_volatile(addr as *mut u32, val);
        }
    }
    fn device_read32(&self, off: u32) -> u32 {
        let addr = self.device_cfg_base + self.device_cfg_offset as u64 + off as u64;
        unsafe { core::ptr::read_volatile(addr as *const u32) }
    }
    fn notify_queue(&self, queue_notify_off: u16) {
        let addr = self.notify_base
            + self.notify_offset as u64
            + (queue_notify_off as u64) * (self.notify_off_multiplier as u64);
        unsafe {
            core::ptr::write_volatile(addr as *mut u16, 0);
        }
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

/// Modern virtio notify offset for queue 0 (stored after init).
static mut MODERN_QUEUE_NOTIFY_OFF: u16 = 0;
/// Stored layout for notify/ISR access from handlers.
static mut MODERN_LAYOUT: Option<VirtioModernLayout> = None;

fn align_up(value: u64, align: u64) -> u64 {
    (value + (align - 1)) & !(align - 1)
}

/// Initialize virtio-blk device via modern (1.0+) PCI transport.
pub(crate) fn init_virtio_modern(bus: u8, dev: u8, func: u8) -> bool {
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[blkdrv] Probing modern virtio transport\n");
    });

    let layout = match scan_virtio_caps(bus, dev, func) {
        Some(l) => l,
        None => return false,
    };

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[blkdrv] Modern virtio caps discovered\n");
    });

    // 1. Reset device
    layout.common_write8(CC_DEVICE_STATUS, 0);
    // 2. Acknowledge
    layout.common_write8(CC_DEVICE_STATUS, VIRTIO_STATUS_ACK);
    // 3. Driver
    layout.common_write8(CC_DEVICE_STATUS, VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER);

    // 4. Feature negotiation. Modern PCI transport requires the
    // VERSION_1 feature; without it a transitional device can accept
    // setup far enough to look initialized while never completing
    // modern virtqueue requests.
    layout.common_write32(CC_DEVICE_FEATURE_SELECT, 0);
    let _dev_features_lo = layout.common_read32(CC_DEVICE_FEATURE);
    layout.common_write32(CC_DEVICE_FEATURE_SELECT, 1);
    let dev_features_hi = layout.common_read32(CC_DEVICE_FEATURE);
    if (dev_features_hi & VIRTIO_F_VERSION_1_HI) == 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] Modern virtio lacks VERSION_1 feature\n");
        });
        return false;
    }

    layout.common_write32(CC_DRIVER_FEATURE_SELECT, 0);
    layout.common_write32(CC_DRIVER_FEATURE, 0); // no features requested
    layout.common_write32(CC_DRIVER_FEATURE_SELECT, 1);
    layout.common_write32(CC_DRIVER_FEATURE, VIRTIO_F_VERSION_1_HI);

    // 5. FEATURES_OK
    layout.common_write8(
        CC_DEVICE_STATUS,
        VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK,
    );
    let status = layout.common_read8(CC_DEVICE_STATUS);
    if (status & VIRTIO_STATUS_FEATURES_OK) == 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] Device did not accept features\n");
        });
        return false;
    }

    // Read capacity from device config (offset 0 = capacity u64)
    let cap_lo = layout.device_read32(0);
    let cap_hi = layout.device_read32(4);
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

    // 6. Queue setup
    layout.common_write16(CC_QUEUE_SELECT, 0);
    let qsize = layout.common_read16(CC_QUEUE_SIZE);
    if qsize == 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] Queue 0 unavailable\n");
        });
        return false;
    }
    layout.common_write16(CC_QUEUE_SIZE, qsize);

    {
        trona_runtime::uinfo!(|_lb| {
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

    // Get physical addresses per-region (pages may not be contiguous)
    let desc_phys = crate::virtio::vaddr_to_phys(vq_base);
    let avail_phys = crate::virtio::vaddr_to_phys(vq_base + avail_off);
    let used_phys = crate::virtio::vaddr_to_phys(vq_base + used_off);
    if desc_phys == 0 || avail_phys == 0 || used_phys == 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[blkdrv] Failed to translate virtqueue ring addresses\n");
        });
        return false;
    }
    unsafe {
        *(&raw mut QUEUE_PHYS) = desc_phys;
    }

    layout.common_write32(CC_QUEUE_DESC_LO, desc_phys as u32);
    layout.common_write32(CC_QUEUE_DESC_HI, (desc_phys >> 32) as u32);
    layout.common_write32(CC_QUEUE_AVAIL_LO, avail_phys as u32);
    layout.common_write32(CC_QUEUE_AVAIL_HI, (avail_phys >> 32) as u32);
    layout.common_write32(CC_QUEUE_USED_LO, used_phys as u32);
    layout.common_write32(CC_QUEUE_USED_HI, (used_phys >> 32) as u32);

    // Save notify offset for this queue
    let queue_notify_off = layout.common_read16(CC_QUEUE_NOTIFY_OFF);
    unsafe {
        *(&raw mut MODERN_QUEUE_NOTIFY_OFF) = queue_notify_off;
    }

    // blkdrv uses synchronous used.idx polling, so queue-completion interrupts
    // only create shared-IRQ churn with no forward progress.
    unsafe {
        let avail_base = (vq_base + avail_off) as *mut u16;
        core::ptr::write_volatile(avail_base, VIRTQ_AVAIL_F_NO_INTERRUPT);
    }
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[blkdrv] Queue interrupts suppressed (polling mode)\n");
    });

    // Enable queue
    layout.common_write16(CC_QUEUE_ENABLE, 1);

    // 7. DRIVER_OK
    layout.common_write8(
        CC_DEVICE_STATUS,
        VIRTIO_STATUS_ACK
            | VIRTIO_STATUS_DRIVER
            | VIRTIO_STATUS_FEATURES_OK
            | VIRTIO_STATUS_DRIVER_OK,
    );

    // Store layout for runtime use
    unsafe {
        *(&raw mut MODERN_LAYOUT) = Some(layout);
    }
    unsafe {
        *(&raw mut VIRTIO_INITIALIZED) = true;
    }

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[blkdrv] Modern virtio initialized OK\n");
    });
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
