//! SaltyOS PCI Enumeration Server
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Scans PCI bus 0, builds a device registry, and distributes BAR/IRQ
//! capabilities to drivers.
//!
//! Architecture-specific config space access is in arch/ modules:
//!   - x86_64: I/O port mechanism 1 (ports 0xCF8/0xCFC)
//!   - aarch64: ECAM memory-mapped access (QEMU virt ECAM at 0x4010_0000)
//!
//! IPC protocol:
//!   Label 1 = PCI_FIND_DEVICE: MR0=vendor_id, MR1=device_id
//!       -> MR0=bus, MR1=dev, MR2=func, MR3=class, MR4=bar0..MR7=bar3
//!   Label 2 = PCI_GET_CAPS: MR0=bus, MR1=dev, MR2=func
//!       -> MR0=bar_phys, MR1=bar_size_bits, MR2=bar_size, MR3=irq
//!   Label 3 = PCI_LIST: -> MR0=count, then (vendor|device, class, bar0) tuples
//!   Label 4 = PCI_READ_CONFIG32: MR0=bus, MR1=dev, MR2=func, MR3=offset -> MR0=value
//!   Label 5 = PCI_GET_BAR_CAP: MR0=bus, MR1=dev, MR2=func, MR3=bar_idx
//!       -> MR0=bar_phys, MR1=bar_size, MR2=bar_is_io, extra_cap #0
//!
//! Capability access:
//!   CAP_SELF_* slots 0..=2 are ABI-stable.
//!   Service/runtime attachments such as the service endpoint, readiness
//!   notification, PCI config access, namesrv, and device_control are resolved
//!   through trona role getters rather than fixed startup slots.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_posix;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;

#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64.rs"]
mod arch;
#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64.rs"]
mod arch;

use trona_kernel::core_types::*;
use trona_kernel::invoke;
use trona_kernel::ipc;
use trona_protocol::common::{
    TRONA_INVALID_ARGUMENT, TRONA_INVALID_OPERATION, TRONA_NOT_FOUND, TRONA_OK, TRONA_OUT_OF_MEMORY,
};
use trona_protocol::namesrv::NAMESRV_REGISTER;
use trona_protocol::pci::*;
use trona_runtime::core::slot_alloc::{OwnedCap, TransferCap};

const CAP_SELF_CSPACE: u64 = 2;
const PCI_IRQ_LEVEL_TRIGGERED: u64 = 1;

#[inline]
fn device_control_cap() -> CapRef {
    trona_runtime::client::caps::device_control().cap_ref()
}

fn create_ioport_cap(
    control_cap: CapRef,
    base_port: u64,
    num_ports: u64,
    dest_cspace: u64,
    dest_slot: u64,
) -> i32 {
    invoke::device_control_create_ioport_depth(
        control_cap,
        base_port,
        num_ports,
        trona_runtime::core::slot_alloc::resolved_cap_ref(dest_cspace),
        dest_slot,
        trona_runtime::core::slot_alloc::slot_invoke_depth(dest_slot),
    )
}

fn create_device_untyped_cap(
    control_cap: CapRef,
    phys: u64,
    size_bits: u64,
    dest_cspace: u64,
    dest_slot: u64,
) -> i32 {
    invoke::device_control_create_device_untyped_depth(
        control_cap,
        phys,
        size_bits,
        trona_runtime::core::slot_alloc::resolved_cap_ref(dest_cspace),
        dest_slot,
        trona_runtime::core::slot_alloc::slot_invoke_depth(dest_slot),
    )
}

fn create_irq_handler_cap(control_cap: CapRef, irq: u64, dest_cspace: u64, dest_slot: u64) -> i32 {
    invoke::device_control_create_irq_handler_depth(
        control_cap,
        irq,
        trona_runtime::core::slot_alloc::resolved_cap_ref(dest_cspace),
        dest_slot,
        PCI_IRQ_LEVEL_TRIGGERED,
        trona_runtime::core::slot_alloc::slot_invoke_depth(dest_slot),
    )
}

#[inline]
fn alloc_runtime_slot() -> Option<trona_runtime::core::slot_alloc::OwnedSlot> {
    trona_runtime::core::slot_alloc::alloc_slot()
}

const MAX_PCI_DEVICES: usize = 64;

struct PciDevice {
    bus: u8,
    dev: u8,
    func: u8,
    vendor_id: u16,
    device_id: u16,
    class_code: u32,
    subsys_id: u32,
    irq_line: u8,
    bars: [u32; 6],
    /// Combined 64-bit physical addresses (handles 64-bit BARs)
    bar_phys: [u64; 6],
    bar_sizes: [u32; 6],
    ioport_slots: [OwnedCap; 6],
    devut_slots: [OwnedCap; 6],
    irq_handler_slot: OwnedCap,
    active: bool,
}

impl PciDevice {
    const fn zeroed() -> Self {
        PciDevice {
            bus: 0,
            dev: 0,
            func: 0,
            vendor_id: 0,
            device_id: 0,
            class_code: 0,
            subsys_id: 0,
            irq_line: 0,
            bars: [0; 6],
            bar_phys: [0; 6],
            bar_sizes: [0; 6],
            ioport_slots: [const { OwnedCap::null() }; 6],
            devut_slots: [const { OwnedCap::null() }; 6],
            irq_handler_slot: OwnedCap::null(),
            active: false,
        }
    }
}

static mut DEVICES: [PciDevice; MAX_PCI_DEVICES] = [const { PciDevice::zeroed() }; MAX_PCI_DEVICES];
static mut DEVICE_COUNT: usize = 0;

fn ipc_ctx() -> *mut IpcContext {
    trona_posix::tls::current_ipc_ctx()
}

const MAX_REPLY_CAPS: usize = trona_kernel::uapi::KERNITE_IPC_MAX_CAPS as usize;

struct PciReply {
    msg: TronaMsg,
    temp_caps: [Option<TransferCap>; MAX_REPLY_CAPS],
    temp_count: usize,
}

impl PciReply {
    fn new(msg: TronaMsg) -> Self {
        Self {
            msg,
            temp_caps: [const { None }; MAX_REPLY_CAPS],
            temp_count: 0,
        }
    }

    fn error(label: u64) -> Self {
        let mut msg = TronaMsg::zeroed();
        msg.label = label;
        Self::new(msg)
    }

    fn attach_cap_copy(&mut self, src_slot: u64) -> bool {
        if src_slot == 0 || self.temp_count >= MAX_REPLY_CAPS {
            return false;
        }
        let Some(temp) = trona_runtime::core::slot_alloc::alloc_slot() else {
            return false;
        };
        let err = invoke::cnode_copy_ref(
            CapRef::flat(CAP_SELF_CSPACE),
            trona_runtime::core::slot_alloc::resolved_cap_ref(src_slot),
            CapRef::flat(CAP_SELF_CSPACE),
            trona_runtime::core::slot_alloc::resolved_cap_ref(temp.addr()),
            // Device/MMIO caps egressed to clients never confer EXECUTE — a
            // client may not map device memory executable (W^X).
            (trona_kernel::uapi::KERNITE_RIGHT_ALL & !trona_kernel::uapi::KERNITE_RIGHT_EXECUTE)
                as u64,
        );
        if err != 0 {
            // copy failed: `temp` (OwnedSlot) Drop frees the empty slot.
            return false;
        }
        // The copy landed a cap; adopt the slot as an OwnedCap and stage it for
        // transfer (signals intent to send via IPC).
        let tc = temp.assume_filled().into_transfer();
        unsafe {
            ipc::set_send_cap_ctx(ipc_ctx(), self.temp_count as i32, tc.slot());
        }
        self.temp_caps[self.temp_count] = Some(tc);
        self.temp_count += 1;
        true
    }

    fn release_temp_caps(&mut self, abort: bool) {
        if self.temp_count != 0 && abort {
            // On abort the IPC send did not happen, so clear the staged caps
            // to avoid a stale send context on the next call.
            unsafe {
                ipc::clear_send_caps_ctx(ipc_ctx());
            }
        }
        // Drop all TransferCaps; Drop impl calls delete_and_free.
        for i in 0..MAX_REPLY_CAPS {
            self.temp_caps[i] = None;
        }
        self.temp_count = 0;
    }
}

/// Probe one PCI BAR size by writing all 1s and reading back.
fn probe_bar_size(bus: u8, dev: u8, func: u8, bar_idx: u8) -> u32 {
    let offset = 0x10 + bar_idx * 4;
    let original = arch::pci_read32(bus, dev, func, offset);
    arch::pci_write32(bus, dev, func, offset, 0xFFFF_FFFF);
    let mask = arch::pci_read32(bus, dev, func, offset);
    arch::pci_write32(bus, dev, func, offset, original);

    if mask == 0 || mask == 0xFFFF_FFFF {
        return 0;
    }

    let is_io = (original & 1) != 0;
    let size_mask = if is_io { mask & !0x3 } else { mask & !0xF };
    (!size_mask).wrapping_add(1)
}

/// Scan PCI bus 0, devices 0-31, all functions (multi-function aware).
fn scan_bus() {
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[pcidrv] Scanning PCI bus 0...\n");
    });

    let mut count = 0usize;
    for dev in 0u8..32 {
        let vendor_device = arch::pci_read32(0, dev, 0, 0);
        let vendor_id = (vendor_device & 0xFFFF) as u16;
        if vendor_id == 0xFFFF || vendor_id == 0 {
            continue;
        }

        // Check multi-function bit: header type (offset 0x0E) bit 7
        let hdr_type_reg = arch::pci_read32(0, dev, 0, 0x0C);
        let hdr_type = (hdr_type_reg >> 16) as u8;
        let func_limit = if (hdr_type & 0x80) != 0 { 8u8 } else { 1u8 };

        for func in 0u8..func_limit {
            if func > 0 {
                let vd = arch::pci_read32(0, dev, func, 0);
                let vid = (vd & 0xFFFF) as u16;
                if vid == 0xFFFF || vid == 0 {
                    continue;
                }
            }

            if count >= MAX_PCI_DEVICES {
                break;
            }

            let vd = arch::pci_read32(0, dev, func, 0);
            let vid = (vd & 0xFFFF) as u16;
            let did = ((vd >> 16) & 0xFFFF) as u16;

            let class_rev = arch::pci_read32(0, dev, func, 0x08);
            let class_code = class_rev >> 8;

            let subsys = arch::pci_read32(0, dev, func, 0x2C);

            let irq_reg = arch::pci_read32(0, dev, func, 0x3C);
            let irq_line = (irq_reg & 0xFF) as u8;

            unsafe {
                let entry = &mut *(&raw mut DEVICES[count]);
                entry.bus = 0;
                entry.dev = dev;
                entry.func = func;
                entry.vendor_id = vid;
                entry.device_id = did;
                entry.class_code = class_code;
                entry.subsys_id = subsys;
                entry.irq_line = irq_line;
                entry.active = true;

                // Read all BARs (raw 32-bit values)
                for bar_idx in 0u8..6 {
                    let offset = 0x10 + bar_idx * 4;
                    entry.bars[bar_idx as usize] = arch::pci_read32(0, dev, func, offset);
                    entry.bar_sizes[bar_idx as usize] = probe_bar_size(0, dev, func, bar_idx);
                }

                // Compute 64-bit physical addresses, handling 64-bit BARs
                {
                    let mut bar_idx = 0u8;
                    while bar_idx < 6 {
                        let bar_raw = entry.bars[bar_idx as usize];
                        if bar_raw == 0 && entry.bar_sizes[bar_idx as usize] == 0 {
                            bar_idx += 1;
                            continue;
                        }
                        let is_io = (bar_raw & 1) != 0;
                        if is_io {
                            entry.bar_phys[bar_idx as usize] = (bar_raw & !3u32) as u64;
                            bar_idx += 1;
                        } else {
                            let bar_type = (bar_raw >> 1) & 3;
                            let lo = (bar_raw & !0xFu32) as u64;
                            if bar_type == 2 && bar_idx < 5 {
                                // 64-bit BAR: combine with next register
                                let hi = entry.bars[(bar_idx + 1) as usize] as u64;
                                entry.bar_phys[bar_idx as usize] = lo | (hi << 32);
                                // Mark next BAR as consumed (part of 64-bit pair)
                                entry.bar_phys[(bar_idx + 1) as usize] = 0;
                                bar_idx += 2;
                            } else {
                                // 32-bit MMIO BAR
                                entry.bar_phys[bar_idx as usize] = lo;
                                bar_idx += 1;
                            }
                        }
                    }
                }

                // Create IoPort caps for I/O space BARs
                for bar_idx in 0u8..6 {
                    let bar_raw = entry.bars[bar_idx as usize];
                    let bar_size = entry.bar_sizes[bar_idx as usize];
                    if bar_raw != 0 && bar_size != 0 && (bar_raw & 1) != 0 {
                        let base_port = entry.bar_phys[bar_idx as usize];
                        let num_ports = bar_size as u64;
                        let Some(slot) = alloc_runtime_slot() else {
                            continue;
                        };
                        let err = create_ioport_cap(
                            device_control_cap(),
                            base_port,
                            num_ports,
                            CAP_SELF_CSPACE,
                            slot.addr(),
                        );
                        if err == 0 {
                            entry.ioport_slots[bar_idx as usize] = slot.assume_filled();
                        } else {
                            // create failed: `slot` (OwnedSlot) Drop frees the empty slot.
                        }
                    }
                }

                // Create device untyped caps for MMIO BARs (using 64-bit phys)
                for bar_idx in 0u8..6 {
                    let bar_raw = entry.bars[bar_idx as usize];
                    let bar_size = entry.bar_sizes[bar_idx as usize];
                    let phys = entry.bar_phys[bar_idx as usize];
                    if phys != 0 && bar_size != 0 && (bar_raw & 1) == 0 {
                        let size_bits = ceil_log2(bar_size as u64);
                        let Some(slot) = alloc_runtime_slot() else {
                            continue;
                        };
                        let err = create_device_untyped_cap(
                            device_control_cap(),
                            phys,
                            size_bits as u64,
                            CAP_SELF_CSPACE,
                            slot.addr(),
                        );
                        if err == 0 {
                            entry.devut_slots[bar_idx as usize] = slot.assume_filled();
                        } else {
                            // create failed: `slot` (OwnedSlot) Drop frees the empty slot.
                        }
                    }
                }

                // Create IRQ handler cap for devices with valid IRQ
                let effective_irq = arch::resolve_pci_irq(dev, func, irq_line);
                if effective_irq != 0 && effective_irq != 0xFF {
                    entry.irq_line = effective_irq;
                    if let Some(slot) = alloc_runtime_slot() {
                        let err = create_irq_handler_cap(
                            device_control_cap(),
                            effective_irq as u64,
                            CAP_SELF_CSPACE,
                            slot.addr(),
                        );
                        if err == 0 {
                            entry.irq_handler_slot = slot.assume_filled();
                        } else {
                            // create failed: `slot` (OwnedSlot) Drop frees the empty slot.
                            trona_runtime::uwarn!(|_lb| {
                                _lb.str(b"[pcidrv] device_control IRQ ");
                                _lb.dec(effective_irq as u64);
                                _lb.str(b" failed: ");
                                _lb.dec(err as u64);
                                _lb.putc(b'\n');
                            });
                        }
                    }
                }
            }

            trona_runtime::udebug!(|_lb| {
                _lb.str(b"[pcidrv]   ");
                _lb.hex(vid as u64);
                _lb.putc(b':');
                _lb.hex(did as u64);
                _lb.str(b" class=");
                _lb.hex(class_code as u64);
                _lb.str(b" fn=");
                _lb.dec(func as u64);
                _lb.str(b" irq=");
                _lb.dec(irq_line as u64);
                _lb.str(b" bar0=");
                _lb.hex(unsafe { (*(&raw const DEVICES[count])).bars[0] } as u64);
                _lb.putc(b'\n');
            });

            count += 1;
        }

        if count >= MAX_PCI_DEVICES {
            break;
        }
    }

    unsafe {
        *(&raw mut DEVICE_COUNT) = count;
    }

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[pcidrv] Found ");
        _lb.dec(count as u64);
        _lb.str(b" PCI device(s)\n");
    });
}

/// Find a device by vendor/device ID. Returns index or None.
fn find_device(vendor_id: u16, device_id: u16) -> Option<usize> {
    let count = unsafe { *(&raw const DEVICE_COUNT) };
    for i in 0..count {
        let d = unsafe { &*(&raw const DEVICES[i]) };
        if d.active && d.vendor_id == vendor_id && d.device_id == device_id {
            return Some(i);
        }
    }
    None
}

/// Register with name service.
fn register_namesrv() -> bool {
    const ENTRY_FLAG_BADGE_AS_CALLER: u64 = 1 << 0;
    const REGISTER_FLAGS_REG: usize = 31;

    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[pcidrv] Registering with namesrv\n");
    });
    let name = b"pcidrv";
    let mut msg = TronaMsg::zeroed();
    msg.label = NAMESRV_REGISTER;
    msg.regs[0] = name.len() as u64;
    let Some(publish_tc) = trona_runtime::client::caps::service_client_ep_for_transfer() else {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[pcidrv] No service client ep to publish\n");
        });
        return false;
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
                _lb.str(b"[pcidrv] namesrv register failed err=");
                _lb.hex(err as u64);
                _lb.str(b" label=");
                _lb.hex(reply.label);
                _lb.str(b"\n");
            });
            return false;
        }
    }
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[pcidrv] registered with namesrv\n");
    });
    true
}

/// Handle PCI_FIND_DEVICE request.
fn handle_find_device(msg: &TronaMsg) -> PciReply {
    let vendor_id = msg.regs[0] as u16;
    let device_id = msg.regs[1] as u16;

    let mut reply = TronaMsg::zeroed();

    match find_device(vendor_id, device_id) {
        Some(idx) => {
            let d = unsafe { &*(&raw const DEVICES[idx]) };
            reply.label = 0;
            reply.length = 8;
            reply.regs[0] = d.bus as u64;
            reply.regs[1] = d.dev as u64;
            reply.regs[2] = d.func as u64;
            reply.regs[3] = d.class_code as u64;
            reply.regs[4] = d.bars[0] as u64;
            reply.regs[5] = d.bars[1] as u64;
            reply.regs[6] = d.bars[2] as u64;
            reply.regs[7] = d.bars[3] as u64;
        }
        None => {
            reply.label = TRONA_NOT_FOUND;
            reply.length = 0;
        }
    }
    PciReply::new(reply)
}

const PCI_COMMAND_IO_SPACE: u16 = 1 << 0;
const PCI_COMMAND_MEMORY_SPACE: u16 = 1 << 1;
const PCI_COMMAND_BUS_MASTER: u16 = 1 << 2;

/// Enable the PCI command bits needed to access a specific BAR.
/// Preserves the upper status half of the command/status register.
fn ensure_bar_access(bus: u8, dev: u8, func: u8, bar_raw: u32, bar_size: u32) {
    if bar_raw == 0 || bar_size == 0 {
        return;
    }

    let mut required = PCI_COMMAND_BUS_MASTER;
    if (bar_raw & 1) != 0 {
        required |= PCI_COMMAND_IO_SPACE;
    } else {
        required |= PCI_COMMAND_MEMORY_SPACE;
    }

    let cmd_status = arch::pci_read32(bus, dev, func, 0x04);
    let cmd = (cmd_status & 0xFFFF) as u16;
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[pcidrv] ensure_bar_access ");
        _lb.dec(bus as u64);
        _lb.putc(b':');
        _lb.dec(dev as u64);
        _lb.putc(b':');
        _lb.dec(func as u64);
        _lb.str(b" bar_raw=");
        _lb.hex(bar_raw as u64);
        _lb.str(b" bar_size=");
        _lb.hex(bar_size as u64);
        _lb.str(b" cmd=");
        _lb.hex(cmd as u64);
        _lb.str(b" required=");
        _lb.hex(required as u64);
        _lb.putc(b'\n');
    });
    if (cmd & required) == required {
        return;
    }

    let new_cmd = cmd | required;
    let new_cmd_status = (cmd_status & !0xFFFF) | new_cmd as u32;
    arch::pci_write32(bus, dev, func, 0x04, new_cmd_status);
    let _readback = arch::pci_read32(bus, dev, func, 0x04);
    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[pcidrv] ensure_bar_access updated ");
        _lb.dec(bus as u64);
        _lb.putc(b':');
        _lb.dec(dev as u64);
        _lb.putc(b':');
        _lb.dec(func as u64);
        _lb.str(b" new_cmd=");
        _lb.hex(new_cmd as u64);
        _lb.str(b" readback=");
        _lb.hex(_readback as u64);
        _lb.putc(b'\n');
    });
}

fn handle_get_caps(msg: &TronaMsg) -> PciReply {
    let bus = msg.regs[0] as u8;
    let dev = msg.regs[1] as u8;
    let func = msg.regs[2] as u8;

    let mut reply = TronaMsg::zeroed();

    let count = unsafe { *(&raw const DEVICE_COUNT) };
    let mut found = None;
    for i in 0..count {
        let d = unsafe { &*(&raw const DEVICES[i]) };
        if d.active && d.bus == bus && d.dev == dev && d.func == func {
            found = Some(i);
            break;
        }
    }

    let idx = match found {
        Some(i) => i,
        None => {
            reply.label = TRONA_NOT_FOUND;
            return PciReply::new(reply);
        }
    };

    let d = unsafe { &*(&raw const DEVICES[idx]) };

    let bar0 = d.bars[0];
    let bar0_size = d.bar_sizes[0];
    let bar0_phys = d.bar_phys[0];
    ensure_bar_access(bus, dev, func, bar0, bar0_size);

    let bar0_is_io = bar0 != 0 && bar0_size != 0 && (bar0 & 1) != 0;
    if bar0_phys != 0 && bar0_size != 0 && !bar0_is_io {
        // MMIO BAR (using 64-bit physical address)
        let size_bits = ceil_log2(bar0_size as u64);
        reply.regs[0] = bar0_phys;
        reply.regs[1] = size_bits as u64;
        reply.regs[2] = bar0_size as u64;
    } else if bar0_is_io {
        // I/O space BAR
        reply.regs[0] = bar0_phys;
        reply.regs[1] = 0;
        reply.regs[2] = bar0_size as u64;
    }

    reply.regs[3] = d.irq_line as u64;
    // regs[4] = BAR type: 0=MMIO, 1=I/O
    reply.regs[4] = if bar0_is_io { 1 } else { 0 };
    // regs[5] = has IRQ handler cap: 0=no, 1=yes (extra cap #1)
    reply.regs[5] = if d.irq_handler_slot.as_raw() != 0 {
        1
    } else {
        0
    };
    reply.label = 0;
    reply.length = 6;

    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[pcidrv] GET_CAPS ");
        _lb.dec(bus as u64);
        _lb.putc(b':');
        _lb.dec(dev as u64);
        _lb.putc(b':');
        _lb.dec(func as u64);
        _lb.str(b" bar0_raw=");
        _lb.hex(bar0 as u64);
        _lb.str(b" bar0_phys=");
        _lb.hex(bar0_phys);
        _lb.str(b" bar0_size=");
        _lb.hex(bar0_size as u64);
        _lb.str(b" bar0_is_io=");
        _lb.dec(bar0_is_io as u64);
        _lb.str(b" ioport_slot=");
        _lb.hex(d.ioport_slots[0].as_raw());
        _lb.str(b" devut_slot=");
        _lb.hex(d.devut_slots[0].as_raw());
        _lb.str(b" irq=");
        _lb.dec(d.irq_line as u64);
        _lb.str(b" irq_slot=");
        _lb.hex(d.irq_handler_slot.as_raw());
        _lb.putc(b'\n');
    });

    let mut out = PciReply::new(reply);
    if bar0_is_io {
        if d.ioport_slots[0].as_raw() == 0 {
            return PciReply::error(TRONA_INVALID_OPERATION);
        }
        if !out.attach_cap_copy(d.ioport_slots[0].as_raw()) {
            out.release_temp_caps(true);
            return PciReply::error(TRONA_OUT_OF_MEMORY);
        }
    } else if bar0_phys != 0 && bar0_size != 0 {
        if d.devut_slots[0].as_raw() == 0 {
            return PciReply::error(TRONA_INVALID_OPERATION);
        }
        if !out.attach_cap_copy(d.devut_slots[0].as_raw()) {
            out.release_temp_caps(true);
            return PciReply::error(TRONA_OUT_OF_MEMORY);
        }
    }

    if d.irq_handler_slot.as_raw() != 0 && !out.attach_cap_copy(d.irq_handler_slot.as_raw()) {
        out.release_temp_caps(true);
        return PciReply::error(TRONA_OUT_OF_MEMORY);
    }

    out
}

/// Handle PCI_LIST request.
fn handle_list() -> PciReply {
    let count = unsafe { *(&raw const DEVICE_COUNT) };
    let mut reply = TronaMsg::zeroed();
    reply.label = 0;
    reply.length = 1 + (count * 3).min(18) as u64;
    reply.regs[0] = count as u64;

    let max = if count > 6 { 6 } else { count };
    for i in 0..max {
        let d = unsafe { &*(&raw const DEVICES[i]) };
        let base = 1 + i * 3;
        if base + 2 < 20 {
            reply.regs[base] = d.vendor_id as u64 | ((d.device_id as u64) << 16);
            reply.regs[base + 1] = d.class_code as u64;
            reply.regs[base + 2] = d.bars[0] as u64;
        }
    }
    PciReply::new(reply)
}

fn ceil_log2(n: u64) -> u8 {
    if n <= 1 {
        return 0;
    }
    64 - (n - 1).leading_zeros() as u8
}

/// PCI_GET_BAR_CAP: Get device untyped (or IoPort) cap for a specific BAR.
/// Request: MR0=bus, MR1=dev, MR2=func, MR3=bar_idx
/// Reply: MR0=bar_phys, MR1=bar_size, MR2=bar_is_io + extra_cap #0
fn handle_get_bar_cap(msg: &TronaMsg) -> PciReply {
    let mut reply = TronaMsg::zeroed();
    if msg.length < 4 {
        reply.label = TRONA_INVALID_ARGUMENT;
        return PciReply::new(reply);
    }
    let bus = msg.regs[0] as u8;
    let dev = msg.regs[1] as u8;
    let func = msg.regs[2] as u8;
    let bar_idx = msg.regs[3] as usize;

    if bar_idx >= 6 {
        reply.label = TRONA_INVALID_ARGUMENT;
        return PciReply::new(reply);
    }

    let count = unsafe { *(&raw const DEVICE_COUNT) };
    let mut found = None;
    for i in 0..count {
        let d = unsafe { &*(&raw const DEVICES[i]) };
        if d.active && d.bus == bus && d.dev == dev && d.func == func {
            found = Some(i);
            break;
        }
    }

    let idx = match found {
        Some(i) => i,
        None => {
            reply.label = TRONA_NOT_FOUND;
            return PciReply::new(reply);
        }
    };

    let d = unsafe { &*(&raw const DEVICES[idx]) };

    let bar_raw = d.bars[bar_idx];
    let bar_size = d.bar_sizes[bar_idx];
    let phys = d.bar_phys[bar_idx];
    ensure_bar_access(bus, dev, func, bar_raw, bar_size);

    if phys == 0 && bar_size == 0 {
        reply.label = TRONA_NOT_FOUND;
        return PciReply::new(reply);
    }

    let is_io = (bar_raw & 1) != 0;

    reply.label = 0;
    reply.length = 3;
    reply.regs[0] = phys;
    reply.regs[1] = bar_size as u64;
    reply.regs[2] = if is_io { 1 } else { 0 };

    trona_runtime::udebug!(|_lb| {
        _lb.str(b"[pcidrv] GET_BAR_CAP ");
        _lb.dec(bus as u64);
        _lb.putc(b':');
        _lb.dec(dev as u64);
        _lb.putc(b':');
        _lb.dec(func as u64);
        _lb.str(b" bar=");
        _lb.dec(bar_idx as u64);
        _lb.str(b" raw=");
        _lb.hex(bar_raw as u64);
        if bar_idx + 1 < 6 {
            _lb.str(b" raw_next=");
            _lb.hex(d.bars[bar_idx + 1] as u64);
        }
        _lb.str(b" phys=");
        _lb.hex(phys);
        _lb.str(b" size=");
        _lb.hex(bar_size as u64);
        _lb.str(b" is_io=");
        _lb.dec(is_io as u64);
        _lb.str(b" ioport_slot=");
        _lb.hex(d.ioport_slots[bar_idx].as_raw());
        _lb.str(b" devut_slot=");
        _lb.hex(d.devut_slots[bar_idx].as_raw());
        _lb.putc(b'\n');
    });

    let cap_slot = if is_io {
        d.ioport_slots[bar_idx].as_raw()
    } else {
        d.devut_slots[bar_idx].as_raw()
    };
    if cap_slot == 0 {
        return PciReply::error(TRONA_INVALID_OPERATION);
    }
    let mut out = PciReply::new(reply);
    if !out.attach_cap_copy(cap_slot) {
        out.release_temp_caps(true);
        return PciReply::error(TRONA_OUT_OF_MEMORY);
    }
    out
}

/// PCI_READ_CONFIG32: Read a 32-bit word from PCI config space.
fn handle_read_config32(msg: &TronaMsg) -> PciReply {
    let mut reply = TronaMsg::zeroed();
    if msg.length < 4 {
        reply.label = TRONA_INVALID_ARGUMENT;
        return PciReply::new(reply);
    }
    let bus = msg.regs[0] as u8;
    let dev = msg.regs[1] as u8;
    let func = msg.regs[2] as u8;
    let offset = msg.regs[3] as u8;
    reply.regs[0] = arch::pci_read32(bus, dev, func, offset) as u64;
    reply.length = 1;
    PciReply::new(reply)
}

/// PCI_WRITE_CONFIG32: Write a 32-bit word to PCI config space.
fn handle_write_config32(msg: &TronaMsg) -> PciReply {
    let mut reply = TronaMsg::zeroed();
    if msg.length < 5 {
        reply.label = TRONA_INVALID_ARGUMENT;
        return PciReply::new(reply);
    }
    let bus = msg.regs[0] as u8;
    let dev = msg.regs[1] as u8;
    let func = msg.regs[2] as u8;
    let offset = msg.regs[3] as u8;
    let value = msg.regs[4] as u32;
    arch::pci_write32(bus, dev, func, offset, value);
    PciReply::new(reply)
}

/// Cookie for the single service-pipe `STATE_READABLE` Watch (kind 0, slot
/// 0, generation 1). pcidrv has one event source, so the cookie is constant.
const PCIDRV_SERVICE_COOKIE: u64 = trona_server::event_loop::encode_cookie(0, 0, 1);

/// Single-source reactor dispatcher. The only armed event is `STATE_READABLE`
/// on the service pipe; each inbound record is routed by PCI label and the
/// reply rides back on the same pipe (txid-correlated).
struct PcidrvDispatcher {
    recv_ep: Cap,
    watch_cap: Cap,
    eq_cap: Cap,
    scratch: Cap,
}

impl trona_server::event_loop::EqDispatcher for PcidrvDispatcher {
    fn resolve_mp_recv(&self, _cookie: u64) -> Option<Cap> {
        Some(self.recv_ep)
    }

    fn dispatch_state(
        &mut self,
        _cookie: u64,
        msg: &TronaMsg,
        _meta: trona_server::event_loop::MpReadMeta,
    ) -> i32 {
        let mut reply = match msg.label {
            PCI_FIND_DEVICE => handle_find_device(msg),
            PCI_GET_CAPS => handle_get_caps(msg),
            PCI_LIST => handle_list(),
            PCI_READ_CONFIG32 => handle_read_config32(msg),
            PCI_WRITE_CONFIG32 => handle_write_config32(msg),
            PCI_GET_BAR_CAP => handle_get_bar_cap(msg),
            _ => PciReply::error(TRONA_INVALID_OPERATION),
        };
        // SAFETY: `ipc_ctx()` is this thread's IPC context; the reply rides
        // the service pipe correlated to the just-read request's txid.
        let err = unsafe { ipc::mp_write_reply_ctx(ipc_ctx(), self.recv_ep, &raw const reply.msg) };
        reply.release_temp_caps(err != 0);
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
            PCIDRV_SERVICE_COOKIE,
        )
    }

    fn handle_overflow(&mut self, _dropped: u64) {}

    fn handle_timer(&mut self, _cookie: u64) {}
}

/// Server main loop: a single-source `EventLoop` reactor. Blocks on the
/// reactor `EventQueue` (`EQ_WAIT`), drains the service pipe when it becomes
/// readable, dispatches by label, and replies. Replaces the former
/// `mp_write_reply_read` tight loop, which spun on `WOULD_BLOCK` once
/// `MP_READ` became non-blocking.
fn server_loop() -> ! {
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[pcidrv] Entering server loop\n");
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
                _lb.str(b"[pcidrv] reactor EventQueue/Watch alloc failed\n");
            });
            idle();
        }
    };
    let eq_cap = eq.borrow().addr();
    let watch_cap = watch.borrow().addr();
    let scratch = trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"pcidrv recv scratch");

    // Arm the service pipe's READABLE edge onto the reactor EQ.
    let _ = trona_kernel::invoke::watch_register(
        trona_kernel::core_types::CapRef::flat(watch_cap),
        trona_kernel::core_types::CapRef::flat(recv_ep),
        trona_kernel::core_types::CapRef::flat(eq_cap),
        trona_kernel::uapi::KERNITE_STATE_READABLE as u64,
        PCIDRV_SERVICE_COOKIE,
    );

    // The EQ / Watch live for the process lifetime; suppress their OwnedCap
    // drop so the caps are never torn down under the running reactor.
    core::mem::forget(eq);
    core::mem::forget(watch);

    let dispatcher = PcidrvDispatcher {
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
        _lb.str(b"[pcidrv] PCI Enumeration Server starting\n");
    });

    arch::pci_init();
    scan_bus();
    if !register_namesrv() {
        idle();
    }
    server_loop()
}

fn idle() -> ! {
    loop {
        let _ = trona_kernel::syscall::yield_now();
    }
}
