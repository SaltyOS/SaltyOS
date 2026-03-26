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
//! Cap layout (set by init service file):
//!   0  = self TCB
//!   1  = self VSpace
//!   2  = self CSpace
//!   3  = server endpoint
//!   14 = readiness notification
//!   64 = PCI config space cap (IoPort on x86_64, ECAM device untyped on aarch64)
//!   65 = name service endpoint

#![no_std]
#![no_main]

extern crate besalt;

#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64.rs"]
mod arch;
#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64.rs"]
mod arch;

use besalt::consts::*;
use besalt::ipc;
use besalt::invoke;
use besalt::types::*;

const CAP_SELF_CSPACE: u64 = 2;
const CAP_SERVER_EP: u64 = 3;
const CAP_READINESS_NTFN: u64 = 14;
const CAP_NAMESERV_EP: u64 = 65;
const CAP_IRQ_CONTROL: u64 = 66;

const MAX_PCI_DEVICES: usize = 64;

/// Next dynamic cap slot for IoPort caps created at runtime
static mut NEXT_CAP_SLOT: u64 = 80;

#[derive(Clone, Copy)]
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
    ioport_slots: [u64; 6],
    devut_slots: [u64; 6],
    irq_handler_slot: u64,
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
            ioport_slots: [0; 6],
            devut_slots: [0; 6],
            irq_handler_slot: 0,
            active: false,
        }
    }
}

static mut DEVICES: [PciDevice; MAX_PCI_DEVICES] = [PciDevice::zeroed(); MAX_PCI_DEVICES];
static mut DEVICE_COUNT: usize = 0;

fn ipc_ctx() -> *mut IpcContext {
    &raw mut besalt::__besalt_ipc_ctx
}

fn signal_ready() {
    let _ = besalt::syscall::syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
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
    besalt::uinfo!(|_lb| { _lb.str(b"[pcisrv] Scanning PCI bus 0...\n"); });

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
                        let slot = *(&raw const NEXT_CAP_SLOT);
                        *(&raw mut NEXT_CAP_SLOT) = slot + 1;
                        let err = invoke::ioport_create(
                            CAP_IRQ_CONTROL, base_port, num_ports,
                            CAP_SELF_CSPACE, slot,
                        );
                        if err == 0 {
                            entry.ioport_slots[bar_idx as usize] = slot;
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
                        let slot = *(&raw const NEXT_CAP_SLOT);
                        *(&raw mut NEXT_CAP_SLOT) = slot + 1;
                        let err = invoke::device_untyped_create(
                            CAP_IRQ_CONTROL, phys, size_bits as u64,
                            CAP_SELF_CSPACE, slot,
                        );
                        if err == 0 {
                            entry.devut_slots[bar_idx as usize] = slot;
                        }
                    }
                }

                // Create IRQ handler cap for devices with valid IRQ
                let effective_irq = arch::resolve_pci_irq(dev, func, irq_line);
                if effective_irq != 0 && effective_irq != 0xFF {
                    entry.irq_line = effective_irq;
                    let slot = *(&raw const NEXT_CAP_SLOT);
                    *(&raw mut NEXT_CAP_SLOT) = slot + 1;
                    let err = invoke::irq_control_get(
                        CAP_IRQ_CONTROL, effective_irq as u64,
                        CAP_SELF_CSPACE, slot,
                    );
                    if err == 0 {
                        entry.irq_handler_slot = slot;
                    } else {
                        besalt::uwarn!(|_lb| {
                            _lb.str(b"[pcisrv] irq_control_get IRQ ");
                            _lb.dec(effective_irq as u64);
                            _lb.str(b" failed: ");
                            _lb.dec(err as u64);
                            _lb.putc(b'\n');
                        });
                    }
                }
            }

            besalt::udebug!(|_lb| {
                _lb.str(b"[pcisrv]   ");
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

    unsafe { *(&raw mut DEVICE_COUNT) = count; }

    besalt::uinfo!(|_lb| {
        _lb.str(b"[pcisrv] Found ");
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
fn register_nameserv() -> bool {
    besalt::udebug!(|_lb| { _lb.str(b"[pcisrv] Registering with nameserv\n"); });
    let name = b"pcisrv";
    let mut msg = BesaltMsg::zeroed();
    msg.label = POSIX_NS_REGISTER;
    msg.regs[0] = name.len() as u64;
    msg.length = 1 + (name.len() as u64 + 7) / 8;
    unsafe {
        let dst = &raw mut msg.regs[1] as *mut u8;
        for i in 0..name.len() {
            *dst.add(i) = name[i];
        }
        ipc::set_send_cap_ctx(ipc_ctx(), 0, CAP_SERVER_EP);
        let mut reply = BesaltMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), CAP_NAMESERV_EP, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != BESALT_OK {
            besalt::uerror!(|_lb| {
                _lb.str(b"[pcisrv] nameserv register failed err=");
                _lb.hex(err as u64);
                _lb.str(b" label=");
                _lb.hex(reply.label);
                _lb.str(b"\n");
            });
            return false;
        }
    }
    besalt::uinfo!(|_lb| { _lb.str(b"[pcisrv] registered with nameserv\n"); });
    true
}

/// Handle PCI_FIND_DEVICE request.
fn handle_find_device(msg: &BesaltMsg) -> BesaltMsg {
    let vendor_id = msg.regs[0] as u16;
    let device_id = msg.regs[1] as u16;

    let mut reply = BesaltMsg::zeroed();

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
            reply.label = BESALT_NOT_FOUND;
            reply.length = 0;
        }
    }
    reply
}

/// Handle PCI_GET_CAPS request.
/// Enable PCI Memory Space + Bus Master for the given device.
/// Idempotent — skips the write if both bits are already set.
fn ensure_bus_master(bus: u8, dev: u8, func: u8) {
    let cmd = arch::pci_read32(bus, dev, func, 0x04) & 0xFFFF;
    if cmd & 0x6 != 0x6 {
        arch::pci_write32(bus, dev, func, 0x04, (cmd | 0x6) as u32);
    }
}

fn handle_get_caps(msg: &BesaltMsg) -> BesaltMsg {
    let bus = msg.regs[0] as u8;
    let dev = msg.regs[1] as u8;
    let func = msg.regs[2] as u8;

    let mut reply = BesaltMsg::zeroed();

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
            reply.label = BESALT_NOT_FOUND;
            return reply;
        }
    };

    let d = unsafe { &*(&raw const DEVICES[idx]) };

    ensure_bus_master(bus, dev, func);

    let bar0 = d.bars[0];
    let bar0_size = d.bar_sizes[0];
    let bar0_phys = d.bar_phys[0];
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
    reply.regs[5] = if d.irq_handler_slot != 0 { 1 } else { 0 };
    reply.label = 0;
    reply.length = 6;

    // Transfer IoPort cap for I/O BAR or device untyped cap for MMIO BAR (extra cap #0)
    if bar0_is_io && d.ioport_slots[0] != 0 {
        unsafe {
            ipc::set_send_cap_ctx(ipc_ctx(), 0, d.ioport_slots[0]);
        }
    } else if !bar0_is_io && d.devut_slots[0] != 0 {
        unsafe {
            ipc::set_send_cap_ctx(ipc_ctx(), 0, d.devut_slots[0]);
        }
    }

    // Transfer IRQ handler cap (extra cap #1)
    if d.irq_handler_slot != 0 {
        unsafe {
            ipc::set_send_cap_ctx(ipc_ctx(), 1, d.irq_handler_slot);
        }
    }

    reply
}

/// Handle PCI_LIST request.
fn handle_list() -> BesaltMsg {
    let count = unsafe { *(&raw const DEVICE_COUNT) };
    let mut reply = BesaltMsg::zeroed();
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
    reply
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
fn handle_get_bar_cap(msg: &BesaltMsg) -> BesaltMsg {
    let mut reply = BesaltMsg::zeroed();
    if msg.length < 4 {
        reply.label = BESALT_INVALID_ARGUMENT;
        return reply;
    }
    let bus = msg.regs[0] as u8;
    let dev = msg.regs[1] as u8;
    let func = msg.regs[2] as u8;
    let bar_idx = msg.regs[3] as usize;

    if bar_idx >= 6 {
        reply.label = BESALT_INVALID_ARGUMENT;
        return reply;
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
            reply.label = BESALT_NOT_FOUND;
            return reply;
        }
    };

    let d = unsafe { &*(&raw const DEVICES[idx]) };

    ensure_bus_master(bus, dev, func);

    let bar_raw = d.bars[bar_idx];
    let bar_size = d.bar_sizes[bar_idx];
    let phys = d.bar_phys[bar_idx];

    if phys == 0 && bar_size == 0 {
        reply.label = BESALT_NOT_FOUND;
        return reply;
    }

    let is_io = (bar_raw & 1) != 0;

    reply.label = 0;
    reply.length = 3;
    reply.regs[0] = phys;
    reply.regs[1] = bar_size as u64;
    reply.regs[2] = if is_io { 1 } else { 0 };

    // Transfer the appropriate cap
    if is_io && d.ioport_slots[bar_idx] != 0 {
        unsafe { ipc::set_send_cap_ctx(ipc_ctx(), 0, d.ioport_slots[bar_idx]); }
    } else if !is_io && d.devut_slots[bar_idx] != 0 {
        unsafe { ipc::set_send_cap_ctx(ipc_ctx(), 0, d.devut_slots[bar_idx]); }
    }

    reply
}

/// PCI_READ_CONFIG32: Read a 32-bit word from PCI config space.
fn handle_read_config32(msg: &BesaltMsg) -> BesaltMsg {
    let mut reply = BesaltMsg::zeroed();
    if msg.length < 4 {
        reply.label = BESALT_INVALID_ARGUMENT;
        return reply;
    }
    let bus = msg.regs[0] as u8;
    let dev = msg.regs[1] as u8;
    let func = msg.regs[2] as u8;
    let offset = msg.regs[3] as u8;
    reply.regs[0] = arch::pci_read32(bus, dev, func, offset) as u64;
    reply.length = 1;
    reply
}

/// PCI_WRITE_CONFIG32: Write a 32-bit word to PCI config space.
fn handle_write_config32(msg: &BesaltMsg) -> BesaltMsg {
    let mut reply = BesaltMsg::zeroed();
    if msg.length < 5 {
        reply.label = BESALT_INVALID_ARGUMENT;
        return reply;
    }
    let bus = msg.regs[0] as u8;
    let dev = msg.regs[1] as u8;
    let func = msg.regs[2] as u8;
    let offset = msg.regs[3] as u8;
    let value = msg.regs[4] as u32;
    arch::pci_write32(bus, dev, func, offset, value);
    reply
}

/// Server main loop.
fn server_loop() -> ! {
    besalt::uinfo!(|_lb| { _lb.str(b"[pcisrv] Entering server loop\n"); });

    let ctx = ipc_ctx();
    let mut msg = BesaltMsg::zeroed();
    let mut badge: u64 = 0;
    unsafe { ipc::recv_ctx(ctx, CAP_SERVER_EP, &raw mut msg, &raw mut badge); }

    loop {
        let reply = match msg.label {
            PCI_FIND_DEVICE => handle_find_device(&msg),
            PCI_GET_CAPS => handle_get_caps(&msg),
            PCI_LIST => handle_list(),
            PCI_READ_CONFIG32 => handle_read_config32(&msg),
            PCI_WRITE_CONFIG32 => handle_write_config32(&msg),
            PCI_GET_BAR_CAP => handle_get_bar_cap(&msg),
            _ => {
                let mut r = BesaltMsg::zeroed();
                r.label = BESALT_INVALID_OPERATION;
                r
            }
        };

        msg = BesaltMsg::zeroed();
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
    besalt::uinfo!(|_lb| { _lb.str(b"[pcisrv] PCI Enumeration Server starting\n"); });

    arch::pci_init();
    scan_bus();
    if !register_nameserv() {
        idle();
    }
    signal_ready();
    server_loop()
}

fn idle() -> ! {
    loop {
        let _ = besalt::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
