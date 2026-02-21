//! SaltyOS PCI Enumeration Server
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Scans PCI bus 0 via I/O port config space (0xCF8/0xCFC), builds a
//! device registry, and distributes BAR/IRQ capabilities to drivers.
//!
//! IPC protocol:
//!   Label 1 = PCI_FIND_DEVICE: MR0=vendor_id, MR1=device_id
//!       -> MR0=bus, MR1=dev, MR2=func, MR3=class, MR4=bar0..MR7=bar3
//!   Label 2 = PCI_GET_CAPS: MR0=bus, MR1=dev, MR2=func
//!       -> MR0=bar_phys, MR1=bar_size_bits, MR2=bar_size, MR3=irq
//!   Label 3 = PCI_LIST: -> MR0=count, then (vendor|device, class, bar0) tuples
//!
//! Cap layout (set by init service file):
//!   0  = self TCB
//!   1  = self VSpace
//!   2  = self CSpace
//!   3  = server endpoint
//!   14 = readiness notification
//!   64 = PCI config space IoPort (0xCF8, 8 ports) -- CopyCap from init slot 15
//!   65 = name service endpoint

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
const CAP_SELF_CSPACE: u64 = 2;
const CAP_SERVER_EP: u64 = 3;
const CAP_READINESS_NTFN: u64 = 14;
const CAP_PCI_IOPORT: u64 = 64;
const CAP_NAMESERV_EP: u64 = 65;
const CAP_IRQ_CONTROL: u64 = 66;

const IPC_BUF_VADDR: u64 = 0x0000_0000_0020_0000;

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
    bar_sizes: [u32; 6],
    ioport_slots: [u64; 6],
    devut_slots: [u64; 6],
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
            bar_sizes: [0; 6],
            ioport_slots: [0; 6],
            devut_slots: [0; 6],
            active: false,
        }
    }
}

static mut DEVICES: [PciDevice; MAX_PCI_DEVICES] = [PciDevice::zeroed(); MAX_PCI_DEVICES];
static mut DEVICE_COUNT: usize = 0;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn ipc_ctx() -> *mut IpcContext {
    &raw mut salty::__salty_ipc_ctx
}

fn signal_ready() {
    let _ = salty::syscall::syscall(SYS_SIGNAL, CAP_READINESS_NTFN, 1, 0, 0, 0, 0);
}

/// Read 32 bits from PCI config space using mechanism 1 (IO ports 0xCF8/0xCFC).
fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr: u32 = (1u32 << 31)
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    invoke::ioport_out32(CAP_PCI_IOPORT, 0, addr);
    invoke::ioport_in32(CAP_PCI_IOPORT, 4)
}

/// Write 32 bits to PCI config space.
fn pci_write32(bus: u8, dev: u8, func: u8, offset: u8, value: u32) {
    let addr: u32 = (1u32 << 31)
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    invoke::ioport_out32(CAP_PCI_IOPORT, 0, addr);
    invoke::ioport_out32(CAP_PCI_IOPORT, 4, value);
}

/// Probe one PCI BAR size by writing all 1s and reading back.
fn probe_bar_size(bus: u8, dev: u8, func: u8, bar_idx: u8) -> u32 {
    let offset = 0x10 + bar_idx * 4;
    let original = pci_read32(bus, dev, func, offset);
    pci_write32(bus, dev, func, offset, 0xFFFF_FFFF);
    let mask = pci_read32(bus, dev, func, offset);
    pci_write32(bus, dev, func, offset, original);

    if mask == 0 || mask == 0xFFFF_FFFF {
        return 0;
    }

    let is_io = (original & 1) != 0;
    let size_mask = if is_io { mask & !0x3 } else { mask & !0xF };
    (!size_mask).wrapping_add(1)
}

/// Scan PCI bus 0, devices 0-31, all functions (multi-function aware).
fn scan_bus() {
    puts(b"[pcisrv] Scanning PCI bus 0...\n");

    let mut count = 0usize;
    for dev in 0u8..32 {
        let vendor_device = pci_read32(0, dev, 0, 0);
        let vendor_id = (vendor_device & 0xFFFF) as u16;
        if vendor_id == 0xFFFF || vendor_id == 0 {
            continue;
        }

        // Check multi-function bit: header type (offset 0x0E) bit 7
        let hdr_type_reg = pci_read32(0, dev, 0, 0x0C);
        let hdr_type = (hdr_type_reg >> 16) as u8;
        let func_limit = if (hdr_type & 0x80) != 0 { 8u8 } else { 1u8 };

        for func in 0u8..func_limit {
            if func > 0 {
                let vd = pci_read32(0, dev, func, 0);
                let vid = (vd & 0xFFFF) as u16;
                if vid == 0xFFFF || vid == 0 {
                    continue;
                }
            }

            if count >= MAX_PCI_DEVICES {
                break;
            }

            let vd = pci_read32(0, dev, func, 0);
            let vid = (vd & 0xFFFF) as u16;
            let did = ((vd >> 16) & 0xFFFF) as u16;

            let class_rev = pci_read32(0, dev, func, 0x08);
            let class_code = class_rev >> 8;

            let subsys = pci_read32(0, dev, func, 0x2C);

            let irq_reg = pci_read32(0, dev, func, 0x3C);
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

                for bar_idx in 0u8..6 {
                    let offset = 0x10 + bar_idx * 4;
                    entry.bars[bar_idx as usize] = pci_read32(0, dev, func, offset);
                    entry.bar_sizes[bar_idx as usize] = probe_bar_size(0, dev, func, bar_idx);
                }

                // Create IoPort caps for I/O space BARs
                for bar_idx in 0u8..6 {
                    let bar_raw = entry.bars[bar_idx as usize];
                    let bar_size = entry.bar_sizes[bar_idx as usize];
                    if bar_raw != 0 && bar_size != 0 && (bar_raw & 1) != 0 {
                        let base_port = (bar_raw & !3u32) as u64;
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

                // Create device untyped caps for MMIO BARs
                for bar_idx in 0u8..6 {
                    let bar_raw = entry.bars[bar_idx as usize];
                    let bar_size = entry.bar_sizes[bar_idx as usize];
                    if bar_raw != 0 && bar_size != 0 && (bar_raw & 1) == 0 {
                        let phys = (bar_raw & !0xFu32) as u64;
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
            }

            {
                let mut lb = LineBuf::new();
                lb.str(b"[pcisrv]   ");
                lb.hex(vid as u64);
                lb.putc(b':');
                lb.hex(did as u64);
                lb.str(b" class=");
                lb.hex(class_code as u64);
                lb.str(b" fn=");
                lb.dec(func as u64);
                lb.str(b" irq=");
                lb.dec(irq_line as u64);
                lb.str(b" bar0=");
                lb.hex(unsafe { (*(&raw const DEVICES[count])).bars[0] } as u64);
                lb.putc(b'\n');
                lb.flush();
            }

            count += 1;
        }

        if count >= MAX_PCI_DEVICES {
            break;
        }
    }

    unsafe { *(&raw mut DEVICE_COUNT) = count; }

    {
        let mut lb = LineBuf::new();
        lb.str(b"[pcisrv] Found ");
        lb.dec(count as u64);
        lb.str(b" PCI device(s)\n");
        lb.flush();
    }
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
fn register_nameserv() {
    let name = b"pcisrv";
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
        ipc::call_ctx(ipc_ctx(), CAP_NAMESERV_EP, &raw const msg, &raw mut reply);
    }
}

/// Handle PCI_FIND_DEVICE request.
fn handle_find_device(msg: &SaltyMsg) -> SaltyMsg {
    let vendor_id = msg.regs[0] as u16;
    let device_id = msg.regs[1] as u16;

    let mut reply = SaltyMsg::zeroed();

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
            reply.label = SALTY_NOT_FOUND;
            reply.length = 0;
        }
    }
    reply
}

/// Handle PCI_GET_CAPS request.
fn handle_get_caps(msg: &SaltyMsg) -> SaltyMsg {
    let bus = msg.regs[0] as u8;
    let dev = msg.regs[1] as u8;
    let func = msg.regs[2] as u8;

    let mut reply = SaltyMsg::zeroed();

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
            reply.label = SALTY_NOT_FOUND;
            return reply;
        }
    };

    let d = unsafe { &*(&raw const DEVICES[idx]) };

    let bar0 = d.bars[0];
    let bar0_size = d.bar_sizes[0];
    let bar0_is_io = bar0 != 0 && bar0_size != 0 && (bar0 & 1) != 0;
    if bar0 != 0 && bar0_size != 0 && !bar0_is_io {
        // MMIO BAR
        let phys = (bar0 & !0xFu32) as u64;
        let size_bits = ceil_log2(bar0_size as u64);
        reply.regs[0] = phys;
        reply.regs[1] = size_bits as u64;
        reply.regs[2] = bar0_size as u64;
    } else if bar0_is_io {
        // I/O space BAR
        let base_port = (bar0 & !3u32) as u64;
        reply.regs[0] = base_port;
        reply.regs[1] = 0;
        reply.regs[2] = bar0_size as u64;
    }

    reply.regs[3] = d.irq_line as u64;
    // regs[4] = BAR type: 0=MMIO, 1=I/O
    reply.regs[4] = if bar0_is_io { 1 } else { 0 };
    reply.label = 0;
    reply.length = 5;

    // Transfer IoPort cap for I/O BAR or device untyped cap for MMIO BAR
    if bar0_is_io && d.ioport_slots[0] != 0 {
        unsafe {
            ipc::set_send_cap_ctx(ipc_ctx(), 0, d.ioport_slots[0]);
        }
    } else if !bar0_is_io && d.devut_slots[0] != 0 {
        unsafe {
            ipc::set_send_cap_ctx(ipc_ctx(), 0, d.devut_slots[0]);
        }
    }

    reply
}

/// Handle PCI_LIST request.
fn handle_list() -> SaltyMsg {
    let count = unsafe { *(&raw const DEVICE_COUNT) };
    let mut reply = SaltyMsg::zeroed();
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

/// Server main loop.
fn server_loop() -> ! {
    puts(b"[pcisrv] Entering server loop\n");

    let ctx = ipc_ctx();
    let mut msg = SaltyMsg::zeroed();
    let mut badge: u64 = 0;
    unsafe { ipc::recv_ctx(ctx, CAP_SERVER_EP, &raw mut msg, &raw mut badge); }

    loop {
        let reply = match msg.label {
            PCI_FIND_DEVICE => handle_find_device(&msg),
            PCI_GET_CAPS => handle_get_caps(&msg),
            PCI_LIST => handle_list(),
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
    puts(b"[pcisrv] PCI Enumeration Server starting\n");

    let _ = invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, IPC_BUF_VADDR);
    unsafe {
        (*ipc_ctx()).ipc_buffer = IPC_BUF_VADDR as *mut IpcBuffer;
    }

    scan_bus();
    register_nameserv();
    signal_ready();
    server_loop()
}
