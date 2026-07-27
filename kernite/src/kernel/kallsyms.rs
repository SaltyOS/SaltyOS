// SPDX-License-Identifier: GPL-2.0-only
//! In-kernel kallsyms lookup for panic diagnostics.

use crate::kernel::printk::{serial_hex_raw, serial_puts_raw};

const KALLSYMS_MAGIC: u32 = 0x4B_53_59_4D;
const KALLSYMS_VERSION: u16 = 1;
const KALLSYMS_ENTRY_SIZE: u16 = 24;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SymbolKind {
    Unknown,
    Text,
    Rodata,
    Data,
    Bss,
    Absolute,
}

#[derive(Clone, Copy)]
pub(crate) struct Symbol {
    pub addr: u64,
    pub size: u32,
    pub kind: SymbolKind,
    pub name: &'static str,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Header {
    magic: u32,
    version: u16,
    entry_size: u16,
    count: u32,
    strings_size: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawEntry {
    addr: u64,
    name_off: u32,
    size: u32,
    kind: u16,
    flags: u16,
}

unsafe extern "C" {
    static __kallsyms_start: u8;
    static __kallsyms_entries: u8;
    static __kallsyms_strings: u8;
    static __kallsyms_end: u8;
}

pub(crate) fn lookup(addr: usize) -> Option<Symbol> {
    lookup_with(addr as u64, KindFilter::Any)
}

pub(crate) fn lookup_code(addr: usize) -> Option<Symbol> {
    lookup_with(addr as u64, KindFilter::Code)
}

pub(crate) fn lookup_data(addr: usize) -> Option<Symbol> {
    lookup_with(addr as u64, KindFilter::Data)
}

pub(crate) fn print_symbol(addr: usize, code_only: bool) {
    let sym = if code_only {
        lookup_code(addr)
    } else {
        lookup(addr)
    };
    if let Some(sym) = sym {
        serial_puts_raw(sym.name);
        serial_puts_raw("+");
        serial_hex_raw((addr as u64).saturating_sub(sym.addr));
        serial_puts_raw("/");
        serial_hex_raw(sym.size as u64);
        serial_puts_raw(" [");
        serial_hex_raw(addr as u64);
        serial_puts_raw("]");
    } else {
        serial_hex_raw(addr as u64);
    }
}

enum KindFilter {
    Any,
    Code,
    Data,
}

fn lookup_with(addr: u64, filter: KindFilter) -> Option<Symbol> {
    let header = header()?;
    let mut lo = 0usize;
    let mut hi = header.count as usize;
    while lo < hi {
        let mid = lo + ((hi - lo) / 2);
        let e = raw_entry(mid)?;
        if e.addr <= addr {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    let mut idx = lo;
    let mut scanned = 0usize;
    while idx > 0 && scanned < 64 {
        idx -= 1;
        scanned += 1;
        let e = raw_entry(idx)?;
        if e.addr > addr {
            continue;
        }
        if e.size != 0 && addr >= e.addr.saturating_add(e.size as u64) {
            if scanned > 1 {
                break;
            }
            continue;
        }
        let kind = decode_kind(e.kind);
        if !matches_filter(kind, &filter) {
            continue;
        }
        return Some(Symbol {
            addr: e.addr,
            size: e.size,
            kind,
            name: symbol_name(e.name_off)?,
        });
    }
    None
}

fn matches_filter(kind: SymbolKind, filter: &KindFilter) -> bool {
    match filter {
        KindFilter::Any => kind != SymbolKind::Unknown,
        KindFilter::Code => kind == SymbolKind::Text,
        KindFilter::Data => matches!(
            kind,
            SymbolKind::Rodata | SymbolKind::Data | SymbolKind::Bss | SymbolKind::Absolute
        ),
    }
}

fn decode_kind(kind: u16) -> SymbolKind {
    match kind {
        1 => SymbolKind::Text,
        2 => SymbolKind::Rodata,
        3 => SymbolKind::Data,
        4 => SymbolKind::Bss,
        5 => SymbolKind::Absolute,
        _ => SymbolKind::Unknown,
    }
}

fn header() -> Option<Header> {
    let start = core::ptr::addr_of!(__kallsyms_start);
    let end = core::ptr::addr_of!(__kallsyms_end);
    if start >= end {
        return None;
    }
    let h = unsafe { core::ptr::read_unaligned(start as *const Header) };
    if h.magic != KALLSYMS_MAGIC
        || h.version != KALLSYMS_VERSION
        || h.entry_size != KALLSYMS_ENTRY_SIZE
    {
        return None;
    }
    Some(h)
}

fn raw_entry(index: usize) -> Option<RawEntry> {
    let h = header()?;
    if index >= h.count as usize {
        return None;
    }
    let base = core::ptr::addr_of!(__kallsyms_entries);
    let ptr = unsafe { base.add(index * KALLSYMS_ENTRY_SIZE as usize) };
    Some(unsafe { core::ptr::read_unaligned(ptr as *const RawEntry) })
}

fn symbol_name(off: u32) -> Option<&'static str> {
    let h = header()?;
    if off >= h.strings_size {
        return None;
    }
    let strings = core::ptr::addr_of!(__kallsyms_strings);
    let mut len = 0usize;
    while off as usize + len < h.strings_size as usize {
        let b = unsafe { *strings.add(off as usize + len) };
        if b == 0 {
            let bytes = unsafe { core::slice::from_raw_parts(strings.add(off as usize), len) };
            return core::str::from_utf8(bytes).ok();
        }
        len += 1;
    }
    None
}
