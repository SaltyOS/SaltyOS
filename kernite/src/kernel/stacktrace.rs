// SPDX-License-Identifier: GPL-2.0-only
//! Architecture context capture and bounded traceback printing.

use crate::kernel::printk::{serial_dec_raw, serial_hex_raw, serial_putc_hw, serial_puts_raw};
use crate::kernel::unwind::{self, Cursor, StackBounds};

pub(crate) const MAX_TRACE_FRAMES: usize = 32;

#[derive(Clone, Copy)]
pub(crate) enum TraceSource {
    Initial,
    DwarfCfi,
    FramePointer,
}

#[derive(Clone, Copy)]
pub(crate) struct TraceFrame {
    pub pc: u64,
    pub sp: u64,
    pub fp: u64,
    pub source: TraceSource,
}

impl TraceFrame {
    const fn empty() -> Self {
        Self {
            pc: 0,
            sp: 0,
            fp: 0,
            source: TraceSource::Initial,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum TraceStop {
    Complete,
    MaxFrames,
    NoStack,
    NoUnwindInfo,
    InvalidFrame,
    RepeatedFrame,
}

pub(crate) struct StackTrace {
    frames: [TraceFrame; MAX_TRACE_FRAMES],
    count: usize,
    stop: TraceStop,
    last_dwarf_stop: Option<unwind::StopReason>,
    dwarf_frames: usize,
    fp_frames: usize,
}

impl StackTrace {
    pub(crate) const fn empty() -> Self {
        Self {
            frames: [TraceFrame::empty(); MAX_TRACE_FRAMES],
            count: 0,
            stop: TraceStop::Complete,
            last_dwarf_stop: None,
            dwarf_frames: 0,
            fp_frames: 0,
        }
    }

    pub(crate) fn capture(ctx: &ArchPanicContext) -> Self {
        let mut trace = Self::empty();
        let Some(bounds) = current_stack_bounds(ctx.sp()) else {
            trace.stop = TraceStop::NoStack;
            return trace;
        };
        let mut cursor = Cursor {
            pc: ctx.pc(),
            sp: ctx.sp(),
            fp: ctx.fp(),
        };
        trace.push(cursor, TraceSource::Initial);

        while trace.count < MAX_TRACE_FRAMES {
            match unwind::unwind_next(cursor, bounds) {
                Ok(next) => {
                    if trace.repeats(next) {
                        trace.stop = TraceStop::RepeatedFrame;
                        break;
                    }
                    cursor = next;
                    trace.dwarf_frames += 1;
                    trace.push(cursor, TraceSource::DwarfCfi);
                    continue;
                }
                Err(reason @ (unwind::StopReason::NoEhFrame | unwind::StopReason::NoFde)) => {
                    trace.last_dwarf_stop = Some(reason);
                    match frame_pointer_next(cursor, bounds) {
                        Some(next) => {
                            if trace.repeats(next) {
                                trace.stop = TraceStop::RepeatedFrame;
                                break;
                            }
                            cursor = next;
                            trace.fp_frames += 1;
                            trace.push(cursor, TraceSource::FramePointer);
                            continue;
                        }
                        None => {
                            trace.stop = TraceStop::NoUnwindInfo;
                            break;
                        }
                    }
                }
                Err(unwind::StopReason::EndOfStack) => {
                    trace.last_dwarf_stop = Some(unwind::StopReason::EndOfStack);
                    trace.stop = TraceStop::Complete;
                    break;
                }
                Err(reason) => {
                    trace.last_dwarf_stop = Some(reason);
                    match frame_pointer_next(cursor, bounds) {
                        Some(next) => {
                            if trace.repeats(next) {
                                trace.stop = TraceStop::RepeatedFrame;
                                break;
                            }
                            cursor = next;
                            trace.fp_frames += 1;
                            trace.push(cursor, TraceSource::FramePointer);
                        }
                        None => {
                            trace.stop = TraceStop::InvalidFrame;
                            break;
                        }
                    }
                }
            }
        }
        if trace.count == MAX_TRACE_FRAMES {
            trace.stop = TraceStop::MaxFrames;
        }
        trace
    }

    fn push(&mut self, cursor: Cursor, source: TraceSource) {
        if self.count >= MAX_TRACE_FRAMES {
            return;
        }
        self.frames[self.count] = TraceFrame {
            pc: cursor.pc,
            sp: cursor.sp,
            fp: cursor.fp,
            source,
        };
        self.count += 1;
    }

    fn repeats(&self, cursor: Cursor) -> bool {
        let mut i = 0usize;
        while i < self.count {
            let f = self.frames[i];
            if f.pc == cursor.pc && f.sp == cursor.sp && f.fp == cursor.fp {
                return true;
            }
            i += 1;
        }
        false
    }

    pub(crate) fn print(&self) {
        serial_puts_raw("-- Call Trace ----------------------------------------------\n");
        serial_puts_raw("unwind: dwarf_frames=");
        serial_dec_raw(self.dwarf_frames as u64);
        serial_puts_raw(" fp_frames=");
        serial_dec_raw(self.fp_frames as u64);
        serial_puts_raw(" dwarf_stop=");
        print_dwarf_stop(self.last_dwarf_stop);
        serial_puts_raw(" stop=");
        print_stop(self.stop);
        serial_putc_hw(b'\n');
        let mut i = 0usize;
        while i < self.count {
            let frame = self.frames[i];
            serial_puts_raw("  #");
            serial_dec_raw(i as u64);
            serial_puts_raw(" [");
            match frame.source {
                TraceSource::Initial => serial_puts_raw("initial"),
                TraceSource::DwarfCfi => serial_puts_raw("dwarf"),
                TraceSource::FramePointer => serial_puts_raw("fp"),
            }
            serial_puts_raw("] ");
            crate::kernel::kallsyms::print_symbol(frame.pc as usize, true);
            serial_puts_raw(" sp=");
            serial_hex_raw(frame.sp);
            serial_puts_raw(" fp=");
            serial_hex_raw(frame.fp);
            serial_putc_hw(b'\n');
            i += 1;
        }
    }
}

fn print_dwarf_stop(stop: Option<unwind::StopReason>) {
    match stop {
        None => serial_puts_raw("none"),
        Some(unwind::StopReason::NoEhFrame) => serial_puts_raw("no_eh_frame"),
        Some(unwind::StopReason::NoFde) => serial_puts_raw("no_fde"),
        Some(unwind::StopReason::EndOfStack) => serial_puts_raw("end_of_stack"),
        Some(unwind::StopReason::Unsupported) => serial_puts_raw("unsupported"),
        Some(unwind::StopReason::InvalidStack) => serial_puts_raw("invalid_stack"),
    }
}

fn print_stop(stop: TraceStop) {
    match stop {
        TraceStop::Complete => serial_puts_raw("complete"),
        TraceStop::MaxFrames => serial_puts_raw("max_frames"),
        TraceStop::NoStack => serial_puts_raw("no_stack"),
        TraceStop::NoUnwindInfo => serial_puts_raw("no_unwind_info"),
        TraceStop::InvalidFrame => serial_puts_raw("invalid_frame"),
        TraceStop::RepeatedFrame => serial_puts_raw("repeated_frame"),
    }
}

fn current_stack_bounds(current_sp: u64) -> Option<StackBounds> {
    let size = crate::kernel::build_info::kernel_stack_size();
    if let Some(bounds) = stack_bounds_from_top(current_tcb_stack_top(), size, current_sp) {
        return Some(bounds);
    }
    if let Some(bounds) = stack_bounds_from_top(arch_kernel_stack_top(), size, current_sp) {
        return Some(bounds);
    }
    let top = current_sp.saturating_add(size);
    let bottom = top.checked_sub(size)?;
    Some(StackBounds { bottom, top })
}

fn stack_bounds_from_top(top: u64, size: u64, current_sp: u64) -> Option<StackBounds> {
    if top == 0 {
        return None;
    }
    let bottom = top.checked_sub(size)?;
    if current_sp < bottom || current_sp > top {
        return None;
    }
    Some(StackBounds { bottom, top })
}

fn current_tcb_stack_top() -> u64 {
    let current = crate::sched::scheduler::scheduler().current();
    if current.is_null() {
        0
    } else {
        unsafe { (*current).kernel_stack_top }
    }
}

fn frame_pointer_next(cursor: Cursor, bounds: StackBounds) -> Option<Cursor> {
    if cursor.fp == 0 || cursor.fp & 7 != 0 {
        return None;
    }
    let next_fp = unwind::read_stack_u64(cursor.fp, bounds)?;
    let ret = unwind::read_stack_u64(cursor.fp.checked_add(8)?, bounds)?;
    if ret == 0 || next_fp <= cursor.fp {
        return None;
    }
    Some(Cursor {
        pc: ret.saturating_sub(1),
        sp: cursor.fp.checked_add(16)?,
        fp: next_fp,
    })
}

#[cfg(target_arch = "x86_64")]
fn arch_kernel_stack_top() -> u64 {
    crate::arch::get_kernel_stack()
}

#[cfg(target_arch = "aarch64")]
fn arch_kernel_stack_top() -> u64 {
    crate::arch::get_kernel_stack()
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
pub(crate) struct ArchPanicContext {
    pub kind: ContextKind,
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rflags: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub vector: u64,
    pub error_code: u64,
    pub irq_state: u64,
}

#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy)]
pub(crate) struct ArchPanicContext {
    pub kind: ContextKind,
    pub elr: u64,
    pub sp: u64,
    pub x29: u64,
    pub x30: u64,
    pub daif: u64,
    pub esr_el1: u64,
    pub far_el1: u64,
    pub ttbr0_el1: u64,
}

#[derive(Clone, Copy)]
pub(crate) enum ContextKind {
    Generic,
    Exception,
}

impl ArchPanicContext {
    pub(crate) fn capture_current() -> Self {
        crate::arch::capture_current_panic_context()
    }

    pub(crate) fn pc(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.rip
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.elr
        }
    }

    pub(crate) fn sp(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.rsp
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.sp
        }
    }

    pub(crate) fn fp(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.rbp
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.x29
        }
    }

    pub(crate) fn print(&self) {
        serial_puts_raw("-- fault context -------------------------------------------\n");
        serial_puts_raw("kind: ");
        match self.kind {
            ContextKind::Generic => serial_puts_raw("generic"),
            ContextKind::Exception => serial_puts_raw("exception"),
        }
        serial_putc_hw(b'\n');
        #[cfg(target_arch = "x86_64")]
        {
            serial_puts_raw("RIP: ");
            serial_hex_raw(self.rip);
            serial_puts_raw(" RSP: ");
            serial_hex_raw(self.rsp);
            serial_puts_raw(" RBP: ");
            serial_hex_raw(self.rbp);
            serial_puts_raw(" RFLAGS: ");
            serial_hex_raw(self.rflags);
            serial_putc_hw(b'\n');
            serial_puts_raw("CR2: ");
            serial_hex_raw(self.cr2);
            serial_puts_raw(" CR3: ");
            serial_hex_raw(self.cr3);
            serial_puts_raw(" irq_state: ");
            serial_hex_raw(self.irq_state);
            serial_putc_hw(b'\n');
            if matches!(self.kind, ContextKind::Exception) {
                serial_puts_raw("vector: ");
                serial_dec_raw(self.vector);
                serial_puts_raw(" error_code: ");
                serial_hex_raw(self.error_code);
                serial_putc_hw(b'\n');
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            serial_puts_raw("ELR: ");
            serial_hex_raw(self.elr);
            serial_puts_raw(" SP: ");
            serial_hex_raw(self.sp);
            serial_puts_raw(" X29: ");
            serial_hex_raw(self.x29);
            serial_puts_raw(" X30: ");
            serial_hex_raw(self.x30);
            serial_putc_hw(b'\n');
            serial_puts_raw("DAIF: ");
            serial_hex_raw(self.daif);
            serial_puts_raw(" ESR_EL1: ");
            serial_hex_raw(self.esr_el1);
            serial_puts_raw(" FAR_EL1: ");
            serial_hex_raw(self.far_el1);
            serial_puts_raw(" TTBR0_EL1: ");
            serial_hex_raw(self.ttbr0_el1);
            serial_putc_hw(b'\n');
        }
    }
}
