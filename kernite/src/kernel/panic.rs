// SPDX-License-Identifier: GPL-2.0-only
//! Unified kernel panic and diagnostic dump path.

use core::fmt::{self, Write};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::kernel::printk::{serial_dec_raw, serial_hex_raw, serial_putc_hw, serial_puts_raw};
use crate::kernel::stacktrace::{ArchPanicContext, StackTrace};

const PANIC_CPU_NONE: usize = usize::MAX;
static PANIC_CPU: AtomicUsize = AtomicUsize::new(PANIC_CPU_NONE);
static PANIC_SEQUENCE: AtomicUsize = AtomicUsize::new(0);
static SECONDARY_CURSOR: AtomicUsize = AtomicUsize::new(0);
static SECONDARY_DROPPED: AtomicUsize = AtomicUsize::new(0);
const SECONDARY_EVENT_CAP: usize = 16;

#[derive(Clone, Copy)]
pub(crate) struct PanicLocation<'a> {
    file: &'a str,
    line: u32,
    column: u32,
}

impl<'a> PanicLocation<'a> {
    pub const fn new(file: &'a str, line: u32, column: u32) -> Self {
        Self { file, line, column }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ReasonArg {
    name: &'static str,
    value: u64,
}

impl ReasonArg {
    pub const fn empty() -> Self {
        Self { name: "", value: 0 }
    }

    pub const fn new(name: &'static str, value: u64) -> Self {
        Self { name, value }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PanicReason<'a> {
    code: u32,
    kind: &'static str,
    expr: Option<&'static str>,
    message: Option<fmt::Arguments<'a>>,
    location: Option<PanicLocation<'a>>,
    args: [ReasonArg; 6],
}

impl<'a> PanicReason<'a> {
    pub const CODE_PANIC: u32 = 0x0000_0001;
    pub const CODE_BUG: u32 = 0x0000_0002;
    pub const CODE_ASSERTION_FAILED: u32 = 0x0000_0003;
    pub const CODE_ASSERTION_EQ_FAILED: u32 = 0x0000_0004;
    pub const CODE_ASSERTION_NE_FAILED: u32 = 0x0000_0005;
    pub const CODE_FATAL_EXCEPTION: u32 = 0x0000_0006;
    pub const CODE_SPINLOCK_TIMEOUT: u32 = 0x0000_0007;
    pub const CODE_KDEBUG_DUMP: u32 = 0x0000_0008;
    pub const CODE_ASSEMBLY: u32 = 0x0000_0009;

    pub fn panic(message: fmt::Arguments<'a>, location: Option<PanicLocation<'a>>) -> Self {
        Self {
            code: Self::CODE_PANIC,
            kind: "panic",
            expr: None,
            message: Some(message),
            location,
            args: [ReasonArg::empty(); 6],
        }
    }

    pub fn fatal_exception(message: fmt::Arguments<'a>) -> Self {
        Self {
            code: Self::CODE_FATAL_EXCEPTION,
            kind: "fatal_exception",
            expr: None,
            message: Some(message),
            location: None,
            args: [ReasonArg::empty(); 6],
        }
    }

    pub fn assertion(
        code: u32,
        kind: &'static str,
        expr: &'static str,
        message: Option<fmt::Arguments<'a>>,
        location: PanicLocation<'a>,
    ) -> Self {
        Self {
            code,
            kind,
            expr: Some(expr),
            message,
            location: Some(location),
            args: [ReasonArg::empty(); 6],
        }
    }

    pub fn bug(
        kind: &'static str,
        expr: Option<&'static str>,
        message: Option<fmt::Arguments<'a>>,
        location: PanicLocation<'a>,
    ) -> Self {
        Self {
            code: Self::CODE_BUG,
            kind,
            expr,
            message,
            location: Some(location),
            args: [ReasonArg::empty(); 6],
        }
    }

    pub fn spinlock_timeout(
        message: fmt::Arguments<'a>,
        location: PanicLocation<'a>,
        args: [ReasonArg; 6],
    ) -> Self {
        Self {
            code: Self::CODE_SPINLOCK_TIMEOUT,
            kind: "spinlock_timeout",
            expr: None,
            message: Some(message),
            location: Some(location),
            args,
        }
    }
}

struct PanicRecord<'a> {
    source: &'static str,
    sequence: usize,
    panic_cpu: usize,
    panic_task: Option<u64>,
    uptime_ns: u64,
    invoke_seq: u64,
    reason: PanicReason<'a>,
    context: ArchPanicContext,
    trace: StackTrace,
}

struct SecondaryEventSlot {
    seq: AtomicU64,
    cpu: AtomicUsize,
    tid: AtomicU64,
    code: AtomicU64,
    ip: AtomicU64,
    uptime: AtomicU64,
    file_ptr: AtomicUsize,
    file_len: AtomicUsize,
    line: AtomicU64,
}

impl SecondaryEventSlot {
    const fn new() -> Self {
        Self {
            seq: AtomicU64::new(0),
            cpu: AtomicUsize::new(0),
            tid: AtomicU64::new(u64::MAX),
            code: AtomicU64::new(0),
            ip: AtomicU64::new(0),
            uptime: AtomicU64::new(0),
            file_ptr: AtomicUsize::new(0),
            file_len: AtomicUsize::new(0),
            line: AtomicU64::new(0),
        }
    }
}

static SECONDARY_EVENTS: [SecondaryEventSlot; SECONDARY_EVENT_CAP] =
    [const { SecondaryEventSlot::new() }; SECONDARY_EVENT_CAP];

struct PanicWriter;

impl Write for PanicWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        serial_puts_raw(s);
        Ok(())
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let location = info
        .location()
        .map(|loc| PanicLocation::new(loc.file(), loc.line(), loc.column()));
    panic_now(format_args!("{}", info.message()), location)
}

pub(crate) fn panic_now(reason: fmt::Arguments<'_>, location: Option<PanicLocation<'_>>) -> ! {
    panic_now_reason("panic", PanicReason::panic(reason, location))
}

pub(crate) fn panic_now_source(
    source: &'static str,
    reason: fmt::Arguments<'_>,
    location: Option<PanicLocation<'_>>,
) -> ! {
    panic_now_reason(source, PanicReason::panic(reason, location))
}

pub(crate) fn panic_now_reason(source: &'static str, reason: PanicReason<'_>) -> ! {
    panic_report(source, reason, None, crate::arch::dump_panic_detail);
    halt_forever()
}

pub(crate) fn fatal_exception<F>(
    source: &'static str,
    reason: fmt::Arguments<'_>,
    dump_arch: F,
) -> !
where
    F: FnOnce(),
{
    panic_report(
        source,
        PanicReason::fatal_exception(reason),
        None,
        dump_arch,
    );
    halt_forever()
}

pub(crate) fn fatal_exception_context<F>(
    source: &'static str,
    reason: fmt::Arguments<'_>,
    context: ArchPanicContext,
    dump_arch: F,
) -> !
where
    F: FnOnce(),
{
    panic_report(
        source,
        PanicReason::fatal_exception(reason),
        Some(context),
        dump_arch,
    );
    halt_forever()
}

pub(crate) fn spinlock_timeout(
    what: &'static str,
    lock_addr: usize,
    contended_location: PanicLocation<'static>,
    acquired_location_addr: usize,
    owner_cpu: u64,
    owner_tid: u64,
    waiting_ns: u64,
) -> ! {
    let reason = PanicReason::spinlock_timeout(
        format_args!("spinlock hard timeout"),
        contended_location,
        [
            ReasonArg::new("lock", lock_addr as u64),
            ReasonArg::new("acquired_location", acquired_location_addr as u64),
            ReasonArg::new("owner_cpu", owner_cpu),
            ReasonArg::new("owner_tid", owner_tid),
            ReasonArg::new("waiting_ns", waiting_ns),
            ReasonArg::empty(),
        ],
    );
    panic_now_reason(what, reason)
}

pub(crate) fn assertion_failed(
    expr: &'static str,
    message: Option<fmt::Arguments<'_>>,
    location: PanicLocation<'static>,
) -> ! {
    panic_now_reason(
        "kassert",
        PanicReason::assertion(
            PanicReason::CODE_ASSERTION_FAILED,
            "assertion_failed",
            expr,
            message,
            location,
        ),
    )
}

pub(crate) fn assertion_eq_failed(
    expr: &'static str,
    message: Option<fmt::Arguments<'_>>,
    location: PanicLocation<'static>,
) -> ! {
    panic_now_reason(
        "kassert_eq",
        PanicReason::assertion(
            PanicReason::CODE_ASSERTION_EQ_FAILED,
            "assertion_eq_failed",
            expr,
            message,
            location,
        ),
    )
}

pub(crate) fn assertion_ne_failed(
    expr: &'static str,
    message: Option<fmt::Arguments<'_>>,
    location: PanicLocation<'static>,
) -> ! {
    panic_now_reason(
        "kassert_ne",
        PanicReason::assertion(
            PanicReason::CODE_ASSERTION_NE_FAILED,
            "assertion_ne_failed",
            expr,
            message,
            location,
        ),
    )
}

pub(crate) fn bug(
    kind: &'static str,
    expr: Option<&'static str>,
    message: Option<fmt::Arguments<'_>>,
    location: PanicLocation<'static>,
) -> ! {
    panic_now_reason("bug", PanicReason::bug(kind, expr, message, location))
}

pub(crate) fn assembly_panic(message: fmt::Arguments<'_>) -> ! {
    panic_now_reason(
        "assembly",
        PanicReason {
            code: PanicReason::CODE_ASSEMBLY,
            kind: "assembly",
            expr: None,
            message: Some(message),
            location: None,
            args: [ReasonArg::empty(); 6],
        },
    )
}

pub(crate) fn dump_system_state(reason: &'static str) {
    serial_puts_raw("\n==================== KDEBUG_DUMP_STATE ====================\n");
    print_reason(&PanicReason {
        code: PanicReason::CODE_KDEBUG_DUMP,
        kind: "kdebug_dump",
        expr: None,
        message: Some(format_args!("{}", reason)),
        location: None,
        args: [ReasonArg::empty(); 6],
    });
    print_cpu_line();
    print_location(None);
    print_uptime();
    crate::kernel::build_info::print_identity_line();
    crate::kernel::build_info::print_full_config();
    let context = ArchPanicContext::capture_current();
    context.print();
    StackTrace::capture(&context).print();
    print_current_task();
    crate::mm::print_lock_diagnostics();
    print_scheduler_snapshot();
    print_memory_snapshot();
    serial_puts_raw("================== END KDEBUG_DUMP_STATE ==================\n");
}

pub(crate) fn suppress_non_panic_cpu_output() -> bool {
    let owner = PANIC_CPU.load(Ordering::Acquire);
    owner != PANIC_CPU_NONE && owner != crate::arch::current_cpu() as usize
}

fn claim_panic_cpu() -> bool {
    let cpu = crate::arch::current_cpu() as usize;
    match PANIC_CPU.compare_exchange(PANIC_CPU_NONE, cpu, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => true,
        Err(owner) if owner == cpu => {
            serial_puts_raw("\nrecursive panic on panic CPU; halting\n");
            false
        }
        Err(_) => false,
    }
}

fn panic_report<F>(
    source: &'static str,
    reason: PanicReason<'_>,
    context: Option<ArchPanicContext>,
    dump_arch: F,
) where
    F: FnOnce(),
{
    crate::arch::cli();
    #[cfg(target_arch = "aarch64")]
    crate::arch::aarch64::timer::stop();

    crate::console::enable();
    let context = context.unwrap_or_else(ArchPanicContext::capture_current);
    let trace = StackTrace::capture(&context);

    if !claim_panic_cpu() {
        record_secondary_event(&reason, &context);
        halt_forever();
    }

    let sequence = PANIC_SEQUENCE.fetch_add(1, Ordering::AcqRel) + 1;
    let record = PanicRecord {
        source,
        sequence,
        panic_cpu: crate::arch::current_cpu() as usize,
        panic_task: current_task_trace_id(),
        uptime_ns: current_uptime_ns(),
        invoke_seq: crate::arch::current_invoke_seq(),
        reason,
        context,
        trace,
    };

    serial_puts_raw("\n");
    serial_puts_raw("============================================================\n");
    serial_puts_raw("KERNEL PANIC [#");
    serial_dec_raw(record.sequence as u64);
    serial_puts_raw("]  ");
    if online_cpu_count() > 1 {
        serial_puts_raw("SMP\n");
    } else {
        serial_puts_raw("UP\n");
    }
    serial_puts_raw("============================================================\n");

    print_panic_metadata(&record);
    print_reason(&record.reason);
    record.context.print();
    record.trace.print();
    print_current_task();
    crate::mm::print_lock_diagnostics();
    print_scheduler_snapshot();
    print_memory_snapshot();
    print_secondary_events();
    serial_puts_raw("-- arch detail ---------------------------------------------\n");
    dump_arch();
    serial_puts_raw("============================================================\n");
}

fn print_panic_metadata(record: &PanicRecord<'_>) {
    serial_puts_raw("CPU: ");
    serial_dec_raw(record.panic_cpu as u64);
    serial_puts_raw("\nPID: ");
    if let Some(tid) = record.panic_task {
        serial_dec_raw(tid);
    } else {
        serial_puts_raw("<none>");
    }
    serial_puts_raw("\npanic_cpu: ");
    serial_dec_raw(record.panic_cpu as u64);
    serial_puts_raw("\npanic_task: ");
    if let Some(tid) = record.panic_task {
        serial_dec_raw(tid);
    } else {
        serial_puts_raw("<none>");
    }
    serial_puts_raw("\nuptime_ns: ");
    serial_dec_raw(record.uptime_ns);
    serial_puts_raw("\ninvoke_seq: ");
    serial_hex_raw(record.invoke_seq);
    serial_puts_raw("\nsource: ");
    serial_puts_raw(record.source);
    serial_putc_hw(b'\n');
    crate::kernel::build_info::print_identity_line();
}

fn print_reason(reason: &PanicReason<'_>) {
    serial_puts_raw("reason:\n  code: ");
    serial_hex_raw(reason.code as u64);
    serial_puts_raw("\n  kind: ");
    serial_puts_raw(reason.kind);
    serial_putc_hw(b'\n');
    if let Some(expr) = reason.expr {
        serial_puts_raw("  expr: ");
        serial_puts_raw(expr);
        serial_putc_hw(b'\n');
    }
    let mut i = 0usize;
    while i < reason.args.len() {
        let arg = reason.args[i];
        if !arg.name.is_empty() {
            serial_puts_raw("  ");
            serial_puts_raw(arg.name);
            serial_puts_raw(": ");
            serial_hex_raw(arg.value);
            serial_putc_hw(b'\n');
        }
        i += 1;
    }
    if let Some(message) = reason.message {
        serial_puts_raw("  message: ");
        let mut writer = PanicWriter;
        let _ = writer.write_fmt(message);
        serial_putc_hw(b'\n');
    }
    if let Some(loc) = reason.location {
        serial_puts_raw("  location: ");
        serial_puts_raw(loc.file);
        serial_putc_hw(b':');
        serial_dec_raw(loc.line as u64);
        serial_putc_hw(b':');
        serial_dec_raw(loc.column as u64);
        serial_putc_hw(b'\n');
    }
}

fn current_uptime_ns() -> u64 {
    let now = crate::arch::now_ns();
    let boot = crate::kernel::time::BOOT_TIME_NS.load(Ordering::Relaxed);
    now.saturating_sub(boot)
}

fn current_task_trace_id() -> Option<u64> {
    let current = crate::sched::scheduler::scheduler().current();
    if current.is_null() {
        None
    } else {
        Some(unsafe { (*current).trace_id() })
    }
}

fn online_cpu_count() -> usize {
    let scheduler = crate::sched::scheduler::scheduler();
    (scheduler.online_cpus as usize).min(crate::arch::MAX_CPUS)
}

fn record_secondary_event(reason: &PanicReason<'_>, context: &ArchPanicContext) {
    let seq = SECONDARY_CURSOR.fetch_add(1, Ordering::AcqRel) + 1;
    if seq > SECONDARY_EVENT_CAP {
        SECONDARY_DROPPED.fetch_add(1, Ordering::AcqRel);
    }
    let slot = &SECONDARY_EVENTS[(seq - 1) % SECONDARY_EVENT_CAP];
    slot.cpu
        .store(crate::arch::current_cpu() as usize, Ordering::Release);
    slot.tid.store(
        current_task_trace_id().unwrap_or(u64::MAX),
        Ordering::Release,
    );
    slot.code.store(reason.code as u64, Ordering::Release);
    slot.ip.store(context.pc(), Ordering::Release);
    slot.uptime.store(current_uptime_ns(), Ordering::Release);
    if let Some(loc) = reason.location {
        slot.file_ptr
            .store(loc.file.as_ptr() as usize, Ordering::Release);
        slot.file_len.store(loc.file.len(), Ordering::Release);
        slot.line.store(loc.line as u64, Ordering::Release);
    } else {
        slot.file_ptr.store(0, Ordering::Release);
        slot.file_len.store(0, Ordering::Release);
        slot.line.store(0, Ordering::Release);
    }
    slot.seq.store(seq as u64, Ordering::Release);
}

fn print_secondary_events() {
    serial_puts_raw("-- secondary CPUs ------------------------------------------\n");
    let cursor = SECONDARY_CURSOR.load(Ordering::Acquire);
    if cursor == 0 {
        serial_puts_raw("secondary CPUs: <none>\n");
        return;
    }
    let first = cursor.saturating_sub(SECONDARY_EVENT_CAP) + 1;
    let mut seq = first;
    while seq <= cursor {
        let slot = &SECONDARY_EVENTS[(seq - 1) % SECONDARY_EVENT_CAP];
        if slot.seq.load(Ordering::Acquire) == seq as u64 {
            serial_puts_raw("  - cpu=");
            serial_dec_raw(slot.cpu.load(Ordering::Acquire) as u64);
            serial_puts_raw(" tid=");
            let tid = slot.tid.load(Ordering::Acquire);
            if tid == u64::MAX {
                serial_puts_raw("<none>");
            } else {
                serial_dec_raw(tid);
            }
            serial_puts_raw(" code=");
            serial_hex_raw(slot.code.load(Ordering::Acquire));
            serial_puts_raw(" ip=");
            crate::kernel::kallsyms::print_symbol(slot.ip.load(Ordering::Acquire) as usize, true);
            serial_puts_raw(" uptime_ns=");
            serial_dec_raw(slot.uptime.load(Ordering::Acquire));
            let file_ptr = slot.file_ptr.load(Ordering::Acquire);
            let file_len = slot.file_len.load(Ordering::Acquire);
            if file_ptr != 0 && file_len != 0 {
                serial_puts_raw(" location=");
                let bytes = unsafe { core::slice::from_raw_parts(file_ptr as *const u8, file_len) };
                if let Ok(s) = core::str::from_utf8(bytes) {
                    serial_puts_raw(s);
                } else {
                    serial_puts_raw("<nonutf8>");
                }
                serial_putc_hw(b':');
                serial_dec_raw(slot.line.load(Ordering::Acquire));
            }
            serial_putc_hw(b'\n');
        }
        seq += 1;
    }
    let dropped = SECONDARY_DROPPED.load(Ordering::Acquire);
    if dropped != 0 {
        serial_puts_raw("dropped_secondary_events: ");
        serial_dec_raw(dropped as u64);
        serial_putc_hw(b'\n');
    }
}

fn print_location(location: Option<PanicLocation<'_>>) {
    if let Some(loc) = location {
        serial_puts_raw("location: ");
        serial_puts_raw(loc.file);
        serial_putc_hw(b':');
        serial_dec_raw(loc.line as u64);
        serial_putc_hw(b':');
        serial_dec_raw(loc.column as u64);
        serial_putc_hw(b'\n');
    } else {
        serial_puts_raw("location: <none>\n");
    }
}

fn print_cpu_line() {
    serial_puts_raw("cpu: ");
    serial_dec_raw(crate::arch::current_cpu() as u64);
    serial_puts_raw(" invoke_seq: ");
    serial_hex_raw(crate::arch::current_invoke_seq());
    serial_puts_raw("\n");
}

fn print_uptime() {
    let now = crate::arch::now_ns();
    let boot = crate::kernel::time::BOOT_TIME_NS.load(Ordering::Relaxed);
    serial_puts_raw("uptime_ns: ");
    serial_dec_raw(now.saturating_sub(boot));
    serial_puts_raw(" boot_time_ns: ");
    serial_dec_raw(boot);
    serial_puts_raw("\n");
}

fn print_current_task() {
    serial_puts_raw("-- current task --------------------------------------------\n");
    let scheduler = crate::sched::scheduler::scheduler();
    let current = scheduler.current();
    if current.is_null() {
        serial_puts_raw("current: <none>\n");
        return;
    }

    unsafe {
        let tcb = &*current;
        serial_puts_raw("task: ");
        serial_hex_raw(current as u64);
        serial_puts_raw(" tid=");
        serial_dec_raw(tcb.trace_id());
        serial_puts_raw(" state=");
        print_thread_state(tcb.state());
        serial_puts_raw(" class=");
        serial_dec_raw(tcb.sched_class as u64);
        serial_puts_raw(" prio=");
        serial_dec_raw(tcb.priority);
        serial_puts_raw(" base_prio=");
        serial_dec_raw(tcb.base_priority);
        serial_puts_raw("\n");

        serial_puts_raw("wait: reason=");
        print_blocked_reason(tcb.blocked_reason);
        serial_puts_raw(" object=");
        serial_hex_raw(tcb.wait_object as u64);
        serial_puts_raw(" side=");
        serial_dec_raw(tcb.wait_side as u64);
        serial_puts_raw(" seq=");
        serial_dec_raw(tcb.wait_seq);
        serial_puts_raw("\n");

        serial_puts_raw("addrspace: vspace=");
        serial_hex_raw(tcb.vspace_root as u64);
        serial_puts_raw(" cspace=");
        serial_hex_raw(tcb.cspace_root as u64);
        serial_puts_raw(" ipc_buffer=");
        serial_hex_raw(tcb.ipc_buffer);
        serial_puts_raw(" fault_pipe=");
        serial_hex_raw(tcb.fault_pipe as u64);
        serial_puts_raw("\n");

        serial_puts_raw("runtime_ns: user=");
        serial_dec_raw(tcb.user_runtime_ns.load(Ordering::Acquire));
        serial_puts_raw(" system=");
        serial_dec_raw(tcb.system_runtime_ns.load(Ordering::Acquire));
        serial_puts_raw("\n");

        serial_puts_raw("user_stack: guard=");
        serial_hex_raw(tcb.user_stack_guard_bottom);
        serial_puts_raw(" min=");
        serial_hex_raw(tcb.user_stack_min);
        serial_puts_raw(" top=");
        serial_hex_raw(tcb.user_stack_top);
        serial_puts_raw("\n");
    }
}

fn print_scheduler_snapshot() {
    serial_puts_raw("-- scheduler -----------------------------------------------\n");
    let scheduler = crate::sched::scheduler::scheduler();
    let online = (scheduler.online_cpus as usize).min(crate::arch::MAX_CPUS);
    serial_puts_raw("online_cpus: ");
    serial_dec_raw(online as u64);
    serial_puts_raw("\n");
    let mut total_context_switches = 0u64;
    for cpu in 0..online {
        total_context_switches = total_context_switches
            .saturating_add(scheduler.context_switches[cpu].load(Ordering::Acquire));
    }
    serial_puts_raw("context_switches_total: ");
    serial_dec_raw(total_context_switches);
    serial_puts_raw("\n");
    for cpu in 0..online {
        serial_puts_raw("cpu");
        serial_dec_raw(cpu as u64);
        serial_puts_raw(": ticks=");
        serial_dec_raw(scheduler.timer_ticks[cpu].load(Ordering::Acquire));
        serial_puts_raw(" ctxsw=");
        serial_dec_raw(scheduler.context_switches[cpu].load(Ordering::Acquire));
        serial_puts_raw(" idle=");
        serial_dec_raw(scheduler.idle_runtime_ns[cpu].load(Ordering::Acquire));
        serial_puts_raw(" user=");
        serial_dec_raw(scheduler.per_cpu_user_runtime_ns[cpu].load(Ordering::Acquire));
        serial_puts_raw(" system=");
        serial_dec_raw(scheduler.per_cpu_system_runtime_ns[cpu].load(Ordering::Acquire));
        serial_puts_raw(" ipi_resched=");
        serial_dec_raw(scheduler.ipi_reschedules[cpu].load(Ordering::Acquire));
        serial_puts_raw("\n");
    }
}

fn print_memory_snapshot() {
    serial_puts_raw("-- memory --------------------------------------------------\n");
    let snap = crate::mm::pmm_memsnapshot();
    serial_puts_raw("pages: total=");
    serial_dec_raw(snap.pages_total as u64);
    serial_puts_raw(" free=");
    serial_dec_raw(snap.pages_free as u64);
    serial_puts_raw(" untyped=");
    serial_dec_raw(snap.pages_untyped_reserved as u64);
    serial_puts_raw(" reserve=");
    serial_dec_raw(snap.reserve_pool_depth as u64);
    serial_puts_raw("\n");
    serial_puts_raw("mo: data=");
    serial_dec_raw(snap.pages_mo_data as u64);
    serial_puts_raw(" meta=");
    serial_dec_raw(snap.pages_mo_meta as u64);
    serial_puts_raw(" anon=");
    serial_dec_raw(snap.pages_anon_private as u64);
    serial_puts_raw(" cow=");
    serial_dec_raw(snap.pages_anon_cow as u64);
    serial_puts_raw(" shm=");
    serial_dec_raw(snap.pages_anon_shared as u64);
    serial_puts_raw(" file=");
    serial_dec_raw(snap.pages_file as u64);
    serial_puts_raw("\n");
    serial_puts_raw("kernel: private=");
    serial_dec_raw(snap.pages_kernel_private as u64);
    serial_puts_raw(" pagetable=");
    serial_dec_raw(snap.kmeta_pagetable as u64);
    serial_puts_raw(" stack=");
    serial_dec_raw(snap.kmeta_kernel_stack as u64);
    serial_puts_raw(" maple=");
    serial_dec_raw(snap.kmeta_maple_node as u64);
    serial_puts_raw(" general=");
    serial_dec_raw(snap.kmeta_general as u64);
    serial_puts_raw(" cow_pool=");
    serial_dec_raw(snap.kmeta_cow_pool as u64);
    serial_puts_raw("\n");
    serial_puts_raw("lru: active=");
    serial_dec_raw(snap.pages_active as u64);
    serial_puts_raw(" inactive=");
    serial_dec_raw(snap.pages_inactive as u64);
    serial_puts_raw(" dirty_file=");
    serial_dec_raw(snap.pages_dirty_file as u64);
    serial_puts_raw(" writeback_file=");
    serial_dec_raw(snap.pages_writeback_file as u64);
    serial_puts_raw("\n");
}

fn print_thread_state(state: crate::task::state::ThreadState) {
    match state {
        crate::task::state::ThreadState::Created => serial_puts_raw("Created"),
        crate::task::state::ThreadState::Configured => serial_puts_raw("Configured"),
        crate::task::state::ThreadState::Runnable => serial_puts_raw("Runnable"),
        crate::task::state::ThreadState::Blocked => serial_puts_raw("Blocked"),
        crate::task::state::ThreadState::Stopped => serial_puts_raw("Stopped"),
        crate::task::state::ThreadState::Dying => serial_puts_raw("Dying"),
    }
}

fn print_blocked_reason(reason: Option<crate::sched::thread::BlockedReason>) {
    match reason {
        None => serial_puts_raw("None"),
        Some(crate::sched::thread::BlockedReason::EventQueueWait) => {
            serial_puts_raw("EventQueueWait")
        }
        Some(crate::sched::thread::BlockedReason::PipeRead) => serial_puts_raw("PipeRead"),
        Some(crate::sched::thread::BlockedReason::PipeCall) => serial_puts_raw("PipeCall"),
        Some(crate::sched::thread::BlockedReason::PipeWrite) => serial_puts_raw("PipeWrite"),
        Some(crate::sched::thread::BlockedReason::DataPipeRead) => serial_puts_raw("DataPipeRead"),
        Some(crate::sched::thread::BlockedReason::DataPipeWrite) => {
            serial_puts_raw("DataPipeWrite")
        }
        Some(crate::sched::thread::BlockedReason::VSpaceWait) => serial_puts_raw("VSpaceWait"),
        Some(crate::sched::thread::BlockedReason::FutexBlocked) => serial_puts_raw("FutexBlocked"),
        Some(crate::sched::thread::BlockedReason::FutexTimedBlocked) => {
            serial_puts_raw("FutexTimedBlocked")
        }
        Some(crate::sched::thread::BlockedReason::PagerFaultBlocked) => {
            serial_puts_raw("PagerFaultBlocked")
        }
    }
}

pub(crate) fn halt_forever() -> ! {
    crate::arch::cli();
    loop {
        crate::arch::halt();
    }
}

/// C-callable panic function for assembly code.
///
/// # Safety
/// `msg` must be a valid NUL-terminated C string pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel_panic(msg: *const u8) -> ! {
    unsafe { panic_cstr(msg) }
}

/// Panic with a C string reason supplied by low-level assembly.
///
/// # Safety
/// `msg` must be null or point to a valid NUL-terminated byte string.
pub unsafe fn panic_cstr(msg: *const u8) -> ! {
    panic_report(
        "assembly",
        PanicReason {
            code: PanicReason::CODE_ASSEMBLY,
            kind: "assembly",
            expr: None,
            message: Some(format_args!("assembly requested panic")),
            location: None,
            args: [ReasonArg::empty(); 6],
        },
        None,
        || unsafe {
            serial_puts_raw("message: ");
            if msg.is_null() {
                serial_puts_raw("<null>");
            } else {
                let mut p = msg;
                while *p != 0 {
                    serial_putc_hw(*p);
                    p = p.add(1);
                }
            }
            serial_putc_hw(b'\n');
        },
    );
    halt_forever()
}
