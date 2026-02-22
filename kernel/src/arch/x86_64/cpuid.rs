//! CPUID Feature Detection
//!
//! Detects CPU features on BSP/APs and maintains:
//! - Per-CPU feature snapshots
//! - Global system-wide feature intersection (AND across online CPUs)
//! - Required feature validation for boot safety
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::{AtomicU32, Ordering};

const FEAT_SSE: u32 = 1 << 0;
const FEAT_SSE2: u32 = 1 << 1;
const FEAT_FXSR: u32 = 1 << 2;
const FEAT_XSAVE: u32 = 1 << 3;
const FEAT_INVARIANT_TSC: u32 = 1 << 4;
const FEAT_SMEP: u32 = 1 << 5;
const FEAT_SMAP: u32 = 1 << 6;
const FEAT_RDRAND: u32 = 1 << 7;
const FEAT_RDSEED: u32 = 1 << 8;

/// Features that must be present on every CPU for this kernel configuration.
const REQUIRED_MASK: u32 = FEAT_SSE | FEAT_SSE2 | FEAT_FXSR;

/// FXSAVE area size baseline.
const DEFAULT_XSAVE_AREA_SIZE: u32 = 512;

#[derive(Clone, Copy)]
struct CpuFeatures {
    bits: u32,
    xsave_area_size: u32,
}

/// Global feature mask = intersection across all registered CPUs.
static GLOBAL_BITS: AtomicU32 = AtomicU32::new(0);

/// Global XSAVE area size used by kernel paths.
///
/// When XSAVE is globally enabled, this tracks the minimum size across CPUs.
/// If XSAVE is globally disabled, this remains at the FXSAVE baseline.
static GLOBAL_XSAVE_AREA_SIZE: AtomicU32 = AtomicU32::new(DEFAULT_XSAVE_AREA_SIZE);

/// Per-CPU feature snapshots for diagnostics and per-CPU dispatch.
static PER_CPU_BITS: [AtomicU32; super::cpu::MAX_CPUS] = {
    const INIT: AtomicU32 = AtomicU32::new(0);
    [INIT; super::cpu::MAX_CPUS]
};

/// Per-CPU XSAVE area sizes.
static PER_CPU_XSAVE_AREA_SIZE: [AtomicU32; super::cpu::MAX_CPUS] = {
    const INIT: AtomicU32 = AtomicU32::new(DEFAULT_XSAVE_AREA_SIZE);
    [INIT; super::cpu::MAX_CPUS]
};

#[inline]
fn has_bit(bits: u32, bit: u32) -> bool {
    bits & bit != 0
}

#[inline]
fn cpu_bits(cpu_id: usize) -> u32 {
    if cpu_id < super::cpu::MAX_CPUS {
        PER_CPU_BITS[cpu_id].load(Ordering::Acquire)
    } else {
        0
    }
}

/// Execute CPUID with manual rbx save/restore (LLVM reserves rbx).
///
/// Returns (eax, ebx, ecx, edx).
unsafe fn cpuid_leaf(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    // SAFETY: rbx is callee-saved and LLVM reserves it, so we must
    // save/restore it manually around cpuid.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inlateout("eax") leaf => eax,
            ebx_out = lateout(reg) ebx,
            inlateout("ecx") subleaf => ecx,
            lateout("edx") edx,
            options(nostack),
        );
    }
    (eax, ebx, ecx, edx)
}

/// CPUID leaf 1: returns (ecx, edx) feature flags.
#[inline]
fn cpuid_leaf1() -> (u32, u32) {
    // SAFETY: CPUID is always safe to call
    let (_, _, ecx, edx) = unsafe { cpuid_leaf(1, 0) };
    (ecx, edx)
}

/// CPUID maximum extended leaf.
#[inline]
fn cpuid_max_extended_leaf() -> u32 {
    // SAFETY: CPUID is always safe to call
    let (eax, _, _, _) = unsafe { cpuid_leaf(0x8000_0000, 0) };
    eax
}

/// Read local CPU feature snapshot.
fn read_local_features() -> CpuFeatures {
    let (ecx, edx) = cpuid_leaf1();

    let mut bits = 0u32;
    if (edx & (1 << 24)) != 0 {
        bits |= FEAT_FXSR;
    }
    if (edx & (1 << 25)) != 0 {
        bits |= FEAT_SSE;
    }
    if (edx & (1 << 26)) != 0 {
        bits |= FEAT_SSE2;
    }
    if (ecx & (1 << 26)) != 0 {
        bits |= FEAT_XSAVE;
    }
    // CPUID leaf 1 ECX bit 30 = RDRAND
    if (ecx & (1 << 30)) != 0 {
        bits |= FEAT_RDRAND;
    }

    // CPUID leaf 7, subleaf 0: structured extended features
    {
        // SAFETY: CPUID is always safe to call
        let (_, ebx7, _, _) = unsafe { cpuid_leaf(7, 0) };
        // EBX bit 7 = SMEP
        if (ebx7 & (1 << 7)) != 0 {
            bits |= FEAT_SMEP;
        }
        // EBX bit 18 = RDSEED
        if (ebx7 & (1 << 18)) != 0 {
            bits |= FEAT_RDSEED;
        }
        // EBX bit 20 = SMAP
        if (ebx7 & (1 << 20)) != 0 {
            bits |= FEAT_SMAP;
        }
    }

    // CPUID 0x80000007 EDX bit 8 = Invariant TSC.
    if cpuid_max_extended_leaf() >= 0x8000_0007 {
        // SAFETY: CPUID is always safe to call
        let (_, _, _, ext_edx) = unsafe { cpuid_leaf(0x8000_0007, 0) };
        if (ext_edx & (1 << 8)) != 0 {
            bits |= FEAT_INVARIANT_TSC;
        }
    }

    let mut xsave_area_size = DEFAULT_XSAVE_AREA_SIZE;
    if has_bit(bits, FEAT_XSAVE) {
        // Leaf 0x0D, subleaf 0: XSAVE area size.
        // SAFETY: CPUID is always safe to call.
        let (_, _, max_size, _) = unsafe { cpuid_leaf(0x0D, 0) };
        if max_size > 0 {
            xsave_area_size = max_size;
        }
    }

    CpuFeatures {
        bits,
        xsave_area_size,
    }
}

fn log_snapshot(cpu_id: usize, f: CpuFeatures) {
    let s = crate::SerialGuard::acquire();
    s.puts("[CPUID] CPU");
    s.dec(cpu_id as u64);
    s.puts(" SSE=");
    s.dec(has_bit(f.bits, FEAT_SSE) as u64);
    s.puts(" SSE2=");
    s.dec(has_bit(f.bits, FEAT_SSE2) as u64);
    s.puts(" FXSR=");
    s.dec(has_bit(f.bits, FEAT_FXSR) as u64);
    s.puts(" XSAVE=");
    s.dec(has_bit(f.bits, FEAT_XSAVE) as u64);
    s.puts(" INV_TSC=");
    s.dec(has_bit(f.bits, FEAT_INVARIANT_TSC) as u64);
    s.puts(" SMEP=");
    s.dec(has_bit(f.bits, FEAT_SMEP) as u64);
    s.puts(" SMAP=");
    s.dec(has_bit(f.bits, FEAT_SMAP) as u64);
    s.puts(" RDRAND=");
    s.dec(has_bit(f.bits, FEAT_RDRAND) as u64);
    s.puts(" RDSEED=");
    s.dec(has_bit(f.bits, FEAT_RDSEED) as u64);
    s.puts(" area_size=");
    s.dec(f.xsave_area_size as u64);
    s.putc(b'\n');
}

fn log_global_downgrade(cpu_id: usize, old_bits: u32, new_bits: u32) {
    let dropped = old_bits & !new_bits;
    if dropped == 0 {
        return;
    }

    let s = crate::SerialGuard::acquire();
    s.puts("[CPUID] Global feature downgrade by CPU");
    s.dec(cpu_id as u64);
    s.puts(":");
    if has_bit(dropped, FEAT_SSE) {
        s.puts(" SSE");
    }
    if has_bit(dropped, FEAT_SSE2) {
        s.puts(" SSE2");
    }
    if has_bit(dropped, FEAT_FXSR) {
        s.puts(" FXSR");
    }
    if has_bit(dropped, FEAT_XSAVE) {
        s.puts(" XSAVE");
    }
    if has_bit(dropped, FEAT_INVARIANT_TSC) {
        s.puts(" INV_TSC");
    }
    if has_bit(dropped, FEAT_SMEP) {
        s.puts(" SMEP");
    }
    if has_bit(dropped, FEAT_SMAP) {
        s.puts(" SMAP");
    }
    if has_bit(dropped, FEAT_RDRAND) {
        s.puts(" RDRAND");
    }
    if has_bit(dropped, FEAT_RDSEED) {
        s.puts(" RDSEED");
    }
    s.putc(b'\n');
}

fn validate_required_features(cpu_id: usize, bits: u32) {
    let missing = REQUIRED_MASK & !bits;
    if missing == 0 {
        return;
    }

    let s = crate::SerialGuard::acquire();
    s.puts("*** FATAL: CPU");
    s.dec(cpu_id as u64);
    s.puts(" missing required CPUID feature(s):");
    if has_bit(missing, FEAT_SSE) {
        s.puts(" SSE");
    }
    if has_bit(missing, FEAT_SSE2) {
        s.puts(" SSE2");
    }
    if has_bit(missing, FEAT_FXSR) {
        s.puts(" FXSR");
    }
    s.putc(b'\n');
    drop(s);

    panic!("Required CPUID features are not consistent across CPUs");
}

/// Run CPUID on the BSP and initialize global/per-CPU state.
pub fn init() {
    let local = read_local_features();
    validate_required_features(0, local.bits);

    GLOBAL_BITS.store(local.bits, Ordering::Release);
    PER_CPU_BITS[0].store(local.bits, Ordering::Release);
    PER_CPU_XSAVE_AREA_SIZE[0].store(local.xsave_area_size, Ordering::Release);

    if has_bit(local.bits, FEAT_XSAVE) {
        GLOBAL_XSAVE_AREA_SIZE.store(local.xsave_area_size, Ordering::Release);
    } else {
        GLOBAL_XSAVE_AREA_SIZE.store(DEFAULT_XSAVE_AREA_SIZE, Ordering::Release);
    }

    log_snapshot(0, local);
}

/// Register AP CPUID features into global/per-CPU state.
///
/// Must be called on each AP before feature-dependent initialization.
pub fn register_ap(cpu_id: usize) {
    if cpu_id >= super::cpu::MAX_CPUS {
        panic!("CPU ID out of range in CPUID registration");
    }

    let local = read_local_features();
    validate_required_features(cpu_id, local.bits);
    log_snapshot(cpu_id, local);

    PER_CPU_BITS[cpu_id].store(local.bits, Ordering::Release);
    PER_CPU_XSAVE_AREA_SIZE[cpu_id].store(local.xsave_area_size, Ordering::Release);

    let old_global = GLOBAL_BITS.fetch_and(local.bits, Ordering::AcqRel);
    let new_global = old_global & local.bits;
    log_global_downgrade(cpu_id, old_global, new_global);

    if has_bit(new_global, FEAT_XSAVE) {
        // XSAVE still globally enabled: keep minimum buffer size across CPUs.
        let local_size = local.xsave_area_size.max(DEFAULT_XSAVE_AREA_SIZE);
        let mut cur = GLOBAL_XSAVE_AREA_SIZE.load(Ordering::Acquire);
        while local_size < cur {
            match GLOBAL_XSAVE_AREA_SIZE.compare_exchange_weak(
                cur,
                local_size,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => cur = observed,
            }
        }
    } else {
        // XSAVE globally disabled after intersection.
        GLOBAL_XSAVE_AREA_SIZE.store(DEFAULT_XSAVE_AREA_SIZE, Ordering::Release);
    }
}

/// Check if SSE is globally supported.
#[inline]
pub fn has_sse() -> bool {
    has_bit(GLOBAL_BITS.load(Ordering::Acquire), FEAT_SSE)
}

/// Check if SSE2 is globally supported.
#[inline]
pub fn has_sse2() -> bool {
    has_bit(GLOBAL_BITS.load(Ordering::Acquire), FEAT_SSE2)
}

/// Check if FXSAVE/FXRSTOR is globally supported.
#[inline]
pub fn has_fxsr() -> bool {
    has_bit(GLOBAL_BITS.load(Ordering::Acquire), FEAT_FXSR)
}

/// Check if XSAVE/XRSTOR is globally supported.
#[inline]
pub fn has_xsave() -> bool {
    has_bit(GLOBAL_BITS.load(Ordering::Acquire), FEAT_XSAVE)
}

/// Check if invariant TSC is globally supported.
#[inline]
pub fn has_invariant_tsc() -> bool {
    has_bit(GLOBAL_BITS.load(Ordering::Acquire), FEAT_INVARIANT_TSC)
}

/// Check if SMEP (Supervisor Mode Execution Prevention) is globally supported.
#[inline]
pub fn has_smep() -> bool {
    has_bit(GLOBAL_BITS.load(Ordering::Acquire), FEAT_SMEP)
}

/// Check if SMAP (Supervisor Mode Access Prevention) is globally supported.
#[inline]
pub fn has_smap() -> bool {
    has_bit(GLOBAL_BITS.load(Ordering::Acquire), FEAT_SMAP)
}

/// Check if RDRAND is globally supported.
#[inline]
pub fn has_rdrand() -> bool {
    has_bit(GLOBAL_BITS.load(Ordering::Acquire), FEAT_RDRAND)
}

/// Check if RDSEED is globally supported.
#[inline]
pub fn has_rdseed() -> bool {
    has_bit(GLOBAL_BITS.load(Ordering::Acquire), FEAT_RDSEED)
}

/// Check if SSE is supported on a specific CPU.
#[inline]
pub fn has_sse_on(cpu_id: usize) -> bool {
    has_bit(cpu_bits(cpu_id), FEAT_SSE)
}

/// Check if SSE2 is supported on a specific CPU.
#[inline]
pub fn has_sse2_on(cpu_id: usize) -> bool {
    has_bit(cpu_bits(cpu_id), FEAT_SSE2)
}

/// Check if FXSAVE/FXRSTOR is supported on a specific CPU.
#[inline]
pub fn has_fxsr_on(cpu_id: usize) -> bool {
    has_bit(cpu_bits(cpu_id), FEAT_FXSR)
}

/// Check if XSAVE/XRSTOR is supported on a specific CPU.
#[inline]
pub fn has_xsave_on(cpu_id: usize) -> bool {
    has_bit(cpu_bits(cpu_id), FEAT_XSAVE)
}

/// Check if invariant TSC is supported on a specific CPU.
#[inline]
pub fn has_invariant_tsc_on(cpu_id: usize) -> bool {
    has_bit(cpu_bits(cpu_id), FEAT_INVARIANT_TSC)
}

/// Get the global XSAVE area size.
#[inline]
pub fn xsave_area_size() -> usize {
    GLOBAL_XSAVE_AREA_SIZE.load(Ordering::Acquire) as usize
}

/// Get the XSAVE area size for a specific CPU.
#[inline]
pub fn xsave_area_size_on(cpu_id: usize) -> usize {
    if cpu_id < super::cpu::MAX_CPUS {
        PER_CPU_XSAVE_AREA_SIZE[cpu_id].load(Ordering::Acquire) as usize
    } else {
        DEFAULT_XSAVE_AREA_SIZE as usize
    }
}
