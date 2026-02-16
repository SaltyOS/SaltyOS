//! CPUID Feature Detection
//!
//! Detects CPU features at boot time via CPUID instruction.
//! Used to determine FPU/SSE/XSAVE capabilities.
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// Cached CPU feature flags
struct CpuFeatures {
    has_sse: bool,
    has_sse2: bool,
    has_fxsr: bool,
    has_xsave: bool,
    xsave_area_size: usize,
}

static mut CPU_FEATURES: CpuFeatures = CpuFeatures {
    has_sse: false,
    has_sse2: false,
    has_fxsr: false,
    has_xsave: false,
    xsave_area_size: 512, // FXSAVE minimum
};

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
fn cpuid_leaf1() -> (u32, u32) {
    // SAFETY: CPUID is always safe to call
    let (_, _, ecx, edx) = unsafe { cpuid_leaf(1, 0) };
    (ecx, edx)
}

/// Run CPUID and cache results. Called once on BSP during early init.
pub fn init() {
    // SAFETY: CPUID is a general-purpose instruction that works regardless
    // of soft-float target. Single-threaded boot context.
    unsafe {
        let (ecx, edx) = cpuid_leaf1();
        CPU_FEATURES.has_fxsr = (edx & (1 << 24)) != 0;
        CPU_FEATURES.has_sse = (edx & (1 << 25)) != 0;
        CPU_FEATURES.has_sse2 = (edx & (1 << 26)) != 0;
        CPU_FEATURES.has_xsave = (ecx & (1 << 26)) != 0;

        // Leaf 0x0D, subleaf 0: XSAVE area size (only if XSAVE supported)
        if CPU_FEATURES.has_xsave {
            let (_, _, max_size, _) = cpuid_leaf(0x0D, 0);
            if max_size > 0 {
                CPU_FEATURES.xsave_area_size = max_size as usize;
            }
        }

        {
            let s = crate::SerialGuard::acquire();
            s.puts("[CPUID] SSE=");
            s.dec(CPU_FEATURES.has_sse as u64);
            s.puts(" SSE2=");
            s.dec(CPU_FEATURES.has_sse2 as u64);
            s.puts(" FXSR=");
            s.dec(CPU_FEATURES.has_fxsr as u64);
            s.puts(" XSAVE=");
            s.dec(CPU_FEATURES.has_xsave as u64);
            s.puts(" area_size=");
            s.dec(CPU_FEATURES.xsave_area_size as u64);
            s.putc(b'\n');
        }
    }
}

/// Check if SSE is supported
#[inline]
pub fn has_sse() -> bool {
    // SAFETY: Written once during single-threaded boot, read-only after
    unsafe { CPU_FEATURES.has_sse }
}

/// Check if SSE2 is supported
#[inline]
pub fn has_sse2() -> bool {
    unsafe { CPU_FEATURES.has_sse2 }
}

/// Check if FXSAVE/FXRSTOR is supported
#[inline]
pub fn has_fxsr() -> bool {
    unsafe { CPU_FEATURES.has_fxsr }
}

/// Check if XSAVE/XRSTOR is supported
#[inline]
pub fn has_xsave() -> bool {
    unsafe { CPU_FEATURES.has_xsave }
}

/// Get the XSAVE area size (max for all supported features)
#[inline]
pub fn xsave_area_size() -> usize {
    unsafe { CPU_FEATURES.xsave_area_size }
}
