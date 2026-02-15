//! C runtime startup
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Entry point for all C programs on SaltyOS. The dynamic linker (`rtld`)
//! calls `_start` (in `crt_start.S`), which calls `__libc_start_main` here.
//!
//! Initialization sequence:
//! 1. Parse the initial stack layout: `argc`, `argv[]`, `envp[]`, `auxv[]`
//! 2. Initialize `environ` from `envp`
//! 3. Parse SaltyOS-specific auxv tags (`AT_SALTY_*`) to set up IPC context
//! 4. Call `tcb_set_ipc_buffer` to configure the per-thread IPC buffer
//! 5. Initialize `ipc_context` for libsalty IPC wrappers
//! 6. Parse auxv for memory manager configuration (untyped cap, vspace, etc.)
//! 7. Initialize the per-process slot allocator (preferring RTLD-exported pool)
//! 8. Initialize `posix_mm` (heap and mmap regions)
//! 9. Set program name from `argv[0]` for BSD `err(3)` functions
//! 10. Initialize FreeBSD rune locale tables for `ctype.h` compatibility
//!
//! Custom auxv tags used by SaltyOS:
//! - `0x1000` (`AT_SALTY_UNTYPED`): untyped memory capability slot
//! - `0x1001` (`AT_SALTY_VSPACE`): VSpace capability slot
//! - `0x1002` (`AT_SALTY_SCRATCH`): scratch virtual address region
//! - `0x1005` (`AT_SALTY_FRAME_SLOT`): frame slot for page mapping
//! - `0x1007` (`AT_SALTY_SLOT_BASE`): slot allocator pool base
//! - `0x1008` (`AT_SALTY_SLOT_COUNT`): slot allocator pool size
//! - `0x1009` (`AT_SALTY_EXPAND_EP`): endpoint for requesting more slots

use crate::env;

/// Maximum number of atexit handlers
const ATEXIT_MAX: usize = 32;

static mut ATEXIT_FUNCS: [Option<unsafe extern "C" fn()>; ATEXIT_MAX] = [None; ATEXIT_MAX];
static mut ATEXIT_COUNT: usize = 0;

/// Called from _start (crt_start.S). Receives a pointer to main() and the
/// initial stack pointer. Parses the stack to extract argc, argv, envp, and
/// auxv. Initializes the C runtime, then calls main().
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_start_main(
    main_fn: unsafe extern "C" fn(i32, *const *const u8, *const *const u8) -> i32,
    stack_ptr: *const u64,
) -> ! {
    unsafe {
        // Stack layout: argc, argv[0], argv[1], ..., NULL, envp[0], ..., NULL, auxv...
        let argc = *stack_ptr as i32;
        let argv = stack_ptr.add(1) as *const *const u8;

        // Find envp: skip past argv (argc pointers + NULL terminator)
        let envp = argv.add(argc as usize + 1) as *const *const u8;

        // Initialize environ
        env::init_environ(envp);

        // Initialize IPC context from auxv if available
        init_ipc_from_auxv(stack_ptr);

        // Initialize memory manager
        init_mm_from_auxv(stack_ptr);

        // Set program name from argv[0] for BSD err(3) functions
        if argc > 0 && !(*argv).is_null() {
            crate::misc_impl::setprogname(*argv);
        }

        // Initialize FreeBSD locale/rune compatibility
        crate::compat::freebsd::rune::init_rune_locale();

        // Probe fd 0: if already open (inherited from exec), skip /dev/console.
        // dup(0) succeeds if fd 0 exists (exec'd process), fails if empty (fresh spawn).
        let probe = salty::posix::posix_dup(0);
        if probe >= 0 {
            // fd 0 exists — inherited from exec caller (getty→bash).
            // Close the test fd and leave fd 0/1/2 as-is.
            salty::posix::posix_close(probe);
        } else {
            // fd 0 doesn't exist — fresh spawn. Open /dev/console.
            let fd0 = salty::posix::posix_open(b"/dev/console\0".as_ptr(), 2); // O_RDWR
            if fd0 >= 0 {
                salty::posix::posix_dup(fd0); // fd 1
                salty::posix::posix_dup(fd0); // fd 2
            }
        }

        // Initialize stdio pointers (stdin/stdout/stderr) so that programs
        // using fprintf(stderr, ...) etc. get valid FILE* from the GOT.
        crate::stdio::ensure_stdio_init();

        // Call main
        let ret = main_fn(argc, argv, envp);

        // Exit
        exit(ret);
    }
}

/// Parse auxv entries from the stack
unsafe fn init_ipc_from_auxv(stack_ptr: *const u64) {
    unsafe {
        let argc = *stack_ptr as usize;
        let argv = stack_ptr.add(1);

        // Skip argv
        let mut p = argv.add(argc + 1); // past NULL terminator

        // Skip envp
        while !(*p as *const u8).is_null() {
            p = p.add(1);
        }
        let _auxv = p.add(1); // past envp NULL terminator — points to auxv pairs
        let ipc_buf_vaddr: u64 = 0x0000_0000_0020_0000;
        salty::invoke::tcb_set_ipc_buffer(salty::CAP_SELF_TCB, ipc_buf_vaddr);
        salty::ipc::ipc_context_init(
            &raw mut salty::__salty_ipc_ctx,
            ipc_buf_vaddr as *mut salty::types::IpcBuffer,
        );
    }
}

/// Initialize the POSIX memory manager and per-process slot allocator from auxv.
///
/// Parses SaltyOS-specific auxiliary vector entries (`AT_SALTY_*`) to discover:
/// - Untyped memory capability (for backing `sbrk`/`mmap` allocations)
/// - VSpace capability (for mapping frames into the address space)
/// - Frame slot and scratch region addresses
/// - Slot allocator pool (base + count) for capability slot management
/// - Expand endpoint (for requesting additional slots from the process manager)
///
/// The RTLD (runtime dynamic linker) may have already consumed some slots while
/// loading shared libraries, so its exported `__salty_slot_base` / `__salty_slot_count`
/// take precedence over the raw auxv values when non-zero. Similarly, the RTLD's
/// `__salty_expand_ep` overrides the auxv expand endpoint.
///
/// After slot allocation setup, the heap region is placed 1 MB after the scratch
/// area, and the `mmap` region starts 16 MB after the heap base.
unsafe fn init_mm_from_auxv(stack_ptr: *const u64) {
    unsafe {
        let argc = *stack_ptr as usize;
        let argv = stack_ptr.add(1);
        let mut p = argv.add(argc + 1);

        while !(*p as *const u8).is_null() {
            p = p.add(1);
        }
        p = p.add(1);

        // Parse auxv
        let mut untyped: u64 = salty::CAP_UNTYPED;
        let mut vspace: u64 = salty::CAP_SELF_VSPACE;
        let mut frame_slot: u64 = 64;
        let mut scratch: u64 = salty::SCRATCH_VADDR;
        let mut slot_base: u64 = 0;
        let mut slot_count: u64 = 0;
        let mut expand_ep: u64 = 0;

        loop {
            let tag = *p;
            let val = *p.add(1);
            if tag == 0 {
                break; // AT_NULL
            }
            match tag {
                0x1000 => untyped = val,     // AT_SALTY_UNTYPED
                0x1001 => vspace = val,      // AT_SALTY_VSPACE
                0x1005 => frame_slot = val,  // AT_SALTY_FRAME_SLOT
                0x1002 => scratch = val,     // AT_SALTY_SCRATCH
                0x1007 => slot_base = val,   // AT_SALTY_SLOT_BASE
                0x1008 => slot_count = val,  // AT_SALTY_SLOT_COUNT
                0x1009 => expand_ep = val,   // AT_SALTY_EXPAND_EP
                _ => {}
            }
            p = p.add(2);
        }

        // Prefer RTLD-exported slot pool info because RTLD advances it past
        // the slots consumed while loading shared libraries.
        let rtld_base = *(&raw const salty::__salty_slot_base);
        let rtld_count = *(&raw const salty::__salty_slot_count);
        if rtld_base != 0 && rtld_count != 0 {
            slot_base = rtld_base;
            slot_count = rtld_count;
        }

        // Prefer RTLD-exported expand EP (set by rtld_main.c from auxv)
        let rtld_expand_ep = *(&raw const salty::__salty_expand_ep);
        if rtld_expand_ep != 0 {
            expand_ep = rtld_expand_ep;
        }

        // Initialize per-process slot allocator only from dynamic slot-pool info.
        // No legacy fallback to __salty_next_frame_slot.
        if slot_base != 0 {
            salty::slot_alloc::slot_alloc_init(slot_base, slot_count, expand_ep);
        }

        // Heap starts after scratch area
        let heap_base = scratch + 0x100000; // 1MB after scratch
        let mmap_base = heap_base + 0x1000000; // 16MB after heap base

        salty::posix_mm::posix_mm_init(
            untyped,
            vspace,
            salty::CAP_SELF_CSPACE,
            frame_slot,
            heap_base,
            mmap_base,
        );
    }
}

/// Register a function to be called at exit
#[unsafe(no_mangle)]
pub unsafe extern "C" fn atexit(func: unsafe extern "C" fn()) -> i32 {
    unsafe {
        if ATEXIT_COUNT >= ATEXIT_MAX {
            return -1;
        }
        ATEXIT_FUNCS[ATEXIT_COUNT] = Some(func);
        ATEXIT_COUNT += 1;
        0
    }
}

/// Exit the program, calling atexit handlers in reverse order
#[unsafe(no_mangle)]
pub unsafe extern "C" fn exit(status: i32) -> ! {
    unsafe {
        // Call atexit handlers in reverse order
        while ATEXIT_COUNT > 0 {
            ATEXIT_COUNT -= 1;
            if let Some(func) = ATEXIT_FUNCS[ATEXIT_COUNT] {
                func();
            }
        }

        // Flush stdio
        crate::stdio::fflush_all();

        // Call _exit
        _exit(status);
    }
}

/// Immediate exit without cleanup
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _exit(status: i32) -> ! {
    unsafe {
        salty::posix::posix_exit(status);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _Exit(status: i32) -> ! {
    unsafe { _exit(status) }
}
