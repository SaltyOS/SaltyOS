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
//! 6. Initialize the per-process slot allocator (preferring RTLD-exported pool)
//! 7. Initialize `posix_mm` with the mmsrv endpoint (slot 7)
//! 8. Set program name from `argv[0]` for BSD `err(3)` functions
//! 9. Initialize FreeBSD rune locale tables for `ctype.h` compatibility
//!
//! Custom auxv tags used by SaltyOS:
//! - `0x1007` (`AT_SALTY_SLOT_BASE`): slot allocator pool base
//! - `0x1008` (`AT_SALTY_SLOT_COUNT`): slot allocator pool size

use crate::env;

// Standard child CSpace layout
const CAP_SELF_TCB: u64 = 0;
const CAP_MMSRV_EP: u64 = 7;

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

        // Initialize TLS for the main thread (must come after IPC + MM init)
        salty::tls::init_main_thread_tls();

        // Set program name from argv[0] for BSD err(3) functions
        if argc > 0 && !(*argv).is_null() {
            crate::compat::freebsd::bsd_misc::setprogname(*argv);
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
        salty::invoke::tcb_set_ipc_buffer(CAP_SELF_TCB, ipc_buf_vaddr);
        salty::ipc::ipc_context_init(
            &raw mut salty::__salty_ipc_ctx,
            ipc_buf_vaddr as *mut salty::types::IpcBuffer,
        );
    }
}

/// Initialize the per-process slot allocator and POSIX memory manager from auxv.
///
/// Parses SaltyOS-specific auxiliary vector entries (`AT_SALTY_*`) to discover
/// the slot allocator pool and the mmsrv endpoint capability. The RTLD may
/// have already consumed some slots, so its exported values take precedence
/// over raw auxv. The mmsrv endpoint (CAP_MMSRV_EP = slot 7) is provided by
/// the process manager at spawn time for all post-mmsrv processes.
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
        let mut slot_base: u64 = 0;
        let mut slot_count: u64 = 0;

        loop {
            let tag = *p;
            let val = *p.add(1);
            if tag == 0 {
                break; // AT_NULL
            }
            match tag {
                0x1007 => slot_base = val,   // AT_SALTY_SLOT_BASE
                0x1008 => slot_count = val,  // AT_SALTY_SLOT_COUNT
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

        let cspace_ntfn = *(&raw const salty::__salty_cspace_ntfn);

        // Initialize per-process slot allocator
        if slot_base != 0 {
            salty::slot_alloc::slot_alloc_init(slot_base, slot_count, cspace_ntfn);
        }

        // Initialize posix_mm with the mmsrv endpoint (slot 7 for post-mmsrv processes)
        salty::posix_mm::posix_mm_init(CAP_MMSRV_EP);
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
