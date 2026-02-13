//! C runtime startup
//! SPDX-License-Identifier: GPL-2.0-only

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

/// Initialize POSIX memory manager from auxv
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

        loop {
            let tag = *p;
            let val = *p.add(1);
            if tag == 0 {
                break; // AT_NULL
            }
            match tag {
                0x1000 => untyped = val,    // AT_SALTY_UNTYPED
                0x1001 => vspace = val,     // AT_SALTY_VSPACE
                0x1005 => frame_slot = val, // AT_SALTY_FRAME_SLOT
                0x1002 => scratch = val,    // AT_SALTY_SCRATCH
                _ => {}
            }
            p = p.add(2);
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
