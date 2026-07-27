SaltyOS release 0.x (vNext)
=============================================

This is the source tree of SaltyOS, a research/hobby operating system
with a minimal trusted computing base, with a LLM-cowork development.

All resource access is mediated through unforgeable capability tokens.
The kernel provides only scheduling, IPC, memory management, and
capabilities — everything else (filesystem, drivers, networking,
process management) runs as isolated userspace servers.

The authoritative source for SaltyOS is available at:

        https://github.com/saltyos/saltyos

WHAT IS SALTYOS?
--------------

  SaltyOS is a capability-based microkernel operating system,
  inspired by seL4, Fuchsia, Mach and Windows NT.

  The kernel is written in Rust (edition 2024, freestanding #![no_std]).
  It runs on x86_64 (BIOS and UEFI) and aarch64 (UEFI only).

  The system supports multi-personality subsystems: POSIX and Win32
  processes run side-by-side, each with their own servers and ABIs.

LICENSING
--------------

  Copyright (C) 2026 Hamin Sung and SaltyOS contributors

  SaltyOS is licensed under the GNU General Public License version 2.
  See the file "LICENSE.md" for the full license text.

  Some files may carry individual license headers; where they do, that
  header governs the file.

PREREQUISITES
--------------

  The following tools are required to build SaltyOS from source:

    - Patched LLVM/Clang
    - Patched Rust
    - NASM (x86_64 assembly)
    - Meson >= 1.1
    - Ninja
    - Python 3
    - just (command runner, https://github.com/casey/just)
    - QEMU (qemu-system-x86_64 / qemu-system-aarch64 / UTM) for testing
    - OVMF or AAVMF (for UEFI boot testing)

  This project does NOT use Cargo (with an exception for ports). 
  All Rust code is compiled through Meson with direct rustc invocation.
  Do not create Cargo.toml files.

CUSTOM TOOLCHAIN
--------------

  SaltyOS includes a patched LLVM/Clang and rustc that know the
  x86_64-unknown-saltyos and aarch64-unknown-saltyos targets:

        just tc setup                   # Create directories
        just tc build host llvm         # Build host Clang/LLD
        just tc build host rust         # Build host rustc
        just tc doctor                  # Validate toolchain
        just tc all                     # Full pipeline

  For quick bootstrap:

        just bootstrap                  # host tc → sysroot → std + cargo → ports

  For cross-compilation (self-hosting):

        just self-host                  # sysroot → cross llvm → cross rust

  Environment setup:

        eval "$(just toolchain-env)"

CONFIGURING
--------------

  SaltyOS uses Meson as its build system.  The default target is
  x86_64.  To configure:

        just setup

  For aarch64 (UEFI-only):

        just arch=aarch64 setup

  Build directories are architecture-qualified: build-x86_64/ and
  build-aarch64/.  To reconfigure an existing build tree:

        just reconfigure -Dkernel_log_level=debug
        just reconfigure -Ddebug_symbols=true

  Notable build options (see meson.options for the full list):

        arch                  x86_64 | aarch64
        build_boot            Build the bootloader (default: true)
        build_kernel          Build the microkernel (default: true)
        build_userland        Build userland components (default: true)
        build_ports           Build port packages (default: false)
        kernel_log_level      error | warn | info | debug | trace
        max_cpus              1–256 (default: 16)
        kernel_stack_size     4096–65536 bytes (default: 16384)
        build_libcxx          auto | true | false

BUILDING
--------------

  To build all components (bootloader, kernel, userland, images):

        just build

  For aarch64:

        just arch=aarch64 build

  To clean everything and start over:

        just distclean

  The build chain compiles: Rust core/compiler_builtins → kernel ELF →
  trona system library → basalt C library → userland programs → CPIO
  initrd → bootable disk image.

RUNNING IN QEMU
--------------

  The simplest way to test is:

        just run

  This builds (if needed) and boots in QEMU with BIOS firmware and a
  single CPU.  Flags can be combined freely:

        just run --smp 4 --uefi --headless --debug

  Some available flags:

        --smp N       Boot with N CPUs
        --mem N(M/G)  Boot with N(M/G) MEM
        --uefi        Use UEFI firmware instead of BIOS
        --headless    Serial-only output (no GUI window)
        --gdb         Start QEMU with GDB server (-s -S)
        --debug       Log interrupts and resets to qemu.log
        --utm         Start with UTM

  For aarch64 (always UEFI):

        just arch=aarch64 run

  Quick rebuild + run shortcut:

        just rr

CODE QUALITY
--------------

  Formatting:

        just fmt              # Format Rust and C sources
        just fmt-check        # Check formatting (CI-safe)

  Warnings:

        just warn             # Full warning scan (both architectures)
        just arch=aarch64 warn

  Sysroot validation:

        just cross-hello      # Validate C cross-compilation
        just cross-hello-cpp  # Validate C++ cross-compilation

SOURCE TREE LAYOUT
--------------

        boot/           - 3-stage bootloader (BIOS + UEFI, C/ASM)
        kernite/        - Microkernel (Rust, freestanding)
          src/
            arch/       - Architecture-specific code (x86_64, aarch64)
            cap/        - Capability system (CNode, Untyped, CDT)
            console/    - Kernel console (serial + framebuffer)
            ipc/        - MessagePipe, DataPipe, EventQueue, Futex, IRQ routing
            mm/         - Virtual memory, MemoryObject, PMM
            sched/      - EDF scheduler, TCB, context switch
            syscall/    - Syscall dispatch, capability invocation
        lib/
          trona/        - System library (Rust, 6 crates)
            kernel/     - ABI layer; consts bindgen-generated from kernite/include/uapi/*.h
            protocol/   - IPC protocol labels and shared types
            server/     - Server-side helpers and well-known cap table
            runtime/    - Runtime support (slot allocator, cap ownership)
            posix/      - POSIX compatibility (Rust API)
            loader/     - ELF/PE loaders, dynamic linkers (rtld)
            win32/      - kernel32 PE DLL (Win32 personality)
            arch/       - Architecture fork stubs (fork.S)
          basalt/       - C/C++ standard library
            c/          - libc.so (C99, POSIX)
            cpp/        - libc++.so (optional, from llvm-project)
        userland/
          core/         - Core servers
            init/       - Init / supervisor
            mmsrv/      - Memory manager server
            rsrcsrv/    - Resource server
            namesrv/    - Name service
            vfs/        - Virtual filesystem server
            logsrv/     - Log server
          drivers/      - Device drivers
            pcidrv/     - PCI enumeration
            blkdrv/     - Block devices (virtio-blk)
            netdrv/     - Network devices (virtio-net)
            dispdrv/    - Display (framebuffer)
            filesystems/
              saltyfs/  - SaltyFS filesystem driver
          servers/      - System servers
            console/    - Serial console
            netsrv/     - TCP/UDP/ICMP network stack
            dnssrv/     - DNS resolver
            posix/      - POSIX personality servers
            win32/      - Win32 personality servers
          services/     - Service unit files (.service)
          tests/        - Runtime test programs
        tools/          - Build helpers, image tools, port builder
        toolchain/      - Custom LLVM/rustc (git submodules)
        ports/          - Third-party software port definitions
        docs/           - Design documents and specifications
        images/         - Rootfs configuration (etc/, manifests)
        tests/          - Host-side cross-compilation tests

PORTS
--------------

  Third-party software is built via declarative .port files:

        just port bash          # Build a single port
        just fetch-ports        # Download all port sources

  Available ports: bash, bzip2, curl, freebsd-utils, htop, make,
  nano, nasm, ncurses, ninja, openpam, openssl, perl, python,
  sudo-rs, wget, xz, zlib, zstd.

DISK IMAGES
--------------

        just image              # Create BIOS disk image
        just image-uefi         # Create UEFI disk image
        just mkrootfs           # Build rootfs.img
        just mksaltyfs          # Generate SaltyFS test image

TESTING
--------------

  There is no cargo test.  Testing is done via QEMU boot and serial
  output observation:

        just build              # Must succeed
        just run                # Smoke test — watch for KERNEL PANIC
        just run --smp 2        # SMP test — races only show with >1 CPU
        just run --smp 4        # Stress test
        just fmt-check          # Formatting check

  The test_runner userland program runs internal test modules and
  prints PASS/FAIL for each case via serial output.

DOCUMENTATION
--------------

  Design documents (read before making architectural changes):

        docs/design/overview.md         System overview
        docs/design/kernel.md           Kernel internals
        docs/design/capability.md       Capability system
        docs/design/ipc.md              IPC design
        docs/design/scheduling.md       Scheduler design
        docs/design/memory.md           Memory management
        docs/design/bootloader.md       Bootloader stages
        docs/design/saltyfs.md          SaltyFS filesystem
        docs/design/posix.md            POSIX compatibility
        docs/design/trona.md            System library
        docs/design/basaltc.md          C library
        docs/design/mmsrv.md            Memory manager server
        docs/design/ports.md            Ports system

  Specifications (read before changing ABI or syscall interfaces):

        docs/spec/syscalls.md           Syscall reference
        docs/spec/abi.md                ABI specification
        docs/spec/boot_protocol.md      Boot protocol

CONTRIBUTING
--------------

  - Use Conventional Commit subjects: feat(scope): ..., fix(scope): ...
