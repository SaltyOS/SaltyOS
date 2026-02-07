# Repository Guidelines

## Project Structure & Module Organization
SaltyOS is split by execution layer:
- `boot/`: 3-stage bootloader (`stage1` ASM, `stage2`/`stage3` C).
- `kernel/src/`: Rust microkernel (arch, capabilities, IPC, memory, scheduler, syscalls).
- `userland/`: C servers/apps (`init`, `console`, `procmgr`, `vfs`, `nameserv`, tests).
- `lib/`: shared userspace libraries (`libsalty`, `libc`).
- `tools/`: build/image/test scripts (`mkimage.py`, `test_boot.sh`, `test_smp.sh`).
- `docs/`: architecture, design notes, and ABI/spec references.
- `build/`: generated artifacts (do not edit manually).

## Build, Test, and Development Commands
- `just setup`: configure Meson build directory.
- `just build`: compile bootloader, kernel, and enabled userland targets.
- `just run` / `just run-smp` / `just run-uefi`: boot in QEMU (BIOS, SMP, UEFI).
- `just test-integration`: boot smoke test via `tools/test_boot.sh`.
- `just test-smp`: SMP smoke test via `tools/test_smp.sh`.
- `just test-all`: run both integration suites.
- `just reconfigure -Dkernel_log_level=debug`: adjust Meson options without rebuilding config.
- `just fmt` and `just fmt-check`: format/check Rust and C sources.

## Coding Style & Naming Conventions
Use 4-space indentation and keep code freestanding-safe (no host libc assumptions). Follow existing naming:
- Rust: `snake_case` functions/modules, `CamelCase` types, `UPPER_SNAKE_CASE` constants.
- C: `snake_case` functions/variables, `UPPER_SNAKE_CASE` macros/capability slot constants.
Preserve SPDX license headers in new files and keep module names aligned with subsystem paths (example: `kernel/src/ipc/...`).

## Testing Guidelines
This repository uses QEMU-based integration testing, not a unit-test framework. Add or update assertions in `tools/test_boot.sh` / `tools/test_smp.sh` by checking serial log markers and absence of fault signatures. Run `just test-all` before opening a PR. Use `BOOT_TIMEOUT=30 just test-integration` for slower hosts.

## Commit & Pull Request Guidelines
Commit history follows Conventional Commits (`feat:`, `fix:`, `docs:`). Keep commits focused and descriptive. PRs should include:
- clear problem/solution summary,
- linked issue(s) when applicable,
- validation commands run (for example, `just build && just test-all`),
- relevant serial log excerpts for boot/runtime behavior changes.
