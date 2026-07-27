# RTLD and Loader Contract

This document defines the current contract and responsibility split between the
SaltyOS startup block, loader helpers, and the runtime dynamic linkers.

---

## 1. Scope

This spec covers:

- process startup input consumed by RTLD
- the boundary between loader helpers and RTLD ownership
- ELF and PE RTLD responsibilities
- runtime ABI publication through `TronaRuntimeV1`
- the PE TLS producer model owned by RTLD

This spec does **not** cover downstream runtime-consumer behavior for future
threads. That is the next phase after this document.

---

## 2. Entry Contract

Every dynamically started process receives:

1. standard auxv entries (`AT_BASE`, `AT_ENTRY`, `AT_PHDR`, ...)
2. one SaltyOS-private auxv entry: `AT_SALTYOS_STARTUP`

`AT_SALTYOS_STARTUP` points to `SaltyOSStartupLayoutV1`.

`SaltyOSStartupLayoutV1` is **bootstrap-only** metadata. It carries validated
pointers / virtual addresses for:

- IPC buffer
- scratch area
- shared-library / DSO window
- capability table
- CSpace layout
- main-image metadata
- preloaded bootstrap image metadata (`mapped_images[]`)

It is **not** the post-link runtime contract, and RTLD does not back-write
mutable state into it.

The only ABI-stable fixed capability slots remain:

| Slot | Meaning |
|------|---------|
| 0 | `CAP_SELF_TCB` |
| 1 | `CAP_SELF_VSPACE` |
| 2 | `CAP_SELF_CSPACE` |

All other startup capabilities are delivered through `SaltyOSCapTableV1`.

---

## 3. Unified RTLD Entry

SaltyOS has one conceptual runtime-linker entry: `rtld_main`.

- **ELF dispatch** derives main-image state from standard auxv state such as
  `AT_PHDR`, `AT_ENTRY`, and `AT_BASE`.
- **PE dispatch** uses `SaltyOSStartupLayoutV1.main_image` to describe the already
  mapped main PE image.

There are no PE-specific auxv tags in the current contract.

---

## 4. Loader vs RTLD Responsibility Split

### 4.1 Loader Helpers

The loader crate provides format-level helpers:

- ELF parsing and relocation helpers
- PE header / section / relocation helpers
- PE import/export helper routines
- CPIO archive iteration

These helpers do **not** own the dynamic dependency graph.

### 4.2 RTLD

RTLD owns dynamic-link semantics.

That includes:

- deciding what objects / DLLs must be loaded
- reserving and mapping image space from RTLD-owned windows
- driving relocation and dependency closure
- publishing finalized runtime metadata
- failing hard on unresolved mandatory linkage

The key design rule is:

> **loader code parses formats; RTLD owns the graph and the process-level
> runtime contract.**

---

## 5. RTLD-Owned Mapping Resources

Both runtime linkers consume `SaltyOSCspaceLayoutV1` directly.

RTLD uses the startup-provided windows for:

- mirrored generic-untyped slots
- persistent frame slots
- shared-library virtual-address space

New RTLD-owned images must be allocated from those windows, not from ad-hoc
consumer-owned state.

---

## 6. ELF RTLD Contract

The ELF RTLD owns:

1. `DT_NEEDED` closure
2. link-map ownership for the preloaded bootstrap DSO set
3. relocation and GOT / PLT setup
4. static TLS layout computation and publication
5. runtime installation before constructors

Current closure properties:

- missing mandatory `DT_NEEDED` from the preloaded startup set is fatal
- missing `trona_runtime_install` is fatal
- runtime state is installed one-way into `TronaRuntimeV1`

---

## 7. PE RTLD Contract

The PE RTLD owns:

1. starting from the pre-mapped main PE image
2. recursive import resolution over the preloaded bootstrap DLL set
3. dependency-first DLL graph validation
4. normal import resolution
5. delay-import resolution
6. dependency-first DLL initialization
7. TLS raw-data setup
8. TLS callback dispatch
9. `DLL_PROCESS_ATTACH`

The PE DLL graph is therefore owned by RTLD, not by:

- consumer code
- filesystem / initrd discovery
- subsystem-specific out-of-band discovery

---

## 8. Runtime ABI Publication

`TronaRuntimeV1` is the finalized post-RTLD contract exported to libtrona /
libc.

It publishes:

- auxv pointer
- startup-block pointer
- capability-table pointer
- CSpace-layout pointer
- RTLD-updated frame-slot state
- shared capability state
- ELF static TLS metadata
- PE TLS producer metadata

Consumers must treat:

- `SaltyOSStartupLayoutV1` as **bootstrap input**
- `TronaRuntimeV1` as **final runtime state**

---

## 9. PE TLS Producer Model

SaltyOS now distinguishes between two thread-pointer contracts:

| Purpose | x86_64 | aarch64 |
|---------|--------|---------|
| runtime TLS base for libtrona / libc | `FS_BASE` | `TPIDR_EL0` |
| PE ABI thread pointer for compiled Win32 TLS | user `GS` base | `x18` |

To support compiled PE TLS access, RTLD installs a minimal TEB-like block at
the PE ABI thread pointer.

The TEB-like block provides:

- `ThreadLocalStoragePointer` at offset `0x58`
- a runtime-TCB back-pointer
- vector-length metadata for the process TLS vector

For the main thread, RTLD also materializes the current TLS vector and fills it
with the process TLS raw blocks.

---

## 10. Published PE TLS Metadata

RTLD publishes the following PE TLS producer state through `TronaRuntimeV1`:

- `pe_abi_tp`
- `pe_tls_vector_len`
- `pe_tls_module_count`
- `pe_tls_modules[]`

Each `pe_tls_modules[]` entry describes:

- TLS slot index
- template base address
- initialized size (`filesz`)
- total size including zero-fill (`memsz`)

This means RTLD no longer keeps PE TLS knowledge as a main-thread-only private
state. Future runtime layers can reconstruct PE TLS for new threads from the
published metadata.

---

## 11. Runtime dlfcn ownership

`dlopen` / `dlsym` / `dlclose` / `dladdr` / `dl_iterate_phdr` / `__tls_get_addr`
are owned by the rtld. libc carries only a thin C ABI shim that locates the
rtld function table and dispatches.

### 11.1 Function table — `RtldDlfcnV1`

The rtld constructs a static `RtldDlfcnV1` (defined in
`lib/trona/uapi/types/core.rs`) whose entries each take a caller-supplied
error buffer as the last two parameters:

| Field | Signature |
|---|---|
| `dlopen` | `(path, flags, errbuf, errbuf_len) -> *mut u8` |
| `dlsym_from` | `(handle, symbol, caller_pc, errbuf, errbuf_len) -> *mut u8` |
| `dlclose` | `(handle, errbuf, errbuf_len) -> i32` |
| `dladdr` | `(addr, info: *mut DlInfo, errbuf, errbuf_len) -> i32` |
| `dl_iterate_phdr` | `(callback, data, errbuf, errbuf_len) -> i32` |
| `tls_addr` | `(module, offset, errbuf, errbuf_len) -> *mut u8` |
| `tls_destroy` | `(thread_id, errbuf, errbuf_len)` |

### 11.2 Loader runtime publication — `TronaLoaderRuntimeV1`

The function table pointer is published through a sibling-of-`TronaRuntimeV1`
descriptor:

| Field | Value |
|---|---|
| `magic` | `0x5452_4C54` ("TLRT") |
| `version` | `1` |
| `flags` | reserved, currently `0` |
| `dlfcn` | `RtldDlfcnV1` instance |

The rtld calls `trona_loader_runtime_install(&loader_v1)` (sibling to
`trona_runtime_install`) immediately after `install_runtime_auxv`. libc looks
the table up via `trona::loader_dlfcn()`. The descriptor is held in a static
inside the rtld; libtrona only stores the pointer, not the contents.

### 11.3 Handle conventions

| Handle value | Meaning |
|---|---|
| `(void*)-1` | RTLD_NEXT — `dlsym` only |
| `null` | RTLD_DEFAULT — global scope lookup |
| `1` | Result of `dlopen(NULL, ...)` — also resolves via global scope |
| any other | Pointer to a `LinkMap` produced by `load_object` |

### 11.4 RTLD_NEXT caller PC

`dlsym(RTLD_NEXT, name)` requires the caller's PC. libc's public `dlsym`
entry routes through a per-arch trampoline (`__dlsym_capture_pc`) that
captures the return address (x86_64 `(%rsp)`, aarch64 `LR`) and tail-calls
`__basaltc_dlsym_with_pc(handle, symbol, caller_pc)`. The rtld then looks up
the LinkMap covering `caller_pc` and starts global-scope search past it.
Stack-walk and DWARF-based alternatives are intentionally not used because
they are fragile under FP-omission and signal contexts.

### 11.5 RUNPATH / RPATH search order

For non-slash dependency names, the rtld searches:

1. The requesting object's `DT_RUNPATH` (when present).
2. Else the requesting object's `DT_RPATH` (legacy).
3. Default system paths: `/usr/lib`, then `/lib`.

Slash-bearing paths are taken verbatim and not subjected to search.

### 11.6 RTLD_GLOBAL / RTLD_LOCAL semantics

Each LinkMap carries a `flags` bit set
(`STARTUP`, `RTLD_GLOBAL`, `RTLD_LOCAL`, `RTLD_NODELETE`,
`RUNTIME_LOADED`, `RELOCATED`, `INIT_DONE`, `FINI_DONE`). Symbols in objects
flagged `RTLD_GLOBAL` join the global scope chain; objects flagged
`RTLD_LOCAL` are reachable only via their own handle and dependency vector.

### 11.7 dlclose lifecycle

`dlclose` decrements `refcount`. When `refcount == 0`:

1. If `STARTUP` is set, dlclose is a no-op (startup objects are pinned).
2. If `RTLD_NODELETE` is set, the chain entry stays mapped and reachable.
3. Otherwise, `DT_FINI_ARRAY` runs in reverse, then `DT_FINI`, then the
   PT_LOAD-derived mapping is `munmap`ped and the LinkMap is unlinked.

### 11.8 Dynamic TLS DTV layout

Per-thread DTV storage lives behind `ThreadLocalBlock::dynamic_tls`. The
layout is rtld-private:

- DTV header (`generation`, `capacity`).
- Followed by `[DtvSlot; capacity]` where each slot stores a per-thread TLS
  block pointer + size.

`__tls_get_addr` in libc dispatches to `RtldDlfcnV1::tls_addr` when the
module ID is at or above `DYNAMIC_TLS_MODULE_BASE` (currently `17`, defined
in `lib/trona/uapi/types/core.rs`). On `pthread_exit`, libc invokes
`RtldDlfcnV1::tls_destroy` to walk the DTV and free per-module blocks before
substrate clears the TLS pointer.

---

## 12. Out of Scope

This document intentionally stops at the RTLD / loader producer boundary.

Still outside this spec:

- substrate/runtime creation of PE TLS state for future threads
- downstream consumer adoption of the published PE TLS metadata
- PE-side `LoadLibrary` / `GetProcAddress` runtime path (no first-party
  consumer yet)

Those are follow-on phases after the RTLD / loader contract is frozen.
