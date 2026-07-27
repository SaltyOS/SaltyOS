==================================================================
RFC-0009: Capability-Bounded W^X and the Code-Loading Authority
==================================================================

:Status: Implemented
:Areas: kernite cap-core (retype/rights) + mm (map surfaces, borrowed-frames MO); mmsrv (map-image, rights attenuation, fork, generic mmap); VFS (exec caps); ldsrv (new loader service); rtld (ELF + PE, linker-as-client); init / PID 1 (bootstrap loader, spawn); drivers (device cap egress); Capabilities (EXECUTE as conferred authority); W^X
:Authors: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5
:Date: 2026-06-25
:Depends: cap_native_spine (capability-mode posture — the loader-capability / confined-process angle; the seam and the W^X enforcement are landable independently for ambient processes)
:Description: One model for *who may run executable code and how W^X is enforced*, system wide. ``EXECUTE`` becomes a **conferred authority**, not a default of object creation: ``UntypedMemory::retype`` mints no ``EXECUTE``, so a process minting frames from its own untyped cannot make executable memory. The only sources of executable memory are (1) a **code-loading authority**, ``ldsrv``, which owns one shared ``READ|EXECUTE`` MemoryObject per distinct code object (the initrd mapped zero-copy for boot objects, a VFS-pager-backed object for disk-only ones) and serves it through a single seam ``resolve_library(name) -> executable MemoryObject`` to the runtime linker and PID 1 alike; and (2) an explicit **JIT exec-authority capability** for anonymous executable memory. The kernel derives every mapping's ``max_prot`` from its backing cap on **every** map surface (closing the raw-frame, demand, and untracked-page holes), and code is mapped through rights-attenuated capabilities of the code object — text ``R-X``, rodata ``R--``, data a private ``R-W`` copy-on-write child — so W^X holds by construction. This RFC subsumes and replaces the ``code_loading_authority`` draft, merging the loader-service design with the system-wide W^X enforcement it depends on.

Problem Statement
=================

Two defects share one root cause — executable memory is not bounded by
capability authority — and a boot failure made both visible.

W^X is enforced only by a userland mirror, and is bypassable
----------------------------------------------------------------

The kernel already derives a mapping's ceiling from the backing cap on the
``MAP_MO`` path (``max_prot_from_cap``, kernite ``src/syscall/vspace.rs``), and
refuses to raise a page above that ceiling (``check_protect_ceiling_locked``,
kernite ``src/mm/vspace.rs``). But the rights that feed it are never attenuated
— every MemoryObject is retyped ``CapRights::ALL`` (kernite
``src/cap/untyped.rs``) — so the kernel ceiling is ``R|W|X`` for all memory, and
the only thing keeping ``.text`` non-writable is ``mmsrv``'s userland
``max_prot_for_region_type`` mirror. That mirror is bypassable:

- **Self-minted executable frames.** ``UntypedMemory::retype`` mints
  ``CapRights::ALL``, and **every process's runtime linker holds a bootstrap
  untyped window** (``CHILD_RTLD_UNTYPED_SLOT_START..END``,
  ``lib/trona/runtime/src/spawn/layout.rs``; consumed by
  ``rtld/cap.rs::alloc_frame_slot``). So untrusted code mints its own
  ``EXECUTE``-bearing frames and maps them executable, then writable — no mirror
  is consulted on a direct kernel invoke. This is how the linker loads a library
  today: it reads the whole file and copies it into an anonymous executable
  mapping.
- **Raw frame map hardcodes the ceiling.** ``syscall_vspace_map`` builds the
  ``VmArea`` with a hardcoded ``max_prot = WRITE | EXECUTE`` ignoring the frame
  cap's rights (kernite ``src/syscall/vspace.rs``).
- **Ungated demand maps.** ``VSPACE_MAP_DEMAND(_RANGE)`` installs mappings —
  executable included — with no backing-cap check.
- **Share-ro alias.** ``share_ro_page_to`` copies a read-only PTE into a second
  VA with no ``VmArea``; an untracked page is treated as unconstrained, so the
  alias can be made writable. (Dormant — no callers — but a real hole.)
- **Clients hold full caps.** ``mmsrv`` returns clients full-rights MO caps
  (``copy_cap_for_reply`` with ``KERNITE_RIGHT_ALL``), and children hold an
  ``ALL``-rights self-VSpace cap; together with the above, a client can
  self-authorize any protection.

The library-loading path forfeits W^X on loaded code, forfeits the
physical-page sharing a file-backed object gets from the VFS page cache (every
process keeps its own copy of ``libc`` text), and is the one code-loading path
the VFS does not mediate. The deeper question is **who authorizes the executable
code a process runs**, and today the answer is "the process itself."

The PE boot failure
-------------------

``init`` stages a whole PE image as a single ``REGION_IMAGE_DATA`` region
(mirror ``R|W``); the PE runtime linker then ``mprotect``\ s each section to
``R|X``; the mirror rejects the ``X`` and the process aborts at
``[ldtrona-pe] mprotect failed``. A self-protecting loader cannot be expressed
as one data region — and, more deeply, it is reaching for executable protection
through a path with no executable authority.

Code delivery is asymmetric and split-brained
---------------------------------------------

Two code-delivery paths exist and disagree. At **bootstrap** (service spawn,
before VFS/name service), PID 1 parses the initrd and pre-maps a program's whole
shared-object closure. At **path execution** (post-boot), PID 1 maps only the
main image and interpreter and the linker resolves the rest — by the
copy-into-anonymous path above. The main image is an authorized ``READ|EXECUTE``
object (VFS open-for-exec); its libraries are not. One process's code is admitted
by two authorities under two policies.

Summary
=======

Make executable memory a **conferred capability**, and the kernel its enforcer:

* **EXECUTE is not a retype default.** ``UntypedMemory::retype`` mints no
  ``EXECUTE``. A process minting frames from its own untyped gets only non-exec
  memory. This is the Fuchsia model (creating a VMO does not make it executable;
  that needs the VMEX authority), composed with seL4-style untyped (untyped still
  creates objects — just not executable ones).

* **Two execution authorities are the only sources of ``EXECUTE``:**

  1. the **code-loading authority** ``ldsrv`` — owns one shared
     ``READ|EXECUTE`` MemoryObject per distinct code object, served through
     ``resolve_library(name) -> executable MemoryObject`` to the linker (for
     ``DT_NEEDED``) and PID 1 (for service-spawn images), the initrd mapped
     zero-copy for boot objects and a VFS-pager-backed object for disk-only ones;
  2. an explicit **JIT exec-authority capability** for anonymous executable
     memory, held by ``init`` and delegated only to JIT-permitted processes.

* **The kernel derives ``max_prot`` from the cap on every map surface** —
  ``MAP_MO`` (already), raw frame ``MAP`` (fix the hardcode), ``MAP_DEMAND``
  (gate ``EXECUTE``) — and default-denies W/X elevation on present-but-untracked
  pages (closing the share-ro alias). The ceiling can never exceed the cap.

* **Code is mapped through rights-attenuated caps of the code object** — text
  ``R-X``, rodata ``R--``, a private copy-on-write data child ``R-W`` — by a
  single ``mmsrv`` map-image-into-envelope operation, with ``mmsrv`` rejecting a
  map whose initial protection exceeds the cap-derived maximum. W^X by
  construction; text frames shared read-only across processes.

* **Non-code memory is non-exec by construction** — generic ``mmap`` strips
  ``EXECUTE`` from its map cap; fork maps children through caps attenuated to the
  parent's ceiling; device caps reach userland without ``EXECUTE``.

After this, the kernel ceiling is the single authoritative W^X enforcer;
``EXECUTE`` exists only where an authority conferred it; and the runtime linker
is a client of one resolution seam, never a self-authorizing copier of code.

(The unrelated reactor-allocation defect — general services read the raw
``__trona_cap_rsrcsrv_ep`` weak symbol instead of the lazy resolver in
``rsrc_alloc_object`` — is fixed separately as a plain bug, not part of this
RFC.)

Stakeholders
============

* **kernite cap-core** — ``retype`` mints no ``EXECUTE``; a privileged
  ``mark_executable`` / exec-conferring operation gated by the exec-authority;
  the borrowed-frames MemoryObject kind.
* **kernite mm** — cap-derived ``max_prot`` on ``MAP`` / ``MAP_DEMAND``;
  ``check_protect_ceiling_locked`` default-deny; the executable-map I-cache path.
* **mmsrv** — the map-image-into-envelope op; rights attenuation everywhere a cap
  is mapped (staging, fault completion, fork, generic mmap); cap-egress
  stripping; the map-time ``prot ≤ max_prot`` check. mmsrv mints **no** executable
  cap and is **not** a JIT conferral point: it only *preserves* ``EXECUTE`` on a
  client-presented (already exec-bearing) ``MMAP_KIND_MO`` cap and leaves the
  kernel ``max_prot`` ceiling to do the gating.
* **VFS** — supplies only a *non-exec* pager-backed MO per vnode plus policy
  input; mints no executable cap and exposes no public open-for-exec. ``ldsrv``
  adopts the per-vnode backing MO and confers ``EXECUTE`` via
  ``mo_mark_executable``.
* **ldsrv (new)** — the ``resolve_library`` server; the identity-keyed code-MO
  cache; initrd and VFS backings; the boot-cache handoff from PID 1.
* **rtld (ELF + PE)** — the linker becomes a ``resolve_library`` client; its
  copy-into-anonymous loader is removed; PE image protection rides the map-image
  op.
* **init / PID 1** — Stage-0 bootstrap loader; per-kind frame caps for
  direct-loader images; minting and delegating the JIT exec-authority cap.
* **drivers** — device cap egress without ``EXECUTE``.

Requirements
============

* **R1** ``EXECUTE`` is conferred only by the two authorities; ``retype`` never
  confers it; no untrusted process can manufacture executable memory from its own
  untyped.
* **R2** Kernel ``VmArea.max_prot`` is the authoritative ceiling on every map
  surface, derived from the backing cap; no surface hardcodes ``W`` or ``X``.
* **R3** Loaded code is W^X by construction (text ``R-X``, rodata ``R--``, data
  ``R-W`` COW), enforced by the cap-derived ceiling, and a sealed/loaded code page
  cannot be made writable via ``mprotect``, a share-ro alias, fork, or a direct
  kernel invoke.
* **R4** All library/main-image resolution goes through the single
  ``resolve_library`` seam; the linker never opens code by path or copies code
  into anonymous memory.
* **R5** One shared code MemoryObject per distinct object across every boot phase;
  two processes running ``libc`` share its text frames.
* **R6** Direct-kernel bypass is tested, not just the mmsrv API.
* **R7** No regression: all ELF programs, core services, and the PE test boot and
  run; full boot reaches all services.

Design
======

Governing principle
-------------------

``EXECUTE`` and ``WRITE`` are capability rights; a mapping's ceiling is exactly
its backing cap's rights, enforced by the kernel on every surface; and
``EXECUTE`` enters the system only where an authority conferred it. W^X then
follows from *which caps carry ``EXECUTE``* — which is none, except the code
objects an authority minted.

Foundation 1 — EXECUTE is a conferred authority
-----------------------------------------------

* ``UntypedMemory::retype`` mints objects **without** ``EXECUTE`` (kernite
  ``src/cap/untyped.rs`` mints ``CapRights::ALL`` today — this is the change). A
  frame or MO a process retypes from its own untyped (the rtld bootstrap untyped,
  an rsrcsrv allocation) is non-executable, and ``cnode_copy`` cannot re-add
  ``EXECUTE`` (it masks ``dst.rights = src.rights & requested``, ``cap/mod.rs``).
  This holds **only together with Foundation 2** — otherwise the raw frame /
  demand map surfaces ignore cap rights and re-introduce executable memory.

* ``EXECUTE`` is conferred by **one new kernel operation**
  ``mo_mark_executable(exec_authority_cap, src_mo_cap, dest_cnode, dest_slot)``:
  gated by the **exec-authority capability**, it installs into ``dest_slot`` a
  *separate* new ``READ|EXECUTE|GRANT|TRANSFER`` capability to the same
  MemoryObject **as a capability-derivation-tree child of the source MO cap** (the
  MemoryObject refcount is incremented; the source cap is **never mutated**, so a
  non-exec backing cap cannot leak ``EXECUTE``). Because the exec cap is a CDT
  child, revoking the source MO cap **cascades** to revoke it and every per-mapping
  cap attenuated from it — so replacing or deleting the backing (e.g. VFS revoking a
  removed file's vnode backing) tears down the running code. ``GRANT`` is required so ``ldsrv`` can
  ``cnode_copy``-attenuate the code cap per mapping (``cnode_copy`` checks source
  ``GRANT``, ``cap/cnode.rs``); ``TRANSFER`` so the code cap can be sent over IPC.
  It needs a new invoke label (next free after ``MO_CLONE_RANGE`` in
  ``include/uapi/invoke.h``) and a new **exec-authority capability type** (no such
  object/cap exists today — ``cap/object.rs``). The Fuchsia
  ``zx_vmo_replace_as_executable`` + VMEX analog.

* The **exec-authority capability** is a new kernel-minted capability, handed to
  PID 1 in its boot caps (a fixed boot slot, alongside the initrd untyped) and
  delegated narrowly to exactly two kinds of holder:

  - **``ldsrv`` — the code authority.** It takes a *non-exec* backing (a VFS
    pager-backed MO for a disk file, or an initrd borrowed-frames MO) and calls
    ``mo_mark_executable`` to obtain the ``READ|EXECUTE`` code MO it then
    rights-attenuates per mapping. **VFS supplies only non-exec pager backing and
    policy input; it never mints executable caps** — open-for-exec is *subsumed by*
    ``resolve_library`` (below), not a separate public exec minter.
  - **JIT-permitted processes.** A JIT exec-authority cap lets a process call
    ``mo_mark_executable`` on an anonymous MO for runtime code generation.

  This is the take-grant control seL4 applies to untyped, narrowed to the
  "make executable" authority.

Foundation 2 — kernel ceiling authoritative on every map surface
----------------------------------------------------------------

* **MAP_MO** already derives ``max_prot`` from the MO cap; correct once
  Foundation 1 + egress stripping stop handing out ``EXECUTE``-bearing caps.
* **Raw frame ``VSPACE_MAP``** — replace the hardcoded
  ``max_prot = WRITE | EXECUTE`` with ``max_prot_from_cap(frame_cap)``; require
  the frame cap to carry ``WRITE`` to map writable and ``EXECUTE`` to map
  executable.
* **``VSPACE_MAP_DEMAND(_RANGE)``** — the demand region's ceiling comes from its
  backing MO cap (set when ``mmsrv`` creates the region); a cap-less raw demand
  map is non-executable / privileged.
* **``check_protect_ceiling_locked``** — a page that is **present or demand-mapped
  but has no covering ``VmArea``** is treated as ceiling ``R`` (deny W/X
  elevation); **absent (hole) pages remain skipped** so sparse ``mprotect`` is
  unaffected; a user VSpace with null tracking denies elevation. PTE-gated so the
  boot-time present-but-untracked maps (PID 1 ELF / stack / initrd / IPC buffer
  via ``VSpace::map`` in kernite ``src/init.rs`` / ``src/elf.rs``, set up once and
  never elevated) do not regress.

Foundation 3 — page tables are typed kernel objects (isolation)
---------------------------------------------------------------

The W^X review surfaced a **pre-existing memory-isolation bypass** broader than
W^X that must be closed for any of the above to mean anything. ``VSPACE_MAP_PT``
installs a process's own ``Frame`` as a live hardware page table
(``install_page_table``) while leaving the caller's *writable data* alias of that
same frame intact — neither the install nor the raw ``VSPACE_MAP`` /
``map_locked`` path refuses the aliased frame. So a process maps frame ``F``
writable (allowed — ``F`` carries ``WRITE``), installs ``F`` as a leaf page
table, then **hand-writes PTEs** through the writable alias: it forges a leaf
entry pointing at *any* physical address with any flags — executable code over
data it wrote, or a window onto **kernel memory** or another address space. This
defeats not only W^X but address-space isolation entirely. It is reachable by
untrusted code: a spawned child holds its own ``VSpace`` cap
(``CAP_SELF_VSPACE``) with ``MAP`` (``RIGHT_ALL`` minus ``EXECUTE``); it is
latent today only because userland policy does not currently vend raw ``Frame``
/ ``Untyped`` authority to untrusted services — a policy the kernel invariant
must **not** depend on.

**Fix — page tables become a distinct typed object (seL4 model).** A new
``ObjectType::PageTable`` is retyped from untyped (so it still draws on the
process's own quota), and ``VSPACE_MAP_PT`` accepts **only a ``PageTable`` cap,
never a ``Frame``**. Because a ``PageTable`` is not a ``Frame``, ``VSPACE_MAP``
(which validates ``ObjectType::Frame``) can never create a *data* mapping of it:
the writable-alias class disappears by type construction — no per-frame state,
no "is this frame mapped writable anywhere" scan. The kernel owns the table's
bytes; the caller only ever invokes map operations, which the kernel constructs
PTE-by-PTE under the Foundation-2 ceilings. Like ``FrameObject``, a
``PageTable``'s ``KernelObject`` header is held **out of band** (the 4 KiB page
is 512 live hardware PTEs and cannot host a header), and it carries a
mapped/unmapped state so a table cannot be installed twice — which would zero a
live table or re-introduce cross-address-space aliasing (seL4 single-maps page
tables). Mirrors seL4 / Fuchsia, where page tables are typed kernel objects
never mappable as data frames. ``PageTable`` is retypeable from untyped (the
``is_retypeable_from_untyped`` ``true`` arm), unlike the authority types.

*Out of scope (noted, not folded):* whether page-table memory is funded from the
process's untyped quota or kernel PMM (the kernel still lazily allocates missing
intermediate user tables via ``ensure_table``) is an orthogonal accounting
question; closing the alias is an isolation fix independent of it.

The code-loading authority (ldsrv)
----------------------------------

All resolution goes through one seam::

    resolve_library(name) -> executable MemoryObject

The linker calls it for each ``DT_NEEDED`` entry by **soname** — ``ldsrv`` owns the
library namespace and resolves the name itself. A program **main image**, however,
is admitted under the **caller's** filesystem authority: ``execve`` (PID 1's spawn
path) first opens the image through the VFS under the caller's credential — which
applies the ``X_OK`` / ``MNT_NOEXEC`` policy — and hands ``ldsrv`` the resulting
**non-exec backing capability**, not a path; ``ldsrv`` confers ``EXECUTE`` on it.
``ldsrv`` never opens a main image by path, which would bypass the caller's
exec-permission check. Behind the seam is always ``ldsrv``; what varies is its
backing and how the name is admitted, not the consumer's view. Every consumer
receives the same ``READ|EXECUTE`` code MemoryObject and maps it — never reads bytes
into an anonymous region.

``ldsrv`` is the **sole minter and authority of ``EXECUTE``** for code
MemoryObjects — *not* their sole refcount holder: each loaded mapping keeps a
durable, rights-attenuated cap (a refcounted reference) to the same code MO, so the
object outlives an ``ldsrv`` cache eviction. ``ldsrv`` does not adopt a code MO
minted by an *untrusted* client in steady state; the one sanctioned adoption is the
trusted PID 1 boot handoff (Stage 1). Its cache holds **one source object per
distinct object**, keyed by a **content digest** of the image bytes (canonical) —
the ELF GNU build-id / PE debug GUID is a fast-path *hint* only, never the identity,
since a producer controls it and equal build-ids over unequal bytes must resolve to
distinct objects — never by soname or caller path — and resolves a name
**rootfs-authoritative once the rootfs is mounted, with the initrd as bootstrap and
fallback** — turning the VFS page cache's per-vnode sharing into system-wide,
cross-phase sharing. A consumer
holds a **loader capability** (its ``ldsrv`` endpoint, in the startup cap table),
not the authority that backs ``ldsrv``; it needs no VFS capability to load code,
which is what a capability-mode process (``cap_native_spine``) requires. ``ldsrv``
is the single admission point and thus the home for a library namespace,
signature/build-id/package admission, and identity-keyed reuse.

Backing:

- **Initrd-resident objects** (boot libraries, any initrd file) are backed by a
  **borrowed-frames MemoryObject over the initrd**, zero-copy and canonical for the
  object's lifetime. ``ldsrv`` does **not** mint these itself and holds no initrd
  untyped: PID 1 — the bootstrap loader, which already owns the initrd and the
  exec-authority — creates a borrowed-frames code MO for **every** initrd code
  object and **adopts** the whole set into ``ldsrv`` at the Stage-1 handoff. This
  keeps a single exec-conferral origin (PID 1 at boot, ``ldsrv`` thereafter) and
  confines the initrd page-alignment requirement of ``mo_populate_borrowed`` to one
  place.
- **Disk-only objects** are resolved through the VFS on first use — ``ldsrv``
  obtains a *non-exec* pager-backed MemoryObject (the VFS is the pager), reads it
  through that read-only cap to compute the content digest, calls
  ``mo_mark_executable`` on it to get the code MO, and caches that as the object's
  canonical code MO. VFS mints no executable cap and exposes no public
  open-for-exec; code resolution is ``ldsrv``'s ``resolve_library`` alone.
  (Per-vnode objects for *data* ``mmap`` are unaffected.)

Concrete mechanism
------------------

*Kernel: borrowed-frames MemoryObject.* The initrd is device-untyped memory —
mappable read-only without retyping — but the existing MO kinds (``Anon``,
``CowChild``, ``FileBacked``, ``Shm``) assume owned, reclaimable RAM. One new MO
kind for **immutable borrowed frames**: mappable read-only into many address
spaces, a valid ``MO_CLONE_RANGE`` copy-on-write parent, handled on every page
path — the map path does **not** retag the borrowed frames as ``MoData``, evict and
resize are short-circuited (the object is immutable), and destroy releases nothing
(the frames belong to the immortal initrd device-untyped). It is created non-exec;
**PID 1** — the sole holder of the initrd untyped and the boot exec-authority —
confers ``READ|EXECUTE`` on it via ``mo_mark_executable`` at Stage 0 and adopts it
into ``ldsrv``; ``ldsrv`` itself confers ``EXECUTE`` only on VFS-backed disk
objects.
Mirrors Fuchsia's physmem VMO and a file-backed section's read-only image pages.

*mmsrv: map an image into a reserved envelope.* One operation places a resolved
object, called identically by the linker and PID 1. Given the source MO and a
per-segment run plan it: reserves the whole load envelope first (a contiguous VA
span, so inter-segment holes stay reserved — ``pc``-in-object and unwind hold);
maps clean file-backed text/rodata **shared read-only** directly from the source;
makes writable data a private ``MO_CLONE_RANGE`` copy-on-write child mapped R/W;
materializes privately any partly-writable / partly-BSS boundary page and
trailing BSS; and returns an **image id** so teardown (``dlclose``) is one grouped
unmap. This generalizes the existing exec-image staging (which already maps
file-backed text, COW data, zero BSS for the main image) into a standalone op.

*W^X by rights attenuation.* ``ldsrv``'s code MO carries ``READ|EXECUTE``
(conferred once via ``mo_mark_executable``). Each mapping uses a **rights-reduced
capability of that same object** — text through ``R+X``,
rodata through ``R``, the data child through ``R+W`` with no execute — because
``VSPACE_MAP_MO`` derives a mapping's maximum protection from its capability's
rights. ``MO_CLONE_RANGE`` needs only ``READ`` on the parent and ``WRITE`` on the
child, so the parent's ``EXECUTE`` does not taint the writable child. ``mmsrv``
rejects, at map time, any initial protection exceeding the region's recorded
maximum — not only a later ``mprotect``. Each attenuated mapping cap is **retained
by ``mmsrv`` as a durable, refcounted backing reference**: it keeps the code MO
alive across an ``ldsrv`` cache *eviction* and is the cap a page fault or fork
re-maps through. An eviction (``ldsrv`` drops its own cap) is distinct from a
*revocation* (the CDT cascade from the source MO cap, which does tear down
``mmsrv``'s attenuated caps too).

PE images (Bug 2)
-----------------

PE images route through the same map-image op: text mapped ``R-X`` from the code
MO, data a ``R-W`` COW child — so the "single ``R|W`` region + rtld ``mprotect``"
that aborts today is gone, and Bug 2 is fixed by construction. The PE-specific
requirement is the import address table: the PE linker writes the IAT (and the
delay-import IAT) **after** mapping (``lib/trona/loader/rtld/pe/main.rs``), and on
the current artifacts (``hello_pe`` and the stress PEs) the IAT sits inside the
**read-only ``.rdata``** section (``kernel32.dll`` has no imports). So the
map-image op MUST carve **every import descriptor's ``FirstThunk`` (IAT) extent**
and each delay-import IAT extent into private ``R-W`` copy-on-write runs **even when
they fall inside an otherwise ``R--`` section**, so the post-map IAT writes land on
writable pages (the ``IMAGE_DIRECTORY_ENTRY_IAT`` data-directory is used only as
cross-validation, never as the sole source). The
same carve covers the other post-map PE writes — the delay-import
``module_handle`` and the TLS ``AddressOfIndex`` (``lib/trona/loader/rtld/pe/main.rs``):
any such target landing in an ``R--`` run is carved ``R-W`` or the image is
rejected. (No base relocations are applied — preferred-base load.) No page is ever
``W+X``; no self-``mprotect`` to executable is needed.

Bootstrap and handoff
---------------------

A loader service cannot load the earliest programs, so the system is permanently
hybrid (staged as Fuchsia's ``userboot`` and NT's ``smss`` stage it):

- **Stage 0 — PID 1 as bootstrap loader.** PID 1 holds the boot exec-authority
  cap at a fixed boot slot (a new constant alongside ``init``'s internal slots —
  ``userland/core/init/src/internal_slots.rs`` — installed by the kernel in
  ``setup_init_cspace``, ``kernite/src/init.rs``). It owns the initrd, creates a
  borrowed-frames MO per boot object on first need, confers ``READ|EXECUTE`` via
  ``mo_mark_executable``, caches it by identity, and maps it via a **PID 1-local
  bootstrap implementation of the map-image op** (``mmsrv`` is not up yet — the op
  is shared logic callable before ``mmsrv`` exists). By handoff time PID 1 has
  created a borrowed-frames code MO for **every** initrd code object (not only the
  boot closure it mapped on first need), so the set it adopts to ``ldsrv`` is
  complete and no runtime resolution falls back to an initrd ``ldsrv`` cannot reach.
  PID 1 itself is loaded by the kernel ELF loader (``load_from_initrd`` →
  ``load_elf``, ``kernite/src/init.rs`` / ``src/elf.rs``); that is the **one trusted
  direct-map path**, exempt as kernel-TCB code. It is ``resolve_library`` for the
  boot closure, ``ldsrv``'s own included.
- **Stage 1 — ``ldsrv`` takes over.** Once ``ldsrv`` is up, PID 1 **transfers the
  canonical code-MO caps** (batched, up to four caps per IPC message, each with its
  content-digest identity) **and the exec-authority capability** over a **private
  init-only adopt channel** — a capability ``ldsrv`` receives in its startup block,
  never the public ``resolve_library`` endpoint, so no other client can forge an
  adoption or steal the authority. The exec-authority is **moved**, not copied, so
  ``EXECUTE`` keeps a single origin. ``ldsrv`` **adopts** them into its cache by
  content identity (no recreation — one MemoryObject identity per object, satisfying
  R5). Readiness is two-staged: publishing the ``resolve_library`` endpoint to the
  name service signals only that ``ldsrv`` exists; ``ldsrv`` does not **serve**
  resolutions until adoption is sealed, and PID 1 spawns no ``resolve_library``
  client before the adopt acknowledgement. This is the one sanctioned adoption of an
  externally-minted code MO. Thereafter ``ldsrv`` is the sole code authority and PID
  1's bootstrap-loader role retires. Every later process gets an ``ldsrv`` loader
  capability in its startup block.
- **Stage 2 — VFS-backed steady state.** ``ldsrv`` resolves non-boot names
  through the VFS, owning and caching the pager-backed MO; boot objects keep their
  canonical borrowed-frames MOs.

Non-code memory
---------------

* **Generic ``mmap``** (``handle_mmap`` / ``handle_mmap_mo`` /
  ``handle_mmap_mo_private`` / heap / stack): anonymous / heap / stack memory is
  mapped through an ``EXECUTE``-stripped cap (the anon MO is non-exec by
  ``retype``), so an ``mmap(PROT_EXEC)`` on it is refused by the kernel ceiling.
  Executable memory is **client-conferred**: a JIT-permitted process (holding the
  JIT exec-authority cap) calls ``mo_mark_executable`` on its **own** MO and maps
  the resulting exec-bearing MO (``MMAP_KIND_MO``); mmsrv **preserves** the inbound
  ``EXECUTE`` (on the region's stored / forked / split backing copies) but never
  confers it and holds no per-client flag — the kernel ``max_prot`` ceiling is the
  gate. Writable-then-executable JIT uses two views of one MO (an ``R-W`` view to
  emit, an ``R-X`` view to run); the kernel refuses a single ``W+X`` PTE, while
  distinct-VA aliases are allowed (aarch64 needs I-cache maintenance after writes).
  This mirrors Fuchsia — ``zx_vmo_replace_as_executable`` gated by the VMEX
  resource held by the JIT runtime, with ``zx_vmar_map`` enforcing
  ``ZX_RIGHT_EXECUTE`` — and Apple's JIT entitlement / CHERI executable
  capabilities; no system centralizes exec-conferral in a userland memory manager.
* **Fork** maps every ``InheritShare`` mapping through a cap attenuated to the
  parent region's ceiling, not the ``ALL``-rights registry cap; COW
  ``InheritCow`` already copies the parent ``max_prot``.
* **Fault completion** maps through the region's attenuated rights, never the full
  registry cap, so a fault cannot re-widen a sealed ceiling.
* **Device, initrd, and static system caps** reach userland without ``EXECUTE``:
  dynamic device caps minted/copied non-exec (``kernite/src/syscall/system.rs``,
  ``dispdrv``, ``pcidrv``); the static framebuffer cap (``insert_static_cap``,
  ``kernite/src/init.rs``) non-exec; and the initrd untyped PID 1 receives dropped
  from ``READ|EXECUTE|GRANT`` to non-exec — ``EXECUTE`` on a borrowed-frames code
  MO comes only from ``mo_mark_executable``. ``VSPACE_MAP_DEVICE_RANGE`` is already
  cap-derived, so a non-exec cap cannot map executable. The "no untrusted cap
  carries ``EXECUTE``" invariant is audited across **every** kernel-minted egress
  (root/system untyped, static system caps included).
* **Direct-loader / PID 1 images** go through the Stage-0 borrowed-frames code-MO
  + map-image path (text ``R-X`` from a ``mo_mark_executable`` code MO), **not**
  raw frame retype + executable map: the current ``DirectImageMapper`` raw-exec
  map (``init/supervisor/loader/elf.rs``) is removed, since retype no longer
  yields ``EXECUTE`` and the raw map ceiling is now cap-derived.

Invariant
=========

Resolution MUST stay behind the single ``resolve_library`` seam; the linker MUST
NOT scatter direct VFS calls or open code by path. The moment it opens a path
directly it has reached around ``ldsrv`` to a VFS capability, defeating both the
capability-mode confinement and the single-authority identity/policy the seam
exists to provide. Independently: no cap reaching an untrusted process carries
``EXECUTE`` except a code cap minted by ``ldsrv`` via ``mo_mark_executable`` or one
conferred via the JIT exec-authority; ``retype`` never confers ``EXECUTE``.

Implementation
==============

In dependency order, each step independently buildable/bootable:

- **kernite cap-core** — ``retype`` mints no ``EXECUTE`` (``cap/untyped.rs``); the
  new **exec-authority capability type** (``cap/object.rs``) and the
  exec-authority-gated ``mo_mark_executable`` invoke (new label,
  ``include/uapi/invoke.h``); the borrowed-frames **``MoKind``** variant
  (``cap/memory_object.rs`` — read-only shared map, ``MO_CLONE_RANGE`` parent,
  no-op destroy).
- **kernite mm** — cap-derived ``max_prot`` on raw ``VSPACE_MAP`` and
  ``VSPACE_MAP_DEMAND``; ``check_protect_ceiling_locked`` PTE-gated default-deny.
- **mmsrv** — the map-image-into-reserved-envelope op (envelope reservation,
  shared-RO text/rodata, ``MO_CLONE_RANGE`` data child, private boundary/BSS,
  image id, grouped unmap, map-time ``prot ≤ max_prot``); rights attenuation on
  every cap-mapping path (staging, fault completion, fork, generic mmap);
  cap-egress ``EXECUTE`` stripping; the JIT exec-authority gate.
- **VFS** — all backing caps non-exec (``VFS_GET_BACKING_MO``, win32 section
  included); no public open-for-exec exec minter; ``ldsrv`` adopts the per-vnode
  backing MO and confers ``EXECUTE`` via ``mo_mark_executable``.
- **ldsrv (new server)** — the ``resolve_library`` protocol; the
  identity-keyed source-MO cache; initrd (borrowed-frames) and VFS (pager)
  backings; the boot-cache handoff from PID 1.
- **rtld (ELF + PE) / PID 1** — both become ``resolve_library`` clients; the
  linker's read-into-anonymous loader and PID 1's per-spawn copy are removed; the
  link map gains multi-run / reserved-hole metadata; ``dlclose`` becomes the
  grouped image unmap; PE protection rides the map-image op (no self-``mprotect``).
- **startup plumbing** — the loader capability (``ldsrv`` endpoint) and, where
  delegated, the JIT exec-authority cap in the startup cap table.
- **drivers / init** — device cap egress non-exec; per-kind frame caps for
  direct-loader images.

Performance
===========

Code text is shared read-only across processes (one physical copy of ``libc``
text system wide) — a net win over today's per-process copy. Rights attenuation
adds a ``cnode_copy`` per mapped run at load time. The cap-derived ceiling is
already read on every ``mprotect``; no IPC fastpath impact.

Backwards Compatibility
=======================

Clean-slate userland against the kernite edge — no ABI-stability window. The
borrowed-frames MO kind, the exec-conferring operation, the map-image op, and the
loader capability are additive; ``ldsrv`` and the linker/PID 1 client conversion
replace the read-into-anonymous and per-spawn-copy paths. The kernel
``VSPACE_MAP`` / ``MAP_DEMAND`` ceiling derivation tightens (rejects exec maps of
non-exec caps); callers hold appropriately-righted caps after the egress changes.

Security Considerations
=======================

* **Kernel-rooted, bypass-tested guarantee.** ``EXECUTE`` exists only where an
  authority conferred it; the kernel ceiling is authoritative on every surface; a
  direct VSpace-cap invoke cannot exceed a ceiling or create exec memory from
  untyped.
* **Untyped retype confers no authority.** Generalizing "``retype`` mints no
  ``EXECUTE``": ``UntypedMemory::retype`` creates only *resource* objects, never
  *authority* objects. ``ObjectType::is_retypeable_from_untyped()`` — an exhaustive
  classification enforced at the retype primitive (the wire decode stays a pure
  translation, and a new object type must declare its retypeability at compile
  time) — rejects the system caps, ``DeviceControl``, ``IrqHandler``, ``IoPort``,
  and the exec-authority. Those are kernel-minted at boot (delegated by
  ``cnode_copy``) or minted by ``DeviceControl`` (the seL4 ``IRQControl`` /
  ``IOPortControl`` model); ``rsrcsrv`` no longer vends ``IrqHandler`` / ``IoPort``
  by retype. This closes the forgery class where a holder of untyped could retype a
  ``SystemControl`` (shut down the machine) or ``DeviceControl`` (mint device caps)
  — the sibling of the ``EXECUTE`` hole this RFC removes.
* **Page tables are unforgeable (isolation, not just W^X).** The W^X review
  surfaced a pre-existing isolation bypass: ``VSPACE_MAP_PT`` installed a user
  ``Frame`` as a live page table while the caller kept a writable data alias, so
  it could hand-write a leaf PTE to *any* phys — kernel memory included.
  Foundation 3 closes it by typing: page tables are a distinct
  ``ObjectType::PageTable`` that ``VSPACE_MAP`` can never data-map, so the alias
  cannot exist. This is a kernel invariant that does **not** rest on userland
  ``Frame`` / ``Untyped`` distribution policy; it is strictly more than W^X.
* **Two narrow code-injection trust roots.** The code exec-authority (held by
  ``ldsrv``) and the JIT exec-authority are the only ways to make memory
  executable; both are delegated narrowly, as Fuchsia restricts VMEX and macOS
  restricts ``allow-jit``.
* **``ldsrv`` admission.** Centralizing resolution lets signature/build-id/package
  checks apply once; it composes with ``principalid_access_control``.
* **Dual-mapping for JIT** keeps each PTE ``W`` xor ``X``; hardware per-thread W^X
  (APRR / ``MAP_JIT`` toggle) is stronger but out of scope.

Testing
=======

* Full boot reaches all services; the PE test runs past the (removed) failing
  ``mprotect`` to its entry; ``libc`` text is one shared physical copy across two
  processes.
* **Direct-kernel bypass tests:** a process invoking its own VSpace cap cannot
  (a) retype an executable frame from its untyped; (b) raw-map a frame
  executable/writable beyond its cap; (c) create an executable demand mapping;
  (d) ``mprotect`` a code page or share-ro alias to add W/X; (e) get exec anon
  memory without the JIT authority; (f) retype an authority object
  (``SystemControl`` / ``DeviceControl`` / ``IrqHandler`` / ``IoPort`` /
  exec-authority) from its untyped — the retype primitive rejects it; (g) install
  a writable ``Frame`` as a page table and forge a PTE — refused because
  ``VSPACE_MAP_PT`` requires a ``PageTable`` cap, and a ``PageTable`` can never be
  data-mapped (``VSPACE_MAP`` validates ``Frame``).
* Sealed/loaded ``.text`` rejects ``mprotect(+W)`` from both mirror and kernel;
  forked child image text shows kernel ``max_prot = R-X``; a fault does not
  re-widen it.
* All ELF programs and core services still boot (regression), including
  direct-loader-staged ones.
* aarch64: the executable map path performs I-cache maintenance.
* ``just warn`` clean after each step.

Drawbacks, Alternatives, and Unknowns
=====================================

* **EXECUTE at egress vs. at retype (rejected egress-only).** Stripping
  ``EXECUTE`` only at cap egress does not hold — a process retypes its own
  untyped and mints ``EXECUTE`` itself. ``retype`` must not confer ``EXECUTE``;
  egress stripping is the complementary measure for caps that *do* carry it
  inside the trust boundary.
* **Per-section staging vs. self-protecting seal.** Routing code through the
  map-image op (text mapped ``R-X`` from the code MO) removes the need for a PE
  self-``mprotect`` seal entirely — cleaner than a load-then-seal, and it unifies
  ELF and PE on one path.
* **No in-kernel page cache.** Unlike Linux (kernel page cache gives free text
  sharing), a microkernel needs the userspace authority (``ldsrv``) to front the
  VFS page cache for cross-process sharing.
* **Decided policy** (formerly the merged loader draft's design unknowns, resolved
  for this implementation):

  - *Rootfs override.* ``ldsrv``'s cache is keyed by a **content digest** of the
    image bytes (canonical identity); the ELF GNU build-id / PE debug GUID is a
    fast-path *hint* only, never the identity (a producer controls it, so equal
    build-ids over unequal bytes must resolve to distinct objects). Different bytes
    are a distinct code MO (no false sharing). The **soname→identity** lookup is a
    separate, mount-namespace-epoched table: a soname resolves **rootfs-authoritative
    once the rootfs is mounted** (the mount invalidates the initrd fallback and any
    cached negative result), with the initrd as bootstrap and fallback; an identical
    artifact (matching digest) returns the one shared MO, a differing one is a new
    MO picked up by new resolutions, while already-running processes keep their
    pinned MO. (Fuchsia content-addressing + macOS/Linux on-disk authority; avoids
    the NT ``KnownDlls`` "reboot to patch" wart.)
  - *Borrowed-frames / initrd lifetime.* **Pinned for system lifetime** — the initrd
    is immortal device-untyped; borrowed-frames code MOs are canonical and never
    re-backed from VFS or reclaimed.
  - *Capability-mode library search.* **``ldsrv`` owns the library namespace and
    search order**; for a ``DT_NEEDED`` library a client passes only a soname over
    ``resolve_library`` and needs no VFS capability. (A program **main image** is the
    exception — it is admitted under the caller's VFS authority and presented to
    ``ldsrv`` as an already-opened non-exec backing, so the ``X_OK`` / ``MNT_NOEXEC``
    check stays with the caller.)
  - *Unified ``ldtrona`` (``elf_pe_coexistence``).* **``ldsrv`` is format-agnostic** —
    ``resolve_library`` returns a code MO plus a minimal header/format summary; the
    ELF and PE linkers each do format-specific mapping. ``ldsrv`` neither depends on
    nor blocks a later ``ldtrona`` unification.
* **Pre-implementation checklist** (engineering items with known answers, not
  design unknowns): the exhaustive cap-egress audit — every kernel- and
  server-minted cap reaching an untrusted process is ``EXECUTE``-free
  (``MM_MO_CREATE``, ``MM_FILE_MMAP``, ``MMAP_KIND_MO``, SHM, VFS backing, device,
  static system caps, child frame caps); and ``MoRegistry`` refcount discipline
  across the map/fork/fault attenuated-cap paths (``mmsrv/src/mo_registry.rs``,
  ``txn.rs``) — for a registry-owned backing (anon / COW / SHM) the registry holds
  the durable MO reference and a per-map attenuated cap may be transient, but for an
  ``ldsrv``-owned code MO ``mmsrv`` **retains a durable attenuated cap** as the
  refcounted reference, so a fault / fork re-map and the code MO's lifetime do not
  depend on ``ldsrv`` keeping its own cap.

Prior Art and References
========================

* **Fuchsia** — ``fuchsia.ldsvc.Loader`` (each process holds a loader channel,
  ``PA_LDSVC_LOADER``, not a filesystem handle; libraries are VMOs from
  content-addressed ``blobfs``, identity-keyed sharing; staged like ``ldsrv``
  via ``userboot``). Execute is a conferred right: a VMO is executable only with
  ``ZX_RIGHT_EXECUTE``, gained via ``zx_vmo_replace_as_executable`` + a **VMEX
  resource** — the model for Foundation 1.
* **seL4** — untyped is the object-creation authority, controlled by
  **distribution** (a variant of take-grant; untrusted domains get a disjoint,
  bounded subset, or none); page protection is bounded by the frame cap's rights
  with execute gated by the ``ExecuteNever`` VM attribute set by the trusted
  mapper. SaltyOS keeps untyped but removes ``EXECUTE`` from its default product,
  so untyped distribution no longer implies execute authority.
* **Genode ROM service** — the linker requests each object as a capability-backed
  ROM dataspace, shared read-only, attached into a reserved linker area — the
  reserved-envelope / multi-run model.
* **Windows NT ``KnownDlls`` / ``smss``** — boot-time authority pre-creates shared
  section objects for well-known DLLs; ``ldsrv``'s Stage 0/1 in NT form. **ACG**
  makes code pages immutable when enabled.
* **macOS** — ``dyld`` shared cache (system libraries pre-linked, shared into
  every process); Hardened Runtime requires the ``com.apple.security.cs.allow-jit``
  entitlement + ``MAP_JIT`` for W+X JIT — the JIT exec-authority model.
* **OpenBSD** — mandatory W^X; executable memory comes from the loader.
* **FreeBSD Capsicum / Casper** — ``ldsrv`` is the code-loading Casper for a
  capability-mode process that holds no VFS capability.
* Related SaltyOS RFCs: RFC-0002 (VM hierarchy / COW tree), RFC-0004 (exec
  memory-object primitives), RFC-0006 (execve caller MO — exec-file cap origin),
  RFC-0008 (per-client control capabilities — cap-as-authority pattern); drafts
  ``cap_native_spine`` (capability-mode posture), ``elf_pe_coexistence`` (unified
  ``ldtrona``), ``principalid_access_control`` (admission policy). This RFC
  subsumes and replaces the ``code_loading_authority`` draft.
