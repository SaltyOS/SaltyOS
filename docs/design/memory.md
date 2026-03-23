# Memory Management Design

## Philosophy

> **PMM** manages kernel-internal metadata pages. **Untyped** is the
> primary source of user data pages. MO **borrows** frames from either
> pool and gives them meaning for userspace. VSpace is an **observer**
> that temporarily views MO's pages.

SaltyOS memory management combines seL4-style capability authority with
Zircon-style virtual memory objects:

- **PMM**: Kernel-internal frame allocator. Provides page table pages,
  radix tree nodes, maple tree nodes, kernel stacks, and other kernel
  metadata. ~1/8 of physical RAM. Not for user data.
- **Untyped**: Raw physical memory, the source of kernel objects (seL4)
  **and MO data pages**. ~7/8 of physical RAM. `MO_COMMIT` with a
  non-zero `ut_cap` carves page-sized frames directly from the untyped's
  watermark. Decommitted frames go to a per-untyped free list for reuse.
- **MemoryObject (MO)**: Borrows frames from untyped (preferred) or PMM
  (fallback) and gives them meaning for userspace. Tracks pages via
  4-level radix tree with per-page backing tags (bit 0 = untyped-backed).
  Maintains reverse mappings to every VSpace that observes its pages.
- **VSpace**: Observes MO pages through mappings. Owns nothing. Uses a
  Maple tree to track virtual address regions.

### Invariants

These three statements must hold at all times. Code that violates any of
them must not be merged.

> 1. Every physical frame has exactly one `FrameOwner` at all times.
> 2. Every change to a frame's owner state must occur through PMM APIs (`alloc`, `free`, or `transfer`).
> 3. Userspace never observes raw frames — only MO capabilities.

---

## Layer Architecture

```
┌─────────────────────────────────────────────────┐
│                  Userspace                      │
│  mmsrv · procmgr · application processes        │
├──────────────── capability boundary ────────────┤
│                                                 │
│   VSpace          MemoryObject       Untyped    │
│   (observer)      (page manager)     (objects)  │
│       │                │                 │      │
│       │    reverse     │    loan/return  │      │
│       └── maps ────────┤                 │      │
│                        │                 │      │
│   ┌────────────────────┴─────────────────┘      │
│   │              PMM                            │
│   │     (sole physical frame owner)             │
│   │     FrameOwner tags · bitmap allocator      │
│   └─────────────────────────────────────────────┤
│                                                 │
│            NodeAllocator trait                  │
│   (generic page-granular allocator interface)   │
│   PMM implements it; test harness can inject    │
│   a static bump allocator instead               │
└─────────────────────────────────────────────────┘
```

---

## PMM Layer (`mm/frame.rs`)

Physical frame allocation and deallocation. The only entry point for
obtaining and releasing physical pages in the entire kernel.

### FrameOwner

Every 4KB frame has a metadata entry tracking its current owner:

**Semantic type** — used in PMM APIs for type-safe ownership transfer:

```rust
enum FrameOwner {
    Free,
    /// User-visible data page owned by an MO.
    MoData { mo: *mut MemoryObject, page_idx: u32 },
    /// MO-internal metadata page (radix tree node, reverse map overflow).
    MoMeta { mo: *mut MemoryObject, subkind: MoMetaKind },
    /// Kernel-private page (page tables, kernel stacks, Maple tree nodes).
    KernelPrivate { subkind: KernelMetaKind },
    /// File-backed page cache entry (future).
    PageCache,
    /// Reserved pool — never reclaimed except under catastrophic OOM.
    EmergencyReserve,
}

enum MoMetaKind { Radix = 0, Rmap = 1 }
enum KernelMetaKind { PageTable = 0, KernelStack = 1, MapleNode = 2 }
```

**Storage representation** — packed into a fixed-size per-frame array
for cache efficiency. The PMM provides `FrameMeta::to_owner()` and
`FrameMeta::set_owner()` to convert between the two representations:

```rust
#[repr(C)]
struct FrameMeta {
    owner_tag: u8,       // FrameOwner discriminant
    subkind: u8,         // MoMetaKind or KernelMetaKind (0 if N/A)
    map_count: u8,       // number of VSpaces mapping this frame (Layer 2 rmap)
    flags: u8,           // DIRTY | REFERENCED | PINNED
    page_idx: u32,       // valid when owner_tag == MoData
    owner_ptr: u64,      // *mut MemoryObject (MoData/MoMeta), 0 otherwise
}
// 16 bytes per frame
// 512 MB RAM → 131K frames × 16 = 2 MB metadata
```

### Allocation API

```rust
impl Pmm {
    /// Allocate a frame with mandatory ownership declaration.
    /// Returns `None` if the free pool (and emergency reserve) is exhausted.
    fn alloc(&mut self, owner: FrameOwner) -> Option<PhysAddr>;

    /// Free a frame. Panics if `expected_owner` does not match the
    /// current tag — catches double-free and use-after-free.
    fn free(&mut self, addr: PhysAddr, expected_owner: FrameOwner);

    /// Transfer ownership between non-Free states (e.g., MoData → MoData
    /// when migrating a page between MOs). Panics on tag mismatch.
    /// Free ↔ allocated transitions use `alloc`/`free` instead.
    fn transfer(&mut self, addr: PhysAddr, old: FrameOwner, new: FrameOwner);

    /// Reverse lookup: given a physical address, return the owner.
    /// O(1) via per-frame metadata array. Used by COW fast-path.
    fn lookup(&self, addr: PhysAddr) -> &FrameMeta;
}
```

---

## NodeAllocator Trait (`mm/node_alloc.rs`)

Generic page-granular allocator interface used by Maple tree and radix
tree. Decouples data structure code from the PMM, enabling:

- Kernel: inject PMM as the allocator
- Tests: inject a static bump allocator (host `cargo test` without PMM)

```rust
/// Page-granular node allocator.
/// All allocations are exactly one page (4096 bytes).
pub trait NodeAllocator {
    /// Allocate a zeroed page. Returns null on failure.
    fn alloc_node(&mut self) -> *mut u8;

    /// Free a previously allocated page.
    /// # Safety
    /// `ptr` must have been returned by `alloc_node` and not yet freed.
    unsafe fn free_node(&mut self, ptr: *mut u8);
}
```

### Kernel implementation

```rust
struct PmmNodeAllocator {
    owner: FrameOwner,  // caller specifies: KernelPrivate or MoMeta{...}
}

impl NodeAllocator for PmmNodeAllocator {
    fn alloc_node(&mut self) -> *mut u8 {
        let phys = pmm().alloc(self.owner)?;
        phys_to_virt(phys) as *mut u8
    }

    unsafe fn free_node(&mut self, ptr: *mut u8) {
        let phys = virt_to_phys(ptr as u64);
        pmm().free(phys, self.owner);
    }
}
```

### Reserve policy for fault paths

The COW fast-path and demand fault paths may need to allocate radix tree
nodes or Maple tree nodes during fault resolution. If PMM is nearly
exhausted, this creates a deadlock: resolving a fault requires a metadata
page, but no pages are available.

**Solution**: PMM maintains an **emergency node reserve** — a small pool
of pre-allocated pages (tagged `EmergencyReserve`) that are only
available to `NodeAllocator` during fault handling. The reserve size is
configurable (default: 32 pages = 128 KB).

```rust
impl Pmm {
    /// Allocate from the emergency reserve. Only callable from
    /// fault handling context (checked via flag on current TCB).
    fn alloc_reserve(&mut self) -> Option<PhysAddr>;

    /// Replenish the reserve pool from free frames.
    /// Called periodically by mmsrv or during idle.
    fn replenish_reserve(&mut self, count: usize);
}
```

When the reserve is depleted, the fault falls through to mmsrv via
VMFault IPC. mmsrv can then trigger OOM handling (kill a process,
flush page cache, etc.) and retry.
```

---

## MemoryObject Layer (`cap/memory_object.rs`)

A MemoryObject (MO) is a capability-exposed kernel object that borrows
physical frames from PMM and provides page-level operations to userspace.

### Structure

```rust
struct MemoryObject {
    header: KernelObject,        // capability refcount (seL4)
    kind: MoKind,
    page_count: u32,             // logical page slots (u32 for TB-scale)
    pages: RadixTreeRoot,        // 4-level radix tree of PhysAddr
    reverse_maps: ReverseMaps,   // which VSpaces map this MO
    cow_parent: CapSlot,         // capability slot referencing parent MO (0 = none)
    first_child: *mut MemoryObject,  // head of intrusive child linked list
    next_sibling: *mut MemoryObject, // next child of same parent
}
```

`cow_parent` is a **capability slot**, not a raw pointer. The capability
system manages the parent MO's refcount: creating a CowChild inserts a
cap into `cow_parent`, incrementing `parent.header.ref_count`. Destroying
the child deletes this cap, decrementing the refcount. This ensures the
parent cannot be freed while any child holds a reference.

To dereference the parent for page resolution, the kernel reads the cap
at `cow_parent` and follows `cap.object` to get `*mut MemoryObject`.
This is O(1) and safe — the cap guarantees the parent is alive.

```rust
enum MoKind {
    /// Anonymous memory (mmap, brk, stack)
    Anon,
    /// COW snapshot child (created by MO_CLONE).
    /// cow_parent is valid and refcounted.
    CowChild,
    /// File-backed memory (future: page cache integration)
    FileBacked,
    /// Shared memory region (future: POSIX shm, cross-process IPC buffers)
    Shm,
}
```

### Page storage: 4-level radix tree

Pages are stored in a radix tree with the same structure as hardware
page tables. Each node is a page (512 × 8-byte entries), allocated from
PMM via `NodeAllocator` with `FrameOwner::MoMeta { mo, kind: Radix }` tag.

```
page_idx bits: [35:27] [26:18] [17:9] [8:0]
                 L4      L3     L2     L1

Level 4 root → 512 entries → Level 3 → ... → Level 1 → PhysAddr

Capacity: 512^4 × 4KB = 256 TB per MO
Depth for common cases:
  ≤ 512 pages (2 MB):    1 level  (1 node = 4 KB overhead)
  ≤ 256K pages (1 GB):   2 levels (up to 513 nodes)
  ≤ 128M pages (512 GB): 3 levels
  > 128M pages:          4 levels
```

Nodes are allocated lazily — empty subtrees have null pointers.
Radix tree nodes are allocated via `NodeAllocator`, which uses PMM
with `FrameOwner::MoMeta { mo, kind: Radix }` tag. This separates
metadata overhead from user-visible data pages in accounting.

### Reverse mappings

Every MO tracks which VSpaces map its pages, enabling:
- Page reclaim (unmap from all VSpaces before freeing)
- MO destruction (invalidate all PTEs, TLB shootdown)

```rust
struct ReverseMaps {
    inline: [ReverseMapEntry; 8],  // covers common case (1-2 VSpaces)
    inline_count: u8,
    overflow: *mut ReverseMapPage, // PMM page chain for > 8 entries
}

struct ReverseMapEntry {
    vspace: *mut VSpace,     // 8
    va_start: u64,           // 8
    page_count: u32,         // 4
    mo_offset: u32,          // 4
    perms: u8,               // 1
    _pad: [u8; 7],           // 7 (align to 8-byte boundary)
}
// 32 bytes per entry

struct ReverseMapPage {
    entries: [ReverseMapEntry; 127], // 127 × 32 = 4064 bytes
    next: *mut ReverseMapPage,       // 8 bytes → 4072 total, 24 bytes padding
}
```

Overflow pages are allocated from PMM with `FrameOwner::MoMeta { mo, kind: Rmap }`
tag, belonging to the MO that owns the reverse map.

### Two-layer reverse map architecture

Reverse maps operate at two granularities. Both layers coexist — the
region layer handles bulk operations; the page layer handles reclaim
and dirty tracking.

**Layer 1 — Region rmap** (described above)

Stored in `ReverseMaps` on the MO. Each entry covers a contiguous VA
range. Used for:
- MO destruction (unmap all regions, TLB shootdown)
- Fork bookkeeping (clone region list)
- `VSPACE_MAP_MO` / `VSPACE_UNMAP_MO` (add/remove entries)

Cost: O(regions) per MO. Typically 1-8 entries.

**Layer 2 — Page-level rmap via FrameMeta**

Each physical frame tracks how many VSpaces map it via a counter in
`FrameMeta`. This enables O(1) reclaimability checks without walking
region rmaps.

This reuses the same `FrameMeta` layout defined in the PMM section
(fields: `owner_tag`, `subkind`, `map_count`, `flags`, `page_idx`,
`owner_ptr` — 16 bytes per frame).

`map_count` is a **reclaimability hint**, not a precise reverse mapping
list. It tells you whether a frame is mapped anywhere (and thus whether
eviction requires PTE walks), but not which specific VSpaces or VAs hold
the mappings. For that, walk the MO's Layer 1 region rmaps.

`map_count` is maintained by the kernel:
- Incremented when `vspace.map()` installs a PTE for this phys addr
- Decremented when `vspace.unmap()` removes a PTE
- COW resolution: old frame's map_count decremented, new frame starts at 1

`flags` bits:
- `DIRTY` (bit 0): set when PTE dirty bit is harvested during page scan.
  Cleared by writeback (future FileBacked path).
- `REFERENCED` (bit 1): set when PTE accessed bit is harvested. Used by
  clock/LRU reclaim algorithms.
- `PINNED` (bit 2): frame cannot be reclaimed (e.g., DMA in progress).

**Reclaim decision** (O(1)):
```
if frame_meta.map_count == 0 && frame_meta.owner_tag == MoData:
    → page is committed in MO but not mapped anywhere
    → immediately reclaimable (decommit from MO, return to PMM)

if frame_meta.map_count > 0 && !frame_meta.flags.PINNED:
    → page is mapped, but can be evicted:
    → walk region rmaps to find and unmap all PTEs
    → then decommit from MO
```

**Actual unmap** (when reclaim needs to evict a mapped page):
```
1. PMM::lookup(phys) → FrameMeta { owner: MoData, mo_ptr, page_idx }
2. mo.reverse_maps → iterate region entries
3. For each region where page_idx is in [mo_offset, mo_offset + page_count):
   vaddr = region.va_start + (page_idx - region.mo_offset) * PAGE_SIZE
   vspace.unmap(vaddr)
   TLB shootdown
4. frame_meta.map_count should now be 0
5. mo.pages.remove(page_idx)
6. PMM::free(phys, MoData { mo, page_idx })
```

This is O(regions) per page — acceptable because reclaim is infrequent
and most MOs have 1-3 region mappings.

**Per-MO dirty bitmap** (optional, for FileBacked writeback):

When `MoKind::FileBacked` is implemented, the MO gains a dirty bitmap
(one bit per page, allocated from PMM as `MoMeta`). The kernel
periodically harvests PTE dirty bits via the region rmap layer:

```
for each region rmap entry:
    for page_idx in mo_offset .. mo_offset + page_count:
        vaddr = va_start + (page_idx - mo_offset) * PAGE_SIZE
        if vspace.harvest_dirty_bit(vaddr):
            mo.dirty_bitmap.set(page_idx)
            frame_meta[phys].flags |= DIRTY
```

This avoids per-page rmap chains while providing page-precise dirty
tracking. The cost is one PTE walk per dirty scan, amortized by batching.

### COW clone

`MO_CLONE` creates a snapshot child. The parent MO is **pinned** by the
child's capability reference — the child holds a cap-refcounted link to
the parent, preventing use-after-free if the parent process exits.

#### Ancestor lifetime rule

`cow_parent` is not a raw pointer. It is a **capability-refcounted
reference**: creating a CowChild increments the parent MO's
`KernelObject::ref_count`. The parent MO cannot be destroyed while any
child references it. This extends transitively: a grandchild pins the
child, which pins the parent.

When the last capability to a CowChild is deleted, the capability
system's drop path triggers MO destruction:

1. Free locally committed pages (walk `child.pages` radix tree,
   return each frame to PMM)
2. Remove self from parent's `first_child` linked list
3. Delete the `cow_parent` CapSlot — this decrements the parent MO's
   `ref_count` via the standard capability deletion path
4. If the parent's ref_count reaches 0, the capability system
   triggers the parent's destruction in turn (same path, recursive)

Destruction is always driven by **capability deletion**, never by
manual `destroy()` calls. The `cow_parent` CapSlot is the sole
reference keeping the parent alive. When it is deleted, the
capability system decides whether the parent survives (other caps
exist) or is destroyed (last cap gone).

This ensures the ancestor chain is always valid without explicit
flattening.

#### Chain depth management

Page resolution walks the `cow_parent` chain, so deep fork trees
(e.g., `bash | bash | bash | ...`) create O(depth) lookup cost.
Two mechanisms bound this:

**Lazy collapse**: When a CowChild is destroyed and its parent's
`ref_count` drops to 1 (exactly one sibling remains), the parent is
a CowChild, and the parent has no locally committed pages, the
remaining sibling is re-pointed directly to the grandparent.

The `first_child` / `next_sibling` intrusive linked list on each MO
tracks which children reference it:

```
MO_CLONE:
  child.next_sibling = parent.first_child
  parent.first_child = child

Destroy (self is a CowChild being destroyed):
  1. Remove self from parent.first_child linked list
  2. Decrement parent.ref_count

  3. Check collapse conditions:
     parent.ref_count == 1
     AND parent.kind == CowChild
     AND parent.pages has no local commits

  4. If all true:
     remaining = parent.first_child       // the one surviving sibling
     old_cap = remaining.cow_parent       // save before overwrite
     remaining.cow_parent = parent.cow_parent  // transfer grandparent cap
     parent.cow_parent = 0                // prevent parent.destroy from
                                          // decrementing grandparent ref
     free_slot(old_cap)                   // release old cap (pointed to parent)
     parent.first_child = null
     parent.destroy()                     // frees empty radix + rmap overflow
```

Ref_count changes:
- Grandparent: unchanged (parent's CapSlot transferred to remaining child)
- Parent: reaches 0, destroyed
- Remaining child: now directly references grandparent, chain shortened by 1

**Eager flatten on resolve**: During page resolution, if the chain
depth exceeds a threshold (default: 8), the resolved page is copied
into the requesting MO as a local page. This amortizes deep chains —
each page is flattened at most once, and subsequent accesses are O(1).

```
resolve_page(page_idx):
    depth = 0
    mo = self
    while mo.pages.get(page_idx).is_none():
        mo = deref_cap(mo.cow_parent)
        depth += 1
    phys = mo.pages.get(page_idx)
    if depth > COW_FLATTEN_THRESHOLD:
        new_phys = pmm.alloc(MoData { self, page_idx })
        memcpy(phys → new_phys)
        self.pages.insert(page_idx, new_phys)
        return new_phys
    return phys
```

This keeps worst-case resolution bounded regardless of fork depth.

#### Clone flow

```
Before:  parent.pages = radix{0:A, 1:B, 2:C}
         parent.kind = Anon

After:   parent.pages = radix{0:A, 1:B, 2:C}  (unchanged, parent retains ownership)
         child.pages = radix{}                  (empty)
         child.kind = CowChild
         child.cow_parent = &parent             (refcounted)
         parent.header.ref_count += 1           (pinned by child)

Page resolution for child:
  1. Check child.pages radix tree
  2. If empty: walk cow_parent chain upward
  3. Return shared PhysAddr (mapped read-only + COW in VSpace)

Write to child page 0 (COW fault):
  1. PMM::alloc(MoData{child, 0}) → new frame D
  2. memcpy(A → D)
  3. child.pages.insert(0, D)
  4. PTE updated: D | WRITABLE, COW bit cleared
  5. Frame A is unchanged — still owned by parent as MoData{parent, 0}
```

No `PMM::transfer` occurs during COW resolution. The parent's frame A
stays with the parent. The child gets a new frame D from PMM. This is
a pure allocation, not a transfer.

### Frame allocation: dual-source model

MO data pages come from **untyped** (primary) or **PMM** (fallback).
The caller provides a `ut_cap` argument to `MO_COMMIT`:

- `ut_cap != 0`: Carve page-sized frames from the untyped watermark
  (or its free list). Radix tree entry tagged with `PHYS_TAG_UNTYPED`
  (bit 0). Per-untyped `alloc_lock` protects watermark and free list.
- `ut_cap == 0`: Allocate from PMM bitmap (fallback/legacy path).
  No tag bit set.

Per-page commit sequence (untyped path):
```
mo.commit_lock.lock()
  reserve_slot(page_idx, BUSY)  ← path + empty check + sentinel, atomic
mo.commit_lock.unlock()
ut.alloc_lock.lock()
  pop free_list or bump watermark → phys
ut.alloc_lock.unlock()
zero page                         ← outside all locks
mo.commit_lock.lock()
  radix leaf = phys | PHYS_TAG_UNTYPED
mo.commit_lock.unlock()
```

Lock ordering: `mo.commit_lock` → `ut.alloc_lock` (never reversed).

When MO decommits a page:
```
mo.commit_lock.lock()
  entry = mo.pages.get(page_idx)
  mo.pages.remove(page_idx)
mo.commit_lock.unlock()
if entry & PHYS_TAG_UNTYPED:
  ut.alloc_lock → push to source untyped free list
else:
  pmm_free(phys)
```

When MO is destroyed:
```
mo.commit_lock.lock()
  for each page in mo.pages:
    for each rmap in mo.reverse_maps:
      unmap PTE, TLB shootdown
    if PHYS_TAG_UNTYPED: batch collect
    else: pmm_free(phys)
mo.commit_lock.unlock()
for each batched untyped page:
  ut.alloc_lock → push to source free list
for each metadata page (radix nodes, rmap overflow):
  pmm.free(phys, FrameOwner::MoMeta { mo, kind })
```

Untyped frame reclaim: `find_untyped_for_phys(phys)` searches the
init-created untyped list by physical range. Design invariant: untyped
source ranges are disjoint and never split.

### Invoke labels

| Label | Value | Operation |
|-------|-------|-----------|
| MO_COMMIT | 0x90 | Allocate frames for page range (arg2=ut_cap, 0=PMM) |
| MO_DECOMMIT | 0x91 | Release physical frames |
| MO_GET_SIZE | 0x92 | Return page count |
| MO_CLONE | 0x93 | Create COW snapshot clone |
| MO_RESIZE | 0x94 | Resize page count |
| VSPACE_MAP_MO | 0x97 | Map MO range into VSpace |
| VSPACE_UNMAP_MO | 0x98 | Unmap MO range from VSpace |

---

## VSpace Layer (`mm/vspace.rs`)

VSpace is the observer layer. It owns nothing — it borrows views of MO
pages and presents them to hardware page tables.

### Structure

```rust
struct VSpace {
    header: KernelObject,
    root: PhysAddr,              // PML4/TTBR0 physical address
    tracking: *mut VSpaceTracking,
    lock: SpinLock,
    // COW pool fields (existing)
}

struct VSpaceTracking {
    // ... existing fields (state, active_count, ASID, etc.) ...
    mappings: MapleTree<VmArea>,  // VAddr → VmArea
}
```

### VmArea

Defined in `vspace.rs`, not in the maple tree module. The maple tree
is a generic data structure (`MapleTree<V: Copy>`) that knows nothing
about VmArea.

```rust
// vspace.rs
struct VmArea {
    mo: *mut MemoryObject,    // raw pointer, refcounted via capability
    mo_offset: u32,           // page offset within MO for this region's start
    page_count: u32,          // number of pages in this region
    perms: u8,                // RWX permissions
}
```

`VmArea` does not own the MO. The MO's lifetime is managed by the
capability system. When a VmArea is created, it registers itself in
the MO's `reverse_maps`. When dropped, it deregisters.

### Maple tree for mappings

VmAreas are stored in a `MapleTree<VmArea>`:

- **Keys**: VA start addresses (u64)
- **Values**: `V` (generic, `VmArea` in this case)
- **Nodes**: allocated from PMM via `NodeAllocator` with
  `FrameOwner::KernelPrivate` tag
- **Properties**: cache-friendly B-tree variant, O(log n) lookup/insert/delete,
  range queries, no self-balancing overhead of red-black trees
- **Generic**: `MapleTree<V: Copy>` — leaf slot count is computed at
  compile time from `size_of::<V>()`. Internal nodes are V-independent.

```rust
// maple_tree.rs
struct MapleTree<V: Copy> {
    root: *mut u8,
    entry_count: usize,
    _phantom: PhantomData<V>,
}

// Leaf: header(16) + N * (pivot(8) + V) where N = (4096 - 16) / (8 + size_of::<V>())
// Internal: header(16) + N * pivot(8) + (N+1) * child(8), V-independent
```

### COW fast-path

When a COW write fault occurs, the kernel resolves it entirely in
the fast-path without IPC to mmsrv:

```
1. Fault at vaddr → read PTE → old_phys
2. PMM::lookup(old_phys) → FrameMeta { tag: MoData, mo_ptr, page_idx }
3. Conditions for fast-path (ALL must be true):
   a. source MO page is present in radix tree
   b. PMM has free frames (or emergency reserve available)
   c. (future: process quota not exceeded)
4. PMM::alloc(MoData { mo: child_mo, page_idx }) → new_phys
5. memcpy(old_phys → new_phys)
6. child_mo.pages.insert(page_idx, new_phys)  // cow_resolve_page
7. PTE: new_phys | WRITABLE, clear COW bit
8. TLB flush
```

If any condition fails, the fault falls through to mmsrv via VMFault
IPC. The kernel handles only the obvious mechanical case — policy
decisions (quota enforcement, OOM handling) belong in mmsrv.

---

## Untyped Memory

Untyped memory creates kernel **objects**, never data pages:

| Object | Created from Untyped |
|--------|---------------------|
| TCB | Yes |
| CNode | Yes |
| VSpace | Yes (PML4 + VSpaceTracking) |
| Endpoint | Yes |
| Notification | Yes |
| SchedContext | Yes |
| MemoryObject struct | Yes (header + radix root) |
| IrqHandler | Yes |
| IoPort | Yes |

Data pages (stack, heap, mmap, shared libs) are always PMM frames
loaned to MemoryObjects. This boundary must not blur — if it does,
memory accounting splits into two systems and invariant 1 breaks.

---

## Page Fault Handling

All user-visible pages are MO pages. Every fault path must identify
the backing MO, commit the page into that MO's radix tree, and
maintain reverse maps and map_count. No path may bypass MO and put
a raw PMM frame directly into a PTE.

### Fast-path (kernel-internal)

For faults that the kernel can resolve without IPC:

**1. COW fault** (present + write + user + COW bit set):

See COW fast-path section above. PMM lookup → find MO → alloc new
frame as `MoData{child_mo, page_idx}` → memcpy → cow_resolve_page
→ PTE update → map_count update.

**2. Demand fault** (present=0 + demand bit set in PTE):

A demand PTE was installed by `VSPACE_MAP_MO` for an uncommitted MO
page. The kernel resolves it by committing the page into the MO:

```
1. Fault at vaddr → read demand PTE → extract flags
2. Lookup VmArea in VSpaceTracking Maple tree → (MO*, mo_offset)
3. page_idx = mo_offset + (vaddr - vma.va_start) / PAGE_SIZE
4. PMM::alloc(MoData { mo, page_idx }) → phys
5. Zero-fill phys
6. mo.pages.insert(page_idx, phys)  // commit into radix tree
7. PTE: phys | flags (from demand PTE), clear demand bit, set present
8. pmm_retain_mapping(phys)  // increment map_count
9. TLB flush
```

If PMM alloc fails, the fault falls through to mmsrv.

**3. Stack growth** (fault near user SP, below current stack mapping):

The kernel extends the stack MO and VMA:

```
1. Fault at vaddr → check: vaddr >= user_stack_min
                          && vaddr < user_stack_top
                          && vaddr < current stack VMA base
2. Lookup stack VmArea in Maple tree
3. Compute new_base = vaddr & ~0xFFF (page-align down)
4. growth_pages = (old_vma.va_start - new_base) / PAGE_SIZE
5. mo.page_count += growth_pages  // extend MO capacity
6. For each new page (bottom-up):
   a. PMM::alloc(MoData { mo, new_page_idx }) → phys
   b. Zero-fill phys
   c. mo.pages.insert(new_page_idx, phys)
   d. vspace.map(new_vaddr, phys, USER_RW)
   e. pmm_retain_mapping(phys)
7. Update VmArea in Maple tree: va_start = new_base,
   page_count += growth_pages, mo_offset adjusted
8. Update MO reverse_maps entry for this VSpace
```

If PMM alloc fails at any step, the fault falls through to mmsrv.

### Slow-path (mmsrv IPC)

Everything else is delivered to the thread's fault handler (mmsrv)
via VMFault IPC:

- MO page not yet committed (no demand PTE, VmArea exists) →
  mmsrv calls `MO_COMMIT` + `VSPACE_MAP_MO`
- No VmArea covers fault address → segfault (mmsrv does not reply,
  thread stays FaultBlocked)
- PMM exhausted in fast-path → mmsrv decides (OOM kill, cache flush)
- Policy decisions (quota enforcement) → mmsrv decides

---

## `no_std` Boundary

The kernel is `#![no_std]` with `core::` only. No `alloc` crate.

| `std`/`alloc` type | Kernel replacement | Source |
|--------------------|--------------------|--------|
| `Vec<T>` | Inline array + PMM page chaining | PMM |
| `BTreeMap<K,V>` | `MapleTree<V>` (NodeAllocator) | PMM |
| `Arc<T>` | Capability refcount | Capability system |
| `Box<T>` (kernel object) | Untyped retype (TCB, CNode, MO struct, etc.) | Untyped |
| `Box<T>` (page/node) | PMM raw pointer + explicit free | PMM / NodeAllocator |
| `HashMap<K,V>` | Radix tree | PMM (NodeAllocator) |

---

## Memory Map (unchanged)

```
┌─────────────────────────────────────────┐ 0xFFFFFFFFFFFFFFFF
│           Kernel Reserved               │
├─────────────────────────────────────────┤ 0xFFFFFFFF80000000
│           Kernel Text/Data/BSS          │
├─────────────────────────────────────────┤ 0xFFFF800000000000
│           Direct Physical Map           │
├─────────────────────────────────────────┤ 0x0000800000000000
│           Non-canonical hole            │
├─────────────────────────────────────────┤ 0x0000000000000000
│           User Space                    │
└─────────────────────────────────────────┘
```

---

## VSpace Page Flags

| Bit | Value | Name | Description |
|-----|-------|------|-------------|
| 0 | 0x01 | WRITABLE | Page is writable |
| 1 | 0x02 | USER | Accessible from user mode |
| 2 | 0x04 | EXECUTABLE | NX bit cleared |
| 3 | 0x08 | CACHE_DISABLE | For device memory |
| 4 | 0x10 | WRITE_THROUGH | Write-through caching |
| 5 | 0x20 | COW | Copy-on-write (PTE bit 9) |

---

## mmsrv Integration

mmsrv is the userspace memory server. It owns root untyped capabilities
and serves memory requests from all processes.

With MO-everywhere, mmsrv's role simplifies:

- **Allocation** (mmap, brk, spawn): Retype `OBJ_MEMORY_OBJECT` from
  untyped, `MO_COMMIT` pages, `VSPACE_MAP_MO` into client
- **Fork**: `MO_CLONE` per unique MO (dedup table prevents double-clone
  when multiple regions share one MO), then register child regions
- **VMFault**: `MO_COMMIT` + `VSPACE_MAP_MO` for demand faults.
  COW write faults are handled by kernel fast-path (never reach mmsrv)
- **Cleanup**: Delete MO cap → MO destruction → reverse map traversal →
  PTE invalidation → PMM frame return

### Region tracking (`MmRegion`)

Each mmsrv client has a list of `MmRegion` entries:

```rust
struct MmRegion {
    base: u64,
    length: u64,
    prot: u8,
    region_type: u8,
    mo_cap: Cap,        // always non-zero (MO-everywhere)
    mo_offset: u32,     // page offset within MO for this region
    active: bool,
}
```

All regions are MO-backed. There is no legacy non-MO path.
