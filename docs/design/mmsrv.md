# Memory Manager Server (mmsrv)

## 1. Overview

mmsrv is the central pager service in SaltyOS, responsible for all userland frame allocation and VSpace mapping. It eliminates per-service memory allocators and hardcoded `MAX_*` pool limits by centralizing frame management in a single server with a growable architecture.

**Key responsibilities:**
- MemoryObject (MO) creation and lifecycle management
- Frame commitment via MO_COMMIT (dual-source: untyped primary, PMM fallback)
- VSpace mapping of MO pages via VSPACE_MAP_MO
- Per-client region tracking (heap, mmap, shared memory, file-backed)
- Demand paging for lazy-allocated regions
- Shared memory object management for VFS
- Dual-mapping windows for procmgr spawn/fork operations
- File-backed mmap coordination with VFS pager

**Design philosophy:**
- **Centralized pager:** All frame allocation flows through mmsrv. Clients never directly retype frames from untyped memory (except rtld/init during bootstrap).
- **MO-based memory model:** User pages are managed through MemoryObject kernel objects. mmsrv creates MOs, commits pages, and maps them via capability invocations.
- **Growable data structures:** Client table, region tables, and SHM table all use dynamic growth via self-mmap to avoid fixed limits.
- **Badge-based isolation:** Each client receives a badged endpoint. The badge identifies the client in all IPC requests and VMFault deliveries.
- **Self-bootstrap:** mmsrv allocates its own internal data structures from its child untyped capability, avoiding recursive IPC to itself.

## 2. Architecture

### Boot Order

```
init (phase 0)
  ↓
console (serial I/O server)
  ↓
nameserv (endpoint registry)
  ↓
mmsrv ← YOU ARE HERE (frame allocator + pager)
  ↓
vfs (filesystem + sockets)
  ↓
procmgr (process manager)
  ↓
...rest of userland
```

mmsrv must start before VFS and procmgr because both need dynamic memory allocation for their internal data structures. Once mmsrv is running, all subsequent services use `posix_mmap()` → mmsrv IPC for frame allocation.

### MO-Based Memory Flow

The standard allocation path through mmsrv uses MemoryObject kernel objects:

```
Client: posix_mmap(len, PROT_RW, MAP_PRIVATE|MAP_ANONYMOUS)
  ↓ IPC (MM_MMAP)
mmsrv:
  1. create_mo(num_pages)           → MO cap via untyped_retype(OBJ_MEMORY_OBJECT)
  2. mo_commit(mo_cap, ut_cap, ...) → commit pages (untyped primary, PMM fallback)
  3. vspace_map_mo(vspace, mo, ...)  → install PTEs from MO pages
  ↓ reply
Client: receives mapped base address
```

For lazy (demand-paged) regions, steps 2-3 happen on VMFault instead of eagerly at mmap time.

### Capability Layout

Set by init in `spawn.rs`:

| Slot | Name | Type | Purpose |
|------|------|------|---------|
| 0 | `CAP_SELF_TCB` | TCB | Own thread control block |
| 1 | `CAP_SELF_VSPACE` | VSpace | Own page table root |
| 2 | `CAP_SELF_CSPACE` | CNode | Own CSpace root (14 bits = 16384 slots) |
| 3 | `CAP_SERVER_EP` | Endpoint | Server endpoint (unbadged) |
| 7 | `CAP_UNTYPED` | Untyped | Child untyped for self-bootstrap |
| 12 | `CAP_INITRD_UNTYPED` | Untyped | Initrd-backed untyped |
| 14 | `CAP_READINESS_NTFN` | Notification | Signal to init when ready |
| 16+ | `CAP_UNTYPED_START` | Untyped | Mirrored parent untyped caps (up to 8) |
| 64 | `CAP_NAMESERV` | Endpoint | Name service endpoint (via NeedEP) |
| 256+ | - | - | Slot allocator pool |
| 15360-16383 | - | - | Receive slot pool (RECV_SLOT_BASE=0x3C00) |

**CNode size:** 14 bits (16384 slots) to support:
- Initial slots (0-255)
- Slot allocator pool (256+)
- Large receive slot pool (1024 slots) for cap transfers

### Startup Sequence

1. **IPC buffer setup:** Map IPC buffer at `0x0000_0000_0020_0000`, configure TCB
2. **Untyped pool init:** Discover all untyped caps (slot 7, slots 16-23), build round-robin source list
3. **Client table alloc:** Allocate 1 page for client table via `self_mmap()`
4. **SHM table alloc:** Allocate 1 page for shared memory object table via `self_mmap()`
5. **Receive slot setup:** Configure receive slot pool (RECV_SLOT_BASE to RECV_SLOT_END)
6. **Nameserv registration:** Register server EP under name "mmsrv"
7. **Signal readiness:** Signal `CAP_READINESS_NTFN` to unblock init
8. **Server loop:** Enter `recv()` → process → `reply_recv()` loop

## 3. IPC Protocol

### Message Labels (0x80-0xA3 Range)

Defined in `lib/trona/uapi/protocol/mmsrv.rs`. Label 0x91 remains
unused; 0x96 is reserved (device mmap handled as subcase of `MM_FILE_MMAP`).

| Label | Name | Source | Purpose |
|-------|------|--------|---------|
| 0x80 | `MM_REGISTER` | procmgr | Register new client + VSpace cap transfer |
| 0x81 | `MM_DEREGISTER` | procmgr | Deregister client on exit |
| 0x82 | `MM_BRK` | client | Set program break (absolute) |
| 0x83 | `MM_SBRK` | client | Increment program break (relative) |
| 0x84 | `MM_MMAP` | client | Anonymous mmap (eager or lazy) |
| 0x85 | `MM_MUNMAP` | client | Unmap and free frames |
| 0x86 | `MM_MPROTECT` | client | Change page protection |
| 0x87 | `MM_MAP_BATCH` | procmgr | Batch-map N pages for spawn |
| 0x88 | `MM_MAP_WINDOW` | procmgr | Dual-map frames (target + caller) |
| 0x89 | `MM_UNMAP_WINDOW` | procmgr | Remove caller-side mapping |
| 0x8A | `MM_SHM_CREATE` | vfs | Create shared memory object |
| 0x8B | `MM_SHM_MAP` | vfs | Map SHM into client VSpace |
| 0x8C | `MM_SHM_UNMAP` | vfs | Unmap SHM from client VSpace |
| 0x8D | `MM_FORK_REGIONS` | procmgr | Clone parent's region state to child |
| 0x8E | `MM_SHM_DESTROY` | vfs | Destroy SHM backing after last close |
| 0x8F | `MM_SHM_RESIZE` | vfs | Resize SHM backing with mapped-tail safety checks |
| 0x90 | `MM_GET_CLIENT_STATS` | any | Query per-client memory usage |
| 0x92 | `MM_REGISTER_SHARED_REGION` | procmgr | Register shared library region |
| 0x93 | `MM_MAP_OBJECT_REGION` | procmgr | Map MO-backed region into client |
| 0x94 | `MM_SYNC_FILE_BACKING` | vfs | Sync file-backed MO to storage |
| 0x95 | `MM_FILE_MMAP` | vfs | File-backed mmap (MO + pager) |
| 0x97 | `MM_SYNC_MMAP_WRITE` | vfs | Sync dirty mmap pages |
| 0x98 | `MM_PROVISION_UNTYPED` | procmgr | Push untyped memory to mmsrv |
| 0x99 | `MM_QUERY_CAPACITY` | any | Query available memory capacity |
| 0x9A | `MM_PAGER_REQUEST` | kernel/vfs | Page-in request (demand paging) |
| 0x9B | `MM_PAGER_WRITE_REQUEST` | kernel/vfs | Write-back request for dirty page |
| 0x9C | `MM_DUMP_PENDING` | debug | Dump pending operations (debug) |
| 0x9D | `MM_REGISTER_PAGER_EP` | vfs | Register backend callback endpoint for file-backed regions |
| 0x9E | `MM_ALLOC_PRIVATE_REGION` | procmgr | Allocate private MO-backed region |
| 0x9F | `MM_ALLOC_PRIVATE_WINDOW` | procmgr | Allocate private dual-mapped window |
| 0xA0 | `MM_ALLOC_INITRD_COPY` | procmgr | Copy initrd data into MO pages |
| 0xA1 | `MM_ALLOC_BOOTINFO_COPY` | procmgr | Copy bootinfo into MO pages |
| 0xA2 | `MM_COPY_FROM_CLIENT_REGION` | procmgr | Copy data from client's region |
| 0xA3 | `MM_ALLOC_PRIVATE_COPY_FROM_CLIENT_REGION` | procmgr | Allocate + copy from client region |

**Note:** 0x91 is currently unused. 0x96 is reserved (device mmap handled as subcase of `MM_FILE_MMAP`).

### Message Layouts

**MM_REGISTER (procmgr → mmsrv):**
```
MR0 = client_badge (unique badge for client's EP)
MR1 = heap_base (virtual address)
MR2 = mmap_base (virtual address)
MR3 = pid (process ID)
+ cap transfer: client's VSpace cap
Reply: label = TRONA_OK
```

**MM_MMAP (client → mmsrv):**
```
MR0 = addr_hint (0 = auto-pick)
MR1 = length (bytes)
MR2 = prot (PROT_READ | PROT_WRITE | PROT_EXEC)
MR3 = flags (MAP_PRIVATE | MAP_ANONYMOUS | MAP_LAZY)
Badge identifies client
Reply: label = TRONA_OK, MR0 = mapped_base
```

**MM_BRK (client → mmsrv):**
```
MR0 = new_break (absolute virtual address)
Badge identifies client
Reply: label = TRONA_OK, MR0 = new_break
```

**MM_MAP_WINDOW (procmgr → mmsrv):**
```
MR0 = target_badge (child process)
MR1 = target_vaddr (where to map in child)
MR2 = window_vaddr (where to map in caller)
MR3 = num_pages
MR4 = vspace_flags (for target mapping)
+ cap transfer: caller's VSpace cap
Reply: label = TRONA_OK, MR0 = pages_mapped
```

**MM_PROVISION_UNTYPED (procmgr → mmsrv):**
```
+ cap transfer: untyped capability
Reply: label = TRONA_OK
```

This is a push model: procmgr provisions additional untyped memory to mmsrv when the system grows, avoiding mmsrv needing to request memory from procmgr (which would create a circular dependency).

**MM_FILE_MMAP (vfs → mmsrv):**
```
MR0 = client_badge
MR1 = length (bytes)
MR2 = prot
MR3 = offset (file offset)
MR4 = pager_ep (endpoint for page-in/write-back)
Reply: label = TRONA_OK, MR0 = mapped_base
```

Creates a file-backed MO. On page fault, mmsrv sends `MM_PAGER_REQUEST` to the registered backend callback endpoint (typically VFS endpoint slot 63) to fill the page. The same callback endpoint is also reused by netsrv async completions, so VFS treats it as a shared backend ingress rather than a pager-only channel.

### File-Backed Pager Verification Plan

The current design assumes a single VFS-owned backend callback endpoint that services both netsrv async completions and mmsrv pager traffic. The minimum runtime verification should check:

1. Backend callback registration succeeds during VFS startup, or VFS logs the service-EP fallback path.
2. `VFS_BACKEND_RESOLVE_BACKING` from mmsrv resolves against the target client badge rather than auto-registering mmsrv as a fake client.
3. First fault on a file-backed `MAP_SHARED` mapping triggers `MM_PAGER_REQUEST` and populates one page from backing storage.
4. Dirtying a shared mapping triggers `MM_PAGER_WRITE_REQUEST` write-back through the same callback endpoint.
5. `ftruncate()` on an mmapped file emits `MM_SYNC_FILE_BACKING` so mmsrv drops pages past the new EOF.
6. netsrv async completions still arrive on the shared backend callback endpoint and are demultiplexed by badge without regressing socket operations.

**VMFault (kernel → mmsrv):**
```
label = 2 (FaultType::VMFault)
MR0 = fault_addr
MR1 = error_code
MR2 = fault_rip
Badge identifies faulting client
Reply: label = TRONA_OK (resume) or error (kill process)
```

## 4. Internal Design

### Self-Bootstrap (Avoiding Recursive IPC)

mmsrv needs memory for its own data structures (client table, region tracking, SHM table), but it **cannot** call `posix_mmap()` because that would send IPC to itself (deadlock).

**Solution:** `self_mmap()` bypasses IPC and directly:
1. Allocates slot via `slot_alloc()`
2. Creates a MemoryObject via `untyped_retype(OBJ_MEMORY_OBJECT)`
3. Commits pages via `mo_commit()`
4. Maps MO into own VSpace via `vspace_map_mo(CAP_SELF_VSPACE, ...)`
5. Returns pointer to the new memory

This direct path is only used for mmsrv's internal allocations. Client allocations still go through the full IPC protocol.

### Client Tracking

**MmClient struct (per client):**
```rust
struct MmClient {
    badge: u64,              // Client's EP badge (unique ID)
    pid: u32,                // Process ID
    active: bool,            // Is this slot occupied?
    vspace_cap: Cap,         // Client's VSpace cap (held by mmsrv)
    heap_base: u64,          // POSIX heap start address
    heap_current: u64,       // Current program break
    mmap_next: u64,          // Next mmap allocation address
    regions: *mut MmRegion,  // Growable region array
    region_count: usize,     // Number of active regions
    region_cap: usize,       // Capacity of region array
}
```

**Client table:**
- Static pointer: `CLIENTS_PTR: *mut MmClient`
- Growable capacity: starts at 1 page (~24 clients), doubles on overflow
- Growth via `self_mmap()` + copy old entries

**Lookup:**
- `find_client_by_badge(badge)` — O(n) scan (acceptable for <100 processes)

### Region Tracking

**MmRegion struct (per memory region):**
```rust
struct MmRegion {
    base: u64,              // Virtual address start
    length: u64,            // Region size in bytes
    prot: u8,               // PROT_READ/WRITE/EXEC
    region_type: u8,        // REGION_HEAP=0 or REGION_MMAP=1
    active: bool,           // Is this region valid?
    lazy: bool,             // Demand-paged (MAP_LAZY)?
    mo_cap: Cap,            // MemoryObject capability (owns the backing pages)
    frame_count: u16,       // Number of frames committed
}
```

**Per-client region list:**
- Growable array (starts at 8 entries, doubles on overflow)
- Each client has independent region tracking
- Regions track MO caps for cleanup on munmap/deregister

**Lazy regions (MAP_LAZY):**
- MO is created but pages are not committed
- VMFault handler commits pages on first access via `mo_commit()` + `vspace_map_mo()`

### Untyped Pool

**Round-robin allocation:**
```rust
unsafe fn retype_any(obj_type: u64, size_bits: u64, dest_slot: Cap) -> i32
```

Scans untyped sources in round-robin order:
1. Start at `UT_HINT` (last successful source)
2. Try `untyped_retype()` on each source
3. If successful, update hint and return
4. If all sources exhausted, return `TRONA_OUT_OF_MEMORY`

**Sources:**
- Slot 7: child untyped (primary)
- Slots 16-23: mirrored parent untypeds (if present)
- Additional untypeds from `MM_PROVISION_UNTYPED` (push model from procmgr)
- Up to 12 total sources (`MAX_UT_SOURCES`)

### Receive Slot Pool

**Purpose:** Cap transfers (MM_REGISTER, MM_MAP_WINDOW, MM_PROVISION_UNTYPED, etc.) need a destination CNode slot.

**Pool layout:**
- Base: 0x3C00 (15360)
- End: 0x4000 (16384)
- Size: 1024 slots

**Allocation strategy:**
- Bump pointer: `NEXT_RECV_SLOT` increments on each `alloc_recv_slot()`
- Current slot: `CURRENT_RECV_SLOT` is configured for next IPC
- Recycling: If handler doesn't keep cap (`RECV_SLOT_KEPT=false`), delete cap and reuse slot
- Permanent keep: If handler sets `RECV_SLOT_KEPT=true` (e.g., MM_REGISTER stores VSpace cap), advance to next slot

**Pool exhaustion:** Returns 0 (unrecoverable error — server restart required)

## 5. Client Lifecycle

### Registration (MM_REGISTER)

**Called by:** procmgr after spawning a new process

**Steps:**
1. Extract client badge, heap_base, mmap_base, pid from message
2. Check for duplicate badge (error if already registered)
3. Find free slot in client table (grow if needed via `self_mmap()`)
4. Receive VSpace cap into `CURRENT_RECV_SLOT`
5. Initialize `MmClient` struct, set `vspace_cap = CURRENT_RECV_SLOT`
6. Mark receive slot as kept (`RECV_SLOT_KEPT=true`)
7. Reply with `TRONA_OK`

**Badge assignment:** procmgr chooses badge = PID (ensures uniqueness)

**Heap/mmap layout:**
- `heap_base` — start of POSIX heap (typically 1 MB after scratch region)
- `heap_current` — initially equals `heap_base` (empty heap)
- `mmap_next` — start of mmap region (typically 16 MB after heap_base)

### Deregistration (MM_DEREGISTER)

**Called by:** procmgr after process exit or kill

**Steps:**
1. Find client by badge
2. Iterate all regions, delete MO caps (kernel reclaims backing pages)
3. Delete VSpace cap held in `vspace_cap`
4. Mark client slot inactive
5. Decrement `CLIENT_COUNT`
6. Reply with `TRONA_OK`

**Cleanup scope:**
- All MO caps tracked in regions are deleted (MO destruction frees committed pages)
- VSpace cap is removed from mmsrv's CSpace
- Kernel handles page table teardown when VSpace cap refcount hits 0

## 6. Frame Allocation

### Eager Allocation (MM_MMAP)

**When:** `MAP_LAZY` flag is NOT set

**Algorithm:**
1. Round length up to 4K page boundary
2. Allocate region struct via `client_add_region()`
3. Create MemoryObject: `create_mo(num_pages)` → `untyped_retype(OBJ_MEMORY_OBJECT)`
4. Commit all pages: `mo_commit(mo_cap, ut_cap, offset, count)` (untyped primary, PMM fallback)
5. Map MO into client VSpace: `vspace_map_mo(client.vspace_cap, mo_cap, vaddr, offset, flags)`
6. Advance `client.mmap_next` by length
7. Reply with mapped base address

**Rollback on failure:** If any step fails, delete MO cap and mark region inactive.

### Lazy Allocation (MM_MMAP with MAP_LAZY)

**When:** `MAP_LAZY` flag is set

**Allocation phase:**
1. Allocate region struct, mark `lazy=true`
2. Create MemoryObject (empty, no pages committed)
3. Advance `client.mmap_next` (reserve virtual address range)
4. Reply with mapped base address

**Demand paging phase (on first access):**
- Process accesses lazy page → page fault → kernel sends VMFault IPC
- mmsrv receives `label=2`, `badge=client`
- Find region containing fault address
- Commit page: `mo_commit(region.mo_cap, ut_cap, page_offset, 1)`
- Map page: `vspace_map_mo(client.vspace_cap, region.mo_cap, page_addr, page_offset, flags)`
- Reply `TRONA_OK` → kernel resumes faulting thread

### Heap Management (MM_BRK/SBRK)

**BRK (absolute):**
```
MR0 = new_break (absolute address)
```

**SBRK (relative):**
```
MR0 = increment (signed, cast to i64)
old_break returned in MR0
```

**Heap region:**
- Type: `REGION_HEAP`
- Backed by a MemoryObject that grows as the heap expands
- Starts at `heap_base`, grows to `heap_current` (rounded up to page boundary)

**Growth algorithm:**
1. Compute old_page and new_page (4K-aligned)
2. Find or create heap region (with MO)
3. If growing:
   - Commit new pages via `mo_commit()`
   - Map new pages via `vspace_map_mo()`
4. If shrinking:
   - Decommit freed pages via `mo_decommit()`
   - Unmap freed pages
5. Update `heap_current`

### Unmapping (MM_MUNMAP)

**Algorithm:**
1. Find region containing base address
2. If region exists:
   - Unmap MO pages from VSpace
   - Delete MO cap (kernel frees committed pages)
   - Mark region `active=false`
3. If no region (e.g., batch-mapped spawn pages):
   - Just unmap pages (no MO cleanup)

### Protection Change (MM_MPROTECT)

**Algorithm:**
1. Find region containing address
2. Convert PROT_* flags to VSPACE_FLAG_*
3. Remap MO pages with new flags via `vspace_map_mo()` with updated permissions
4. Update `region.prot`

## 7. Spawn/Fork Integration

### Batch Mapping (MM_MAP_BATCH)

**Purpose:** procmgr needs to map N pages into a child's VSpace during spawn (for code, data, stack).

**Protocol:**
```
MR0 = target_badge
MR1 = start_vaddr
MR2 = num_pages
MR3 = vspace_flags
Reply: MR0 = pages_mapped
```

**Algorithm:**
1. Find client by target_badge
2. Create MO, commit all pages
3. Map MO into target's VSpace via `vspace_map_mo()`
4. Return number of pages successfully mapped (partial success allowed)

**Partial success:** If commit fails midway, return the count of successfully mapped pages. Procmgr decides whether to retry or abort.

### Write Window (MM_MAP_WINDOW / MM_ALLOC_PRIVATE_WINDOW)

**Purpose:** procmgr needs to write to a child's VSpace (copy ELF segments, initialize stack).

**Dual-mapping strategy:**
1. Create MO and commit pages
2. Map MO into **target's VSpace** (read/write/user flags from MR4)
3. Map **same MO** into **caller's VSpace** (write window at window_vaddr, always writable)
4. Caller writes data via window
5. Caller sends MM_UNMAP_WINDOW to remove window mapping

**Cap ownership:** MO cap stays in mmsrv's CSpace. Both mappings reference the same MO (and thus the same underlying pages). Window removal only unmaps from caller; target mapping persists.

**Receive slot handling:**
- Caller's VSpace cap transferred via IPC
- Used for window mapping
- Deleted after operation (transient cap)

### Region Cloning (MM_FORK_REGIONS)

**Purpose:** procmgr calls this after COW fork to clone parent's memory layout to child.

**Protocol:**
```
MR0 = parent_badge
MR1 = child_badge
Reply: TRONA_OK
```

**What's cloned:**
- `heap_base`, `heap_current`, `mmap_next` (memory layout pointers)
- Region list (deep copy of region structs)
- **NOT** MO caps directly — COW-managed by kernel via MO clone

**Why not clone MO caps?**
- Kernel handles COW via MO clone and `vspace_clone_cow_page()` during fork
- mmsrv doesn't track COW frames until they're written (lazy breakage)
- Child's MO entries stay unresolved — VMFault on write → mmsrv commits new page

## 8. Shared Memory (SHM)

### Creation (MM_SHM_CREATE)

**Caller:** VFS (on behalf of `shm_open()` client)

**Protocol:**
```
MR0 = shm_id (hash of shm name)
MR1 = num_pages
Reply: TRONA_OK
```

**Algorithm:**
1. Check for duplicate shm_id (error if exists)
2. Find free slot in SHM table (grow if needed)
3. Allocate one frame cap per page from the frame pool / retype path
4. Store the frame-cap array in `ShmObject` with `active=true`

**SHM lifetime:** Created by VFS on first truncate, remains reachable while a name or live fd exists, and is destroyed by VFS via `MM_SHM_DESTROY` after `shm_unlink()` plus the last close.

### Resize (MM_SHM_RESIZE)

**Caller:** VFS (on behalf of `ftruncate()` on an existing SHM object)

**Protocol:**
```
MR0 = shm_id
MR1 = new_num_pages
Reply: TRONA_OK or error
```

**Policy:**
1. Grow is allowed in place by appending newly allocated frames to the SHM backing.
2. Shrink is allowed only if no live shared mapping covers bytes beyond the new end.
3. Existing mappings are never auto-expanded or auto-relocated; callers must create a new mapping to observe grown capacity.

### Mapping (MM_SHM_MAP)

**Caller:** VFS (on behalf of `mmap(fd, ...)` where fd is SHM)

**Protocol:**
```
MR0 = shm_id
MR1 = client_badge
MR2 = vaddr (0 = auto-pick)
MR3 = prot (vspace flags)
Reply: MR0 = actual_vaddr
```

**Algorithm:**
1. Find SHM object by ID (error if not found)
2. Find client by badge
3. Pick vaddr (auto: use `client.mmap_next`, explicit: use MR2)
4. Map SHM's backing frames directly into client VSpace via `vspace_map()`
5. If auto-pick, advance `client.mmap_next`
6. Return mapped address

**Shared access:** Multiple clients can map the same SHM frame set. All shared mappings see the same physical frames.

### Unmapping (MM_SHM_UNMAP)

**Caller:** VFS (on behalf of `munmap()` or `close(fd)`)

**Protocol:**
```
MR0 = shm_id
MR1 = client_badge
MR2 = vaddr
Reply: TRONA_OK
```

**Algorithm:**
1. Find SHM object by ID
2. Find client by badge
3. Unmap SHM-backed pages from client VSpace

**Frame lifetime:** MO remains alive (not deleted). Other mappings persist.

### Destruction (MM_SHM_DESTROY)

**Caller:** VFS (after unlink and last close)

**Protocol:**
```
MR0 = shm_id
Reply: TRONA_OK
```

**Algorithm:**
1. Find SHM object by ID
2. Return all frame caps to the frame pool
3. Mark the SHM slot inactive for reuse

**Idempotence:** Destroy is idempotent. If the SHM object is already gone, mmsrv still returns `TRONA_OK`.

## 9. Demand Paging (VMFault Handling)

### VMFault IPC Format

Sent by kernel when userland process accesses unmapped/COW page:

```
label = 2 (FaultType::VMFault)
MR0 = fault_addr (virtual address of fault)
MR1 = error_code (x86 PF error bits / aarch64 ESR)
MR2 = fault_rip (instruction pointer at fault)
Badge = faulting client's badge
```

**Delivery:** Thread blocks, kernel sends IPC to thread's fault endpoint (which is mmsrv's server EP, badged with client badge).

**Resume:** Reply with `TRONA_OK` → kernel restores thread's register state and resumes execution.

### VMFault Handler Algorithm

1. **Identify client:** `find_client_by_badge(badge)`
   - Error if client not registered (orphaned fault)
2. **Find region:** `find_region_by_addr(client, page_addr)`
   - If no region: segfault (reply `TRONA_INVALID_ARGUMENT` → procmgr kills process)
3. **Commit page:** `mo_commit(region.mo_cap, ut_cap, page_offset, 1)`
   - Dual-source: tries untyped first, falls back to PMM
4. **Map page:** `vspace_map_mo(client.vspace_cap, region.mo_cap, page_addr, page_offset, flags)`
   - Convert `region.prot` to vspace flags
   - If map fails: reply `TRONA_BAD_ADDRESS`
5. **Resume:** Reply `TRONA_OK` → thread resumes at faulting instruction

### COW vs Lazy Distinction

- **Lazy (MAP_LAZY):** MO created with no committed pages
- **COW (fork):** Kernel maps MO pages read-only via COW clone, write triggers VMFault, mmsrv commits new page into child's MO

Both use the same VMFault handler. The only difference is the initial state.

## 10. File-Backed Mmap

### MM_FILE_MMAP

**Purpose:** VFS requests file-backed memory mapping on behalf of `mmap(fd, ...)`.

**Flow:**
1. VFS resolves the fd into a backing identity (`FILE`, `MOUNT`, `DEVICE`, or `SHM`)
2. VFS sends `MM_FILE_MMAP` with fd, offset, length, protection, and map flags
3. mmsrv dispatches by backing kind:
  - `FILE` / `MOUNT`: MO + pager-backed lazy mapping
  - `DEVICE`: direct device-cap mapping
  - `SHM` + `MAP_SHARED`: direct frame mapping of the shared backing
  - `SHM` + `MAP_PRIVATE`: eager snapshot into a private MO
4. mmsrv records a region entry and returns the mapped base address

**Why SHM is separate from file pagering:** POSIX shared memory has stable backing frames owned by mmsrv already. Treating it as a pager-backed tmpfs file leaks the wrong identity into the common mmap path and makes resize/lifetime semantics harder to define.

### MM_SYNC_MMAP_WRITE / MM_SYNC_FILE_BACKING

For dirty page write-back:
1. mmsrv sends `MM_PAGER_WRITE_REQUEST` to VFS pager
2. VFS writes dirty page data back to storage
3. `MM_SYNC_FILE_BACKING` with `MM_SYNC_BACKING_TRUNCATE` flag handles ftruncate

## 11. Bootstrap Path (rtld Exception)

### Why rtld Can't Use mmsrv

**Problem:** rtld runs **before** mmsrv in the boot order (rtld is embedded in init, which is phase 0; mmsrv is phase 2).

**Solution:** rtld uses direct untyped retype:
- Receives `AT_TRONA_UNTYPED` via auxv
- Directly calls `untyped_retype()` + `vspace_map()`
- No IPC to mmsrv

### procmgr Shared Library Cache

**Problem:** procmgr maintains a shared library cache (loads `libtrona.so`, `libc.so` once, maps into all children). This cache needs frames, but procmgr can't use mmsrv (circular dependency — mmsrv uses procmgr for process management).

**Solution:** procmgr also has its own child untyped capability:
- Allocates cache frames directly via `untyped_retype()`
- Maps cache frames into children via `vspace_map(child_vspace_cap, ...)`

### Transition Point

Once a process is spawned by procmgr:
- It receives `CAP_MMSRV_EP` (slot 7, badged endpoint)
- All `posix_mmap()` calls go through mmsrv IPC
- No direct untyped access (slot allocator uses mmsrv for frame allocation)

## 12. Error Code Semantics

### Frame Allocation Errors

| Error Code | Value | Condition |
|------------|-------|-----------|
| `TRONA_OUT_OF_MEMORY` | 5 | `slot_alloc()` fails, `retype_any()` exhausts all untypeds, MO creation fails |
| `TRONA_BAD_ADDRESS` | 10 | `vspace_map_mo()` fails (address conflict, invalid VSpace, PT allocation failure) |
| `TRONA_INVALID_ARGUMENT` | 4 | Bad parameters (length=0, addr misaligned, segfault on unknown region) |
| `TRONA_NOT_FOUND` | 6 | Client badge not registered, SHM ID not found |
| `TRONA_ALREADY_EXISTS` | 8 | Duplicate client badge, duplicate SHM ID |

**Key distinction:** `TRONA_OUT_OF_MEMORY` means "ran out of capability resources" (slots or frames). `TRONA_BAD_ADDRESS` means "vspace_map_mo rejected the request" (address conflict, page table issues, bad VSpace cap).

### VMFault Error Handling

- **TRONA_OK:** Page committed and mapped → resume thread
- **TRONA_BAD_ADDRESS:** vspace_map_mo failed (rare, indicates kernel state corruption) → procmgr should kill process
- **TRONA_INVALID_ARGUMENT:** No region covers fault address (segfault) → procmgr delivers SIGSEGV
- **TRONA_OUT_OF_MEMORY:** MO commit failed → procmgr should kill process (or swap to disk, if supported)

## 13. Performance Considerations

### Client Lookup: O(n) vs Hash Table

Current: Linear scan (`find_client_by_badge()`)
- Acceptable for <100 processes
- Simple implementation, no collision handling
- Cache-friendly for small tables

Future: Hash table with chaining when CLIENT_COUNT > 64

### Region Lookup: O(n) per Client

Current: Linear scan within client's region list
- Typical client has <10 regions (heap + few mmap regions)
- O(n) is acceptable for small n

Future: Interval tree if clients have >50 regions

### MO-Based Allocation Benefits

- Batch commit: `mo_commit()` can commit multiple pages in one invocation
- Batch map: `vspace_map_mo()` maps MO page range in one invocation
- Reduced cap overhead: one MO cap per region instead of one frame cap per page

### Untyped Round-Robin Fairness

Round-robin scan ensures all untypeds are used evenly, avoiding premature exhaustion of one source. Hint caching (`UT_HINT`) amortizes scan cost to O(1) in steady state.

## 14. Limitations and Future Work

**Current limitations:**
- **No page eviction:** Once committed, MO pages stay until process exit (no swap, no reclaim)
- **No SHM reference counting:** SHM objects persist until server restart
- **No quota enforcement:** Clients can allocate unlimited frames (bounded only by available untyped memory)
- **No NUMA awareness:** All frames come from single untyped pool (no node affinity)
- **No huge pages:** Only 4K pages supported

**Future enhancements:**
- **LRU eviction:** Track page access bits, evict cold pages to swap
- **SHM lifecycle:** Delete SHM MO when all mappings removed
- **Per-client quotas:** Enforce `RLIMIT_AS` via region tracking
- **Async VMFault batching:** Handle multiple faults in one IPC (for sequential access patterns)

## 15. Debugging and Introspection

### Serial Logging

mmsrv logs key events to serial console:
```
[MMSRV] registered client badge=0x1234 pid=42 heap=0x20000000 mmap=0x21000000
[MMSRV] MMAP: client=0x1234 addr=0x21000000 len=8192 prot=RW eager
[MMSRV] VMFault: badge=0x1234 addr=0x21001234 → committed page at 0x21001000
[MMSRV] deregistered client badge=0x1234 pid=42
```

### MM_DUMP_PENDING (Debug)

Label 0x9C dumps internal state of pending operations to serial output.

### MM_QUERY_CAPACITY

Label 0x99 returns available memory capacity:
- Client count, region count, SHM count
- Per-client memory usage (sum of region frame counts)
- Untyped pool watermarks (how much memory allocated from each source)

### Crash Recovery

**Current:** Server panic = system halt (no recovery)

**Future:** Procmgr could respawn mmsrv on crash, but state loss is catastrophic (all client MO references lost). Better strategy: kernel-level checkpointing of mmsrv state.

## 16. Cross-References

- **[Memory Design](memory.md)** — MemoryObject kernel implementation, RadixTree, COW semantics, dual-source commit
- **[Capability Design](capability.md)** — MO invoke labels (0x90-0x97), VSPACE_MAP_MO
- **[POSIX Compatibility](posix.md)** — How `posix_mmap()`/`brk()`/`sbrk()` delegate to mmsrv
- **[trona Design](trona.md)** — Slot allocator's use of mmsrv for frame allocation
- **[Kernel Memory Management](memory.md)** — Untyped retype, VSpace mapping, COW implementation
- **[IPC Design](ipc.md)** — Endpoint badging, cap transfer, fault delivery
