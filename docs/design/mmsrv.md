# Memory Manager Server (mmsrv)

## 1. Overview

mmsrv is the central pager service in SaltyOS, responsible for all userland frame allocation and VSpace mapping. It eliminates per-service memory allocators and hardcoded `MAX_*` pool limits by centralizing frame management in a single server with a growable architecture.

**Key responsibilities:**
- Frame allocation from untyped memory (seL4-style retype)
- VSpace mapping of frames into client address spaces
- Per-client region tracking (heap, mmap, shared memory)
- Demand paging for lazy-allocated regions
- Shared memory object management for VFS
- Dual-mapping windows for procmgr spawn/fork operations

**Design philosophy:**
- **Centralized pager:** All frame allocation flows through mmsrv. Clients never directly retype frames from untyped memory (except rtld/init during bootstrap).
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

### Message Labels (0x80-0x8D Range)

Defined in `lib/libsalty/src/consts.rs`:

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

### Message Layouts

**MM_REGISTER (procmgr → mmsrv):**
```
MR0 = client_badge (unique badge for client's EP)
MR1 = heap_base (virtual address)
MR2 = mmap_base (virtual address)
MR3 = pid (process ID)
+ cap transfer: client's VSpace cap
Reply: label = SALTY_OK
```

**MM_MMAP (client → mmsrv):**
```
MR0 = addr_hint (0 = auto-pick)
MR1 = length (bytes)
MR2 = prot (PROT_READ | PROT_WRITE | PROT_EXEC)
MR3 = flags (MAP_PRIVATE | MAP_ANONYMOUS | MAP_LAZY)
Badge identifies client
Reply: label = SALTY_OK, MR0 = mapped_base
```

**MM_BRK (client → mmsrv):**
```
MR0 = new_break (absolute virtual address)
Badge identifies client
Reply: label = SALTY_OK, MR0 = new_break
```

**MM_MAP_WINDOW (procmgr → mmsrv):**
```
MR0 = target_badge (child process)
MR1 = target_vaddr (where to map in child)
MR2 = window_vaddr (where to map in caller)
MR3 = num_pages
MR4 = vspace_flags (for target mapping)
+ cap transfer: caller's VSpace cap
Reply: label = SALTY_OK, MR0 = pages_mapped
```

**VMFault (kernel → mmsrv):**
```
label = 2 (FaultType::VMFault)
MR0 = fault_addr
MR1 = error_code
MR2 = fault_rip
Badge identifies faulting client
Reply: label = SALTY_OK (resume) or error (kill process)
```

## 4. Internal Design

### Self-Bootstrap (Avoiding Recursive IPC)

mmsrv needs memory for its own data structures (client table, region tracking, SHM table), but it **cannot** call `posix_mmap()` because that would send IPC to itself (deadlock).

**Solution:** `self_mmap()` bypasses IPC and directly:
1. Allocates slot via `slot_alloc()`
2. Retypes frame from child untyped via `retype_any()`
3. Maps frame into own VSpace via `vspace_map(CAP_SELF_VSPACE, ...)`
4. Zero-fills the page
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
    frame_caps: *mut Cap,   // Array of frame capability slots
    frame_count: u16,       // Number of frames allocated
    frame_cap_capacity: u16,// Capacity of frame_caps array
}
```

**Per-client region list:**
- Growable array (starts at 8 entries, doubles on overflow)
- Each client has independent region tracking
- Regions track frame caps for cleanup on munmap/deregister

**Lazy regions (MAP_LAZY):**
- `frame_caps` entries are 0 (unallocated sentinel)
- VMFault handler allocates frames on first access
- Hybrid growth strategy for frame_caps array:
  - Small (<128): double capacity
  - Medium (128-1024): grow by 50%
  - Large (>1024): grow by 256 entries

### Untyped Pool

**Round-robin allocation:**
```rust
unsafe fn retype_any(obj_type: u64, size_bits: u64, dest_slot: Cap) -> i32
```

Scans untyped sources in round-robin order:
1. Start at `UT_HINT` (last successful source)
2. Try `untyped_retype()` on each source
3. If successful, update hint and return
4. If all sources exhausted, return `SALTY_OUT_OF_MEMORY`

**Sources:**
- Slot 7: child untyped (primary)
- Slots 16-23: mirrored parent untypeds (if present)
- Up to 12 total sources (`MAX_UT_SOURCES`)

### Receive Slot Pool

**Purpose:** Cap transfers (MM_REGISTER, MM_MAP_WINDOW, MM_UNMAP_WINDOW) need a destination CNode slot.

**Pool layout:**
- Base: 0x3C00 (15360)
- End: 0x4000 (16384)
- Size: 1024 slots

**Allocation strategy:**
- Bump pointer: `NEXT_RECV_SLOT` increments on each `alloc_recv_slot()`
- Current slot: `CURRENT_RECV_SLOT` is configured for next IPC
- Recycling: If handler doesn't keep cap (`RECV_SLOT_KEPT=false`), delete cap and reuse slot
- Permanent keep: If handler sets `RECV_SLOT_KEPT=true` (e.g., MM_REGISTER stores VSpace cap), advance to next slot

**Pool exhaustion:** Returns 0 (unrecoverable error — server restarts required)

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
7. Reply with `SALTY_OK`

**Badge assignment:** procmgr chooses badge = PID (ensures uniqueness)

**Heap/mmap layout:**
- `heap_base` — start of POSIX heap (typically 1 MB after scratch region)
- `heap_current` — initially equals `heap_base` (empty heap)
- `mmap_next` — start of mmap region (typically 16 MB after heap_base)

### Deregistration (MM_DEREGISTER)

**Called by:** procmgr after process exit or kill

**Steps:**
1. Find client by badge
2. Iterate all regions, unmap and delete frame caps
3. Delete VSpace cap held in `vspace_cap`
4. Mark client slot inactive
5. Decrement `CLIENT_COUNT`
6. Reply with `SALTY_OK`

**Cleanup scope:**
- All frame caps tracked in regions are deleted (returned to untyped)
- VSpace cap is removed from mmsrv's CSpace
- Kernel handles page table teardown when VSpace cap refcount hits 0

## 6. Frame Allocation

### Eager Allocation (MM_MMAP)

**When:** `MAP_LAZY` flag is NOT set

**Algorithm:**
1. Round length up to 4K page boundary
2. Allocate region struct via `client_add_region()`
3. Allocate frame_caps array via `alloc_frame_cap_array(num_pages)`
4. For each page:
   - Allocate CNode slot via `slot_alloc()`
   - Retype frame via `retype_any(OBJ_FRAME, 0, slot)`
   - Map frame via `vspace_map(client.vspace_cap, slot, vaddr, flags)`
   - Store slot in `frame_caps[i]`
5. Advance `client.mmap_next` by length
6. Reply with mapped base address

**Rollback on failure:** If any step fails, unmap/delete all previously allocated frames and mark region inactive.

### Lazy Allocation (MM_MMAP with MAP_LAZY)

**When:** `MAP_LAZY` flag is set

**Allocation phase:**
1. Allocate region struct, mark `lazy=true`
2. Set `frame_count=0`, all `frame_caps` entries = 0
3. Advance `client.mmap_next` (reserve virtual address range)
4. Reply with mapped base address

**Demand paging phase (on first access):**
- Process accesses lazy page → #PF → kernel sends VMFault IPC
- mmsrv receives `label=2`, `badge=client`
- Find region containing fault address
- Check `frame_caps[page_idx] == 0` → unallocated
- Allocate frame via `slot_alloc()` + `retype_any()`
- Map frame via `vspace_map()`
- Store slot in `frame_caps[page_idx]`, increment `frame_count`
- Reply `SALTY_OK` → kernel resumes faulting thread

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
- Starts at `heap_base`, grows to `heap_current` (rounded up to page boundary)
- Frame caps tracked in growable array (initial capacity: 64 frames)

**Growth algorithm:**
1. Compute old_page and new_page (4K-aligned)
2. Find or create heap region
3. If growing:
   - Grow frame_caps array if needed (doubling strategy)
   - For each new page: `slot_alloc()` + `retype_any()` + `vspace_map()`
   - Track frame caps in region
4. If shrinking:
   - Unmap freed pages via `vspace_unmap()`
   - Delete frame caps via `cnode_delete()`
   - Reduce `frame_count`
5. Update `heap_current`

### Unmapping (MM_MUNMAP)

**Algorithm:**
1. Find region containing base address
2. If region exists:
   - For each page: `vspace_unmap()` + `cnode_delete(frame_cap)`, zero frame_caps entry
   - If entire region unmapped, mark `active=false`
3. If no region (e.g., batch-mapped spawn pages):
   - Just unmap pages (no frame cap cleanup)

### Protection Change (MM_MPROTECT)

**Algorithm:**
1. Find region containing address
2. Convert PROT_* flags to VSPACE_FLAG_*
3. For each page in range:
   - `vspace_unmap(vaddr)`
   - `vspace_map(frame_cap, vaddr, new_flags)`
4. Update `region.prot`

**Note:** Requires frame cap tracking. Regions without frame_caps (e.g., device mappings) silently succeed (no-op).

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
2. For each page:
   - Allocate slot, retype frame
   - Map into target's VSpace
   - Increment mapped count
3. Return number of pages successfully mapped (partial success allowed)

**Partial success:** If retype fails midway, return the count of successfully mapped pages. Procmgr decides whether to retry or abort.

### Write Window (MM_MAP_WINDOW)

**Purpose:** procmgr needs to write to a child's VSpace (copy ELF segments, initialize stack).

**Dual-mapping strategy:**
1. Allocate frames via `retype_any()`
2. Map each frame into **target's VSpace** (read/write/user flags from MR4)
3. Map **same frame** into **caller's VSpace** (write window at window_vaddr, always writable)
4. Caller writes data via window
5. Caller sends MM_UNMAP_WINDOW to remove window mapping

**Cap ownership:** Frame caps stay in mmsrv's CSpace. Both mappings reference the same underlying frame. Window removal only unmaps from caller; target mapping persists.

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
Reply: SALTY_OK
```

**What's cloned:**
- `heap_base`, `heap_current`, `mmap_next` (memory layout pointers)
- Region list (deep copy of region structs)
- **NOT** frame caps — COW-managed by kernel

**Why not clone frame caps?**
- Kernel handles COW via `vspace_clone_cow_page()` during fork
- mmsrv doesn't track COW frames until they're written (lazy breakage)
- Child's frame_caps stay null — VMFault on write → mmsrv allocates new frame

## 8. Shared Memory (SHM)

### Creation (MM_SHM_CREATE)

**Caller:** VFS (on behalf of `shm_open()` client)

**Protocol:**
```
MR0 = shm_id (hash of shm name)
MR1 = num_pages
Reply: SALTY_OK
```

**Algorithm:**
1. Check for duplicate shm_id (error if exists)
2. Find free slot in SHM table (grow if needed)
3. Allocate frame_caps array
4. For each page: `slot_alloc()` + `retype_any(OBJ_FRAME)`
5. Store in ShmObject struct with `active=true`

**SHM lifetime:** Created by VFS, destroyed when all mappings removed (reference counting not yet implemented — SHM objects persist until server restart).

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
4. For each SHM frame: `vspace_map(client.vspace_cap, shm.frame_caps[i], vaddr+i*4K, flags)`
5. If auto-pick, advance `client.mmap_next`
6. Return mapped address

**Rollback on failure:** Unmap all previously mapped pages.

**Shared access:** Multiple clients can map the same SHM object. All see the same physical frames (shared memory semantics).

### Unmapping (MM_SHM_UNMAP)

**Caller:** VFS (on behalf of `munmap()` or `close(fd)`)

**Protocol:**
```
MR0 = shm_id
MR1 = client_badge
MR2 = vaddr
Reply: SALTY_OK
```

**Algorithm:**
1. Find SHM object by ID
2. Find client by badge
3. For each page: `vspace_unmap(client.vspace_cap, vaddr+i*4K)`

**Frame lifetime:** Frames remain in SHM object (not deleted). Other mappings persist.

## 9. Demand Paging (VMFault Handling)

### VMFault IPC Format

Sent by kernel when userland process accesses unmapped/COW page:

```
label = 2 (FaultType::VMFault)
MR0 = fault_addr (virtual address of fault)
MR1 = error_code (x86 PF error bits)
MR2 = fault_rip (instruction pointer at fault)
Badge = faulting client's badge
```

**Delivery:** Thread blocks, kernel sends IPC to thread's fault endpoint (which is mmsrv's server EP, badged with client badge).

**Resume:** Reply with `SALTY_OK` → kernel restores thread's register state and resumes execution.

### VMFault Handler Algorithm

1. **Identify client:** `find_client_by_badge(badge)`
   - Error if client not registered (orphaned fault)
2. **Find region:** `find_region_by_addr(client, page_addr)`
   - If no region: segfault (reply `SALTY_INVALID_ARGUMENT` → procmgr kills process)
3. **Check allocation status:** `region.frame_caps[page_idx]`
   - If `!= 0`: already allocated (COW/race), reply `SALTY_OK` (kernel retries, succeeds)
   - If `== 0`: unallocated (lazy or COW breakage)
4. **Allocate frame:**
   - `slot_alloc()` → get CNode slot
   - `retype_any(OBJ_FRAME, 0, slot)` → create frame
5. **Map frame:**
   - Convert `region.prot` to vspace flags
   - `vspace_map(client.vspace_cap, slot, page_addr, flags)`
   - If map fails: reply `SALTY_BAD_ADDRESS` (vspace_map error, not OOM)
6. **Track frame:** `region.frame_caps[page_idx] = slot`, increment `region.frame_count`
7. **Resume:** Reply `SALTY_OK` → thread resumes at faulting instruction

### Lazy Region Growth

If `page_idx >= region.frame_cap_capacity`:
- Grow `frame_caps` array via `grow_frame_cap_array()`
- Hybrid growth: small regions double, medium +50%, large +256
- Update `region.frame_cap_capacity`

### COW vs Lazy Distinction

- **Lazy (MAP_LAZY):** Region created with `frame_count=0`, all entries zeroed
- **COW (fork):** Kernel maps pages read-only, write triggers VMFault, mmsrv allocates new frame

Both use the same VMFault handler. The only difference is the initial state.

## 10. Bootstrap Path (rtld Exception)

### Why rtld Can't Use mmsrv

**Problem:** rtld runs **before** mmsrv in the boot order (rtld is embedded in init, which is phase 0; mmsrv is phase 2).

**Solution:** rtld uses direct untyped retype:
- Receives `AT_SALTY_UNTYPED` via auxv
- Directly calls `untyped_retype()` + `vspace_map()`
- No IPC to mmsrv

### procmgr Shared Library Cache

**Problem:** procmgr maintains a shared library cache (loads `libsalty.so`, `libc.so` once, maps into all children). This cache needs frames, but procmgr can't use mmsrv (circular dependency — mmsrv uses procmgr for process management).

**Solution:** procmgr also has its own child untyped capability:
- Allocates cache frames directly via `untyped_retype()`
- Maps cache frames into children via `vspace_map(child_vspace_cap, ...)`

### Transition Point

Once a process is spawned by procmgr:
- It receives `CAP_MMSRV_EP` (slot 7, badged endpoint)
- All `posix_mmap()` calls go through mmsrv IPC
- No direct untyped access (slot allocator uses mmsrv for frame allocation)

## 11. Error Code Semantics

### Frame Allocation Errors

| Error Code | Value | Condition |
|------------|-------|-----------|
| `SALTY_OUT_OF_MEMORY` | 5 | `slot_alloc()` fails, `retype_any()` exhausts all untypeds, frame_caps array allocation fails |
| `SALTY_BAD_ADDRESS` | 10 | `vspace_map()` fails (address conflict, invalid VSpace, PT allocation failure) |
| `SALTY_INVALID_ARGUMENT` | 4 | Bad parameters (length=0, addr misaligned, segfault on unknown region) |
| `SALTY_NOT_FOUND` | 6 | Client badge not registered, SHM ID not found |
| `SALTY_ALREADY_EXISTS` | 8 | Duplicate client badge, duplicate SHM ID |

**Key distinction:** `SALTY_OUT_OF_MEMORY` means "ran out of capability resources" (slots or frames). `SALTY_BAD_ADDRESS` means "vspace_map rejected the request" (address conflict, page table issues, bad VSpace cap).

### VMFault Error Handling

- **SALTY_OK:** Frame allocated and mapped → resume thread
- **SALTY_BAD_ADDRESS:** vspace_map failed (rare, indicates kernel state corruption) → procmgr should kill process
- **SALTY_INVALID_ARGUMENT:** No region covers fault address (segfault) → procmgr delivers SIGSEGV
- **SALTY_OUT_OF_MEMORY:** Frame allocation failed → procmgr should kill process (or swap to disk, if supported)

## 12. Performance Considerations

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

### Frame Cap Tracking Overhead

Each region tracks frame caps (8 bytes per page). For a 1 GB region:
- 256K pages × 8 bytes = 2 MB metadata overhead
- Acceptable (0.2% overhead)

Lazy regions with sparse access have minimal overhead (only allocated pages tracked).

### Untyped Round-Robin Fairness

Round-robin scan ensures all untypeds are used evenly, avoiding premature exhaustion of one source. Hint caching (`UT_HINT`) amortizes scan cost to O(1) in steady state.

## 13. Limitations and Future Work

**Current limitations:**
- **No page eviction:** Once allocated, frames stay until process exit (no swap, no reclaim)
- **No SHM reference counting:** SHM objects persist until server restart
- **No quota enforcement:** Clients can allocate unlimited frames (bounded only by available untyped memory)
- **No NUMA awareness:** All frames come from single untyped pool (no node affinity)
- **No huge pages:** Only 4K pages supported

**Future enhancements:**
- **LRU eviction:** Track page access bits, evict cold pages to swap
- **SHM lifecycle:** Delete SHM object when all mappings removed
- **Per-client quotas:** Enforce `RLIMIT_AS` via region tracking
- **Batch operations:** Optimize multi-page allocation with single IPC (reduce round-trips)
- **Async VMFault batching:** Handle multiple faults in one IPC (for sequential access patterns)

## 14. Debugging and Introspection

### Serial Logging

mmsrv logs key events to serial console:
```
[MMSRV] registered client badge=0x1234 pid=42 heap=0x20000000 mmap=0x21000000
[MMSRV] MMAP: client=0x1234 addr=0x21000000 len=8192 prot=RW eager
[MMSRV] VMFault: badge=0x1234 addr=0x21001234 → allocated page at 0x21001000
[MMSRV] deregistered client badge=0x1234 pid=42
```

### State Inspection (future)

Planned: Debug IPC label to query server state:
- Client count, region count, SHM count
- Per-client memory usage (sum of region frame counts)
- Untyped pool watermarks (how much memory allocated from each source)

### Crash Recovery

**Current:** Server panic = system halt (no recovery)

**Future:** Procmgr could respawn mmsrv on crash, but state loss is catastrophic (all client VSpace mappings lost). Better strategy: kernel-level checkpointing of mmsrv state.

## 15. Cross-References

- **[POSIX Compatibility](posix.md)** — How `posix_mmap()`/`brk()`/`sbrk()` delegate to mmsrv
- **[libsalty Design](libsalty.md)** — Slot allocator's use of mmsrv for frame allocation
- **[Process Manager](procmgr.md)** — Spawn/fork integration with MM_MAP_BATCH/MM_MAP_WINDOW/MM_FORK_REGIONS
- **[VFS Design](vfs.md)** — SHM object lifecycle and mmap integration
- **[Kernel Memory Management](memory.md)** — Untyped retype, VSpace mapping, COW implementation
- **[IPC Design](ipc.md)** — Endpoint badging, cap transfer, fault delivery
