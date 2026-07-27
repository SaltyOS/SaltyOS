===============================================================
Randomness Service and Device Randomness Routing
===============================================================

:Status: Draft
:Areas: KernelRng; system services; VFS; devfs; POSIX; security
:Authors: Hamin Sung
:Reviewers: GPT-5
:Date: 2026-06-28
:Depends: none
:Description: Define the long-term randomness architecture for SaltyOS:
  keep the kernel's ``KernelRng`` as a small capability-bounded entropy
  primitive, move DRBG/reseed/device policy into a dedicated userland
  ``rngsrv``, and make VFS route ``/dev/random`` and ``/dev/urandom`` to that
  service instead of owning CSPRNG state itself.

Status and Scope
================

This is a long-term design draft. It does not describe the immediate
``/dev/urandom`` test fix; that short-term decision is recorded in
``docs/adrs/0005_kernel_rng_byte_read_urandom.rst``.

This RFC covers:

- the ownership boundary between kernite, ``rngsrv``, VFS/devfs, libc, and
  ordinary applications;
- the device routing model for ``/dev/random`` and ``/dev/urandom``;
- the capability distribution model for raw kernel entropy;
- bootstrapping and migration from the current direct ``KernelRng`` users.

It does not specify the exact DRBG construction, entropy accounting algorithm,
or wire message numbers. Those should be chosen when the service is made
landable.

Problem Statement
=================

SaltyOS currently has two valid but incomplete pieces:

- kernite exposes ``KernelRng`` as a capability invocation that copies hardware
  RNG bytes into a caller buffer;
- POSIX-facing consumers need stable randomness APIs: ``getrandom``,
  ``getentropy``, ``arc4random``, ``/dev/urandom``, protocol IDs, ASLR seeds,
  and eventually security-sensitive service keys.

The tempting quick implementation is to put a ChaCha20 CSPRNG in VFS because
``/dev/urandom`` is a filesystem path. That is not the right ownership
boundary. VFS should name and route device nodes; it should not own global
randomness policy, entropy source selection, reseeding cadence, health checks,
or fork/boot transition semantics. If VFS owns those details, libc and services
will either duplicate CSPRNG state or depend on a filesystem server for
security policy that is not filesystem-specific.

The kernel should also not grow a broad randomness subsystem by default.
SaltyOS is a capability microkernel: the kernel should keep the minimal
primitive that requires privileged hardware access and address-space copying,
while userland owns policy that can be restarted, audited, tested, and evolved.

Design
======

Authority split
---------------

``KernelRng`` remains a small kernel object:

- capability type: ``KernelRng``;
- required right: ``READ``;
- operation: byte-buffer ``RNG_READ(user_buf, user_len)``;
- source: hardware RNG / seed instruction support available to kernite.

``KernelRng`` is not the ordinary application API in the final design. It is a
raw entropy capability distributed only to:

- early boot components that must run before ``rngsrv`` is ready;
- ``rngsrv`` itself;
- tightly scoped kernel-adjacent services that have an explicit reason to
  consume raw entropy.

``rngsrv`` becomes the policy owner:

- holds ``KernelRng`` and any future entropy-source capabilities;
- seeds and reseeds a DRBG;
- exposes request/response APIs for random bytes;
- owns readiness state and failure behavior;
- publishes a service endpoint through namesrv;
- serves ``/dev/random`` and ``/dev/urandom`` backend requests on behalf of
  VFS/devfs.

VFS/devfs becomes a router:

- ``/dev/urandom`` and ``/dev/random`` are device nodes in the namespace;
- open/read/write/ioctl semantics are projected by VFS;
- actual random-byte reads are forwarded to ``rngsrv``;
- VFS holds no DRBG key, counter, reseed timer, or entropy estimator.

libc remains a consumer:

- ``getrandom`` and ``getentropy`` call the service once it is available;
- ``arc4random`` may keep a per-process userspace DRBG seeded by ``rngsrv`` for
  amortized small reads;
- during the bootstrap window, libc may temporarily use direct ``KernelRng`` if
  the process was explicitly granted that cap.

Boot phases
-----------

The migration should be staged:

1. **Current repair.** ``/dev/urandom`` and libc use ``KernelRng`` directly
   through the byte API. This removes deterministic output without adding VFS
   policy.
2. **Introduce ``rngsrv``.** Init spawns ``rngsrv`` after namesrv and before
   services that require stable randomness. ``rngsrv`` receives ``KernelRng``
   and registers readiness with namesrv.
3. **Route device reads.** VFS opens ``/dev/random`` and ``/dev/urandom`` as
   device nodes backed by ``rngsrv``. The old direct devfs read path becomes an
   early-boot fallback only, then is removed when boot ordering is strict.
4. **Narrow raw cap distribution.** Ordinary spawned processes stop receiving
   ``KernelRng`` by default. They receive libc/runtime access to ``rngsrv``
   instead. Direct ``KernelRng`` is opt-in for privileged components.
5. **Add richer sources.** ``rngsrv`` can add device, timer, interrupt, disk,
   network, or virtio-rng sources without changing VFS or libc API shape.

Device semantics
----------------

``/dev/urandom``:

- non-blocking after the service reaches its "ready" state;
- returns as many bytes as requested or an error on service failure;
- does not expose entropy-accounting details to callers.

``/dev/random``:

- should exist as a distinct node for compatibility;
- exact blocking semantics are an open question. Linux-style historical
  blocking is not obviously useful once the DRBG is initialized, but some
  software expects the path to exist.

``write`` to either node:

- may be accepted later as entropy injection if the caller has an explicit
  capability/right;
- should not silently affect the pool for unprivileged callers.

Failure model
-------------

If ``KernelRng`` hardware access is unavailable, the kernel returns an error.
``rngsrv`` decides whether it can continue from persisted seeds, virtio-rng, or
other entropy sources. The kernel should not silently downgrade to predictable
bytes. VFS and libc should report the service error instead of synthesizing
randomness locally.

Security Considerations
=======================

- **Single policy point.** A dedicated service keeps reseed cadence, DRBG state,
  readiness, and health checks in one auditable place.
- **Least authority.** Ordinary applications do not need raw ``KernelRng``.
  Removing it from the default spawn cap set narrows blast radius.
- **Fork safety.** Per-process ``arc4random`` state must reseed or derive
  child state after ``fork``. ``rngsrv`` can provide fresh seeds; libc remains
  responsible for local post-fork state transitions.
- **No VFS secrets.** VFS should not retain CSPRNG keys. Compromising a
  filesystem server should not expose global randomness state.
- **Boot readiness.** Early services must either block until ``rngsrv`` is
  ready or explicitly accept direct ``KernelRng`` bootstrap authority.

Rejected Alternatives
=====================

- **VFS-local ChaCha20 DRBG.** Simple and already present in ``vfs_old``, but
  it puts security policy in a filesystem server and makes future entropy
  sources harder to centralize.
- **Kernel-owned full CSPRNG service.** Keeps device reads simple, but pushes
  policy, algorithms, accounting, and reseeding into the microkernel. SaltyOS
  should keep kernel authority small unless a policy must be in kernel space.
- **libc-only randomness.** It cannot implement ``/dev/random`` or
  ``/dev/urandom`` device semantics, and each process would need its own
  bootstrap/reseed policy.
- **Keep raw ``KernelRng`` in every process forever.** Convenient, but it makes
  the raw entropy primitive ambient within the SaltyOS process model and
  weakens capability discipline.

Prior Art and References
========================

- **Fuchsia/Zircon.** Zircon exposes a kernel CPRNG syscall,
  ``zx_cprng_draw``, and documents it as kernel CPRNG output suitable for
  cryptographic use. Heavy consumers are expected to use it to seed their own
  userspace PRNG rather than repeatedly drawing unbounded amounts through the
  syscall. Reference:
  https://fuchsia.dev/reference/syscalls/cprng_draw
- **MINIX 3.** Randomness is a separate system driver/service, not VFS core.
  The driver lives under ``minix/drivers/system/random`` and is configured as
  ``service random``. References:
  https://github.com/Stichting-MINIX-Research-Foundation/minix/blob/4db99f4012570a577414fe2a43697b2f239b699e/minix/drivers/system/random/main.c
  and
  https://github.com/Stichting-MINIX-Research-Foundation/minix/blob/4db99f4012570a577414fe2a43697b2f239b699e/minix/drivers/system/random/random.c
- **Redox.** Redox has a dedicated ``randd`` daemon that registers a ``rand``
  scheme and serves random device paths from a ChaCha20-based generator.
  References:
  https://github.com/redox-os/randd/blob/master/README.md
  and
  https://github.com/redox-os/randd/blob/master/src/main.rs

Open Questions
==============

- Should ``/dev/random`` block after initial readiness, or should it be an alias
  with stricter error reporting?
- Should ``rngsrv`` expose a memory-mapped or shared-ring fast path for large
  consumers, or is message-pipe IPC enough?
- Which persisted seed mechanism should be used before the filesystem trust
  and integrity model is finalized?
- Which components retain direct ``KernelRng`` after raw cap distribution is
  narrowed?

Testing
=======

The eventual service implementation should add tests for:

- two consecutive ``/dev/urandom`` reads are not identical;
- ``getrandom`` and ``getentropy`` fill exact byte counts;
- ``arc4random`` reseeds after ``fork``;
- VFS read paths fail cleanly when ``rngsrv`` is unavailable;
- ordinary processes cannot invoke raw ``KernelRng`` after the cap-distribution
  migration;
- privileged bootstrap components that retain ``KernelRng`` still work before
  namesrv publishes ``rngsrv``.
