================================================================
ADR-0005: KernelRng byte reads for /dev/urandom
================================================================

:Status: Implemented
:Areas: kernite system caps; libtrona syscall wrappers; basalt libc
  randomness APIs; VFS devfs; netsrv
:Authors: Hamin Sung
:Reviewers: GPT 5.5
:Date: 2026-06-28
:Supersedes: none
:Depends: ``docs/spec/syscalls.md`` (``KernelRng`` ``RNG_READ`` byte-buffer
  ABI)
:Description: Treat the existing ``KernelRng`` ``RNG_READ`` invoke as a
  byte-buffer operation, remove the stale 64-bit sample wrapper, route
  ``/dev/urandom`` through that byte ABI, and update libc and networking
  call sites to request the exact byte widths they need.

Context
=======

The boot test runner exposed a concrete VFS regression::

    [TEST_FS] Test 13: /dev/urandom
    [TEST_FS] FAIL: two urandom reads identical

The failure was not in the kernel RNG implementation. The current syscall
surface had already moved to a ``KernelRng`` capability invocation where
``RNG_READ`` accepts ``(user_buf, user_len)`` and copies random bytes into the
caller's address space. ``docs/spec/syscalls.md`` documented that byte-buffer
shape.

The userspace wrapper and some callers were stale:

- ``lib/trona/kernel/src/syscall.rs`` exposed
  ``rng_read(rng_cap) -> Option<u64>`` and invoked ``RNG_READ`` with zero
  buffer arguments.
- ``lib/basalt/c/src/getrandom.rs``, ``lib/basalt/c/src/stdlib.rs``, and
  netsrv call sites consumed that old 64-bit sample API.
- current VFS devfs implemented ``/dev/urandom`` as a deterministic byte
  pattern, so two equal-length reads returned identical buffers.

``vfs_old`` had a ChaCha20-based ``/dev/urandom`` implementation inside VFS.
That code proved the historical intent, but copying it into current VFS would
put RNG state and reseed policy in a filesystem server. That is the wrong
long-term layering for a capability microkernel and would create another
randomness implementation to reconcile later.

Decision
========

Use the kernel/documented ABI as the source of truth:

- ``KernelRng`` ``RNG_READ`` is a byte-buffer invocation:
  ``arg0 = user_buf``, ``arg1 = user_len``, return value = bytes copied.
- libtrona exposes one wrapper, ``rng_read_bytes(rng_cap, dst, len)``. The
  stale ``rng_read(rng_cap) -> Option<u64>`` wrapper is removed instead of
  kept as a compatibility shim.
- Every caller requests the byte width it actually needs:

  - ``getrandom`` and ``getentropy`` pass the caller buffer directly;
  - libc ``arc4random`` seeding asks for 32 key bytes;
  - DNS transaction IDs ask for 2 bytes;
  - DHCP transaction IDs and TCP ISNs ask for 4 bytes;
  - ``/dev/urandom`` asks for the read length and returns the kernel byte
    count.

This is a short-term repair, not the long-term randomness architecture. The
long-term service split is tracked by the draft
``docs/rfcs/draft/randomness_service.rst``.

Consequences
============

Positive
--------

- ``/dev/urandom`` no longer returns a deterministic repeating pattern.
- There is one public wrapper shape for the ``RNG_READ`` label, matching the
  kernel dispatcher and syscall spec.
- Existing 16-bit, 32-bit, and buffer consumers no longer depend on a
  misleading "64-bit sample" abstraction.
- VFS does not grow a local ChaCha20 DRBG or reseed policy.

Negative
--------

- Small scalar consumers now carry a few lines of stack-buffer boilerplate.
  This is intentional: the ABI is byte-oriented, and a sample helper would
  preserve the old mental model.
- ``/dev/urandom`` still depends directly on every process receiving
  ``KernelRng``. A dedicated userland randomness service should narrow that
  authority later.

Rejected alternatives
=====================

- **Kang the vfs_old ChaCha20 implementation into current VFS.** This would
  pass the immediate test, but it makes VFS own randomness policy and creates
  duplicated DRBG state outside the kernel/service boundary.
- **Keep ``rng_read_u64`` as a convenience API.** That preserves the stale
  sample-oriented interface after the ABI moved to buffers. Callers should be
  visibly migrated to the byte API.
- **Implement ``/dev/urandom`` in libc only.** It would not fix reads through
  the filesystem path and would leave VFS's device semantics inconsistent with
  POSIX-facing tests.

Implementation
==============

- ``lib/trona/kernel/src/syscall.rs`` removes ``rng_read`` and adds
  ``rng_read_bytes``.
- ``lib/basalt/c/src/getrandom.rs`` uses ``rng_read_bytes`` for
  ``getrandom`` and ``getentropy``.
- ``lib/basalt/c/src/stdlib.rs`` seeds the local ChaCha20 ``arc4random``
  state with a single 32-byte ``KernelRng`` read, falling back to the existing
  clock mixing only when the kernel read fails.
- ``userland/core/vfs/src/fs/devfs/vops.rs`` routes ``DevKind::Urandom``
  reads through ``KernelRng``.
- ``userland/servers/netsrv/src/net/{dns,dhcp,socket/tcp}.rs`` request
  fixed-size byte buffers for protocol IDs and sequence numbers.
- ``docs/spec/trona-api.md`` and ``docs/spec/basaltc-api.md`` are updated to
  describe the byte-buffer API.

Testing
=======

The expected behavioral check is the runtime ``test_fs`` case:
``/dev/urandom`` must return a non-zero buffer, and two consecutive reads of
the same length must differ. Build and boot verification are recorded in the
change summary for the implementation commit.
