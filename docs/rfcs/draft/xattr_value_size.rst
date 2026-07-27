==================================================================
Decouple xattr Value Size from the Path-Component Limit
==================================================================

:Status: Draft
:Areas: VFS; SaltyFS
:Authors: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5
:Date: 2026-06-22
:Depends: (none)
:Description: An extended-attribute *value* is bounded by the path-component name limit (144 bytes) — an unrelated constant far below realistic xattr sizes. Bound the value by a value-appropriate limit and carry it through the bulk-payload path, leaving the name limit alone.

Problem Statement
=================

The xattr path bounds a *value* by the maximum length of a single path component
(``WALK_NAME_MAX``, 144 bytes): a set rejects a longer value and copies it into a
name-sized inline buffer. An xattr value has nothing to do with a path component,
and 144 bytes is far below realistic xattr sizes — ordinary user xattrs exceed it.
The limit is an accidental reuse of the name constant, not a storage constraint:
the SaltyFS backend already stores large values on disk (a small inline form, and
an indirect form that spills a large value through a hidden inode's extents).

Summary
=======

Decouple the xattr value size from the path-component limit. Bound a value by a
dedicated, value-appropriate ceiling and carry it through the shared-memory
payload path the way other bulk metadata travels, removing the name-sized inline
value buffer. The set and get paths agree on the limit. No SaltyFS on-disk format
change is needed.

Stakeholders
============

:Author: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5

Requirements
============

- An xattr value MUST NOT be bounded by the path-component limit; its ceiling MUST
  be a dedicated value-size limit.
- The value MUST travel through the bulk shared-memory payload path, not a
  name-sized inline buffer.
- The set and get paths MUST agree on the limit.
- No SaltyFS on-disk format change.

Design
======

The value travels through the mount's shared-memory payload region, as bulk
metadata already does, bounded by a dedicated ``XATTR_VALUE_MAX`` rather than the
path-component constant; the name-sized inline value buffer and the
name-limit rejection are removed, and the read path returns the value the same
way. The SaltyFS backend's existing inline / indirect storage handles the size on
disk, so the change is confined to how the value is transferred, not how it is
stored.

Implementation
==============

Not yet implemented; this RFC is ``Draft``. The change is confined to the xattr
transfer path and the new ``XATTR_VALUE_MAX`` constant; the SaltyFS backend
storage and on-disk format are untouched.

Performance
===========

Negligible: the value already moves through shared memory on the set path; only
the artificial 144-byte ceiling and the redundant inline copy are removed.

Ergonomics
==========

A ``setxattr`` of a realistic value succeeds instead of failing at 144 bytes; no
caller change.

Backwards Compatibility
=======================

An xattr-transfer adjustment between the VFS and the backend. No on-disk format
change and no feature flag — existing images already store large values through
the indirect form. The public ``setxattr`` / ``getxattr`` surface is unchanged
except that values up to ``XATTR_VALUE_MAX`` now succeed.

Security Considerations
=======================

``XATTR_VALUE_MAX`` is a bounded ceiling and the shared-memory region is
size-checked, so the change admits no unbounded allocation. It removes a foot-gun
where a value silently failed to store at 144 bytes.

Testing
=======

``just warn`` clean on x86_64 and aarch64. Round-trip a value larger than 144
bytes (set then get returns the same bytes); a value near the ceiling; a value
over it rejected cleanly; the SaltyFS indirect-storage path exercised for a large
value.

Drawbacks, Alternatives, and Unknowns
=====================================

- **Leave the 144-byte cap.** Rejected: it silently breaks realistic xattrs and
  contradicts the bulk payload path the set path already sets up.
- **Unknown: the exact ``XATTR_VALUE_MAX``.** A page covers typical xattrs; a
  larger ceiling leans harder on the indirect storage path and is deferred until a
  concrete need appears.

Prior Art and References
========================

- **Linux** — an xattr value size is bounded per-filesystem (ext4 caps a single
  xattr at one block), not by the path-component limit; the value travels
  independently of the name.
