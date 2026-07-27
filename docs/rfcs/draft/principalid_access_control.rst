==================================================================
PrincipalId Access Control for Co-Equal POSIX and Win32
==================================================================

:Status: Draft
:Areas: VFS; Authorization; SaltyFS; Personalities
:Authors: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5
:Date: 2026-06-22
:Depends: (none)
:Description: One native file-authorization model — ``AccessControl``, an ``Acl`` of ``Ace`` over a neutral ``PrincipalId`` namespace — into which both POSIX (uid/gid/mode) and Win32 (SIDs/DACL) map symmetrically, so neither personality is the canonical and neither is a guest. The ACL semantics copy NFSv4/NT; only the principal namespace and the on-disk form are SaltyOS-owned. POSIX mode and NT security descriptors become boundary projections of the one canonical ``AccessControl``.

Problem Statement
=================

The VFS has one native authorization identity — POSIX uid/gid/mode — and treats
Win32 as a guest layered on top: a Win32 access derives a single SID from the
caller's uid and evaluates a security-descriptor xattr that has no relationship to
the file's POSIX metadata. The goal is the opposite: POSIX (which also carries
the Linux compatibility surface) and Win32 are **co-equal first-class**
authorization identities, and a single file opened by a POSIX process and a Win32
process answers both coherently with neither personality a guest.

The crux is that a single shared object cannot have two authoritative
representations: when a POSIX ``chmod`` and an NT ``SetSecurity`` express
conflicting policies, "may principal P access?" has two answers, and resolving the
conflict requires a deterministic tiebreaker — which is a single canonical
representation. Picking either personality's model as that canonical subordinates
the other per object. The resolution is a **neutral third canonical**: a SaltyOS
``AccessControl`` over a neutral ``PrincipalId`` namespace, with ACL semantics
rich enough (NFSv4/NT class) to losslessly encode POSIX mode. Then enforcement is
native for both personalities, neither namespace nor the on-disk form privileges a
personality, and the only residual asymmetry — that a POSIX ``stat`` shows a lossy
view of a rich ACL — is POSIX's inherent expressiveness limit, not a subordination
the design imposes.

"First-class" is therefore defined as native enforcement for your principals, a
non-subordinate namespace, and native storage of your own model — not a lossless
view of the other model's richer constructs, which is impossible across models of
unequal expressiveness.

Authorization is bypassed entirely today (every caller is root, and the
permission helpers are unused), so this model is a foundation: it becomes live
only once real per-process credentials reach the VFS.

Summary
=======

One canonical model and two boundary projections.

Every securable object has one ``AccessControl`` — an owner and group
``PrincipalId`` and an ``Acl`` of ordered ``Ace`` (each an allow/deny of a rights
mask to a ``PrincipalId`` or well-known, with inheritance flags). ``PrincipalId``
is a neutral namespace; POSIX uid/gid and NT SIDs are *aliases* of a
``PrincipalId``, resolved by a principal-ID-primary account authority.

The caller is a ``Principal`` token, personality-tagged (POSIX uid/gid/groups, or
NT SID set / privileges), whose identities resolve to ``PrincipalId``\s and are
evaluated against the object's one ``Acl`` — one canonical, one evaluation, no
per-object-model dispatch.

POSIX mode and NT security descriptors are *projections* of the canonical
``AccessControl``, never the stored truth: ``stat`` derives mode from the ``Acl``,
``chmod`` edits it under a reconcile policy, and the Win32 query/set maps the NT
security descriptor in and out. A *trivial* ``Acl`` — one that exactly encodes a
mode — is not stored at all; the inode keeps the owner/group ``PrincipalId`` and
mode bits and the trivial ``Acl`` is synthesized, so ordinary files cost nothing
extra on disk.

The NFSv4/NT ACL-evaluation algorithm is reused as the evaluation kernel; only the
principal namespace and the on-disk form are SaltyOS-owned.

Stakeholders
============

:Author: Hamin Sung
:Reviewers: Claude Opus 4.8, GPT 5.5
:Consumers: VFS core, the in-memory backends, SaltyFS, the POSIX and Win32
   personalities, and the credential-handoff path in ``init`` / ``exec``.

Requirements
============

- POSIX and Win32 MUST be co-equal: the canonical model privileges neither
  personality's namespace nor on-disk form, and each enforces natively against its
  own identities.
- A single shared object MUST yield one coherent decision for both personalities;
  their identities MUST refer to the same ``PrincipalId``\s via the account
  authority.
- The ACL evaluation semantics MUST copy NFSv4/NT; novel authorization semantics
  MUST NOT be invented.
- A Win32 security descriptor MUST round-trip losslessly within an advertised
  subset; POSIX ``chmod`` / ``stat`` / ``access`` MUST be predictable under a
  stated reconcile policy.
- The canonical on-disk form MUST be SaltyOS-native and defined now, while
  clean-slate, so no migration is needed when enforcement goes live.
- Evaluation MUST fail closed on a malformed descriptor.
- This layer is *authorization*, named to avoid "security", which denotes the
  kernel capability model.

Design
======

The neutral identity
--------------------

``PrincipalId`` is a SaltyOS-owned principal handle. The account authority is
principal-ID-primary: a principal has a ``PrincipalId`` and may carry a POSIX
alias (uid/gid) and/or an NT alias (SID), but neither alias is required and
neither namespace is canonical. NFSv4/NT well-knowns (``owner@`` / ``group@`` /
``everyone@``, and SYSTEM / Administrators / Everyone) are first-class entries,
not derived from a uid. This RFC specifies the authority's interface and a
deterministic bootstrap; a populated account database is future work.

The subject
-----------

The caller is a ``Principal`` token, personality-tagged because the carried extras
differ — POSIX carries uid/euid/gid/groups, NT carries a primary SID, group SIDs,
and privileges. At an access check the token resolves to the ``PrincipalId``\s it
represents plus its effective privileges, and that set is evaluated against the
object's one ``Acl``.

The object
----------

An object's authorization is one ``AccessControl`` — owner and group
``PrincipalId`` and an ``Acl`` of ordered ``Ace``. There is no second
representation: POSIX mode and NT descriptors are computed projections. In-memory
backends hold it per vnode; SaltyFS holds it on disk (below); the synthetic
pseudo-filesystems carry a generated value and are not made writable
authorization objects here.

Evaluation
----------

One path: resolve the ``Principal`` to its ``PrincipalId``\s and privileges, then
evaluate the ``Acl`` with the reused NFSv4/NT walk — ordered ACEs, explicit deny
short-circuits, allow bits accumulate, granted iff every requested right is
covered, with owner rights and bypass privileges applied per the model below. A
trivial ``Acl`` evaluates identically to the POSIX rwx check by construction. The
core walk holds no policy and only gates whether to ask per personality — POSIX
checks each directory component's search bit, Win32 follows default
bypass-traverse.

The authorization model (normative)
-----------------------------------

Because the namespace and on-disk form are SaltyOS-owned, the semantics around the
copied ACL walk are SaltyOS's to define, and MUST be specified — a model that
leaves them implicit is both an incomplete Windows target and a POSIX-surprising
bespoke model. Normative: the special principals and their fixed correspondence
between ``owner@`` / ``group@`` / ``everyone@`` and the Windows well-knowns; the
rights mask (a superset of POSIX rwx that maps to and from NT's granular rights,
with the rwx triple a defined coarse projection); the recognized privileges and
their bypass effects (bypass-traverse, take-ownership, backup/restore, and the
root DAC-override equivalent, stated as privileges rather than a bare uid-0 test);
owner and group handling and chown authorization; inheritance and the default ACL
on create; and whether a mandatory integrity label participates (which may be
deferred, but the position MUST be explicit).

The boundary projections
------------------------

POSIX ``stat`` derives the mode triple from the ``Acl``; ``access`` evaluates it
directly; ``chmod`` edits it under a reconcile policy modeled on the ZFS
``aclmode`` choices — pass-through, discard, group-mask, or restricted — with
**restricted** the default, so a naive ``chmod`` cannot silently drop ACL
information. setuid/setgid/sticky, which the ACL does not express, are stored as
side flags. The Win32 set maps an inbound security descriptor into the
``AccessControl`` through the account authority, and the query projects the
``Acl`` back; within an advertised subset the round-trip is lossless, and a
descriptor outside the subset is rejected rather than silently dropped.
Authorization checks on the credential-less attribute paths are enforced at the
ops layer, before the backend, from the request ``Principal`` and the object's
current ``AccessControl``; evaluation fails closed on a malformed descriptor.

On-disk representation
----------------------

SaltyFS stores a non-trivial ``AccessControl`` as a native typed item keyed by
inode, gated by a feature flag — a SaltyOS-native form, not a generic xattr and
not an NT descriptor blob. The trivial-ACL optimization keeps the common case
free: an ordinary POSIX file stores only its owner/group ``PrincipalId`` and mode
bits, with no item, and the trivial ``Acl`` is synthesized; only a non-trivial ACL
materializes the item. Storing owner/group as a ``PrincipalId`` even in this
compact form is what keeps an ordinary file on the neutral canonical rather than
making POSIX its native truth. A non-trivial authorization change touches the
inode and the item together and so must be written transactionally, since a crash
must not leave them inconsistent.

Credential handoff
------------------

For any of this to be observable, real per-process ``Principal``\s must reach the
VFS: ``init`` / ``exec`` stamp a process's ``Principal`` from its identity, and
``spawn`` / ``fork`` define inheritance, so a client holds a real ``Principal``
instead of root. Until this is wired the model is inert; with it, it becomes
testable.

Implementation
==============

In flight; this RFC is ``Draft``. A workable order lands the subject type and a
neutral DAC primitive first (the seam other in-flight work can adopt), then the
canonical ``AccessControl`` and the evaluation kernel with the normative model,
the account authority, the SaltyFS native item with transaction semantics, and
finally the credential handoff that turns enforcement live. Every non-root path is
inert until that last step.

Performance
===========

Ordinary POSIX files pay nothing extra on disk. Evaluating a trivial ``Acl`` is
the rwx test by construction; a rich ACL pays the ordered DACL walk. Reconcile
runs only on mutation.

Ergonomics
==========

Personalities build a ``Principal`` once per request. The account authority hides
id mapping behind one principal-ID-primary interface, and one canonical
``AccessControl`` means a backend never reaches across to a separate descriptor to
answer a query.

Backwards Compatibility
=======================

Clean-slate: no on-disk migration; a feature flag gates the native item. The
credential-bearing VOP signatures change from the POSIX-shaped credential to the
``Principal`` token. The public POSIX and Win32 syscall surfaces are unchanged in
shape.

Security Considerations
=======================

This is the VFS authorization layer, distinct from the kernel capability layer
that is the real object-access boundary. It changes no live posture until the
credential handoff lands; it is the foundation for one coherent, non-subordinate
decision per shared object. The principal risk is a "neutral ACL" that becomes
both an incomplete Windows target and a POSIX-surprising bespoke model, mitigated
only by the normative model above being fully specified. The accepted residual
asymmetry is POSIX's lossy view of a rich ACL, inherent to its expressiveness.

Testing
=======

``just warn`` clean on x86_64 and aarch64; non-root behaviour is inert and
reviewed structurally until the credential handoff lands. With it: a POSIX and a
Win32 process opening one file under their native identities and getting coherent
decisions; a Win32 set-then-query lossless round-trip within the advertised
subset; ``chmod`` reconcile per policy; and the POSIX per-component search-bit
traversal gate.

Documentation
=============

The VFS design docs gain the ``Principal`` / ``PrincipalId`` / ``Acl`` /
``AccessControl`` vocabulary, the account authority, the single-canonical
evaluation, and the boundary projections, and correct the note that the VFS is
"personality neutral": the mechanism is neutral; authorization is one canonical
model both personalities map into.

Drawbacks, Alternatives, and Unknowns
=====================================

- **An NT security descriptor as the canonical.** Rejected: makes Win32 the
  privileged namespace and on-disk truth; POSIX is imported into the SID world.
- **POSIX mode as the canonical.** Rejected: POSIX cannot encode a rich ACL, so
  NT loses real expressiveness.
- **Two authoritative representations.** Rejected: incoherent on a shared object;
  any tiebreaker is a canonical by another name.
- **A per-object authoritative side.** Rejected: the other personality is still a
  guest on that object — per-object subordination.
- **Known limitation:** a POSIX ``stat`` of a rich ACL is lossy, accepted by the
  "first-class" definition, which excludes lossless cross-model views.
- **Unknowns:** the exact rights mask and privilege set; whether a mandatory
  integrity label participates; the reconcile-policy default per mount; the
  on-disk item layout.

Prior Art and References
========================

- **ZFS / OpenZFS** — a single NFSv4 ACL is canonical and POSIX mode is synced via
  ``aclmode`` (``restricted`` rejects a ``chmod`` that would drop ACL
  information); the reconcile vocabulary is taken from it. This is
  superset-canonical, not co-equal.
- **NFSv4 (RFC 8881)** — standardizes rich-ACL / mode interaction and requires that
  a mapping to an internal model not enforce weaker than the ACL; the
  lossless-within-subset rule mirrors this.
- **Samba ``vfs_acl_xattr``** — stores the NT ACL in an xattr for Windows fidelity
  but depends on a consistent uid/gid↔SID mapping and carries two security stores;
  the warning that motivates a single canonical.
- **AFS / DCE DFS** — keep their own ACL identity/rights model canonical and let
  Unix adapt — the nearest neutral-third-canonical prior art, though not a
  POSIX + Win32 co-equal case.
- **Windows NT** — claimed peer environment subsystems but unified security under
  one token model; the "claimed first-class, actually subordinate" case this RFC
  avoids.
