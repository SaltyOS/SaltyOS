==================
SaltyOS Draft RFCs
==================

Speculative, in-flight design drafts. The numbered RFCs in the parent directory
are accepted or under active implementation; these are not yet assigned numbers
(a number is claimed when a draft is accepted). Each draft lists its
prerequisites in a ``:Depends:`` header; the dependency order is shown below.

Dependency order
================

Personality and layering — a chain::

    substrate_neutralization
        └─ cap_native_spine            (depends: substrate_neutralization)
            └─ elf_pe_coexistence      (depends: substrate_neutralization
                                                  + cap_native_spine)

Authorization and storage — standalone, in the VFS area::

    principalid_access_control         (the neutral AccessControl model;
                                        consumed by cap_native_spine)
    xattr_value_size                   (extended-attribute value sizing)

System services — standalone::

    randomness_service                 (KernelRng-backed rngsrv and
                                        device-random routing)

(The former ``code_loading_authority`` draft has been promoted into and merged
with **RFC-0009: Capability-Bounded W^X and the Code-Loading Authority** in the
parent directory.)

Drafts
======

- **substrate_neutralization** — Personality-Neutral Substrate and C Runtime.
  Landable now; the foundation the personality and the engine build on.
- **cap_native_spine** — The SaltyOS-Native Personality and the Object Spine.
  The native personality (interop + capability) and its object model.
- **elf_pe_coexistence** — ELF + PE In-Process Coexistence Engine. Experimental;
  the deferred engine that completes cross-format interop.
- **principalid_access_control** — PrincipalId Access Control for co-equal POSIX
  and Win32. The neutral file-authorization model.
- **xattr_value_size** — Decouple xattr value size from the path-component limit.
- **randomness_service** — KernelRng-backed userland randomness service and
  device-random routing.
