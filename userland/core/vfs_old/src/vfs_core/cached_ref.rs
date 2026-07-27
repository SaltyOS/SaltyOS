// SPDX-License-Identifier: GPL-2.0-only
//! Identity + handle pair with cached handle hint.
//!
//! Many VFS structural links are (`stable_identity`,
//! `arena_handle_cache`) pairs: the identity is authoritative and
//! survives arena slot recycling, while the handle is a fast-path
//! hint that can go stale. Before this module those pairs lived as
//! two separate fields on `Mount`, `Vnode`, and `ClientState` —
//! copy-paste of invalidation protocol at every read site, and
//! `xxx` + `xxx_id` naming that invited drift between the two.
//!
//! [`CachedRef`] bundles the two values into one field with a
//! uniform [`CachedRef::resolve`] API: look up the handle hint in
//! the backing arena, verify that the resolved slot still carries
//! the stored identity, and re-resolve through the slower identity
//! → handle path on mismatch. Writers update both fields through
//! [`CachedRef::set`] so the pair never diverges.
//!
//! [`ResolveByIdentity`] is the trait each identity-addressable
//! domain implements so [`CachedRef::resolve`] can walk from id to
//! current handle without knowing the concrete arena shape. Today
//! the instances are:
//! - `ResolveByIdentity<FsInstanceId, MountHandle>` on `VfsState`
//! - `ResolveByIdentity<VnodeKey, VnodeHandle>` on `VfsState`
//!
//! Future instances (page-cache objects keyed by `(FsInstanceId,
//! BackendNodeId, offset)`, inotify watches keyed by `(VnodeKey,
//! WatchId)`, etc.) slot in without modifying this module.

/// Pair of stable identity + arena-handle hint.
///
/// `Id` is the identity the resolver trusts; `Handle` is the
/// arena-handle cache. The pair is kept consistent by the module
/// invariants: setters always update both, and readers either
/// resolve through the identity or consult the handle hint followed
/// by an identity re-verification via [`CachedRef::resolve`].
///
/// `id()` is cheap and authoritative; `handle_hint()` is a
/// best-effort cache that may be stale (different epoch / different
/// identity after slot recycling) — never blindly dereference the
/// hint without an identity re-check.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct CachedRef<Id: Copy + Eq, Handle: Copy> {
    id: Id,
    handle: Handle,
}

impl<Id: Copy + Eq, Handle: Copy> CachedRef<Id, Handle> {
    /// Construct a new pair with the given authoritative identity
    /// and a hint for the current handle. The hint is not verified
    /// — callers that don't have a current handle on hand should
    /// use [`CachedRef::new_id_only`] with a default-sentinel
    /// handle instead.
    #[inline]
    pub(crate) const fn new(id: Id, handle: Handle) -> Self {
        CachedRef { id, handle }
    }

    /// Construct a pair whose handle hint is definitely stale
    /// (typically set to the type's `INVALID` / zero sentinel).
    /// Subsequent [`CachedRef::resolve`] reads will fall through to
    /// the resolver.
    #[inline]
    pub(crate) const fn new_id_only(id: Id, invalid_handle: Handle) -> Self {
        CachedRef {
            id,
            handle: invalid_handle,
        }
    }

    /// Authoritative identity — always trust this over the handle
    /// hint.
    #[inline]
    pub(crate) const fn id(&self) -> Id {
        self.id
    }

    /// Cached handle hint. Callers must pair every read with either
    /// an identity check or a resolver round trip; prefer
    /// [`CachedRef::resolve`] over direct hint use.
    #[inline]
    pub(crate) const fn handle_hint(&self) -> Handle {
        self.handle
    }

    /// Overwrite both the identity and the handle hint atomically.
    /// Use when both values are known simultaneously (e.g. mount /
    /// vget success).
    #[inline]
    pub(crate) fn set(&mut self, id: Id, handle: Handle) {
        self.id = id;
        self.handle = handle;
    }

    /// Overwrite only the identity, marking the handle as stale.
    /// The next [`CachedRef::resolve`] will fall through to the
    /// resolver.
    #[inline]
    pub(crate) fn set_id_only(&mut self, id: Id, invalid_handle: Handle) {
        self.id = id;
        self.handle = invalid_handle;
    }

    /// Refresh the cached handle hint without changing the
    /// identity. Used by [`CachedRef::resolve`] on a hit path after
    /// a resolver round trip.
    #[inline]
    pub(crate) fn update_handle(&mut self, handle: Handle) {
        self.handle = handle;
    }
}

// Domain-specific sentinels. Each pair gets a const INVALID so
// zeroed / detached structures don't need to hand-construct the
// invalid pair every time. Separate impl blocks keep the generic
// helpers above unencumbered.

impl CachedRef<crate::vfs_core::identity::VnodeKey, crate::vfs_core::vnode::VnodeHandle> {
    pub(crate) const INVALID: Self = CachedRef {
        id: crate::vfs_core::identity::VnodeKey::INVALID,
        handle: crate::vfs_core::vnode::VnodeHandle::INVALID,
    };
}

impl CachedRef<crate::vfs_core::identity::FsInstanceId, crate::vfs_core::mount::MountHandle> {
    pub(crate) const INVALID: Self = CachedRef {
        id: crate::vfs_core::identity::FsInstanceId::INVALID,
        handle: crate::vfs_core::mount::MountHandle::INVALID,
    };
}

/// Domain trait: a single implementation per (identity, handle) pair
/// that VFS needs to look up. `VfsState` implements two instances —
/// `(FsInstanceId, MountHandle)` and `(VnodeKey, VnodeHandle)` —
/// and `CachedRef::resolve` routes through this trait so the
/// identity-handle pair type never needs to know the concrete
/// arena shape.
pub(crate) trait ResolveByIdentity<Id: Copy + Eq, Handle: Copy> {
    /// Walk from the stable identity to the current arena handle.
    /// Returns `None` when the identity has been retired (unmount /
    /// vnode release without replacement).
    fn resolve(&self, id: Id) -> Option<Handle>;

    /// Cross-check that `handle` still resolves to a slot whose
    /// stored identity equals `id`. Returns `true` when the handle
    /// hint is still a valid fast path; `false` when a slot
    /// recycling has invalidated it. `CachedRef::resolve` uses this
    /// to decide whether to fall back to the identity walk.
    fn handle_still_matches(&self, id: Id, handle: Handle) -> bool;
}

impl<Id, Handle> CachedRef<Id, Handle>
where
    Id: Copy + Eq,
    Handle: Copy,
{
    /// Resolve the pair to a current handle through the supplied
    /// resolver. Fast path: verify the cached handle still points
    /// to a slot carrying this identity; on hit return the hint
    /// unchanged. Slow path: walk identity → handle, update the
    /// cached hint, return the fresh handle.
    ///
    /// Returns `None` when the identity has been retired (e.g.
    /// unmount, vnode release, session teardown).
    ///
    /// The resolver borrow is `&R` so callers can keep other `&mut`
    /// borrows on the surrounding struct open during resolution —
    /// `VfsState` reads are all shared-borrow friendly.
    pub(crate) fn resolve<R>(&mut self, resolver: &R) -> Option<Handle>
    where
        R: ResolveByIdentity<Id, Handle> + ?Sized,
    {
        // Fully-qualified calls disambiguate when the resolver type
        // implements multiple `ResolveByIdentity<_, _>` instances
        // (e.g. `VfsState` implements both
        // `<FsInstanceId, MountHandle>` and `<VnodeKey, VnodeHandle>`).
        if <R as ResolveByIdentity<Id, Handle>>::handle_still_matches(
            resolver,
            self.id,
            self.handle,
        ) {
            return Some(self.handle);
        }
        let fresh = <R as ResolveByIdentity<Id, Handle>>::resolve(resolver, self.id)?;
        self.handle = fresh;
        Some(fresh)
    }

    /// Const-borrow variant: resolve without updating the cached
    /// hint. Used by read paths that cannot take `&mut` on the
    /// owning struct. Performance is a hair worse on repeated
    /// lookups (no hint update) but semantically identical.
    pub(crate) fn resolve_ro<R>(&self, resolver: &R) -> Option<Handle>
    where
        R: ResolveByIdentity<Id, Handle> + ?Sized,
    {
        if <R as ResolveByIdentity<Id, Handle>>::handle_still_matches(
            resolver,
            self.id,
            self.handle,
        ) {
            return Some(self.handle);
        }
        <R as ResolveByIdentity<Id, Handle>>::resolve(resolver, self.id)
    }
}
