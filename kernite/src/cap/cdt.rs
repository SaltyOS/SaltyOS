//! Capability Derivation Tree (CDT)
//!
//! Manages capability derivation relationships with zero heap allocation.
//! All operations are O(1) except revoke which is O(d) where d is
//! the number of descendants.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::slot::{
    CapSlot, INVALID_SLOT, SlotState, free_slot, get_cap, get_meta, is_transit_pinned,
    nullify_capability, update_meta,
};

/// CDT operations
///
/// The CDT is a tree structure where:
/// - Each capability slot has at most one parent
/// - Each capability can have multiple children
/// - Revoke deletes all descendants recursively
pub struct CDT;

impl CDT {
    /// Insert capability as CDT root (no parent)
    ///
    /// Used for initial capabilities created from untyped memory.
    pub fn insert_root(slot: CapSlot) {
        update_meta(slot, |meta| {
            meta.cdt_parent = INVALID_SLOT;
            meta.cdt_first_child = INVALID_SLOT;
            meta.cdt_next = INVALID_SLOT;
            meta.cdt_prev = INVALID_SLOT;
        });
    }

    /// Insert child capability into CDT
    ///
    /// Insert child_slot as a child of parent_slot.
    /// Time complexity: O(1)
    pub fn insert_child(parent_slot: CapSlot, child_slot: CapSlot) {
        // Get parent's current first child
        let old_first = get_meta(parent_slot).cdt_first_child;

        // Insert child at head of parent's child list
        update_meta(child_slot, |child_meta| {
            child_meta.cdt_parent = parent_slot;
            child_meta.cdt_next = old_first;
            child_meta.cdt_prev = INVALID_SLOT;
        });

        // Update old first child's prev pointer (if exists)
        if old_first != INVALID_SLOT {
            update_meta(old_first, |meta| meta.cdt_prev = child_slot);
        }

        // Update parent's first child
        update_meta(parent_slot, |meta| meta.cdt_first_child = child_slot);
    }

    /// Remove capability from CDT
    ///
    /// Unlinks the capability from the CDT by updating
    /// parent, prev, and next pointers.
    /// Time complexity: O(1)
    pub fn remove(slot: CapSlot) {
        let meta = get_meta(slot);

        let parent = meta.cdt_parent;
        let prev = meta.cdt_prev;
        let next = meta.cdt_next;

        // Update previous sibling's next pointer
        if prev != INVALID_SLOT {
            update_meta(prev, |meta| meta.cdt_next = next);
        } else if parent != INVALID_SLOT {
            // We were first child - update parent
            update_meta(parent, |meta| meta.cdt_first_child = next);
        }

        // Update next sibling's prev pointer
        if next != INVALID_SLOT {
            update_meta(next, |meta| meta.cdt_prev = prev);
        }

        // Clear all CDT links
        update_meta(slot, |meta| {
            meta.cdt_parent = INVALID_SLOT;
            meta.cdt_first_child = INVALID_SLOT;
            meta.cdt_next = INVALID_SLOT;
            meta.cdt_prev = INVALID_SLOT;
        });
    }

    /// Detach `slot` from its parent and sibling list, re-rooting it as
    /// a CDT root while PRESERVING its own child subtree. Unlike
    /// `remove`, which also clears `cdt_first_child` (orphaning the
    /// subtree), this keeps the slot's children attached so an
    /// in-transit (transit-pinned) cap survives a parent revoke / delete
    /// with its derivations intact.
    fn detach_to_root(slot: CapSlot) {
        let meta = get_meta(slot);
        let parent = meta.cdt_parent;
        let prev = meta.cdt_prev;
        let next = meta.cdt_next;

        // Unlink from the sibling list / parent's first-child pointer.
        if prev != INVALID_SLOT {
            update_meta(prev, |meta| meta.cdt_next = next);
        } else if parent != INVALID_SLOT {
            update_meta(parent, |meta| meta.cdt_first_child = next);
        }
        if next != INVALID_SLOT {
            update_meta(next, |meta| meta.cdt_prev = prev);
        }

        // Become a root: clear parent / sibling links but KEEP
        // cdt_first_child so the subtree travels with this slot.
        update_meta(slot, |meta| {
            meta.cdt_parent = INVALID_SLOT;
            meta.cdt_next = INVALID_SLOT;
            meta.cdt_prev = INVALID_SLOT;
        });
    }

    /// Re-parent every direct child of `slot` to `slot`'s own parent before
    /// `slot` is torn down. A single delete preserves derivations, but
    /// re-parenting ordinary derived caps to the grandparent — rather than
    /// orphaning them as independent CDT roots — keeps them reachable from an
    /// ancestor's `revoke`. This matches seL4's MDB relink on capability
    /// delete, where `emptySlot` bypasses the deleted node by linking its
    /// predecessor directly to its successor. A transit-pinned child is owned
    /// by an in-flight IPC carrier and must survive a parent revoke / delete
    /// with its subtree intact, so it is detached to a CDT root instead. When
    /// `slot` is itself a root (no grandparent), ordinary children also stay
    /// roots. No-op on the common childless path.
    fn reparent_children(slot: CapSlot) {
        let grandparent = get_meta(slot).cdt_parent;
        let mut child = Self::first_child(slot);
        while child != INVALID_SLOT {
            let next = get_meta(child).cdt_next;
            // Detach from `slot`'s child list first: this keeps the
            // sibling-list walk consistent (it advances `slot`'s
            // `cdt_first_child` and clears the next child's `cdt_prev`) and
            // preserves the child's own subtree via `cdt_first_child`.
            Self::detach_to_root(child);
            // Ordinary derived caps re-parent to the grandparent so an
            // ancestor revoke still reaches them; transit-pinned in-flight
            // caps stay roots so their carrier can dispose of them.
            if grandparent != INVALID_SLOT && !is_transit_pinned(child) {
                Self::insert_child(grandparent, child);
            }
            child = next;
        }
    }

    /// Check if capability has children
    pub fn has_children(slot: CapSlot) -> bool {
        get_meta(slot).cdt_first_child != INVALID_SLOT
    }

    /// Get first child of capability
    pub fn first_child(slot: CapSlot) -> CapSlot {
        get_meta(slot).cdt_first_child
    }

    /// Get parent of capability
    pub fn parent(slot: CapSlot) -> CapSlot {
        get_meta(slot).cdt_parent
    }

    /// Revoke all descendants of a capability
    ///
    /// This is the CORE revocation operation. It recursively deletes
    /// all descendants in the CDT. Uses pure recursion with NO heap
    /// allocation (no Vec/VecDeque).
    ///
    /// Time complexity: O(d) where d is number of descendants
    /// Space complexity: O(d) on stack (recursive calls)
    pub fn revoke(slot: CapSlot) {
        crate::kernel::printk::ktrace!(|g| {
            g.puts("[CDT] revoke slot=");
            g.hex(slot as u64);
            g.putc(b'\n');
        });
        // Revoke all children first (depth-first). A transit-pinned
        // child is owned by an in-flight IPC carrier and must survive:
        // detach it from this slot (so the loop makes progress and this
        // slot can be deleted) and re-root it with its subtree intact.
        // The carrier's unpin-and-delete path disposes of it when
        // transit ends.
        while Self::has_children(slot) {
            let child = Self::first_child(slot);
            if is_transit_pinned(child) {
                Self::detach_to_root(child);
            } else {
                Self::revoke(child); // Recursive, no queue needed
            }
        }

        // After all children are revoked or re-rooted, delete this
        // capability (a no-op if this slot is itself transit-pinned).
        Self::delete_capability(slot);
    }

    /// Delete a single capability (per-cap bookkeeping only).
    ///
    /// Performs:
    /// 1. Remove from CDT (cap-to-cap derivation tree).
    /// 2. Decrement object refcount — when the LAST reference goes,
    ///    the object enters the reaper queue, which performs every
    ///    object-level cleanup step (unlink from parent untyped's
    ///    children list, reclaim the carved phys range to
    ///    `UntypedReserved`, release the root reservation if this is
    ///    a root untyped, run the type-specific destructor, and push
    ///    the freed bytes onto the parent's freelist). Per-cap state
    ///    below is just slot bookkeeping.
    /// 3. Nullify capability + free the slot.
    ///
    /// # Safety
    /// Must be called under CAP_LOCK. Safe to call on already-deleted
    /// slots (idempotent due to `SlotState::Free` guard).
    pub(crate) fn delete_capability(slot: CapSlot) {
        let meta = get_meta(slot);

        // Guard against double-delete: if slot already free, return immediately.
        // This can happen when CNode cleanup iterates slots that were already
        // deleted by a prior CDT::revoke of their parent.
        if meta.state == SlotState::Free {
            return;
        }

        // A transit-pinned slot is owned by an in-flight IPC carrier.
        // Leave it fully intact — CDT linkage, object refcount, capability
        // payload, and slot identity (generation) — so a concurrent CSpace
        // teardown cannot pull the cap out from under a deferred install.
        // The carrier's unpin-and-delete path runs this again once transit
        // ends.
        if is_transit_pinned(slot) {
            return;
        }

        // Re-parent every direct child to this slot's own parent before
        // tearing this slot down, so no child keeps a dangling `cdt_parent`
        // into this slot once it is freed and reused. A single delete
        // preserves derivations; re-parenting ordinary derived caps to the
        // grandparent (rather than orphaning them as roots) keeps them
        // reachable from an ancestor's `revoke`, matching seL4's MDB relink.
        // Transit-pinned in-flight caps are detached to a root so their
        // carrier can dispose of them. `revoke` is the path that kills a
        // subtree.
        Self::reparent_children(slot);

        Self::remove(slot);

        let cap = get_cap(slot);
        if !cap.is_null() {
            unsafe {
                super::refcount::release_object(cap.object, cap.obj_type);
            }
        }

        crate::kernel::printk::ktrace!(|g| {
            g.puts("[CDT] delete slot=");
            g.hex(slot as u64);
            g.puts(" type=");
            g.hex(cap.obj_type as u64);
            g.puts(" gen=");
            g.hex(super::slot::get_generation(slot));
            g.putc(b'\n');
        });
        nullify_capability(slot);
        free_slot(slot);
    }

    /// Get count of direct children
    ///
    /// Time complexity: O(c) where c is number of children
    pub fn child_count(slot: CapSlot) -> usize {
        let mut count = 0;
        let mut current = Self::first_child(slot);

        while current != INVALID_SLOT {
            count += 1;
            current = get_meta(current).cdt_next;
        }

        count
    }

    /// Get total count of all descendants
    ///
    /// Time complexity: O(d) where d is total descendants
    pub fn descendant_count(slot: CapSlot) -> usize {
        let mut count = 0;
        let mut child = Self::first_child(slot);

        while child != INVALID_SLOT {
            // Count this child's subtree
            count += 1 + Self::descendant_count(child);
            child = get_meta(child).cdt_next;
        }

        count
    }

    /// Verify CDT integrity (for debugging/testing)
    ///
    /// Checks:
    /// - All child->parent links are valid
    /// - Sibling lists are correctly linked
    /// - No cycles exist
    pub fn verify_integrity() -> Result<(), super::cnode::CapError> {
        use super::cnode::CapError;
        use crate::cap::slot::{get_meta, max_slots};

        for slot in 0..max_slots() {
            let slot = slot as CapSlot;
            let meta = get_meta(slot);

            // Skip free slots
            if meta.state == super::slot::SlotState::Free {
                continue;
            }

            // Verify child->parent links
            let mut child = meta.cdt_first_child;
            while child != INVALID_SLOT {
                let child_meta = get_meta(child);
                if child_meta.cdt_parent != slot {
                    return Err(CapError::InvalidState);
                }
                child = child_meta.cdt_next;
            }

            // Verify sibling links
            let mut prev = INVALID_SLOT;
            let mut current = meta.cdt_next;
            while current != INVALID_SLOT {
                if get_meta(current).cdt_prev != prev {
                    return Err(CapError::InvalidState);
                }
                prev = current;
                current = get_meta(current).cdt_next;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::slot::{alloc_slot, free_slot};
    use super::*;

    #[test]
    fn test_insert_root() {
        let slot = alloc_slot().unwrap();
        CDT::insert_root(slot);

        assert_eq!(CDT::parent(slot), INVALID_SLOT);
        assert!(!CDT::has_children(slot));

        free_slot(slot);
    }

    #[test]
    fn test_insert_child() {
        let parent = alloc_slot().unwrap();
        let child = alloc_slot().unwrap();

        CDT::insert_root(parent);
        CDT::insert_child(parent, child);

        assert_eq!(CDT::parent(child), parent);
        assert_eq!(CDT::first_child(parent), child);
        assert!(CDT::has_children(parent));

        free_slot(parent);
        free_slot(child);
    }

    #[test]
    fn test_remove() {
        let parent = alloc_slot().unwrap();
        let child = alloc_slot().unwrap();

        CDT::insert_root(parent);
        CDT::insert_child(parent, child);
        CDT::remove(child);

        assert_eq!(CDT::parent(child), INVALID_SLOT);
        assert!(!CDT::has_children(parent));

        free_slot(parent);
        free_slot(child);
    }

    #[test]
    fn test_multiple_children() {
        let parent = alloc_slot().unwrap();
        let child1 = alloc_slot().unwrap();
        let child2 = alloc_slot().unwrap();
        let child3 = alloc_slot().unwrap();

        CDT::insert_root(parent);
        CDT::insert_child(parent, child1);
        CDT::insert_child(parent, child2);
        CDT::insert_child(parent, child3);

        // child3 should be first (inserted at head)
        assert_eq!(CDT::first_child(parent), child3);
        assert_eq!(CDT::child_count(parent), 3);

        free_slot(parent);
        free_slot(child1);
        free_slot(child2);
        free_slot(child3);
    }

    #[test]
    fn test_revoke_single_level() {
        // Build: root -> {child1, child2, child3}
        let root = alloc_slot().unwrap();
        let child1 = alloc_slot().unwrap();
        let child2 = alloc_slot().unwrap();
        let child3 = alloc_slot().unwrap();

        CDT::insert_root(root);
        CDT::insert_child(root, child1);
        CDT::insert_child(root, child2);
        CDT::insert_child(root, child3);

        assert_eq!(CDT::child_count(root), 3);

        // Revoke all children of root by revoking each subtree.
        // CDT::revoke deletes the target AND its descendants,
        // so we revoke children one at a time via first_child.
        while CDT::has_children(root) {
            let child = CDT::first_child(root);
            CDT::revoke(child);
        }

        // Root should have no children; children's slots were freed
        assert!(!CDT::has_children(root));
        assert_eq!(CDT::child_count(root), 0);

        free_slot(root);
    }

    #[test]
    fn test_revoke_deep_tree() {
        // Build a 3-level tree:
        //   root -> A -> A1
        //               A2
        //        -> B -> B1
        let root = alloc_slot().unwrap();
        let a = alloc_slot().unwrap();
        let a1 = alloc_slot().unwrap();
        let a2 = alloc_slot().unwrap();
        let b = alloc_slot().unwrap();
        let b1 = alloc_slot().unwrap();

        CDT::insert_root(root);
        CDT::insert_child(root, a);
        CDT::insert_child(a, a1);
        CDT::insert_child(a, a2);
        CDT::insert_child(root, b);
        CDT::insert_child(b, b1);

        // Verify tree structure
        assert_eq!(CDT::child_count(root), 2);
        assert_eq!(CDT::child_count(a), 2);
        assert_eq!(CDT::child_count(b), 1);
        assert_eq!(CDT::descendant_count(root), 5);

        // Revoke subtree rooted at A (should delete A, A1, A2)
        CDT::revoke(a);

        // Root should only have B left
        assert_eq!(CDT::child_count(root), 1);
        assert_eq!(CDT::first_child(root), b);
        assert_eq!(CDT::descendant_count(root), 2); // B + B1

        // Revoke subtree rooted at B (should delete B, B1)
        CDT::revoke(b);

        assert!(!CDT::has_children(root));
        assert_eq!(CDT::descendant_count(root), 0);

        free_slot(root);
    }

    #[test]
    fn test_descendant_count() {
        // Build: root -> A -> A1
        //             -> B
        let root = alloc_slot().unwrap();
        let a = alloc_slot().unwrap();
        let a1 = alloc_slot().unwrap();
        let b = alloc_slot().unwrap();

        CDT::insert_root(root);
        CDT::insert_child(root, a);
        CDT::insert_child(a, a1);
        CDT::insert_child(root, b);

        assert_eq!(CDT::descendant_count(root), 3); // A + A1 + B
        assert_eq!(CDT::descendant_count(a), 1); // A1
        assert_eq!(CDT::descendant_count(b), 0);
        assert_eq!(CDT::descendant_count(a1), 0);

        // Clean up
        CDT::remove(a1);
        CDT::remove(a);
        CDT::remove(b);
        free_slot(root);
        free_slot(a);
        free_slot(a1);
        free_slot(b);
    }
}
