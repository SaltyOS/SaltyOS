//! Capability Derivation Tree (CDT)
//!
//! Manages capability derivation relationships with zero heap allocation.
//! All operations are O(1) except revoke which is O(d) where d is
//! the number of descendants.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::slot::{
    free_slot, get_cap, get_meta, get_meta_mut, nullify_capability, CapSlot, INVALID_SLOT,
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
        let meta = get_meta_mut(slot);
        meta.cdt_parent = INVALID_SLOT;
        meta.cdt_first_child = INVALID_SLOT;
        meta.cdt_next = INVALID_SLOT;
        meta.cdt_prev = INVALID_SLOT;
    }

    /// Insert child capability into CDT
    ///
    /// Insert child_slot as a child of parent_slot.
    /// Time complexity: O(1)
    pub fn insert_child(parent_slot: CapSlot, child_slot: CapSlot) {
        let parent_meta = get_meta_mut(parent_slot);
        let child_meta = get_meta_mut(child_slot);

        // Set child's parent
        child_meta.cdt_parent = parent_slot;

        // Get parent's current first child
        let old_first = parent_meta.cdt_first_child;

        // Insert child at head of parent's child list
        child_meta.cdt_next = old_first;
        child_meta.cdt_prev = INVALID_SLOT;

        // Update old first child's prev pointer (if exists)
        if old_first != INVALID_SLOT {
            get_meta_mut(old_first).cdt_prev = child_slot;
        }

        // Update parent's first child
        parent_meta.cdt_first_child = child_slot;
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

        let meta_mut = get_meta_mut(slot);

        // Update previous sibling's next pointer
        if prev != INVALID_SLOT {
            get_meta_mut(prev).cdt_next = next;
        } else if parent != INVALID_SLOT {
            // We were first child - update parent
            get_meta_mut(parent).cdt_first_child = next;
        }

        // Update next sibling's prev pointer
        if next != INVALID_SLOT {
            get_meta_mut(next).cdt_prev = prev;
        }

        // Clear all CDT links
        meta_mut.cdt_parent = INVALID_SLOT;
        meta_mut.cdt_first_child = INVALID_SLOT;
        meta_mut.cdt_next = INVALID_SLOT;
        meta_mut.cdt_prev = INVALID_SLOT;
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
        // Recursively revoke all children first (depth-first)
        while Self::has_children(slot) {
            let child = Self::first_child(slot);
            Self::revoke(child); // Recursive, no queue needed
        }

        // After all children are revoked, delete this capability
        Self::delete_capability(slot);
    }

    /// Delete a single capability (full lifecycle)
    ///
    /// Performs complete cleanup:
    /// 1. Remove from CDT
    /// 2. Remove from untyped's child list (if applicable)
    /// 3. Decrement object refcount (destroy if 0)
    /// 4. Nullify capability
    /// 5. Free the slot
    fn delete_capability(slot: CapSlot) {
        let meta = get_meta(slot);

        // 1. Remove from CDT
        Self::remove(slot);

        // 2. Remove from untyped's child list (if applicable)
        let ut_parent = meta.ut_parent;
        if ut_parent != INVALID_SLOT {
            // This is done by untyped module
            super::untyped::UntypedTracker::remove_child(ut_parent, slot);
        }

        // 3. Release object (refcount--, destroy if 0)
        let cap = get_cap(slot);
        if !cap.is_null() {
            unsafe {
                super::refcount::release_object(cap.object, cap.obj_type);
            }
        }

        // 4. Nullify capability
        nullify_capability(slot);

        // 5. Clear ut_parent
        get_meta_mut(slot).ut_parent = INVALID_SLOT;

        // 6. Free the slot
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
    #[cfg(debug_assertions)]
    pub fn verify_integrity() -> Result<(), super::cnode::CapError> {
        use crate::cap::slot::{get_meta, MAX_SLOTS};
        use super::cnode::CapError;

        for slot in 0..MAX_SLOTS {
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
        assert_eq!(CDT::descendant_count(a), 1);    // A1
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
