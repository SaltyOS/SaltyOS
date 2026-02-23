//! search -- binary search tree (tsearch/tfind/tdelete/twalk)
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! POSIX.1-2001 binary search tree functions. Uses an unbalanced BST, which is
//! the minimum required by POSIX. Nodes are allocated via `malloc`/`free`.

use crate::malloc::{free, malloc};
use core::ptr;

/// Internal binary search tree node.
#[repr(C)]
struct TNode {
    key: *const u8,
    left: *mut TNode,
    right: *mut TNode,
}

/// Allocate and initialize a new tree node with the given key.
unsafe fn tnode_new(key: *const u8) -> *mut TNode {
    // SAFETY: malloc returns a valid pointer or null; we initialize all fields.
    unsafe {
        let p = malloc(core::mem::size_of::<TNode>()) as *mut TNode;
        if p.is_null() {
            return ptr::null_mut();
        }
        (*p).key = key;
        (*p).left = ptr::null_mut();
        (*p).right = ptr::null_mut();
        p
    }
}

/// `tsearch` — insert or find a key in the binary search tree.
///
/// If the key is found, returns a pointer to the matching node's key slot.
/// If not found, inserts a new node and returns a pointer to its key slot.
/// Returns null on allocation failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsearch(
    key: *const u8,
    rootp: *mut *mut u8,
    compar: unsafe extern "C" fn(*const u8, *const u8) -> i32,
) -> *mut u8 {
    unsafe {
        if rootp.is_null() {
            return ptr::null_mut();
        }

        let rootp = rootp as *mut *mut TNode;
        let mut cur = rootp;

        while !(*cur).is_null() {
            let cmp = compar(key, (**cur).key);
            if cmp < 0 {
                cur = &raw mut (**cur).left;
            } else if cmp > 0 {
                cur = &raw mut (**cur).right;
            } else {
                // Found — return pointer to existing node (cast to void*)
                return *cur as *mut u8;
            }
        }

        // Not found — insert
        let node = tnode_new(key);
        if node.is_null() {
            return ptr::null_mut();
        }
        *cur = node;
        node as *mut u8
    }
}

/// `tfind` — find a key in the binary search tree without inserting.
///
/// Returns a pointer to the matching node, or null if not found.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tfind(
    key: *const u8,
    rootp: *const *mut u8,
    compar: unsafe extern "C" fn(*const u8, *const u8) -> i32,
) -> *mut u8 {
    unsafe {
        if rootp.is_null() {
            return ptr::null_mut();
        }

        let mut node = *(rootp as *const *mut TNode);

        while !node.is_null() {
            let cmp = compar(key, (*node).key);
            if cmp < 0 {
                node = (*node).left;
            } else if cmp > 0 {
                node = (*node).right;
            } else {
                return node as *mut u8;
            }
        }

        ptr::null_mut()
    }
}

/// `tdelete` — delete a key from the binary search tree.
///
/// Returns a pointer to the parent of the deleted node, or to the new root
/// if the root was deleted. Returns null if the key was not found.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tdelete(
    key: *const u8,
    rootp: *mut *mut u8,
    compar: unsafe extern "C" fn(*const u8, *const u8) -> i32,
) -> *mut u8 {
    unsafe {
        if rootp.is_null() {
            return ptr::null_mut();
        }

        let rootp = rootp as *mut *mut TNode;
        let mut cur = rootp;
        let mut parent: *mut TNode = ptr::null_mut();

        while !(*cur).is_null() {
            let cmp = compar(key, (**cur).key);
            if cmp < 0 {
                parent = *cur;
                cur = &raw mut (**cur).left;
            } else if cmp > 0 {
                parent = *cur;
                cur = &raw mut (**cur).right;
            } else {
                // Found the node to delete
                let node = *cur;

                if (*node).left.is_null() {
                    // No left child — replace with right child
                    *cur = (*node).right;
                } else if (*node).right.is_null() {
                    // No right child — replace with left child
                    *cur = (*node).left;
                } else {
                    // Two children — find in-order successor (leftmost in right subtree)
                    let mut succ_parent = &raw mut (*node).right;
                    while !(**succ_parent).left.is_null() {
                        succ_parent = &raw mut (**succ_parent).left;
                    }
                    let succ = *succ_parent;
                    // Replace successor with its right child
                    *succ_parent = (*succ).right;
                    // Copy successor's key into the node being deleted
                    (*node).key = (*succ).key;
                    // Free the successor node instead
                    free(succ as *mut u8);
                    if parent.is_null() {
                        return *rootp as *mut u8;
                    }
                    return parent as *mut u8;
                }

                free(node as *mut u8);
                if parent.is_null() {
                    return *rootp as *mut u8;
                }
                return parent as *mut u8;
            }
        }

        // Key not found
        ptr::null_mut()
    }
}

/// Recursive helper for `twalk`.
unsafe fn twalk_recurse(
    node: *const TNode,
    action: unsafe extern "C" fn(*const u8, i32, i32),
    depth: i32,
) {
    unsafe {
        if node.is_null() {
            return;
        }

        let is_leaf = (*node).left.is_null() && (*node).right.is_null();

        if is_leaf {
            // VISIT::leaf = 3
            action(node as *const u8, 3, depth);
        } else {
            // VISIT::preorder = 0
            action(node as *const u8, 0, depth);
            twalk_recurse((*node).left, action, depth + 1);
            // VISIT::postorder = 1
            action(node as *const u8, 1, depth);
            twalk_recurse((*node).right, action, depth + 1);
            // VISIT::endorder = 2
            action(node as *const u8, 2, depth);
        }
    }
}

/// `twalk` — walk the binary search tree in order, calling `action` for each node.
///
/// The `action` callback receives: a pointer to the node, the visit order
/// (preorder/postorder/endorder/leaf), and the depth (root = 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn twalk(
    root: *const u8,
    action: unsafe extern "C" fn(*const u8, i32, i32),
) {
    unsafe {
        twalk_recurse(root as *const TNode, action, 0);
    }
}
