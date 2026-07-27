// SPDX-License-Identifier: GPL-2.0-only
//! B-tree read and copy-on-write (COW) mutation operations.

use crate::alloc::{alloc_block, bitmap_flush, free_block};
use crate::block::{cache_flush_block, read_block, read_block_mut, write_block, write_superblock};
use crate::consts::*;
use crate::crc::crc32c_btree_node;
use crate::types::*;
use crate::{BLOCK_SIZE, SB};

/// Search a leaf node for an item matching the given key.
/// Returns pointer to item data within the block, and its size.
pub(crate) fn btree_leaf_find(block_data: *const u8, key: &BTreeKey) -> Option<(*const u8, u32)> {
    unsafe {
        let hdr = &*(block_data as *const BTreeNodeHeader);
        if hdr.level != 0 {
            return None; // not a leaf
        }

        let items_start = block_data.add(core::mem::size_of::<BTreeNodeHeader>());
        let item_size = core::mem::size_of::<BTreeItem>();

        for i in 0..hdr.num_items as usize {
            let item_ptr = items_start.add(i * item_size) as *const BTreeItem;
            let item = core::ptr::read_unaligned(item_ptr);
            if item.key.cmp(key) == core::cmp::Ordering::Equal {
                let data_ptr = block_data.add(item.offset as usize);
                return Some((data_ptr, item.size));
            }
        }
        None
    }
}

/// Search a leaf node for all items with matching object_id and item_type.
/// Calls the callback for each match. Returns number found.
#[allow(dead_code)]
pub(crate) fn btree_leaf_find_all<F>(
    block_data: *const u8,
    object_id: u64,
    item_type: u8,
    mut callback: F,
) -> u32
where
    F: FnMut(&BTreeKey, *const u8, u32),
{
    unsafe {
        let hdr = &*(block_data as *const BTreeNodeHeader);
        if hdr.level != 0 {
            return 0;
        }

        let items_start = block_data.add(core::mem::size_of::<BTreeNodeHeader>());
        let item_size = core::mem::size_of::<BTreeItem>();
        let mut count = 0u32;

        for i in 0..hdr.num_items as usize {
            let item_ptr = items_start.add(i * item_size) as *const BTreeItem;
            let item = core::ptr::read_unaligned(item_ptr);
            if item.key.object_id == object_id && item.key.item_type == item_type {
                let data_ptr = block_data.add(item.offset as usize);
                callback(&item.key, data_ptr, item.size);
                count += 1;
            }
        }
        count
    }
}

/// Walk the B-tree from root to find the leaf containing the given key.
/// Returns pointer to the leaf block data, or null if not found.
pub(crate) fn btree_search(root_block: u64, key: &BTreeKey) -> *const u8 {
    let mut current_block = root_block;

    for _depth in 0..16 {
        let data = read_block(current_block);
        if data.is_null() {
            return core::ptr::null();
        }

        let hdr = unsafe { &*(data as *const BTreeNodeHeader) };

        // Verify magic
        if hdr.magic != BTREE_NODE_MAGIC {
            return core::ptr::null();
        }

        // Verify checksum
        let bs = unsafe { *(&raw const BLOCK_SIZE) } as usize;
        let computed = crc32c_btree_node(data, bs);
        if computed != hdr.checksum {
            return core::ptr::null();
        }

        // Leaf node: return it
        if hdr.level == 0 {
            return data;
        }

        // Internal node: binary search for child
        let ptrs_start = unsafe { data.add(core::mem::size_of::<BTreeNodeHeader>()) };
        let ptr_size = core::mem::size_of::<BTreePointer>();
        let num_ptrs = hdr.num_items as usize;

        if num_ptrs == 0 {
            return core::ptr::null();
        }

        // Find the rightmost pointer whose key <= search key
        let mut child_block = unsafe {
            let p = core::ptr::read_unaligned(ptrs_start as *const BTreePointer);
            p.block_nr
        };

        for i in 0..num_ptrs {
            let p = unsafe {
                core::ptr::read_unaligned(ptrs_start.add(i * ptr_size) as *const BTreePointer)
            };
            if p.key.cmp(key) != core::cmp::Ordering::Greater {
                child_block = p.block_nr;
            } else {
                break;
            }
        }

        current_block = child_block;
    }

    core::ptr::null() // max depth exceeded
}

/// Find the separator key for the next leaf after the one containing `key`.
/// Walks the path from root to leaf, then looks for the next sibling child pointer
/// in parent/ancestor nodes. Returns None if the current leaf is the last one.
fn find_next_leaf_key(root_block: u64, key: &BTreeKey) -> Option<BTreeKey> {
    let path = btree_search_path(root_block, key)?;

    if path.depth == 0 {
        return None; // Root is the only leaf
    }

    // Walk up from the leaf's parent to find a level with a next child
    let mut lev = path.depth;
    while lev > 0 {
        lev -= 1;
        let parent_block = path.blocks[lev];
        let child_idx = path.indices[lev] as usize;

        let parent_data = read_block(parent_block);
        if parent_data.is_null() {
            continue;
        }
        let hdr = unsafe { &*(parent_data as *const BTreeNodeHeader) };
        let next_idx = child_idx + 1;
        if next_idx < hdr.num_items as usize {
            let ptrs_start = unsafe { parent_data.add(core::mem::size_of::<BTreeNodeHeader>()) };
            let ptr_size = core::mem::size_of::<BTreePointer>();
            let next_ptr = unsafe {
                core::ptr::read_unaligned(ptrs_start.add(next_idx * ptr_size) as *const BTreePointer)
            };
            return Some(next_ptr.key);
        }
    }

    None
}

/// Iterate all B-tree items for a given inode and item type across multiple leaves.
/// Calls `callback` for each matching item. The callback returns true to continue
/// or false to stop early. Returns total number of items visited.
pub(crate) fn btree_find_all_for_ino<F>(
    root_block: u64,
    ino: u64,
    item_type: u8,
    mut callback: F,
) -> u32
where
    F: FnMut(&BTreeKey, *const u8, u32) -> bool,
{
    let mut total = 0u32;
    let mut search_key = BTreeKey {
        object_id: ino,
        item_type,
        offset: 0,
    };
    let mut prev_leaf_block: u64 = u64::MAX;

    for _ in 0..1024 {
        let leaf = btree_search(root_block, &search_key);
        if leaf.is_null() {
            break;
        }

        let hdr = unsafe { &*(leaf as *const BTreeNodeHeader) };
        if hdr.num_items == 0 {
            break;
        }

        // Same leaf detection: if btree_search routes us back to the same leaf,
        // use parent pointers to find the next leaf's separator key.
        if hdr.block_nr == prev_leaf_block {
            match find_next_leaf_key(root_block, &search_key) {
                Some(next_key) => {
                    if next_key.object_id > ino
                        || (next_key.object_id == ino && next_key.item_type > item_type)
                    {
                        break; // Past our range
                    }
                    search_key = next_key;
                    prev_leaf_block = u64::MAX;
                    continue;
                }
                None => break,
            }
        }
        prev_leaf_block = hdr.block_nr;

        let mut stopped = false;
        let mut saw_past_range = false;
        let mut next_search_key: Option<BTreeKey> = None;

        // SAFETY: leaf pointer is valid and points to a mapped B-tree node block.
        // Items are read via read_unaligned to handle packed layout.
        unsafe {
            let items_start = leaf.add(core::mem::size_of::<BTreeNodeHeader>());
            let item_size = core::mem::size_of::<BTreeItem>();

            for i in 0..hdr.num_items as usize {
                let item =
                    core::ptr::read_unaligned(items_start.add(i * item_size) as *const BTreeItem);

                if item.key.cmp(&search_key) == core::cmp::Ordering::Less {
                    continue;
                }

                if item.key.object_id == ino && item.key.item_type == item_type {
                    let data_ptr = leaf.add(item.offset as usize);
                    if !callback(&item.key, data_ptr, item.size) {
                        stopped = true;
                        total += 1;
                        break;
                    }
                    total += 1;

                    if item.key.offset == u64::MAX {
                        saw_past_range = true;
                        break;
                    }

                    next_search_key = Some(BTreeKey {
                        object_id: ino,
                        item_type,
                        offset: item.key.offset + 1,
                    });
                    continue;
                }

                if item.key.object_id > ino
                    || (item.key.object_id == ino && item.key.item_type > item_type)
                {
                    saw_past_range = true;
                    break;
                }
            }
        }

        if stopped || saw_past_range {
            break;
        }

        match next_search_key {
            Some(next_key) => {
                search_key = next_key;
            }
            None => match find_next_leaf_key(root_block, &search_key) {
                Some(next_key) => {
                    if next_key.object_id > ino
                        || (next_key.object_id == ino && next_key.item_type > item_type)
                    {
                        break;
                    }
                    search_key = next_key;
                    prev_leaf_block = u64::MAX;
                }
                None => break,
            },
        }
    }

    total
}

/// Search the B-tree for a specific item.
pub(crate) fn btree_find_item(root_block: u64, key: &BTreeKey) -> Option<(*const u8, u32)> {
    let leaf = btree_search(root_block, key);
    if leaf.is_null() {
        return None;
    }
    btree_leaf_find(leaf, key)
}

/// Forward-scan every leaf in the tree and return the highest `object_id`
/// carrying a `TRONA_INODE_ITEM`. Returns `0` if the tree is empty.
///
/// Unlike a first-hole walk, this inspects every inode record regardless of
/// gaps produced by prior deletions, so the returned value is the authoritative
/// maximum live inode id at the moment of the call. Used by the one-time
/// `legacy_upgrade_next_inode_seq` path on volumes predating the on-disk
/// `SB.next_inode_seq` field.
pub(crate) fn btree_max_inode_object_id(root_block: u64) -> u64 {
    let mut max_ino: u64 = 0;
    let mut search_key = BTreeKey {
        object_id: 0,
        item_type: 0,
        offset: 0,
    };
    let mut prev_leaf_block: u64 = u64::MAX;

    // Bounded iteration count matches `btree_find_all_for_ino`'s safety cap.
    // At 1024 leaves per pass this tolerates multi-million-inode volumes; if
    // we ever need more we can lift the bound to a `BLOCK_COUNT / fan-out`
    // expression.
    for _ in 0..(1024 * 1024) {
        let leaf = btree_search(root_block, &search_key);
        if leaf.is_null() {
            break;
        }

        let hdr = unsafe { &*(leaf as *const BTreeNodeHeader) };
        if hdr.num_items == 0 {
            break;
        }

        // Same-leaf detection: if `btree_search` routes us back to the leaf
        // we already visited, advance via the parent pointer to the next
        // sibling's separator.
        if hdr.block_nr == prev_leaf_block {
            match find_next_leaf_key(root_block, &search_key) {
                Some(next_key) => {
                    search_key = next_key;
                    continue;
                }
                None => break,
            }
        }
        prev_leaf_block = hdr.block_nr;

        unsafe {
            let items_start = leaf.add(core::mem::size_of::<BTreeNodeHeader>());
            let item_size = core::mem::size_of::<BTreeItem>();

            for i in 0..hdr.num_items as usize {
                let item =
                    core::ptr::read_unaligned(items_start.add(i * item_size) as *const BTreeItem);
                if item.key.item_type == TRONA_INODE_ITEM && item.key.object_id > max_ino {
                    max_ino = item.key.object_id;
                }
            }
        }

        match find_next_leaf_key(root_block, &search_key) {
            Some(next_key) => {
                search_key = next_key;
            }
            None => break,
        }
    }

    max_ino
}

/// Walk the B-tree from root to leaf, recording the path for COW propagation.
pub(crate) fn btree_search_path(root_block: u64, key: &BTreeKey) -> Option<BTreePath> {
    let mut path = BTreePath {
        blocks: [0; MAX_BTREE_DEPTH],
        indices: [0; MAX_BTREE_DEPTH],
        depth: 0,
    };
    let mut current_block = root_block;
    let mut level = 0;

    loop {
        if level >= MAX_BTREE_DEPTH {
            return None;
        }
        path.blocks[level] = current_block;

        let data = read_block(current_block);
        if data.is_null() {
            return None;
        }
        let hdr = unsafe { &*(data as *const BTreeNodeHeader) };
        if hdr.magic != BTREE_NODE_MAGIC {
            return None;
        }

        if hdr.level == 0 {
            path.depth = level;
            return Some(path);
        }

        // Internal node: find child
        let ptrs_start = unsafe { data.add(core::mem::size_of::<BTreeNodeHeader>()) };
        let ptr_size = core::mem::size_of::<BTreePointer>();
        let num_ptrs = hdr.num_items as usize;
        if num_ptrs == 0 {
            return None;
        }

        let mut child_idx = 0u32;
        let mut child_block =
            unsafe { core::ptr::read_unaligned(ptrs_start as *const BTreePointer).block_nr };
        for i in 0..num_ptrs {
            let p = unsafe {
                core::ptr::read_unaligned(ptrs_start.add(i * ptr_size) as *const BTreePointer)
            };
            if p.key.cmp(key) != core::cmp::Ordering::Greater {
                child_block = p.block_nr;
                child_idx = i as u32;
            } else {
                break;
            }
        }
        path.indices[level] = child_idx;
        current_block = child_block;
        level += 1;
    }
}

/// Allocate a new block and copy the contents of an existing block into it.
pub(crate) fn cow_copy_block(old_block: u64) -> Option<u64> {
    let new_block = alloc_block()?;
    let old_data = read_block(old_block);
    if old_data.is_null() {
        free_block(new_block);
        return None;
    }

    let mut buf = [0u8; 4096];
    unsafe {
        for i in 0..4096 {
            buf[i] = *old_data.add(i);
        }
    }

    // Update header: block_nr and generation
    unsafe {
        let hdr = &mut *(buf.as_mut_ptr() as *mut BTreeNodeHeader);
        hdr.block_nr = new_block;
        hdr.generation = (*(&raw const SB)).generation + 1;
    }

    // Recompute CRC32c
    let bs = unsafe { *(&raw const BLOCK_SIZE) } as usize;
    unsafe {
        let hdr = &mut *(buf.as_mut_ptr() as *mut BTreeNodeHeader);
        hdr.checksum = 0;
    }
    let checksum = crc32c_btree_node(buf.as_ptr(), bs);
    unsafe {
        let hdr = &mut *(buf.as_mut_ptr() as *mut BTreeNodeHeader);
        hdr.checksum = checksum;
    }

    if !write_block(new_block, buf.as_ptr()) {
        free_block(new_block);
        return None;
    }
    Some(new_block)
}

/// COW propagate from a modified child up to the root.
/// Returns the new root block number.
pub(crate) fn cow_propagate_up(
    path: &BTreePath,
    start_level: usize,
    new_child_block: u64,
    freed: &mut [u64; MAX_BTREE_DEPTH],
    freed_count: &mut usize,
) -> Option<u64> {
    let mut child_block = new_child_block;

    if start_level == 0 {
        return Some(child_block);
    }

    let mut level = start_level - 1;
    loop {
        let old_parent = path.blocks[level];
        let child_idx = path.indices[level] as usize;

        let new_parent = cow_copy_block(old_parent)?;
        freed[*freed_count] = old_parent;
        *freed_count += 1;

        // Update child pointer in new parent
        let parent_data = read_block_mut(new_parent);
        if parent_data.is_null() {
            return None;
        }
        unsafe {
            let ptrs_start = parent_data.add(core::mem::size_of::<BTreeNodeHeader>());
            let ptr_size = core::mem::size_of::<BTreePointer>();
            let ptr_loc = ptrs_start.add(child_idx * ptr_size);
            // BTreePointer layout: key(17) + block_nr(8) + generation(8)
            let block_nr_offset = 17;
            core::ptr::write_unaligned(ptr_loc.add(block_nr_offset) as *mut u64, child_block);
            let ngen = (*(&raw const SB)).generation + 1;
            core::ptr::write_unaligned(ptr_loc.add(block_nr_offset + 8) as *mut u64, ngen);
        }

        // Recompute CRC32c
        let bs = unsafe { *(&raw const BLOCK_SIZE) } as usize;
        unsafe {
            let hdr = &mut *(parent_data as *mut BTreeNodeHeader);
            hdr.checksum = 0;
        }
        let checksum = crc32c_btree_node(parent_data as *const u8, bs);
        unsafe {
            let hdr = &mut *(parent_data as *mut BTreeNodeHeader);
            hdr.checksum = checksum;
        }
        cache_flush_block(new_parent);

        child_block = new_parent;

        if level == 0 {
            break;
        }
        level -= 1;
    }

    Some(child_block)
}

/// Rebuild a leaf block from a list of items.
pub(crate) fn rebuild_leaf(
    out_buf: &mut [u8; 4096],
    owner: u64,
    generation: u64,
    block_nr: u64,
    items: &[LeafItem],
    count: usize,
) -> bool {
    let hdr_size = core::mem::size_of::<BTreeNodeHeader>();
    let item_entry_size = core::mem::size_of::<BTreeItem>();

    let data_area_start = hdr_size + count * item_entry_size;
    let total_data: usize = items[..count].iter().map(|it| it.data_len).sum();
    if data_area_start + total_data > 4096 {
        return false;
    }

    for b in out_buf.iter_mut() {
        *b = 0;
    }

    unsafe {
        let hdr = &mut *(out_buf.as_mut_ptr() as *mut BTreeNodeHeader);
        hdr.magic = BTREE_NODE_MAGIC;
        hdr.checksum = 0;
        hdr.owner = owner;
        hdr.generation = generation;
        hdr.block_nr = block_nr;
        hdr.num_items = count as u32;
        hdr.level = 0;
        hdr.flags = 0;
    }

    let mut data_offset = data_area_start;
    for i in 0..count {
        let item = BTreeItem {
            key: items[i].key,
            offset: data_offset as u32,
            size: items[i].data_len as u32,
        };
        unsafe {
            core::ptr::write_unaligned(
                out_buf.as_mut_ptr().add(hdr_size + i * item_entry_size) as *mut BTreeItem,
                item,
            );
            for j in 0..items[i].data_len {
                out_buf[data_offset + j] = items[i].data[j];
            }
        }
        data_offset += items[i].data_len;
    }

    let checksum = crc32c_btree_node(out_buf.as_ptr(), 4096);
    unsafe {
        let hdr = &mut *(out_buf.as_mut_ptr() as *mut BTreeNodeHeader);
        hdr.checksum = checksum;
    }
    true
}

/// Collect all items from a leaf block into the items array.
/// Returns the number of items collected.
pub(crate) fn collect_leaf_items(
    leaf_data: *const u8,
    items: &mut [LeafItem; MAX_LEAF_ITEMS],
) -> usize {
    unsafe {
        let hdr = &*(leaf_data as *const BTreeNodeHeader);
        let items_start = leaf_data.add(core::mem::size_of::<BTreeNodeHeader>());
        let item_size = core::mem::size_of::<BTreeItem>();
        let count = (hdr.num_items as usize).min(MAX_LEAF_ITEMS);

        for i in 0..count {
            let item =
                core::ptr::read_unaligned(items_start.add(i * item_size) as *const BTreeItem);
            items[i].key = item.key;
            items[i].data_len = (item.size as usize).min(256);
            let src = leaf_data.add(item.offset as usize);
            for j in 0..items[i].data_len {
                items[i].data[j] = *src.add(j);
            }
        }
        count
    }
}

/// Insert an item into a sorted items array. Returns new count.
pub(crate) fn insert_into_items(
    items: &mut [LeafItem; MAX_LEAF_ITEMS],
    count: usize,
    key: &BTreeKey,
    data: &[u8],
) -> usize {
    if count >= MAX_LEAF_ITEMS {
        return count;
    }

    // Find insertion point
    let mut pos = count;
    for i in 0..count {
        if items[i].key.cmp(key) == core::cmp::Ordering::Greater {
            pos = i;
            break;
        }
    }

    // Shift items right
    let mut i = count;
    while i > pos {
        items[i].key = items[i - 1].key;
        items[i].data_len = items[i - 1].data_len;
        items[i].data = items[i - 1].data;
        i -= 1;
    }

    // Insert new item
    items[pos].key = *key;
    items[pos].data_len = data.len().min(256);
    for j in 0..items[pos].data_len {
        items[pos].data[j] = data[j];
    }

    count + 1
}

/// Remove an item from a sorted items array by key. Returns new count.
pub(crate) fn remove_from_items(
    items: &mut [LeafItem; MAX_LEAF_ITEMS],
    count: usize,
    key: &BTreeKey,
) -> usize {
    for i in 0..count {
        if items[i].key.cmp(key) == core::cmp::Ordering::Equal {
            // Shift left
            for j in i..count - 1 {
                items[j].key = items[j + 1].key;
                items[j].data_len = items[j + 1].data_len;
                items[j].data = items[j + 1].data;
            }
            return count - 1;
        }
    }
    count
}

/// Build a new internal (level>0) node with two children.
pub(crate) fn build_internal_node(
    out_buf: &mut [u8; 4096],
    generation: u64,
    block_nr: u64,
    level: u16,
    left_key: &BTreeKey,
    left_block: u64,
    right_key: &BTreeKey,
    right_block: u64,
) -> bool {
    for b in out_buf.iter_mut() {
        *b = 0;
    }

    unsafe {
        let hdr = &mut *(out_buf.as_mut_ptr() as *mut BTreeNodeHeader);
        hdr.magic = BTREE_NODE_MAGIC;
        hdr.checksum = 0;
        hdr.owner = 0;
        hdr.generation = generation;
        hdr.block_nr = block_nr;
        hdr.num_items = 2;
        hdr.level = level;
        hdr.flags = 0;
    }

    let hdr_size = core::mem::size_of::<BTreeNodeHeader>();
    let ptr_size = core::mem::size_of::<BTreePointer>();

    let left_ptr = BTreePointer {
        key: *left_key,
        block_nr: left_block,
        generation,
    };
    let right_ptr = BTreePointer {
        key: *right_key,
        block_nr: right_block,
        generation,
    };

    unsafe {
        core::ptr::write_unaligned(
            out_buf.as_mut_ptr().add(hdr_size) as *mut BTreePointer,
            left_ptr,
        );
        core::ptr::write_unaligned(
            out_buf.as_mut_ptr().add(hdr_size + ptr_size) as *mut BTreePointer,
            right_ptr,
        );
    }

    let checksum = crc32c_btree_node(out_buf.as_ptr(), 4096);
    unsafe {
        let hdr = &mut *(out_buf.as_mut_ptr() as *mut BTreeNodeHeader);
        hdr.checksum = checksum;
    }
    true
}

/// After a leaf split at non-root depth, insert right_block as a sibling
/// next to left_block in its parent internal node.
/// Walks from SB.root_tree to find the internal node containing left_block,
/// COW-inserts the right pointer, and propagates changes up to root.
fn insert_right_sibling(
    search_root: u64,
    left_block: u64,
    right_key: &BTreeKey,
    right_block: u64,
) -> Option<u64> {
    let ngen = unsafe { (*(&raw const SB)).generation + 1 };

    // Walk tree to find the internal node containing left_block as a child
    let mut path_blocks = [0u64; MAX_BTREE_DEPTH];
    let mut path_indices = [0u32; MAX_BTREE_DEPTH];
    let mut depth = 0usize;
    let mut current_block = search_root;

    let mut found_parent: u64 = 0;
    let mut found_child_idx: usize = 0;

    loop {
        if depth >= MAX_BTREE_DEPTH {
            return None;
        }
        let data = read_block(current_block);
        if data.is_null() {
            return None;
        }
        let hdr = unsafe { &*(data as *const BTreeNodeHeader) };
        if hdr.magic != BTREE_NODE_MAGIC || hdr.level == 0 {
            return None;
        }

        let ptrs_start = unsafe { data.add(core::mem::size_of::<BTreeNodeHeader>()) };
        let ptr_size = core::mem::size_of::<BTreePointer>();
        let num_ptrs = hdr.num_items as usize;

        // Search for left_block among children
        let mut found = false;
        for i in 0..num_ptrs {
            let p = unsafe {
                core::ptr::read_unaligned(ptrs_start.add(i * ptr_size) as *const BTreePointer)
            };
            if p.block_nr == left_block {
                found_parent = current_block;
                found_child_idx = i;
                found = true;
                break;
            }
        }
        if found {
            break;
        }

        // Descend using right_key to guide navigation
        path_blocks[depth] = current_block;
        let mut next_child_idx = 0u32;
        let mut next_child =
            unsafe { core::ptr::read_unaligned(ptrs_start as *const BTreePointer).block_nr };
        for i in 0..num_ptrs {
            let p = unsafe {
                core::ptr::read_unaligned(ptrs_start.add(i * ptr_size) as *const BTreePointer)
            };
            if p.key.cmp(right_key) != core::cmp::Ordering::Greater {
                next_child = p.block_nr;
                next_child_idx = i as u32;
            } else {
                break;
            }
        }
        path_indices[depth] = next_child_idx;
        current_block = next_child;
        depth += 1;
    }

    let parent_block = found_parent;
    let child_idx = found_child_idx;

    // Insert right_key/right_block at position child_idx + 1 in parent
    let parent_data = read_block(parent_block);
    if parent_data.is_null() {
        return None;
    }
    let parent_hdr = unsafe { &*(parent_data as *const BTreeNodeHeader) };
    let num_ptrs = parent_hdr.num_items as usize;
    let ptr_size = core::mem::size_of::<BTreePointer>();
    let hdr_size = core::mem::size_of::<BTreeNodeHeader>();
    let max_ptrs = (4096 - hdr_size) / ptr_size;

    if num_ptrs >= max_ptrs {
        // Internal node is full — extremely rare (>122 children). Fail gracefully.
        return None;
    }

    // COW the parent and insert the pointer
    let new_parent = match cow_copy_block(parent_block) {
        Some(b) => b,
        None => return None,
    };
    let new_parent_data = read_block_mut(new_parent);
    if new_parent_data.is_null() {
        free_block(new_parent);
        return None;
    }

    unsafe {
        let ptrs_start = new_parent_data.add(hdr_size);
        let insert_pos = child_idx + 1;
        // Shift pointers right to make room
        let mut i = num_ptrs;
        while i > insert_pos {
            let src = ptrs_start.add((i - 1) * ptr_size);
            let dst = ptrs_start.add(i * ptr_size) as *mut u8;
            for b in 0..ptr_size {
                *dst.add(b) = *src.add(b);
            }
            i -= 1;
        }
        // Write new pointer
        let new_ptr = BTreePointer {
            key: *right_key,
            block_nr: right_block,
            generation: ngen,
        };
        core::ptr::write_unaligned(
            ptrs_start.add(insert_pos * ptr_size) as *mut BTreePointer,
            new_ptr,
        );
        // Update header
        let hdr = &mut *(new_parent_data as *mut BTreeNodeHeader);
        hdr.num_items = (num_ptrs + 1) as u32;
        hdr.generation = ngen;
        hdr.checksum = 0;
    }
    let checksum = crc32c_btree_node(new_parent_data as *const u8, 4096);
    unsafe {
        let hdr = &mut *(new_parent_data as *mut BTreeNodeHeader);
        hdr.checksum = checksum;
    }
    cache_flush_block(new_parent);

    // Propagate new_parent up — returns the final root without touching SB
    if depth == 0 {
        // parent_block was the root — new_parent replaces it
        free_block(parent_block);
        Some(new_parent)
    } else {
        let prop_path = BTreePath {
            blocks: path_blocks,
            indices: path_indices,
            depth,
        };
        let mut freed = [0u64; MAX_BTREE_DEPTH];
        let mut freed_count = 0usize;
        let final_root =
            match cow_propagate_up(&prop_path, depth, new_parent, &mut freed, &mut freed_count) {
                Some(r) => r,
                None => return None,
            };
        free_block(parent_block);
        for i in 0..freed_count {
            free_block(freed[i]);
        }
        Some(final_root)
    }
}

/// COW B-tree insert with leaf split when leaf is full.
fn btree_cow_insert_split(
    path: &BTreePath,
    items: &mut [LeafItem; MAX_LEAF_ITEMS],
    total_count: usize,
) -> bool {
    let ngen = unsafe { (*(&raw const SB)).generation + 1 };
    let leaf_block = path.blocks[path.depth];

    // Split at midpoint
    let mid = total_count / 2;

    // Allocate two new leaf blocks
    let left_block = match alloc_block() {
        Some(b) => b,
        None => return false,
    };
    let right_block = match alloc_block() {
        Some(b) => b,
        None => {
            free_block(left_block);
            return false;
        }
    };

    // Build left leaf
    let mut left_buf = [0u8; 4096];
    if !rebuild_leaf(&mut left_buf, 0, ngen, left_block, items, mid) {
        free_block(left_block);
        free_block(right_block);
        return false;
    }
    if !write_block(left_block, left_buf.as_ptr()) {
        free_block(left_block);
        free_block(right_block);
        return false;
    }

    // Build right leaf (items[mid..total_count])
    let mut right_items: [LeafItem; MAX_LEAF_ITEMS] = unsafe { core::mem::zeroed() };
    let right_count = total_count - mid;
    for i in 0..right_count {
        right_items[i].key = items[mid + i].key;
        right_items[i].data_len = items[mid + i].data_len;
        right_items[i].data = items[mid + i].data;
    }
    let mut right_buf = [0u8; 4096];
    if !rebuild_leaf(
        &mut right_buf,
        0,
        ngen,
        right_block,
        &right_items,
        right_count,
    ) {
        free_block(left_block);
        free_block(right_block);
        return false;
    }
    if !write_block(right_block, right_buf.as_ptr()) {
        free_block(left_block);
        free_block(right_block);
        return false;
    }

    let left_key = items[0].key;
    let right_key = items[mid].key;

    if path.depth == 0 {
        // Root was a leaf — create new internal root
        let new_root = match alloc_block() {
            Some(b) => b,
            None => {
                free_block(left_block);
                free_block(right_block);
                return false;
            }
        };
        let mut root_buf = [0u8; 4096];
        build_internal_node(
            &mut root_buf,
            ngen,
            new_root,
            1,
            &left_key,
            left_block,
            &right_key,
            right_block,
        );
        if !write_block(new_root, root_buf.as_ptr()) {
            free_block(left_block);
            free_block(right_block);
            free_block(new_root);
            return false;
        }

        free_block(leaf_block);
        unsafe {
            (*(&raw mut SB)).root_tree = new_root;
        }
    } else {
        // Non-root leaf split: propagate left_block up, then insert right_block
        // Both steps must complete before SB is committed.

        // Step 1: Propagate left_block up (replaces old leaf pointer in parent)
        // Do NOT update SB yet — compute new_root only.
        let mut freed = [0u64; MAX_BTREE_DEPTH];
        let mut freed_count = 0usize;
        let new_root =
            match cow_propagate_up(path, path.depth, left_block, &mut freed, &mut freed_count) {
                Some(r) => r,
                None => {
                    free_block(left_block);
                    free_block(right_block);
                    return false;
                }
            };

        // Step 2: Insert right_block into parent using the uncommitted new_root
        let final_root = match insert_right_sibling(new_root, left_block, &right_key, right_block) {
            Some(r) => r,
            None => {
                // Rollback: free new blocks, keep leaf_block intact
                free_block(left_block);
                free_block(right_block);
                free_block(new_root);
                for i in 0..freed_count {
                    free_block(freed[i]);
                }
                return false;
            }
        };

        // Both steps succeeded — now commit: update SB and free old blocks
        free_block(leaf_block);
        unsafe {
            (*(&raw mut SB)).root_tree = final_root;
        }
        for i in 0..freed_count {
            free_block(freed[i]);
        }
    }

    if !bitmap_flush() {
        return false;
    }
    if !write_superblock() {
        return false;
    }
    true
}

/// Insert an item into the B-tree using COW.
pub(crate) fn btree_cow_insert(key: &BTreeKey, data: &[u8]) -> bool {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    let path = match btree_search_path(root_tree, key) {
        Some(p) => p,
        None => return false,
    };

    let leaf_block = path.blocks[path.depth];
    let leaf_data = read_block(leaf_block);
    if leaf_data.is_null() {
        return false;
    }

    // Collect existing items + insert new one
    let mut items: [LeafItem; MAX_LEAF_ITEMS] = unsafe { core::mem::zeroed() };
    let count = collect_leaf_items(leaf_data, &mut items);
    let total_count = insert_into_items(&mut items, count, key, data);

    // Try to fit in a single leaf
    let new_leaf = match alloc_block() {
        Some(b) => b,
        None => return false,
    };

    let ngen = unsafe { (*(&raw const SB)).generation + 1 };
    let mut leaf_buf = [0u8; 4096];
    if !rebuild_leaf(&mut leaf_buf, 0, ngen, new_leaf, &items, total_count) {
        // Leaf is full — need to split
        free_block(new_leaf);
        return btree_cow_insert_split(&path, &mut items, total_count);
    }

    if !write_block(new_leaf, leaf_buf.as_ptr()) {
        free_block(new_leaf);
        return false;
    }

    // COW propagate up
    let mut freed = [0u64; MAX_BTREE_DEPTH];
    let mut freed_count = 0usize;
    let new_root = match cow_propagate_up(&path, path.depth, new_leaf, &mut freed, &mut freed_count)
    {
        Some(r) => r,
        None => return false,
    };

    unsafe {
        (*(&raw mut SB)).root_tree = new_root;
    }

    // Free old blocks
    free_block(leaf_block);
    for i in 0..freed_count {
        free_block(freed[i]);
    }

    if !bitmap_flush() {
        return false;
    }
    if !write_superblock() {
        return false;
    }
    true
}

/// Delete an item from the B-tree using COW.
pub(crate) fn btree_cow_delete(key: &BTreeKey) -> bool {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    let path = match btree_search_path(root_tree, key) {
        Some(p) => p,
        None => return false,
    };

    let leaf_block = path.blocks[path.depth];
    let leaf_data = read_block(leaf_block);
    if leaf_data.is_null() {
        return false;
    }

    let mut items: [LeafItem; MAX_LEAF_ITEMS] = unsafe { core::mem::zeroed() };
    let count = collect_leaf_items(leaf_data, &mut items);
    let new_count = remove_from_items(&mut items, count, key);
    if new_count == count {
        return false; // item not found
    }

    let new_leaf = match alloc_block() {
        Some(b) => b,
        None => return false,
    };

    let ngen = unsafe { (*(&raw const SB)).generation + 1 };
    let mut leaf_buf = [0u8; 4096];
    if !rebuild_leaf(&mut leaf_buf, 0, ngen, new_leaf, &items, new_count) {
        free_block(new_leaf);
        return false;
    }

    if !write_block(new_leaf, leaf_buf.as_ptr()) {
        free_block(new_leaf);
        return false;
    }

    let mut freed = [0u64; MAX_BTREE_DEPTH];
    let mut freed_count = 0usize;
    let new_root = match cow_propagate_up(&path, path.depth, new_leaf, &mut freed, &mut freed_count)
    {
        Some(r) => r,
        None => return false,
    };

    unsafe {
        (*(&raw mut SB)).root_tree = new_root;
    }

    free_block(leaf_block);
    for i in 0..freed_count {
        free_block(freed[i]);
    }

    if !bitmap_flush() {
        return false;
    }
    if !write_superblock() {
        return false;
    }
    true
}

/// Update an existing item's data in the B-tree using COW.
pub(crate) fn btree_cow_update(key: &BTreeKey, data: &[u8]) -> bool {
    let root_tree = unsafe { (*(&raw const SB)).root_tree };
    let path = match btree_search_path(root_tree, key) {
        Some(p) => p,
        None => return false,
    };

    let leaf_block = path.blocks[path.depth];
    let leaf_data = read_block(leaf_block);
    if leaf_data.is_null() {
        return false;
    }

    let mut items: [LeafItem; MAX_LEAF_ITEMS] = unsafe { core::mem::zeroed() };
    let count = collect_leaf_items(leaf_data, &mut items);

    // Find and replace the matching item's data
    let mut found = false;
    for i in 0..count {
        if items[i].key.cmp(key) == core::cmp::Ordering::Equal {
            items[i].data_len = data.len().min(256);
            for j in 0..items[i].data_len {
                items[i].data[j] = data[j];
            }
            found = true;
            break;
        }
    }
    if !found {
        return false;
    }

    let new_leaf = match alloc_block() {
        Some(b) => b,
        None => return false,
    };

    let ngen = unsafe { (*(&raw const SB)).generation + 1 };
    let mut leaf_buf = [0u8; 4096];
    if !rebuild_leaf(&mut leaf_buf, 0, ngen, new_leaf, &items, count) {
        free_block(new_leaf);
        return false;
    }

    if !write_block(new_leaf, leaf_buf.as_ptr()) {
        free_block(new_leaf);
        return false;
    }

    let mut freed = [0u64; MAX_BTREE_DEPTH];
    let mut freed_count = 0usize;
    let new_root = match cow_propagate_up(&path, path.depth, new_leaf, &mut freed, &mut freed_count)
    {
        Some(r) => r,
        None => return false,
    };

    unsafe {
        (*(&raw mut SB)).root_tree = new_root;
    }

    free_block(leaf_block);
    for i in 0..freed_count {
        free_block(freed[i]);
    }

    if !bitmap_flush() {
        return false;
    }
    if !write_superblock() {
        return false;
    }
    true
}
