//! VSpace COW frame pool management — stub module.
//!
//! With MO-based COW, the kernel handles COW resolution internally via the
//! MemoryObject hidden node. The SPSC ring pool infrastructure is no longer
//! needed. init_pool and teardown_pool are retained as no-ops to avoid
//! breaking callers during the transition.

use crate::types::MmClient;
use trona::types::Cap;

/// No-op: MO-based COW does not need a userspace frame pool.
pub(crate) unsafe fn init_pool(_client: *mut MmClient) -> bool {
    true
}

/// No-op: MO-based COW does not need pool teardown.
pub(crate) unsafe fn teardown_pool(_vspace_cap: Cap) {
}
