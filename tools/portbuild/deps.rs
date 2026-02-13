//! Dependency resolver (stub for future use)
//! SPDX-License-Identifier: GPL-2.0-only

use crate::parser::PortConfig;

/// Check if all build dependencies are satisfied.
/// Currently a no-op stub — returns Ok for any port.
pub fn check_deps(_port: &PortConfig, _available: &[String]) -> Result<(), String> {
    // Future: topological sort, check ports are built
    Ok(())
}
