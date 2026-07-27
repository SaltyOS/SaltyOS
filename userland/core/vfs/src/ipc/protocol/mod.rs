// SPDX-License-Identifier: GPL-2.0-only
//
//! Protocol label namespaces. Three disjoint hex blocks: the
//! client-facing public set, the backend-facing wire, and the
//! mmsrv pager callback labels. Each lives in its own module so
//! the in-tree dispatcher can `match` on a tight numeric set
//! without false sharing across boundaries.

pub(crate) mod backend;
pub(crate) mod correlation;
pub(crate) mod public;
