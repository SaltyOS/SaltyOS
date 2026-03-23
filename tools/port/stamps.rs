//! Incremental build stamps
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Each build phase records a stamp file containing an input hash.
//! On re-run, if the hash matches, the phase is skipped.
//! If a phase's inputs change, that stamp and all later stamps are invalidated.

use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use crate::config::BuildEnv;
use crate::parser::PortConfig;
use crate::vars;

/// Ordered list of phases for invalidation cascading
const PHASE_ORDER: &[&str] = &[
    "fetch",
    "extract",
    "patch",
    "prepare",
    "configure",
    "build",
    "stage",
];

pub struct StampManager {
    stamp_dir: PathBuf,
}

impl StampManager {
    pub fn new(port_dir: &Path) -> Self {
        let stamp_dir = vars::work_dir(port_dir).join(".stamps");
        StampManager { stamp_dir }
    }

    /// Check if a phase can be skipped.
    /// Returns true if the stamp matches (skip), false if we need to re-run.
    /// When returning false, invalidates this phase and all later phases.
    pub fn check(&self, phase: &str, input_hash: &str) -> bool {
        let stamp_path = self.stamp_dir.join(phase);
        if let Ok(existing) = fs::read_to_string(&stamp_path) {
            if existing.trim() == input_hash {
                return true;
            }
        }
        // Invalidate this phase and all later ones
        self.invalidate_from(phase);
        false
    }

    /// Record a stamp after successful phase completion
    pub fn write(&self, phase: &str, input_hash: &str) {
        let _ = fs::create_dir_all(&self.stamp_dir);
        let stamp_path = self.stamp_dir.join(phase);
        let _ = fs::write(&stamp_path, input_hash);
    }

    /// Remove stamps for `phase` and all phases after it
    fn invalidate_from(&self, phase: &str) {
        let mut found = false;
        for &p in PHASE_ORDER {
            if p == phase {
                found = true;
            }
            if found {
                let stamp_path = self.stamp_dir.join(p);
                let _ = fs::remove_file(&stamp_path);
            }
        }
    }
}

fn hash_string(s: &str) -> String {
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Hash fetch inputs: URL + expected sha256
pub fn hash_fetch_inputs(port: &PortConfig) -> String {
    hash_string(&format!("{}:{}", port.source_url, port.source_sha256))
}

/// Hash extract inputs: URL (determines the distfile)
pub fn hash_extract_inputs(port: &PortConfig) -> String {
    hash_string(&port.source_url)
}

/// Hash patch inputs: contents of all *.patch files in patches/
pub fn hash_patch_inputs(port_dir: &Path) -> String {
    let patches_dir = port_dir.join("patches");
    if !patches_dir.is_dir() {
        return hash_string("no-patches");
    }

    let mut patches: Vec<PathBuf> = fs::read_dir(&patches_dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "patch").unwrap_or(false))
        .collect();
    patches.sort();

    let mut combined = String::new();
    for p in &patches {
        if let Ok(content) = fs::read_to_string(p) {
            combined.push_str(&content);
        }
    }
    hash_string(&combined)
}

/// Hash prepare inputs: [prepare] script + [autoconf_cache] content
pub fn hash_prepare_inputs(port: &PortConfig) -> String {
    let mut combined = port.prepare_script.clone();
    for (k, v) in &port.autoconf_cache {
        combined.push_str(k);
        combined.push('=');
        combined.push_str(v);
        combined.push('\n');
    }
    hash_string(&combined)
}

/// Hash configure inputs: configure args + CFLAGS + LDFLAGS + targets_cflags
pub fn hash_configure_inputs(port: &PortConfig, env: &BuildEnv) -> String {
    let mut combined = format!("{:?}:{}", port.build_type, port.configure_args.join("|"));
    combined.push_str(&env.cflags);
    combined.push_str(&env.ldflags);
    combined.push_str(&port.targets_cflags);
    hash_string(&combined)
}
