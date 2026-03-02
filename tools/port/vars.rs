//! Variable substitution engine
//! SPDX-License-Identifier: GPL-2.0-only

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::config::BuildEnv;
use crate::parser::PortConfig;

pub fn work_dir(port_dir: &Path) -> PathBuf {
    port_dir.join("work")
}

/// Shared distfiles directory: ports/distfiles/ (sibling to port dirs)
pub fn distfiles_dir(port_dir: &Path) -> PathBuf {
    port_dir
        .parent()
        .unwrap_or(port_dir)
        .join("distfiles")
}

fn preferred_source_subdir(port: &PortConfig) -> String {
    let default = format!("{}-{}", port.name, port.version);
    if port.source_subdir.trim().is_empty() {
        return default;
    }

    let mut vars = HashMap::new();
    vars.insert("name".to_string(), port.name.clone());
    vars.insert("version".to_string(), port.version.clone());

    let resolved = substitute(&port.source_subdir, &vars)
        .trim()
        .trim_matches('/')
        .to_string();
    if resolved.is_empty() {
        default
    } else {
        resolved
    }
}

pub fn preferred_source_dir(port: &PortConfig, port_dir: &Path) -> PathBuf {
    work_dir(port_dir).join(preferred_source_subdir(port))
}

pub fn resolve_source_dir(port: &PortConfig, port_dir: &Path) -> Option<PathBuf> {
    let work = work_dir(port_dir);
    if !work.is_dir() {
        return None;
    }

    let preferred = preferred_source_dir(port, port_dir);
    if preferred.is_dir() {
        return Some(preferred);
    }

    let default = work.join(format!("{}-{}", port.name, port.version));
    if default != preferred && default.is_dir() {
        return Some(default);
    }

    let mut dirs = Vec::new();
    let entries = std::fs::read_dir(&work).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() && !name.to_string_lossy().starts_with('.') {
            dirs.push(path);
        }
    }

    if dirs.len() == 1 {
        dirs.pop()
    } else {
        None
    }
}

/// Build a variable map from port config and environment
pub fn build_var_map(port: &PortConfig, port_dir: &Path, env: &BuildEnv) -> HashMap<String, String> {
    let mut vars = HashMap::new();

    // From [port] section
    vars.insert("name".to_string(), port.name.clone());
    vars.insert("version".to_string(), port.version.clone());

    // Directories
    let work = work_dir(port_dir);
    let src = resolve_source_dir(port, port_dir)
        .unwrap_or_else(|| preferred_source_dir(port, port_dir));
    let source_subdir = src
        .strip_prefix(&work)
        .ok()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| preferred_source_subdir(port));

    vars.insert("WORKDIR".to_string(), work.to_string_lossy().to_string());
    vars.insert("SRCDIR".to_string(), src.to_string_lossy().to_string());
    vars.insert("SOURCE_SUBDIR".to_string(), source_subdir);
    vars.insert("PORTDIR".to_string(), port_dir.to_string_lossy().to_string());
    vars.insert("BUILDDIR".to_string(), env.build_root.to_string_lossy().to_string());

    // Cross-compile info
    vars.insert("SALTY_HOST".to_string(), env.salty_host.clone());
    vars.insert("SALTY_INC".to_string(), env.salty_inc.to_string_lossy().to_string());
    vars.insert("NPROC".to_string(), env.nproc.to_string());

    // Project and toolchain paths
    let project_root = env.build_root.parent().unwrap_or(&env.build_root);
    vars.insert("REPOROOT".to_string(), project_root.to_string_lossy().to_string());

    let sysroot = env.build_root.join("sysroot");
    vars.insert("SYSROOT".to_string(), sysroot.to_string_lossy().to_string());

    vars.insert("CXX".to_string(), env.cxx.clone());
    vars.insert("TOOLCHAIN_PREFIX".to_string(), env.toolchain_prefix.to_string_lossy().to_string());

    vars
}

/// Replace all ${var} occurrences in a string
pub fn substitute(s: &str, vars: &HashMap<String, String>) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if i + 1 < len && bytes[i] == b'$' && bytes[i + 1] == b'{' {
            // Find closing brace
            if let Some(end) = s[i + 2..].find('}') {
                let var_name = &s[i + 2..i + 2 + end];
                if let Some(value) = vars.get(var_name) {
                    result.push_str(value);
                } else {
                    // Keep unresolved variables as-is
                    result.push_str(&s[i..i + 2 + end + 1]);
                }
                i += 2 + end + 1;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }

    result
}

/// Substitute variables in a list of strings
pub fn substitute_list(items: &[String], vars: &HashMap<String, String>) -> Vec<String> {
    items.iter().map(|s| substitute(s, vars)).collect()
}
