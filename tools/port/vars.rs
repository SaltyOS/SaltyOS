//! Variable substitution engine
//! SPDX-License-Identifier: GPL-2.0-only

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::config::BuildEnv;
use crate::parser::PortConfig;

/// Work directory for port builds, qualified by target architecture.
///
/// Uses `SALTYOS_ARCH` env var or falls back to build dir name detection.
/// Uses `work-{arch}/` format for all architectures (e.g. `work-x86_64/`).
pub fn work_dir(port_dir: &Path) -> PathBuf {
    let arch = detect_arch();
    port_dir.join(format!("work-{}", arch))
}

fn detect_arch() -> String {
    if let Ok(a) = std::env::var("SALTYOS_ARCH") {
        return a;
    }
    // Infer from -b <build_dir> argument name
    let args: Vec<String> = std::env::args().collect();
    for i in 0..args.len().saturating_sub(1) {
        if args[i] == "-b" && args[i + 1].contains("aarch64") {
            return "aarch64".to_string();
        }
    }
    "x86_64".to_string()
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

/// Distfile name: "{name}-{version}.{ext}" derived from port metadata and URL.
///
/// Uses the port name and version to form a predictable filename, with the
/// extension extracted from the source URL (e.g. `.tar.gz`, `.tgz`).
pub fn distfile_name(port: &PortConfig, url: &str) -> String {
    // Extract extension from URL (handle .tar.gz, .tar.xz, .tar.bz2, .tgz, etc.)
    let url_filename = url.rsplit('/').next().unwrap_or("");
    let ext = if url_filename.contains(".tar.") {
        // e.g. "foo.tar.gz" → ".tar.gz"
        let idx = url_filename.find(".tar.").unwrap();
        &url_filename[idx..]
    } else if let Some(idx) = url_filename.rfind('.') {
        &url_filename[idx..]
    } else {
        ".tar.gz"
    };
    format!("{}-{}{}", port.name, port.version, ext)
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

    // Architecture info — derived from the target triple (e.g. "x86_64-unknown-saltyos")
    let arch = env.salty_host.split('-').next().unwrap_or("x86_64").to_string();
    // FreeBSD machine dir name: x86_64 → amd64, aarch64 → arm64
    let freebsd_machine = match arch.as_str() {
        "x86_64" => "amd64".to_string(),
        "aarch64" => "arm64".to_string(),
        other => other.to_string(),
    };
    vars.insert("ARCH".to_string(), arch.clone());
    vars.insert("MACHINE".to_string(), freebsd_machine.clone());
    vars.insert("MACHINE_INCLUDE".to_string(), format!("{}/include", freebsd_machine));

    // Arch-qualified work/stage directory names (e.g. "work-x86_64", "stage-x86_64")
    // Allows .port files to reference dependency dirs: ${PORTDIR}/../dep/${ARCH_WORK}/...
    vars.insert("ARCH_WORK".to_string(), format!("work-{}", arch));
    vars.insert("ARCH_STAGE".to_string(), format!("stage-{}", arch));

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
