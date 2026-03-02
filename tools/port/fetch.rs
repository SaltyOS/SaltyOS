//! Fetch and checksum phases
//! SPDX-License-Identifier: GPL-2.0-only

use std::path::Path;
use std::process::Command;

use crate::config::BuildEnv;
use crate::parser::PortConfig;
use crate::vars;

pub fn do_fetch(port: &PortConfig, port_dir: &Path, env: &BuildEnv) -> Result<(), String> {
    let var_map = vars::build_var_map(port, port_dir, env);
    let url = vars::substitute(&port.source_url, &var_map);

    if url.is_empty() {
        return Ok(()); // No source to fetch
    }

    let distfiles = vars::distfiles_dir(port_dir);
    std::fs::create_dir_all(&distfiles)
        .map_err(|e| format!("Cannot create distfiles/: {}", e))?;

    // Extract filename from URL
    let filename = url
        .rsplit('/')
        .next()
        .ok_or_else(|| "Cannot determine filename from URL".to_string())?;

    let target = distfiles.join(filename);

    if target.exists() {
        if env.verbose {
            println!("   Already downloaded: {}", target.display());
        }
        return Ok(());
    }

    if env.verbose {
        println!("   Downloading: {}", url);
    }

    let status = Command::new("curl")
        .args(["-fSL", "-o"])
        .arg(&target)
        .arg(&url)
        .status()
        .map_err(|e| format!("Failed to run curl: {}", e))?;

    if !status.success() {
        return Err(format!("curl failed with status {}", status));
    }

    Ok(())
}

pub fn do_checksum(port: &PortConfig, port_dir: &Path, env: &BuildEnv) -> Result<(), String> {
    if port.source_sha256 == "SKIP" || port.source_sha256.is_empty() {
        return Ok(());
    }

    let var_map = vars::build_var_map(port, port_dir, env);
    let url = vars::substitute(&port.source_url, &var_map);

    let distfiles = vars::distfiles_dir(port_dir);
    let filename = url
        .rsplit('/')
        .next()
        .ok_or_else(|| "Cannot determine filename from URL".to_string())?;

    let target = distfiles.join(filename);
    if !target.exists() {
        return Err(format!("Source file not found: {}", target.display()));
    }

    let output = Command::new("sha256sum")
        .arg(&target)
        .output()
        .map_err(|e| format!("Failed to run sha256sum: {}", e))?;

    if !output.status.success() {
        return Err("sha256sum failed".to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let computed = stdout
        .split_whitespace()
        .next()
        .ok_or_else(|| "Cannot parse sha256sum output".to_string())?;

    if computed != port.source_sha256 {
        return Err(format!(
            "Checksum mismatch:\n  expected: {}\n  got:      {}",
            port.source_sha256, computed
        ));
    }

    Ok(())
}
