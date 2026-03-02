//! Extract phase
//! SPDX-License-Identifier: GPL-2.0-only

use std::path::Path;
use std::process::Command;

use crate::config::BuildEnv;
use crate::parser::PortConfig;
use crate::vars;

pub fn do_extract(port: &PortConfig, port_dir: &Path, env: &BuildEnv) -> Result<(), String> {
    let var_map = vars::build_var_map(port, port_dir, env);
    let url = vars::substitute(&port.source_url, &var_map);

    if url.is_empty() {
        return Ok(());
    }

    let filename = url
        .rsplit('/')
        .next()
        .ok_or_else(|| "Cannot determine filename from URL".to_string())?;

    let distfile = vars::distfiles_dir(port_dir).join(filename);
    if !distfile.exists() {
        return Err(format!("Source file not found: {}", distfile.display()));
    }

    if let Some(src_dir) = vars::resolve_source_dir(port, port_dir) {
        if src_dir.is_dir() {
            if env.verbose {
                println!("   Already extracted: {}", src_dir.display());
            }
            return Ok(());
        }
    }

    let work_dir = vars::work_dir(port_dir);
    std::fs::create_dir_all(&work_dir)
        .map_err(|e| format!("Cannot create work/: {}", e))?;

    if env.verbose {
        println!("   Extracting: {}", distfile.display());
    }

    let mut cmd = Command::new("tar");
    cmd.arg("xf").arg(&distfile).current_dir(&work_dir);

    let status = cmd
        .status()
        .map_err(|e| format!("Failed to run tar: {}", e))?;

    if !status.success() {
        return Err(format!("tar extraction failed with status {}", status));
    }

    Ok(())
}
