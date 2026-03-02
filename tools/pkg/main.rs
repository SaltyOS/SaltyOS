//! pkg — SaltyOS package tool (host-side)
//! SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::{self, Command};

fn usage() {
    eprintln!("Usage: pkg <command> [options]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  install   Install packages from a local repo into a host staging root");
    eprintln!();
    eprintln!("pkg install options:");
    eprintln!("  --root <dir>            Staging root directory (required)");
    eprintln!("  --repo <dir>            Package repo directory, e.g. build/pkgrepo (required)");
    eprintln!("  --manifest-out <file>   Write mkrootfs-compatible dst=src manifest");
    eprintln!("  --packages-file <file>  Package list file (repeatable, supports @include)");
    eprintln!("  --clean-root            Remove and recreate --root before install");
    eprintln!("  -v, --verbose           Verbose output");
    eprintln!("  <packages...>           Additional package names");
}

#[derive(Debug, Clone)]
struct InstallOptions {
    root: PathBuf,
    repo: PathBuf,
    manifest_out: Option<PathBuf>,
    packages_files: Vec<PathBuf>,
    packages: Vec<String>,
    clean_root: bool,
    verbose: bool,
}

#[derive(Debug, Clone)]
struct RepoPkg {
    name: String,
    version: String,
    arch: String,
    path: PathBuf,
    pkginfo_text: String,
    files_text: String,
    depends: Vec<String>,
}

fn die(msg: impl AsRef<str>) -> ! {
    eprintln!("Error: {}", msg.as_ref());
    process::exit(1);
}

fn parse_args() -> Result<InstallOptions, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        process::exit(1);
    }

    match args[1].as_str() {
        "install" => parse_install_args(&args[2..]),
        "-h" | "--help" | "help" => {
            usage();
            process::exit(0);
        }
        other => Err(format!("Unknown command: {}", other)),
    }
}

fn parse_install_args(args: &[String]) -> Result<InstallOptions, String> {
    let mut root: Option<PathBuf> = None;
    let mut repo: Option<PathBuf> = None;
    let mut manifest_out: Option<PathBuf> = None;
    let mut packages_files = Vec::new();
    let mut packages = Vec::new();
    let mut clean_root = false;
    let mut verbose = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--root" => {
                i += 1;
                if i >= args.len() {
                    return Err("--root requires a path".to_string());
                }
                root = Some(PathBuf::from(&args[i]));
            }
            "--repo" => {
                i += 1;
                if i >= args.len() {
                    return Err("--repo requires a path".to_string());
                }
                repo = Some(PathBuf::from(&args[i]));
            }
            "--manifest-out" => {
                i += 1;
                if i >= args.len() {
                    return Err("--manifest-out requires a path".to_string());
                }
                manifest_out = Some(PathBuf::from(&args[i]));
            }
            "--packages-file" => {
                i += 1;
                if i >= args.len() {
                    return Err("--packages-file requires a path".to_string());
                }
                packages_files.push(PathBuf::from(&args[i]));
            }
            "--clean-root" => clean_root = true,
            "-v" | "--verbose" => verbose = true,
            "-h" | "--help" => {
                usage();
                process::exit(0);
            }
            s if s.starts_with('-') => return Err(format!("Unknown option: {}", s)),
            other => packages.push(other.to_string()),
        }
        i += 1;
    }

    let root = root.ok_or_else(|| "--root is required".to_string())?;
    let repo = repo.ok_or_else(|| "--repo is required".to_string())?;

    Ok(InstallOptions {
        root,
        repo,
        manifest_out,
        packages_files,
        packages,
        clean_root,
        verbose,
    })
}

fn tar_capture_file(pkg: &Path, member_names: &[&str]) -> Result<Option<Vec<u8>>, String> {
    for name in member_names {
        let out = Command::new("tar")
            .arg("-xOf")
            .arg(pkg)
            .arg(name)
            .output()
            .map_err(|e| format!("Failed to run tar for {}: {}", pkg.display(), e))?;
        if out.status.success() {
            return Ok(Some(out.stdout));
        }
    }
    Ok(None)
}

fn tar_list(pkg: &Path) -> Result<Vec<String>, String> {
    let out = Command::new("tar")
        .arg("-tf")
        .arg(pkg)
        .output()
        .map_err(|e| format!("Failed to run tar -tf {}: {}", pkg.display(), e))?;
    if !out.status.success() {
        return Err(format!(
            "tar -tf failed for {} (status {})",
            pkg.display(),
            out.status
        ));
    }
    let s = String::from_utf8(out.stdout)
        .map_err(|e| format!("tar -tf output was not UTF-8 for {}: {}", pkg.display(), e))?;
    Ok(s.lines().map(|l| l.to_string()).collect())
}

fn parse_kv_lines(text: &str) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.entry(k.trim().to_string())
                .or_default()
                .push(v.trim().to_string());
        }
    }
    out
}

fn normalize_dep_name(dep: &str) -> Option<String> {
    let dep = dep.trim();
    if dep.is_empty() {
        return None;
    }
    let mut end = 0;
    for (idx, ch) in dep.char_indices() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '+' || ch == '-' {
            end = idx + ch.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 {
        Some(dep.to_string())
    } else {
        Some(dep[..end].to_string())
    }
}

fn scan_repo(repo_dir: &Path, verbose: bool) -> Result<BTreeMap<String, RepoPkg>, String> {
    if !repo_dir.is_dir() {
        return Err(format!("repo not found: {}", repo_dir.display()));
    }

    let mut pkgs = BTreeMap::new();
    let mut entries: Vec<_> = fs::read_dir(repo_dir)
        .map_err(|e| format!("Cannot read repo {}: {}", repo_dir.display(), e))?
        .flatten()
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.ends_with(".pkg.tar") {
            continue;
        }

        let pkginfo_bytes = tar_capture_file(&path, &["./.PKGINFO", ".PKGINFO"])?
            .ok_or_else(|| format!("{}: missing .PKGINFO", path.display()))?;
        let files_bytes = tar_capture_file(&path, &["./.FILES", ".FILES"])?.unwrap_or_default();

        let pkginfo_text = String::from_utf8(pkginfo_bytes)
            .map_err(|e| format!("{}: .PKGINFO is not UTF-8: {}", path.display(), e))?;
        let files_text = String::from_utf8(files_bytes)
            .map_err(|e| format!("{}: .FILES is not UTF-8: {}", path.display(), e))?;

        let kv = parse_kv_lines(&pkginfo_text);
        let pkgname = kv.get("pkgname").and_then(|v| v.first()).cloned()
            .ok_or_else(|| format!("{}: .PKGINFO missing pkgname", path.display()))?;
        let pkgver = kv.get("pkgver").and_then(|v| v.first()).cloned()
            .ok_or_else(|| format!("{}: .PKGINFO missing pkgver", path.display()))?;
        let arch = kv.get("arch").and_then(|v| v.first()).cloned().unwrap_or_default();
        let depends = kv.get("depend")
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|d| normalize_dep_name(&d))
            .filter(|d| !d.is_empty())
            .collect::<Vec<_>>();

        if pkgs.contains_key(&pkgname) {
            return Err(format!(
                "duplicate package name in repo {}: {}",
                repo_dir.display(),
                pkgname
            ));
        }

        if verbose {
            println!("[pkg] repo: {} {} -> {}", pkgname, pkgver, path.display());
        }

        pkgs.insert(pkgname.clone(), RepoPkg {
            name: pkgname,
            version: pkgver,
            arch,
            path,
            pkginfo_text,
            files_text,
            depends,
        });
    }

    Ok(pkgs)
}

fn load_packages_file_recursive(
    path: &Path,
    verbose: bool,
    stack: &mut Vec<PathBuf>,
    out: &mut Vec<String>,
) -> Result<(), String> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("Cannot get cwd: {}", e))?
            .join(path)
    };
    let path = fs::canonicalize(&path)
        .map_err(|e| format!("package list not found {}: {}", path.display(), e))?;

    if stack.iter().any(|p| p == &path) {
        let mut chain = stack.clone();
        chain.push(path.clone());
        return Err(format!(
            "package list include cycle: {}",
            chain.iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(" -> ")
        ));
    }

    if verbose {
        println!("[pkg] load package list: {}", path.display());
    }

    stack.push(path.clone());
    let content = fs::read_to_string(&path)
        .map_err(|e| format!("Cannot read package list {}: {}", path.display(), e))?;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("@include ") {
            let inc = path.parent().unwrap_or_else(|| Path::new(".")).join(rest.trim());
            load_packages_file_recursive(&inc, verbose, stack, out)?;
            continue;
        }
        out.push(line.to_string());
    }
    stack.pop();
    Ok(())
}

fn resolve_install_order(
    requested: &[String],
    repo: &BTreeMap<String, RepoPkg>,
) -> Result<Vec<RepoPkg>, String> {
    let mut order = Vec::new();
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();

    fn visit(
        name: &str,
        repo: &BTreeMap<String, RepoPkg>,
        visiting: &mut HashSet<String>,
        visited: &mut HashSet<String>,
        order: &mut Vec<RepoPkg>,
    ) -> Result<(), String> {
        if visited.contains(name) {
            return Ok(());
        }
        if !repo.contains_key(name) {
            return Err(format!("package not found in repo: {}", name));
        }
        if !visiting.insert(name.to_string()) {
            return Err(format!("dependency cycle detected involving package: {}", name));
        }
        let pkg = repo.get(name).unwrap();
        for dep in &pkg.depends {
            visit(dep, repo, visiting, visited, order)?;
        }
        visiting.remove(name);
        visited.insert(name.to_string());
        order.push(pkg.clone());
        Ok(())
    }

    for name in requested {
        visit(name, repo, &mut visiting, &mut visited, &mut order)?;
    }
    Ok(order)
}

fn normalize_tar_path(raw: &str) -> Result<Option<PathBuf>, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == "./" {
        return Ok(None);
    }
    let mut s = trimmed;
    while let Some(rest) = s.strip_prefix("./") {
        s = rest;
    }
    if s.is_empty() {
        return Ok(None);
    }
    let p = Path::new(s);
    if p.is_absolute() {
        return Err(format!("absolute path not allowed in package payload: {}", raw));
    }
    let mut normalized = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Normal(c) => normalized.push(c),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!("path traversal not allowed in package payload: {}", raw));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!("invalid path component in package payload: {}", raw));
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Ok(None);
    }
    Ok(Some(normalized))
}

fn extract_package_payload(pkg: &RepoPkg, root: &Path, verbose: bool) -> Result<Vec<PathBuf>, String> {
    let members = tar_list(&pkg.path)?;

    let meta_names = [".PKGINFO", ".FILES", ".SALTYPORT_MANIFEST"];
    let mut payload_entries = Vec::new();
    for raw in &members {
        let is_dir = raw.ends_with('/');
        let Some(rel) = normalize_tar_path(raw)? else {
            continue;
        };
        if rel.parent().unwrap_or_else(|| Path::new(".")) == Path::new(".")
            && meta_names.iter().any(|m| rel == Path::new(m))
        {
            continue;
        }
        if !is_dir {
            payload_entries.push(rel);
        }
    }

    let status = Command::new("tar")
        .arg("-xpf")
        .arg(&pkg.path)
        .arg("-C")
        .arg(root)
        .status()
        .map_err(|e| format!("Failed to run tar extract for {}: {}", pkg.path.display(), e))?;
    if !status.success() {
        return Err(format!(
            "tar extract failed for {} (status {})",
            pkg.path.display(),
            status
        ));
    }

    for meta in meta_names {
        let p = root.join(meta);
        if p.exists() || p.is_symlink() {
            let _ = fs::remove_file(&p);
        }
    }

    if verbose {
        println!("[pkg] installed {} ({} payload entries)", pkg.name, payload_entries.len());
    }
    Ok(payload_entries)
}

fn write_local_db(root: &Path, pkg: &RepoPkg, installed_payload: &[PathBuf]) -> Result<(), String> {
    let db_dir = root.join("var/lib/pkg/local").join(&pkg.name);
    fs::create_dir_all(&db_dir)
        .map_err(|e| format!("Cannot create local pkg DB dir {}: {}", db_dir.display(), e))?;

    fs::write(db_dir.join("PKGINFO"), &pkg.pkginfo_text)
        .map_err(|e| format!("Cannot write PKGINFO for {}: {}", pkg.name, e))?;

    let mut files_text = String::new();
    let mut sorted = installed_payload.to_vec();
    sorted.sort();
    sorted.dedup();
    for rel in sorted {
        files_text.push_str(&rel.to_string_lossy());
        files_text.push('\n');
    }
    if !pkg.files_text.is_empty() {
        // Keep package-provided file list under a separate file for debugging/compat.
        fs::write(db_dir.join("PKG_FILES_RAW"), &pkg.files_text)
            .map_err(|e| format!("Cannot write PKG_FILES_RAW for {}: {}", pkg.name, e))?;
    }
    fs::write(db_dir.join("FILES"), files_text)
        .map_err(|e| format!("Cannot write FILES for {}: {}", pkg.name, e))?;

    Ok(())
}

fn collect_manifest_entries_recursive(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) -> Result<(), String> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| format!("Cannot read directory {}: {}", dir.display(), e))?
        .flatten()
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| format!("Cannot stat {}: {}", path.display(), e))?;
        if meta.is_dir() {
            collect_manifest_entries_recursive(root, &path, out)?;
            continue;
        }
        if meta.file_type().is_symlink() {
            return Err(format!(
                "root staging contains symlink (mkrootfs path manifest cannot encode symlink yet): {}",
                path.display()
            ));
        }
        if !meta.is_file() {
            return Err(format!("unsupported file type in root staging: {}", path.display()));
        }
        let rel = path.strip_prefix(root)
            .map_err(|e| format!("Cannot relativize {}: {}", path.display(), e))?;
        let dst = format!("/{}", rel.to_string_lossy().replace('\\', "/"));
        let src = fs::canonicalize(&path)
            .map_err(|e| format!("Cannot canonicalize {}: {}", path.display(), e))?
            .display()
            .to_string();
        out.push((dst, src));
    }
    Ok(())
}

fn write_manifest(path: &Path, entries: &[(String, String)]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create directory {}: {}", parent.display(), e))?;
    }
    let mut text = String::new();
    for (dst, src) in entries {
        text.push_str(dst);
        text.push('=');
        text.push_str(src);
        text.push('\n');
    }
    fs::write(path, text)
        .map_err(|e| format!("Cannot write manifest {}: {}", path.display(), e))
}

fn cmd_install(opts: InstallOptions) -> Result<(), String> {
    let cwd = std::env::current_dir().map_err(|e| format!("Cannot get cwd: {}", e))?;
    let root = if opts.root.is_absolute() { opts.root } else { cwd.join(opts.root) };
    let repo = if opts.repo.is_absolute() { opts.repo } else { cwd.join(opts.repo) };
    let manifest_out = opts.manifest_out.map(|p| if p.is_absolute() { p } else { cwd.join(p) });

    let mut requested = Vec::new();
    for list_file in &opts.packages_files {
        load_packages_file_recursive(list_file, opts.verbose, &mut Vec::new(), &mut requested)?;
    }
    for p in opts.packages {
        let s = p.trim();
        if !s.is_empty() {
            requested.push(s.to_string());
        }
    }
    if requested.is_empty() {
        return Err("no packages requested (use positional names or --packages-file)".to_string());
    }

    if opts.clean_root && root.exists() {
        fs::remove_dir_all(&root)
            .map_err(|e| format!("Cannot remove root {}: {}", root.display(), e))?;
    }
    fs::create_dir_all(&root)
        .map_err(|e| format!("Cannot create root {}: {}", root.display(), e))?;

    let repo_pkgs = scan_repo(&repo, opts.verbose)?;
    let order = resolve_install_order(&requested, &repo_pkgs)?;

    if opts.verbose {
        let names = order.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", ");
        println!("[pkg] install order: {}", names);
    }

    for pkg in &order {
        let installed = extract_package_payload(pkg, &root, opts.verbose)?;
        write_local_db(&root, pkg, &installed)?;
    }

    if let Some(manifest_path) = &manifest_out {
        let mut entries = Vec::new();
        collect_manifest_entries_recursive(&root, &root, &mut entries)?;
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        write_manifest(manifest_path, &entries)?;
        if opts.verbose {
            println!(
                "[pkg] wrote rootfs manifest: {} ({} files)",
                manifest_path.display(),
                entries.len()
            );
        }
    }

    println!("pkg: installed {} package(s) into {}", order.len(), root.display());
    Ok(())
}

fn main() {
    match parse_args().and_then(cmd_install) {
        Ok(()) => {}
        Err(e) => die(e),
    }
}
