//! Build phases: prepare, configure, build, stage, package
//! SPDX-License-Identifier: GPL-2.0-only

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::BuildEnv;
use crate::parser::{BuildType, PortConfig};
use crate::vars;

fn validate_install_path(install_path: &str) -> Result<(), String> {
    if install_path.is_empty() {
        return Err("Install path is empty".to_string());
    }

    let path = Path::new(install_path);
    if path.is_absolute() {
        return Err(format!(
            "Install path must be relative to package/rootfs, got absolute path: {}",
            install_path
        ));
    }

    for comp in path.components() {
        match comp {
            Component::Normal(_) => {}
            Component::CurDir => {
                return Err(format!(
                    "Install path must not contain '.' segments: {}",
                    install_path
                ));
            }
            Component::ParentDir => {
                return Err(format!(
                    "Install path must not contain '..' segments: {}",
                    install_path
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "Install path contains invalid root/prefix component: {}",
                    install_path
                ));
            }
        }
    }

    Ok(())
}

fn package_arch(env: &BuildEnv) -> &str {
    env.salty_host.split('-').next().unwrap_or(&env.salty_host)
}

fn sanitize_pkg_component(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '+' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Shell-quote a string if it contains characters that need quoting
fn shell_quote(s: &str) -> String {
    if s.contains(' ') || s.contains('\'') || s.contains('"') || s.contains('$') || s.contains('\\') {
        format!("'{}'", s.replace('\'', "'\\''"))
    } else {
        s.to_string()
    }
}

/// Run a shell command in a given directory with env vars
fn run_shell(
    cmd_str: &str,
    cwd: &Path,
    env_vars: &HashMap<String, String>,
    verbose: bool,
) -> Result<(), String> {
    if verbose {
        println!("   $ {}", cmd_str);
    }

    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(cmd_str).current_dir(cwd);

    for (k, v) in env_vars {
        cmd.env(k, v);
    }

    let status = cmd
        .status()
        .map_err(|e| format!("Failed to execute shell: {}", e))?;

    if !status.success() {
        return Err(format!("Command failed (status {}): {}", status, cmd_str));
    }

    Ok(())
}

/// Build cross-compile environment variables, with optional per-port overrides
fn cross_env(
    env: &BuildEnv,
    overrides: &HashMap<String, String>,
    var_map: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut vars = HashMap::new();

    vars.insert("CC".to_string(), env.cc.clone());
    vars.insert("CXX".to_string(), env.cxx.clone());
    vars.insert("CFLAGS".to_string(), env.cflags.clone());
    // Autotools preprocessor probes often run $CPP directly without
    // appending $CFLAGS, so bake target/sysroot flags into CPP/CXXCPP.
    vars.insert("CPP".to_string(), format!("{} {} -E", env.cc, env.cflags));
    vars.insert("CXXCPP".to_string(), format!("{} {} -E", env.cxx, env.cflags));
    vars.insert("LDFLAGS".to_string(), env.ldflags.clone());
    vars.insert("LIBS".to_string(), env.libs.clone());
    vars.insert("AR".to_string(), env.ar.clone());
    vars.insert("RANLIB".to_string(), env.ranlib.clone());
    vars.insert("STRIP".to_string(), env.strip.clone());

    // Host build tools (mkbuiltins, mksyntax, etc.) must use native compiler
    vars.insert("CC_FOR_BUILD".to_string(), "cc".to_string());
    vars.insert("CFLAGS_FOR_BUILD".to_string(), String::new());
    vars.insert("LDFLAGS_FOR_BUILD".to_string(), String::new());

    // Prevent autotools from trying to run target binaries
    vars.insert("cross_compiling".to_string(), "yes".to_string());

    // Apply per-port environment overrides from [env] section,
    // substituting ${BUILDDIR}, ${SRCDIR} etc. in values.
    for (k, v) in overrides {
        vars.insert(k.clone(), vars::substitute(v, var_map));
    }

    // Support EXTRA_CFLAGS / EXTRA_LDFLAGS / EXTRA_LIBS: append to the
    // computed value instead of replacing it.  This lets port files add
    // flags (e.g. -std=gnu89) without duplicating the base cross-compile
    // flags that the port tool computes from the project layout.
    for (extra_key, base_key) in [
        ("EXTRA_CFLAGS", "CFLAGS"),
        ("EXTRA_LDFLAGS", "LDFLAGS"),
        ("EXTRA_LIBS", "LIBS"),
    ] {
        if let Some(extra) = vars.remove(extra_key) {
            if let Some(base) = vars.get_mut(base_key) {
                base.push(' ');
                base.push_str(&extra);
            }
        }
    }

    vars
}

/// Generate config.cache from [autoconf_cache] entries
pub fn generate_config_cache(port: &PortConfig, port_dir: &Path, env: &BuildEnv) -> Result<(), String> {
    if port.autoconf_cache.is_empty() {
        return Ok(());
    }

    let src = vars::resolve_source_dir(port, port_dir)
        .unwrap_or_else(|| vars::preferred_source_dir(port, port_dir));

    if !src.exists() {
        return Err(format!("Source directory not found: {}", src.display()));
    }

    let mut content = String::new();
    for (key, value) in &port.autoconf_cache {
        let _ = writeln!(content, "{}=${{{}={}}}", key, key, value);
    }

    fs::write(src.join("config.cache"), &content)
        .map_err(|e| format!("Cannot write config.cache: {}", e))?;

    if env.verbose {
        println!("   Generated config.cache ({} entries)", port.autoconf_cache.len());
    }

    Ok(())
}

/// Apply patches from patches/ directory (sorted, -p1)
pub fn do_patch(port: &PortConfig, port_dir: &Path, env: &BuildEnv) -> Result<(), String> {
    let patches_dir = port_dir.join("patches");
    if !patches_dir.is_dir() {
        return Ok(());
    }

    let mut patches: Vec<std::path::PathBuf> = fs::read_dir(&patches_dir)
        .map_err(|e| format!("Cannot read patches/: {}", e))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "patch").unwrap_or(false))
        .collect();
    patches.sort();

    if patches.is_empty() {
        return Ok(());
    }

    let src = vars::resolve_source_dir(port, port_dir)
        .unwrap_or_else(|| vars::preferred_source_dir(port, port_dir));

    if !src.exists() {
        return Err(format!("Source directory not found: {}", src.display()));
    }

    for patch in &patches {
        if env.verbose {
            println!("   Applying: {}", patch.file_name().unwrap_or_default().to_string_lossy());
        }

        let output = Command::new("patch")
            .args(["-p1", "--forward", "-i"])
            .arg(patch)
            .current_dir(&src)
            .output()
            .map_err(|e| format!("Failed to run patch: {}", e))?;

        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // If every hunk was already applied, that's fine — skip it
            if stdout.contains("Reversed (or previously applied) patch detected") {
                if env.verbose {
                    println!("   Already applied, skipping.");
                }
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(format!(
                    "patch -p1 failed for {}:\n{}\n{}",
                    patch.display(), stdout, stderr
                ));
            }
        }
    }

    Ok(())
}

pub fn do_prepare(port: &PortConfig, port_dir: &Path, env: &BuildEnv) -> Result<(), String> {
    if port.prepare_script.is_empty() {
        return Ok(());
    }

    let var_map = vars::build_var_map(port, port_dir, env);
    let script = vars::substitute(&port.prepare_script, &var_map);
    let src = vars::resolve_source_dir(port, port_dir)
        .unwrap_or_else(|| vars::preferred_source_dir(port, port_dir));

    if !src.exists() {
        return Err(format!("Source directory not found: {}", src.display()));
    }

    let cross_vars = cross_env(env, &port.env_overrides, &var_map);
    run_shell(&script, &src, &cross_vars, env.verbose)
}

pub fn do_configure(port: &PortConfig, port_dir: &Path, env: &BuildEnv) -> Result<(), String> {
    let src = vars::resolve_source_dir(port, port_dir)
        .unwrap_or_else(|| vars::preferred_source_dir(port, port_dir));
    if !src.exists() {
        return Err(format!("Source directory not found: {}", src.display()));
    }

    let var_map = vars::build_var_map(port, port_dir, env);
    let cross_vars = cross_env(env, &port.env_overrides, &var_map);

    match port.build_type {
        BuildType::Autotools => {
            // Check if already configured
            if src.join("Makefile").exists() && src.join("config.status").exists() {
                if env.verbose {
                    println!("   Already configured (Makefile exists)");
                }
                return Ok(());
            }

            let configure = src.join("configure");
            if !configure.exists() {
                return Err(format!(
                    "configure script not found: {}",
                    configure.display()
                ));
            }

            let mut args = vec![
                format!("--host={}", env.autotools_host),
                "--prefix=/usr".to_string(),
            ];

            let substituted_args = vars::substitute_list(&port.configure_args, &var_map);
            args.extend(substituted_args);

            let cmd_str = format!("./configure {}", args.join(" "));
            run_shell(&cmd_str, &src, &cross_vars, env.verbose)
        }
        BuildType::CMake => {
            let build = src.join("_build");
            fs::create_dir_all(&build)
                .map_err(|e| format!("Cannot create build dir: {}", e))?;

            let mut args = vec![
                format!("-DCMAKE_C_COMPILER={}", env.cc),
                format!("-DCMAKE_CXX_COMPILER={}", env.cxx),
                format!("-DCMAKE_C_FLAGS={}", env.cflags),
                format!("-DCMAKE_EXE_LINKER_FLAGS={}", env.ldflags),
                "-DCMAKE_INSTALL_PREFIX=/usr".to_string(),
            ];

            let substituted_args = vars::substitute_list(&port.configure_args, &var_map);
            args.extend(substituted_args);

            let quoted: Vec<String> = args.iter().map(|a| shell_quote(a)).collect();
            let cmd_str = format!("cmake {} ..", quoted.join(" "));
            run_shell(&cmd_str, &build, &cross_vars, env.verbose)
        }
        BuildType::Make | BuildType::Custom | BuildType::Targets => {
            // No configure step
            Ok(())
        }
        BuildType::Meson => {
            let cmd_str = format!(
                "meson setup _build --cross-file={}",
                "cross.ini"
            );
            run_shell(&cmd_str, &src, &cross_vars, env.verbose)
        }
    }
}

pub fn do_build(port: &PortConfig, port_dir: &Path, env: &BuildEnv) -> Result<(), String> {
    let src = vars::resolve_source_dir(port, port_dir)
        .unwrap_or_else(|| vars::preferred_source_dir(port, port_dir));
    if !src.exists() {
        return Err(format!("Source directory not found: {}", src.display()));
    }

    let var_map = vars::build_var_map(port, port_dir, env);
    let cross_vars = cross_env(env, &port.env_overrides, &var_map);

    match port.build_type {
        BuildType::Autotools | BuildType::Make | BuildType::Custom => {
            let cmd_str = format!("make -j{}", env.nproc);
            run_shell(&cmd_str, &src, &cross_vars, env.verbose)
        }
        BuildType::CMake => {
            let cmd_str = format!("cmake --build _build -j {}", env.nproc);
            run_shell(&cmd_str, &src, &cross_vars, env.verbose)
        }
        BuildType::Meson => {
            let cmd_str = "meson compile -C _build".to_string();
            run_shell(&cmd_str, &src, &cross_vars, env.verbose)
        }
        BuildType::Targets => {
            do_build_targets(port, port_dir, env)
        }
    }
}

/// Direct compilation for [targets] build type — no Makefile needed
pub fn do_build_targets(port: &PortConfig, port_dir: &Path, env: &BuildEnv) -> Result<(), String> {
    let src = vars::resolve_source_dir(port, port_dir)
        .unwrap_or_else(|| vars::preferred_source_dir(port, port_dir));
    if !src.exists() {
        return Err(format!("Source directory not found: {}", src.display()));
    }

    let out_dir = src.join(".salty-build");
    fs::create_dir_all(&out_dir)
        .map_err(|e| format!("Cannot create .salty-build/: {}", e))?;

    let var_map = vars::build_var_map(port, port_dir, env);
    let cross_vars = cross_env(env, &port.env_overrides, &var_map);
    let common_cflags = vars::substitute(&port.targets_cflags, &var_map);

    for target in &port.targets {
        let sources: Vec<String> = target
            .sources
            .iter()
            .map(|s| {
                let substituted = vars::substitute(s, &var_map);
                src.join(&substituted).to_string_lossy().to_string()
            })
            .collect();

        let extra = vars::substitute_list(&target.extra_flags, &var_map);

        let out_path = out_dir.join(&target.name);

        // Ensure parent directory exists (e.g. .salty-build/bin/)
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create output dir: {}", e))?;
        }

        let cflags = cross_vars.get("CFLAGS").cloned().unwrap_or_default();
        let ldflags = cross_vars.get("LDFLAGS").cloned().unwrap_or_default();
        let libs = cross_vars.get("LIBS").cloned().unwrap_or_default();

        let cmd_str = format!(
            "{cc} {cflags} {tcflags} {extra} {ldflags} -o {out} {srcs} {libs}",
            cc = env.cc,
            cflags = cflags,
            tcflags = common_cflags,
            extra = extra.join(" "),
            ldflags = ldflags,
            out = out_path.display(),
            srcs = sources.join(" "),
            libs = libs,
        );

        if env.verbose {
            println!("   [{}]", target.name);
        }
        run_shell(&cmd_str, &src, &cross_vars, env.verbose)?;
    }

    Ok(())
}

pub fn do_stage(
    port: &PortConfig,
    port_dir: &Path,
    output_dir: &Path,
    env: &BuildEnv,
) -> Result<(), String> {
    if port.install_map.is_empty() {
        return Err("No [install] mappings defined".to_string());
    }

    let var_map = vars::build_var_map(port, port_dir, env);
    let src = vars::resolve_source_dir(port, port_dir)
        .unwrap_or_else(|| vars::preferred_source_dir(port, port_dir));
    let stage_dir = port_dir.join("stage");
    fs::create_dir_all(&stage_dir)
        .map_err(|e| format!("Cannot create stage/: {}", e))?;

    // Port-specific output directory: output_dir/<port_name>/
    let port_out = output_dir.join(&port.name);
    fs::create_dir_all(&port_out)
        .map_err(|e| format!("Cannot create port output dir: {}", e))?;

    let mut manifest = String::new();

    for (install_path_raw, artifact_ref) in &port.install_map {
        let install_path = vars::substitute(install_path_raw, &var_map);
        let artifact = vars::substitute(artifact_ref, &var_map);
        validate_install_path(&install_path)?;

        // Resolve source artifact based on build type
        let src_file = match port.build_type {
            BuildType::Targets => src.join(".salty-build").join(&artifact),
            _ => src.join(&artifact),
        };

        if !src_file.exists() {
            return Err(format!("Install source not found: {}", src_file.display()));
        }

        // Preserve install path in output: port_out/<install_path>
        let output_target = port_out.join(&install_path);
        if let Some(parent) = output_target.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create output subdir: {}", e))?;
        }

        // Stage with same path structure
        let stage_target = stage_dir.join(&install_path);
        if let Some(parent) = stage_target.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create stage subdir: {}", e))?;
        }

        fs::copy(&src_file, &stage_target)
            .map_err(|e| format!("Cannot copy to stage: {}", e))?;

        // Strip with llvm-strip (use --strip-debug for .a archives to preserve symbol tables)
        let strip_flag = if install_path.ends_with(".a") {
            "--strip-debug"
        } else {
            "--strip-all"
        };
        let strip_status = Command::new(&env.strip)
            .args([strip_flag, "-o"])
            .arg(&output_target)
            .arg(&stage_target)
            .status();

        match strip_status {
            Ok(s) if s.success() => {
                if env.verbose {
                    println!("   {} -> {}/{}", install_path, port.name, install_path);
                }
            }
            _ => {
                // If strip fails, just copy unstripped
                fs::copy(&stage_target, &output_target)
                    .map_err(|e| format!("Cannot copy to output: {}", e))?;
                if env.verbose {
                    println!("   {} -> {}/{} (unstripped)", install_path, port.name, install_path);
                }
            }
        }

        // Manifest entry: install_path=port_name/install_path
        let _ = writeln!(manifest, "{}={}/{}", install_path, port.name, install_path);
    }

    // Write manifest file
    let manifest_path = output_dir.join(format!("{}.manifest", port.name));
    fs::write(&manifest_path, &manifest)
        .map_err(|e| format!("Cannot write manifest: {}", e))?;

    if env.verbose {
        println!("   Manifest: {}", manifest_path.display());
    }

    Ok(())
}

pub fn do_package(
    port: &PortConfig,
    port_dir: &Path,
    output_dir: &Path,
    env: &BuildEnv,
) -> Result<(), String> {
    let port_out = output_dir.join(&port.name);
    if !port_out.is_dir() {
        return Err(format!(
            "Port output directory not found (run stage/build first): {}",
            port_out.display()
        ));
    }

    let manifest_path = output_dir.join(format!("{}.manifest", port.name));
    if !manifest_path.is_file() {
        return Err(format!(
            "Port manifest not found (run stage/build first): {}",
            manifest_path.display()
        ));
    }

    let mut port_manifest = fs::read_to_string(&manifest_path)
        .map_err(|e| format!("Cannot read manifest {}: {}", manifest_path.display(), e))?;
    let mut rel_files: Vec<PathBuf> = Vec::new();
    let mut total_size: u64 = 0;
    for (lineno, raw_line) in port_manifest.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let (install_path_raw, output_ref) = line.split_once('=').ok_or_else(|| {
            format!(
                "Invalid manifest entry in {}:{}: expected dst=src, got '{}'",
                manifest_path.display(),
                lineno + 1,
                line
            )
        })?;
        let install_path = install_path_raw.trim();
        validate_install_path(install_path)?;
        let output_ref = output_ref.trim();
        let expected_prefix = format!("{}/", port.name);
        if !output_ref.starts_with(&expected_prefix) {
            return Err(format!(
                "Manifest {}:{} has unexpected source '{}'; expected prefix '{}'",
                manifest_path.display(),
                lineno + 1,
                output_ref,
                expected_prefix
            ));
        }
        let payload_file = port_out.join(install_path);
        let meta = fs::symlink_metadata(&payload_file).map_err(|e| {
            format!(
                "Packaged file listed in manifest not found: {} ({})",
                payload_file.display(),
                e
            )
        })?;
        if !meta.is_file() {
            return Err(format!(
                "Unsupported packaged file type (only regular files supported): {}",
                payload_file.display()
            ));
        }
        total_size += meta.len();
        rel_files.push(PathBuf::from(install_path));
    }

    if rel_files.is_empty() {
        return Err(format!(
            "No packaged files listed in {} for port {}",
            manifest_path.display(),
            port.name
        ));
    }

    rel_files.sort();
    for pair in rel_files.windows(2) {
        if pair[0] == pair[1] {
            return Err(format!(
                "Duplicate install path in manifest {}: {}",
                manifest_path.display(),
                pair[0].display()
            ));
        }
    }

    if !port_manifest.ends_with('\n') {
        port_manifest.push('\n');
    }

    let arch = package_arch(env);
    let pkg_basename = format!(
        "{}-{}-{}.pkg.tar",
        sanitize_pkg_component(&port.name),
        sanitize_pkg_component(&port.version),
        sanitize_pkg_component(arch),
    );

    let repo_root = output_dir
        .parent()
        .unwrap_or(output_dir)
        .join("pkgrepo");
    fs::create_dir_all(&repo_root)
        .map_err(|e| format!("Cannot create package repo dir {}: {}", repo_root.display(), e))?;
    let pkg_path = repo_root.join(pkg_basename);

    let builddate = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut pkginfo = String::new();
    let _ = writeln!(pkginfo, "pkgname = {}", port.name);
    let _ = writeln!(pkginfo, "pkgver = {}", port.version);
    let _ = writeln!(pkginfo, "arch = {}", arch);
    let _ = writeln!(pkginfo, "builddate = {}", builddate);
    let _ = writeln!(pkginfo, "packager = SaltyOS port");
    let _ = writeln!(pkginfo, "size = {}", total_size);
    let _ = writeln!(pkginfo, "filecount = {}", rel_files.len());
    if !port.description.is_empty() {
        let _ = writeln!(pkginfo, "pkgdesc = {}", port.description);
    }
    if !port.homepage.is_empty() {
        let _ = writeln!(pkginfo, "url = {}", port.homepage);
    }
    if !port.license.is_empty() {
        let _ = writeln!(pkginfo, "license = {}", port.license);
    }
    for dep in &port.depends_runtime {
        if !dep.is_empty() {
            let _ = writeln!(pkginfo, "depend = {}", dep);
        }
    }

    let mut filelist = String::new();
    for rel in &rel_files {
        let path_str = rel.to_string_lossy();
        let _ = writeln!(filelist, "{}", path_str);
    }

    let work_dir = port_dir.join("work");
    fs::create_dir_all(&work_dir)
        .map_err(|e| format!("Cannot create work dir {}: {}", work_dir.display(), e))?;
    let pkg_root = work_dir.join(format!(
        ".pkgroot-{}-{}",
        sanitize_pkg_component(&port.name),
        std::process::id()
    ));
    if pkg_root.exists() {
        fs::remove_dir_all(&pkg_root)
            .map_err(|e| format!("Cannot clean temp package dir {}: {}", pkg_root.display(), e))?;
    }
    fs::create_dir_all(&pkg_root)
        .map_err(|e| format!("Cannot create temp package dir {}: {}", pkg_root.display(), e))?;

    let pkginfo_path = pkg_root.join(".PKGINFO");
    let files_path = pkg_root.join(".FILES");
    let port_manifest_path = pkg_root.join(".SALTYPORT_MANIFEST");
    fs::write(&pkginfo_path, pkginfo)
        .map_err(|e| format!("Cannot write {}: {}", pkginfo_path.display(), e))?;
    fs::write(&files_path, filelist)
        .map_err(|e| format!("Cannot write {}: {}", files_path.display(), e))?;
    fs::write(&port_manifest_path, port_manifest)
        .map_err(|e| format!("Cannot write {}: {}", port_manifest_path.display(), e))?;

    for rel in &rel_files {
        let src_path = port_out.join(rel);
        let dst_path = pkg_root.join(rel);
        if let Some(parent) = dst_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create directory {}: {}", parent.display(), e))?;
        }
        fs::copy(&src_path, &dst_path)
            .map_err(|e| format!("Cannot copy {} -> {}: {}", src_path.display(), dst_path.display(), e))?;
    }

    let tar_status = Command::new("tar")
        .arg("-cf")
        .arg(&pkg_path)
        .arg("-C")
        .arg(&pkg_root)
        .arg(".")
        .status()
        .map_err(|e| format!("Failed to run tar: {}", e))?;

    let cleanup_result = fs::remove_dir_all(&pkg_root);

    if !tar_status.success() {
        let _ = cleanup_result;
        return Err(format!(
            "tar failed while creating package {} (status {})",
            pkg_path.display(),
            tar_status
        ));
    }

    if let Err(e) = cleanup_result {
        return Err(format!(
            "Package created but failed to clean temp dir {}: {}",
            pkg_root.display(),
            e
        ));
    }

    println!("   Package: {}", pkg_path.display());
    Ok(())
}
