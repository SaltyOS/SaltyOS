//! Build phases: prepare, configure, build, stage
//! SPDX-License-Identifier: GPL-2.0-only

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::config::BuildEnv;
use crate::parser::{BuildType, PortConfig};
use crate::vars;

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
    vars.insert("CFLAGS".to_string(), env.cflags.clone());
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
    // flags that portbuild computes from the project layout.
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
                format!("-DCMAKE_C_FLAGS={}", env.cflags),
                format!("-DCMAKE_EXE_LINKER_FLAGS={}", env.ldflags),
                "-DCMAKE_INSTALL_PREFIX=/usr".to_string(),
            ];

            let substituted_args = vars::substitute_list(&port.configure_args, &var_map);
            args.extend(substituted_args);

            let cmd_str = format!("cmake {} ..", args.join(" "));
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

/// Flatten an initrd path to an output filename: "bin/echo" -> "echo.elf"
/// Preserves `.so` extensions for shared library outputs.
fn flatten_to_elf(initrd_path: &str) -> String {
    let base = initrd_path.rsplit('/').next().unwrap_or(initrd_path);
    if base.ends_with(".elf") || base.ends_with(".so") || base.ends_with(".a") {
        base.to_string()
    } else {
        format!("{}.elf", base)
    }
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
    fs::create_dir_all(output_dir)
        .map_err(|e| format!("Cannot create output dir: {}", e))?;

    let mut manifest = String::new();

    for (initrd_path_raw, artifact_ref) in &port.install_map {
        let initrd_path = vars::substitute(initrd_path_raw, &var_map);
        let artifact = vars::substitute(artifact_ref, &var_map);

        // Resolve source artifact based on build type
        let src_file = match port.build_type {
            BuildType::Targets => src.join(".salty-build").join(&artifact),
            _ => src.join(&artifact),
        };

        if !src_file.exists() {
            return Err(format!("Install source not found: {}", src_file.display()));
        }

        // Output name: flatten initrd_path to "name.elf"
        let out_name = flatten_to_elf(&initrd_path);
        let stage_target = stage_dir.join(&out_name);
        let output_target = output_dir.join(&out_name);

        // Copy to stage
        fs::copy(&src_file, &stage_target)
            .map_err(|e| format!("Cannot copy to stage: {}", e))?;

        // Strip with llvm-strip (use --strip-debug for .a archives to preserve symbol tables)
        let strip_flag = if out_name.ends_with(".a") {
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
                    println!("   {} -> {}", initrd_path, out_name);
                }
            }
            _ => {
                // If strip fails, just copy unstripped
                fs::copy(&stage_target, &output_target)
                    .map_err(|e| format!("Cannot copy to output: {}", e))?;
                if env.verbose {
                    println!("   {} -> {} (unstripped)", initrd_path, out_name);
                }
            }
        }

        // Manifest entry: initrd_path=out_name
        let _ = writeln!(manifest, "{}={}", initrd_path, out_name);
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
