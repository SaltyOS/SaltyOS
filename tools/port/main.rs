//! port — SaltyOS ports build tool
//! SPDX-License-Identifier: GPL-2.0-only

mod parser;
mod vars;
mod fetch;
mod extract;
mod build;
mod config;
mod deps;
mod stamps;

use std::path::{Path, PathBuf};
use std::process;

fn usage() {
    eprintln!("Usage: port <command> <port-dir> [options]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  build   <port-dir>   Full build (all phases)");
    eprintln!("  package <port-dir>   Package staged output into build/pkgrepo/");
    eprintln!("  fetch   <port-dir>   Download source only");
    eprintln!("  clean   <port-dir>   Remove work/ and stage/");
    eprintln!("  info    <port-dir>   Show parsed port config");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -o, --output <dir>     Output directory (default: build/ports/)");
    eprintln!("  -b, --build-dir <dir>  Meson build root (default: build/)");
    eprintln!("  -j, --jobs <n>         Parallel jobs (default: nproc)");
    eprintln!("  -v, --verbose          Show subprocess output");
    eprintln!("  --skip-fetch           Skip download phase");
    eprintln!("  --phase <name>         Run single phase");
}

struct Options {
    command: String,
    port_dir: PathBuf,
    output_dir: PathBuf,
    build_dir: PathBuf,
    jobs: usize,
    verbose: bool,
    skip_fetch: bool,
    phase: Option<String>,
}

fn parse_args() -> Options {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        usage();
        process::exit(1);
    }

    let command = args[1].clone();
    let port_dir = PathBuf::from(&args[2]);

    let mut output_dir = PathBuf::from("build/ports");
    let mut build_dir = PathBuf::from("build");
    let mut jobs = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let mut verbose = false;
    let mut skip_fetch = false;
    let mut phase = None;

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                i += 1;
                if i < args.len() {
                    output_dir = PathBuf::from(&args[i]);
                }
            }
            "-b" | "--build-dir" => {
                i += 1;
                if i < args.len() {
                    build_dir = PathBuf::from(&args[i]);
                }
            }
            "-j" | "--jobs" => {
                i += 1;
                if i < args.len() {
                    jobs = args[i].parse().unwrap_or(1);
                }
            }
            "-v" | "--verbose" => {
                verbose = true;
            }
            "--skip-fetch" => {
                skip_fetch = true;
            }
            "--phase" => {
                i += 1;
                if i < args.len() {
                    phase = Some(args[i].clone());
                }
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                usage();
                process::exit(1);
            }
        }
        i += 1;
    }

    Options {
        command,
        port_dir,
        output_dir,
        build_dir,
        jobs,
        verbose,
        skip_fetch,
        phase,
    }
}

fn main() {
    let opts = parse_args();

    // Resolve port directory to absolute path
    let port_dir = if opts.port_dir.is_absolute() {
        opts.port_dir.clone()
    } else {
        std::env::current_dir().unwrap().join(&opts.port_dir)
    };

    if !port_dir.is_dir() {
        eprintln!("Error: Port directory not found: {}", port_dir.display());
        process::exit(1);
    }

    // Find the .port file
    let port_file = find_port_file(&port_dir);
    if port_file.is_none() {
        eprintln!("Error: No .port file found in {}", port_dir.display());
        process::exit(1);
    }
    let port_file = port_file.unwrap();

    // Parse port config
    let port_config = match parser::parse_port_file(&port_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error parsing {}: {}", port_file.display(), e);
            process::exit(1);
        }
    };

    // Set up build environment
    let build_env = config::BuildEnv::new(
        &opts.build_dir,
        &port_dir,
        opts.jobs,
        opts.verbose,
    );

    match opts.command.as_str() {
        "info" => {
            println!("{}", port_config);
            process::exit(0);
        }
        "package" => {
            run_phase("package", || build::do_package(&port_config, &port_dir, &opts.output_dir, &build_env));
            process::exit(0);
        }
        "clean" => {
            // Remove all work-* directories (all architectures)
            if let Ok(entries) = std::fs::read_dir(&port_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with("work-") && entry.path().is_dir() {
                        std::fs::remove_dir_all(entry.path()).ok();
                        println!("Removed {}", entry.path().display());
                    }
                }
            }
            if let Ok(entries) = std::fs::read_dir(&port_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with("stage-") && entry.path().is_dir() {
                        std::fs::remove_dir_all(entry.path()).ok();
                        println!("Removed {}", entry.path().display());
                    }
                }
            }
            process::exit(0);
        }
        "fetch" => {
            run_phase("fetch", || fetch::do_fetch(&port_config, &port_dir, &build_env));
            process::exit(0);
        }
        "build" => {
            // Run phases based on --phase or all
            if let Some(ref phase_name) = opts.phase {
                run_single_phase(phase_name, &port_config, &port_dir, &build_env, &opts);
            } else {
                run_all_phases(&port_config, &port_dir, &build_env, &opts);
            }
        }
        _ => {
            eprintln!("Unknown command: {}", opts.command);
            usage();
            process::exit(1);
        }
    }
}

fn find_port_file(port_dir: &Path) -> Option<PathBuf> {
    if let Ok(entries) = std::fs::read_dir(port_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "port").unwrap_or(false) {
                return Some(path);
            }
        }
    }
    None
}

fn run_phase<F: FnOnce() -> Result<(), String>>(name: &str, f: F) {
    print!("=> {}... ", name);
    match f() {
        Ok(()) => println!("done"),
        Err(e) => {
            println!("FAILED");
            eprintln!("   Error: {}", e);
            process::exit(1);
        }
    }
}

fn run_single_phase(
    phase: &str,
    port: &parser::PortConfig,
    port_dir: &Path,
    env: &config::BuildEnv,
    opts: &Options,
) {
    match phase {
        "fetch" => run_phase("fetch", || fetch::do_fetch(port, port_dir, env)),
        "checksum" => run_phase("checksum", || fetch::do_checksum(port, port_dir, env)),
        "extract" => run_phase("extract", || extract::do_extract(port, port_dir, env)),
        "patch" => run_phase("patch", || build::do_patch(port, port_dir, env)),
        "config-cache" => run_phase("config-cache", || build::generate_config_cache(port, port_dir, env)),
        "prepare" => run_phase("prepare", || build::do_prepare(port, port_dir, env)),
        "configure" => run_phase("configure", || build::do_configure(port, port_dir, env)),
        "build" => run_phase("build", || build::do_build(port, port_dir, env)),
        "stage" => run_phase("stage", || build::do_stage(port, port_dir, &opts.output_dir, env)),
        "package" => run_phase("package", || build::do_package(port, port_dir, &opts.output_dir, env)),
        _ => {
            eprintln!("Unknown phase: {}", phase);
            process::exit(1);
        }
    }
}

fn run_all_phases(
    port: &parser::PortConfig,
    port_dir: &Path,
    env: &config::BuildEnv,
    opts: &Options,
) {
    println!("=== Building port: {} {} ===", port.name, port.version);

    let stmgr = stamps::StampManager::new(port_dir);

    // fetch
    if !opts.skip_fetch {
        let hash = stamps::hash_fetch_inputs(port);
        if !stmgr.check("fetch", &hash) {
            run_phase("fetch", || fetch::do_fetch(port, port_dir, env));
            stmgr.write("fetch", &hash);
        } else {
            println!("=> fetch... skipped (cached)");
        }
    }

    // checksum
    run_phase("checksum", || fetch::do_checksum(port, port_dir, env));

    // extract
    let hash = stamps::hash_extract_inputs(port);
    if !stmgr.check("extract", &hash) {
        run_phase("extract", || extract::do_extract(port, port_dir, env));
        stmgr.write("extract", &hash);
    } else {
        println!("=> extract... skipped (cached)");
    }

    // patch (after extract, before prepare)
    let hash = stamps::hash_patch_inputs(port_dir);
    if !stmgr.check("patch", &hash) {
        run_phase("patch", || build::do_patch(port, port_dir, env));
        stmgr.write("patch", &hash);
    } else {
        println!("=> patch... skipped (cached)");
    }

    // config-cache generation (before prepare, always run — fast)
    run_phase("config-cache", || build::generate_config_cache(port, port_dir, env));

    // prepare
    let hash = stamps::hash_prepare_inputs(port);
    if !stmgr.check("prepare", &hash) {
        run_phase("prepare", || build::do_prepare(port, port_dir, env));
        stmgr.write("prepare", &hash);
    } else {
        println!("=> prepare... skipped (cached)");
    }

    // configure
    let hash = stamps::hash_configure_inputs(port, env);
    if !stmgr.check("configure", &hash) {
        run_phase("configure", || build::do_configure(port, port_dir, env));
        stmgr.write("configure", &hash);
    } else {
        println!("=> configure... skipped (cached)");
    }

    // build (always run — source changes are hard to track)
    run_phase("build", || build::do_build(port, port_dir, env));

    // stage (always run — writes manifest, fast)
    run_phase("stage", || build::do_stage(port, port_dir, &opts.output_dir, env));

    // package (always run — emits build/pkgrepo/*.pkg.tar)
    run_phase("package", || build::do_package(port, port_dir, &opts.output_dir, env));

    println!("=== Port {} {} built successfully ===", port.name, port.version);
}
