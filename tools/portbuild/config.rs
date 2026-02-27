//! Cross-compile environment configuration
//! SPDX-License-Identifier: GPL-2.0-only

use std::path::{Path, PathBuf};

pub struct BuildEnv {
    pub cc: String,
    pub cflags: String,
    pub ldflags: String,
    pub libs: String,
    pub ar: String,
    pub ranlib: String,
    pub strip: String,
    pub autotools_host: String,
    pub besalt_host: String,
    pub besalt_inc: PathBuf,
    pub build_root: PathBuf,
    pub nproc: usize,
    pub verbose: bool,
}

impl BuildEnv {
    pub fn new(build_dir: &Path, _port_dir: &Path, jobs: usize, verbose: bool) -> Self {
        let build_root = if build_dir.is_absolute() {
            build_dir.to_path_buf()
        } else {
            std::env::current_dir().unwrap().join(build_dir)
        };

        // besaltc include path: <project_root>/lib/besalt/c/include
        // We derive project root from build_root (build_root is usually <project>/build)
        let project_root = build_root.parent().unwrap_or(&build_root);
        let besalt_inc = project_root.join("lib").join("besalt").join("c").join("include");

        // Paths to libbesalt/libc build artifacts for linking
        let libbesalt_dir = build_root.join("lib").join("besalt").join("lib");
        let besaltc_dir = build_root.join("lib").join("besalt").join("c");
        let rust_dir = build_root.join("rust");

        // Resolve the SaltyOS clang: prefer SALTYOS_TOOLCHAIN_PREFIX env var,
        // then derive from build_root (../../build-toolchain/prefix).
        // Falls back to system clang if the custom binary is not found.
        let cc = {
            let prefix = std::env::var("SALTYOS_TOOLCHAIN_PREFIX")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    build_root
                        .parent()
                        .unwrap_or(&build_root)
                        .join("build-toolchain")
                        .join("prefix")
                });
            let cc_path = prefix.join("bin").join("clang");
            if cc_path.is_file() {
                cc_path.to_string_lossy().into_owned()
            } else {
                "clang".to_string()
            }
        };

        // Get clang's resource directory for compiler-provided headers
        // (float.h, stdarg.h builtins, etc.). Use the same clang as CC so
        // headers match the compiler.
        let clang_resource_dir = std::process::Command::new(&cc)
            .args(["--print-resource-dir"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();

        // Build CFLAGS for cross compilation
        // -fno-builtin omitted: autotools needs builtin recognition for function checks
        // Ports are built in hosted mode for autotools probes; keep builtins enabled.
        // -fPIC is implied by --target=x86_64-unknown-saltyos.
        let cflags = format!(
            "-nostdinc -fno-stack-protector \
             -isystem {besalt_inc} \
             -isystem {clang_res}/include \
             --target=x86_64-unknown-saltyos",
            besalt_inc = besalt_inc.display(),
            clang_res = clang_resource_dir,
        );

        // LDFLAGS: linker search paths and flags (autotools prepends before source)
        // -fuse-ld=lld and the executable dynamic linker are provided by the target.
        let ldflags = format!(
            "-nostdlib -nostartfiles \
             --target=x86_64-unknown-saltyos \
             -L{besaltc} -L{libbesalt} -L{rust}",
            besaltc = besaltc_dir.display(),
            libbesalt = libbesalt_dir.display(),
            rust = rust_dir.display(),
        );

        // LIBS: objects and libraries (autotools appends after source)
        let libs = format!(
            "{besaltc}/crt_start.o \
             -lc -lbesalt \
             {rust}/core.o {rust}/compiler_builtins.o",
            besaltc = besaltc_dir.display(),
            rust = rust_dir.display(),
        );

        BuildEnv {
            cc,
            cflags,
            ldflags,
            libs,
            ar: "llvm-ar".to_string(),
            ranlib: "llvm-ranlib".to_string(),
            strip: "llvm-strip".to_string(),
            // Autotools' config.sub does not know "saltyos" yet. Use a canonical
            // host tuple for configure while keeping the real target in CC/CFLAGS.
            autotools_host: "x86_64-unknown-elf".to_string(),
            besalt_host: "x86_64-unknown-saltyos".to_string(),
            besalt_inc,
            build_root,
            nproc: jobs,
            verbose,
        }
    }
}
