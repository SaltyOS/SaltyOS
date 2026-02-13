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
    pub salty_host: String,
    pub salty_inc: PathBuf,
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

        // saltyc include path: <project_root>/lib/saltyc/include
        // We derive project root from build_root (build_root is usually <project>/build)
        let project_root = build_root.parent().unwrap_or(&build_root);
        let salty_inc = project_root.join("lib").join("saltyc").join("include");

        // Paths to libsalty/libc build artifacts for linking
        let libsalty_dir = build_root.join("lib").join("libsalty");
        let saltyc_dir = build_root.join("lib").join("saltyc");
        let rust_dir = build_root.join("rust");

        // Get clang's resource directory for compiler-provided headers
        // (float.h, stdarg.h builtins, etc.)
        let clang_resource_dir = std::process::Command::new("clang")
            .args(["--print-resource-dir"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();

        // Build CFLAGS for cross compilation
        // -fno-builtin omitted: autotools needs builtin recognition for function checks
        let cflags = format!(
            "-ffreestanding -nostdlib -nostdinc \
             -fno-stack-protector \
             -mno-red-zone -fPIC \
             -isystem {salty_inc} \
             -isystem {clang_res}/include \
             --target=x86_64-unknown-none",
            salty_inc = salty_inc.display(),
            clang_res = clang_resource_dir,
        );

        // LDFLAGS: linker search paths and flags (autotools prepends before source)
        let ldflags = format!(
            "-nostdlib -nostartfiles \
             -fuse-ld=lld \
             --target=x86_64-unknown-none \
             -L{saltyc} -L{libsalty} -L{rust} \
             -Wl,--dynamic-linker,/lib/ld-salty.so",
            saltyc = saltyc_dir.display(),
            libsalty = libsalty_dir.display(),
            rust = rust_dir.display(),
        );

        // LIBS: objects and libraries (autotools appends after source)
        let libs = format!(
            "{saltyc}/crt_start.o \
             -lc -lsalty \
             {rust}/core.o {rust}/compiler_builtins.o",
            saltyc = saltyc_dir.display(),
            rust = rust_dir.display(),
        );

        BuildEnv {
            cc: "clang".to_string(),
            cflags,
            ldflags,
            libs,
            ar: "llvm-ar".to_string(),
            ranlib: "llvm-ranlib".to_string(),
            strip: "llvm-strip".to_string(),
            salty_host: "x86_64-unknown-none".to_string(),
            salty_inc,
            build_root,
            nproc: jobs,
            verbose,
        }
    }
}
