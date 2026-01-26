//! Build script for SaltyOS kernel
//! Compiles the assembly files and links them into the kernel

use std::env;
use std::path::PathBuf;

fn main() {
    // Assembly files to compile
    let asm_files = [
        "src/arch/x86_64/boot.S",
        "src/arch/x86_64/interrupts.S",
        "src/arch/x86_64/syscall.S",
    ];

    // Only rebuild if the assembly files change
    for asm_file in &asm_files {
        println!("cargo:rerun-if-changed={}", asm_file);
    }

    // Get output directory
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Try to find a suitable compiler
    let compilers = ["x86_64-elf-gcc", "x86_64-linux-gnu-gcc", "gcc"];
    let compiler = compilers
        .iter()
        .find(|cc| {
            std::process::Command::new(*cc)
                .arg("--version")
                .output()
                .is_ok()
        })
        .unwrap_or(&compilers[2]); // Fallback to gcc

    // Compile each assembly file
    for asm_file in &asm_files {
        let obj_name = asm_file
            .rsplit('/')
            .next()
            .unwrap()
            .replace(".S", ".o");
        let boot_o = out_dir.join(&obj_name);

        // Compile .S to .o
        let status = std::process::Command::new(compiler)
            .arg("-c")
            .arg(asm_file)
            .arg("-o")
            .arg(&boot_o)
            .arg("-m64")
            .arg("-ffreestanding")
            .arg("-nostdlib")
            .arg("-fno-stack-protector")
            .arg("-fPIC")
            .status()
            .expect(&format!("Failed to compile {}", asm_file));

        if !status.success() {
            panic!("Failed to compile {}", asm_file);
        }

        // Tell cargo to link the object file
        println!("cargo:rustc-link-arg={}", boot_o.display());
    }
}
