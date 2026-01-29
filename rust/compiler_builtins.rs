//! Compiler builtins for freestanding environment
//!
//! Rust provides `compiler_builtins` as a port of LLVM's `compiler-rt`.
//! Since we do not need the vast majority of them, we avoid the dependency
//! by providing this file.
//!
//! These intrinsics are defined to panic at runtime to catch mistakes.
//! Kernel code should not use 128-bit integers or floating point.
//!
//! SPDX-License-Identifier: GPL-2.0-only

#![no_std]
#![allow(internal_features)]
#![feature(compiler_builtins)]
#![compiler_builtins]
#![no_builtins]

macro_rules! define_panicking_intrinsics(
    ($reason: tt, { $($ident: ident, )* }) => {
        $(
            #[doc(hidden)]
            #[unsafe(export_name = stringify!($ident))]
            pub extern "C" fn $ident() {
                panic!($reason);
            }
        )*
    }
);

define_panicking_intrinsics!("`f32` should not be used", {
    __addsf3,
    __eqsf2,
    __extendsfdf2,
    __gesf2,
    __lesf2,
    __ltsf2,
    __mulsf3,
    __nesf2,
    __truncdfsf2,
    __unordsf2,
});

define_panicking_intrinsics!("`f64` should not be used", {
    __adddf3,
    __eqdf2,
    __ledf2,
    __ltdf2,
    __muldf3,
    __unorddf2,
});

define_panicking_intrinsics!("`i128` should not be used", {
    __ashrti3,
    __muloti4,
    __multi3,
});

define_panicking_intrinsics!("`u128` should not be used", {
    __ashlti3,
    __lshrti3,
    __udivmodti4,
    __udivti3,
    __umodti3,
});
