# SaltyOS x86_64 CMake toolchain file
# SPDX-License-Identifier: GPL-2.0-only
#
# Usage:
#   cmake -DCMAKE_TOOLCHAIN_FILE=tools/cross/saltyos-x86_64.cmake \
#         -DSALTYOS_SYSROOT=/path/to/sysroot ...
#
# Requires the SaltyOS patched LLVM/Clang with x86_64-unknown-saltyos target.

set(CMAKE_SYSTEM_NAME SaltyOS)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Add repo-local CMake modules so Platform/SaltyOS*.cmake are found.
# CMAKE_CURRENT_LIST_DIR = tools/cross/, so ../cmake = tools/cmake/
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/../cmake")

# Use SaltyOS sysroot (must be set by caller or environment)
if(NOT DEFINED SALTYOS_SYSROOT)
    if(DEFINED ENV{SALTYOS_SYSROOT})
        set(SALTYOS_SYSROOT "$ENV{SALTYOS_SYSROOT}")
    else()
        message(FATAL_ERROR "SALTYOS_SYSROOT must be set (cmake -DSALTYOS_SYSROOT=... or environment)")
    endif()
endif()

set(CMAKE_SYSROOT "${SALTYOS_SYSROOT}")

# Compilers — use the SaltyOS-patched clang
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_ASM_COMPILER clang)
set(CMAKE_AR llvm-ar)
set(CMAKE_RANLIB llvm-ranlib)
set(CMAKE_STRIP llvm-strip)
set(CMAKE_LINKER lld)

# Target triple
set(triple x86_64-unknown-saltyos)
set(CMAKE_C_COMPILER_TARGET ${triple})
set(CMAKE_CXX_COMPILER_TARGET ${triple})
set(CMAKE_ASM_COMPILER_TARGET ${triple})

# Compiler flags
set(CMAKE_C_FLAGS_INIT "-fPIC")
set(CMAKE_CXX_FLAGS_INIT "-fPIC -fno-exceptions -fno-rtti")

# Linker flags
set(CMAKE_EXE_LINKER_FLAGS_INIT "-nostdlib -nostartfiles -fuse-ld=lld -z max-page-size=4096")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-nostdlib -nostartfiles -fuse-ld=lld -z max-page-size=4096")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "-nostdlib -nostartfiles -fuse-ld=lld -z max-page-size=4096")

# Cross-compilation settings
set(CMAKE_CROSSCOMPILING TRUE)
set(CMAKE_FIND_ROOT_PATH "${SALTYOS_SYSROOT}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# SaltyOS does not support running target executables during build
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
