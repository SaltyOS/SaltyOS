# SaltyOS compiler-rt builtins target cache for the host LLVM build.
#
# This follows the LLVM/Fuchsia model of declaring a dedicated builtins target
# instead of piggybacking on LLVM_RUNTIME_TARGETS for a freestanding target.

get_filename_component(_saltyos_cmake_module_path
  "${CMAKE_CURRENT_LIST_DIR}/../../cmake"
  ABSOLUTE)

set(BUILTINS_x86_64-unknown-saltyos_CMAKE_SYSTEM_NAME SaltyOS CACHE STRING "")
set(BUILTINS_x86_64-unknown-saltyos_CMAKE_SYSTEM_PROCESSOR x86_64 CACHE STRING "")
set(BUILTINS_x86_64-unknown-saltyos_CMAKE_MODULE_PATH "${_saltyos_cmake_module_path}" CACHE STRING "")
set(BUILTINS_x86_64-unknown-saltyos_CMAKE_BUILD_TYPE Release CACHE STRING "")
set(BUILTINS_x86_64-unknown-saltyos_COMPILER_RT_BAREMETAL_BUILD ON CACHE BOOL "")

foreach(lang C CXX ASM)
  set(BUILTINS_x86_64-unknown-saltyos_CMAKE_${lang}_FLAGS
    "--target=x86_64-unknown-saltyos -ffreestanding"
    CACHE STRING "")
endforeach()

foreach(type SHARED MODULE EXE)
  set(BUILTINS_x86_64-unknown-saltyos_CMAKE_${type}_LINKER_FLAGS
    "-fuse-ld=lld"
    CACHE STRING "")
endforeach()

set(BUILTINS_x86_64-unknown-saltyos_COMPILER_RT_BUILTINS_ENABLE_PIC ON CACHE BOOL "")
