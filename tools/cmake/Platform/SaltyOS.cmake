# SaltyOS CMake platform module
# SPDX-License-Identifier: GPL-2.0-only
#
# Loaded by CMake after compiler detection when CMAKE_SYSTEM_NAME=SaltyOS.
# Defines ELF shared library conventions matching the SaltyOS sysroot layout.

set(CMAKE_DL_LIBS "")
set(CMAKE_SHARED_LIBRARY_RPATH_ORIGIN_TOKEN "\$ORIGIN")
set(CMAKE_SHARED_LIBRARY_SUFFIX ".so")

# Shared libraries with no builtin soname may not be linked safely by
# specifying the file path.
set(CMAKE_PLATFORM_USES_PATH_WHEN_NO_SONAME 1)

include(Platform/UnixPaths)
