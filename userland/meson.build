# SaltyOS Userland Build
# SPDX-License-Identifier: GPL-2.0-only

# Userland is only built when build_userland=true
# Each component is a separate executable

# Core system services (boot-essential)
subdir('core/init')
# rtld is now built from lib/trona/loader/ (ld_trona_so)
subdir('core/namesrv')
subdir('core/rsrcsrv')
subdir('core/mmsrv')
subdir('core/logsrv')
subdir('core/vfs')
subdir('core/ldsrv')
# core/procmgr is archived for history only; init owns the active spawn /
# lifecycle path and procmgr's legacy ABI is intentionally not built.

# Higher-level system servers
subdir('servers/console')
subdir('servers/win32/win32_csrss')
subdir('servers/posix/posix_ttysrv')
subdir('servers/posix/posix_getty')
subdir('servers/posix/posix_login')
subdir('servers/netsrv')
subdir('servers/dnssrv')

# Hardware drivers
subdir('drivers/blkdrv')
subdir('drivers/pcidrv')
subdir('drivers/netdrv')
subdir('drivers/dispdrv')

# Filesystems
subdir('drivers/filesystems/saltyfs')

# Tests and demos
subdir('tests/test_runner')
subdir('tests/hello_pe')
