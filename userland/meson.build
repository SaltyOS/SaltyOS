# SaltyOS Userland Build
# SPDX-License-Identifier: GPL-2.0-only

# Userland is only built when build_userland=true
# Each component is a separate executable

# Core system services (boot-essential)
subdir('core/init')
# rtld is now built from lib/trona/rtld/ (ld_trona_so)
subdir('core/nameserv')
subdir('core/mmsrv')
subdir('core/procmgr')

# Higher-level system servers
subdir('servers/vfs')
subdir('servers/console')
subdir('servers/ttyd')
subdir('servers/getty')
subdir('servers/netsrv')
subdir('servers/dnssrv')

# Hardware drivers
subdir('drivers/blkdrv')
subdir('drivers/pcisrv')
subdir('drivers/netdrv')
subdir('drivers/display')

# Filesystems
subdir('fs/saltyfs')

# Tests and demos
subdir('tests/test_runner')
