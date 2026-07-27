/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * kernite UAPI umbrella header.
 *
 * The single source of truth for every value that crosses the
 * kernel/userland boundary: ABI version, syscall trap, error codes,
 * capability rights, object types + sizes, capability invocation
 * labels, watchable state flags, EventQueue / MessagePipe wire
 * formats, fault delivery labels, and bootloader handoff TLVs.
 *
 * Authored as C headers so any FFI-capable language can consume the
 * same definitions; the kernite kernel (Rust) and trona substrate
 * (Rust) generate Rust bindings via bindgen at build time.
 */

#ifndef KERNITE_UAPI_KERNITE_H
#define KERNITE_UAPI_KERNITE_H

#include "version.h"
#include "syscall.h"
#include "error.h"
#include "rights.h"
#include "object.h"
#include "invoke.h"
#include "vmem.h"
#include "event.h"
#include "ipc.h"
#include "fault.h"
#include "boot.h"
#include "startup.h"

#endif /* KERNITE_UAPI_KERNITE_H */
