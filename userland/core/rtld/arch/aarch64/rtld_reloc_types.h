/* SPDX-License-Identifier: GPL-2.0-only */
/* AArch64 ELF relocation types for rtld */

#ifndef RTLD_ARCH_RELOC_TYPES_H
#define RTLD_ARCH_RELOC_TYPES_H

#define R_NONE          0     /* R_AARCH64_NONE */
#define R_ABS64       257     /* R_AARCH64_ABS64 */
#define R_GLOB_DAT   1025     /* R_AARCH64_GLOB_DAT */
#define R_JUMP_SLOT  1026     /* R_AARCH64_JUMP_SLOT */
#define R_RELATIVE   1027     /* R_AARCH64_RELATIVE */
#define R_DTPMOD64   1028     /* R_AARCH64_TLS_DTPMOD */
#define R_DTPOFF64   1029     /* R_AARCH64_TLS_DTPREL */
#define R_TPOFF64    1030     /* R_AARCH64_TLS_TPREL */
#define R_TLSDESC    1031     /* R_AARCH64_TLSDESC */

#endif
