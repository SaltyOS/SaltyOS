/* SPDX-License-Identifier: GPL-2.0-only */
/* x86_64 ELF relocation types for rtld */

#ifndef RTLD_ARCH_RELOC_TYPES_H
#define RTLD_ARCH_RELOC_TYPES_H

#define R_NONE          0   /* R_X86_64_NONE */
#define R_ABS64         1   /* R_X86_64_64 */
#define R_GLOB_DAT      6   /* R_X86_64_GLOB_DAT */
#define R_JUMP_SLOT     7   /* R_X86_64_JUMP_SLOT */
#define R_RELATIVE      8   /* R_X86_64_RELATIVE */
#define R_DTPMOD64     16   /* R_X86_64_DTPMOD64 */
#define R_DTPOFF64     17   /* R_X86_64_DTPOFF64 */
#define R_TPOFF64      18   /* R_X86_64_TPOFF64 */

#endif
