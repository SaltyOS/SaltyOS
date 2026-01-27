/* SaltyOS Stage 1 EFI File Loading
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Load Stage2/EFI from ESP
 */

#include "efi.h"
#include "../../common/types.h"

/* Stage1 no longer exposes a raw load helper; Stage2 is loaded via LoadImage */
int efi_load_stage2(EFI_HANDLE image, EFI_SYSTEM_TABLE *st) {
    (void)image;
    (void)st;
    return -1;
}
