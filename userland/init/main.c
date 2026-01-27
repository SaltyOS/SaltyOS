/* SaltyOS Init Process
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * First userspace process. Receives initial capabilities from kernel
 * and bootstraps the system.
 */

#include "../../lib/libsalty/salty.h"

/* Well-known capability slots in init's CSpace */
#define CAP_SELF_TCB        0
#define CAP_SELF_VSPACE     1
#define CAP_SELF_CSPACE     2
#define CAP_PROCMGR_EP      3
#define CAP_VFS_EP          4
#define CAP_NAMESERV_EP     5
#define CAP_UNTYPED_START   16

/* Entry point */
void _start(void) {
    /* Init receives:
     * - All untyped memory capabilities
     * - Initial endpoints for system servers
     * - Device capabilities
     */

    /* TODO: Create process manager */

    /* TODO: Create VFS server */

    /* TODO: Create name service */

    /* TODO: Create console driver */

    /* TODO: Start shell or login */

    /* Loop forever (init should never exit) */
    for (;;) {
        salty_yield();
    }
}
