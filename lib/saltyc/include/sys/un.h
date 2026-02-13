/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SYS_UN_H__
#define __SYS_UN_H__

#ifndef __SOCKADDR_UN_DEFINED__
#define __SOCKADDR_UN_DEFINED__
struct sockaddr_un {
    unsigned short sun_family;
    char           sun_path[108];
};
#endif

#endif /* __SYS_UN_H__ */
