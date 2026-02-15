/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SYS_IOCTL_H__
#define __SYS_IOCTL_H__

#define TIOCGWINSZ  0x5413
#define TIOCSWINSZ  0x5414
#define FIONREAD    0x541B
#define TIOCSCTTY   0x540E
#define TIOCGPGRP   0x540F
#define TIOCSPGRP   0x5410
#define TIOCNOTTY   0x5422

struct winsize {
    unsigned short ws_row;
    unsigned short ws_col;
    unsigned short ws_xpixel;
    unsigned short ws_ypixel;
};

extern int ioctl(int fd, unsigned long request, ...);

#endif /* __SYS_IOCTL_H__ */
