/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __TERMIOS_H__
#define __TERMIOS_H__

#define NCCS 32

struct termios {
    unsigned int  c_iflag;
    unsigned int  c_oflag;
    unsigned int  c_cflag;
    unsigned int  c_lflag;
    unsigned char c_line;
    unsigned char c_cc[NCCS];
    unsigned int  c_ispeed;
    unsigned int  c_ospeed;
};

typedef unsigned int speed_t;
typedef unsigned int tcflag_t;
typedef unsigned char cc_t;

/* c_cc indices */
#define VINTR    0
#define VQUIT    1
#define VERASE   2
#define VKILL    3
#define VEOF     4
#define VTIME    5
#define VMIN     6
#define VSTART   8
#define VSTOP    9
#define VSUSP    10
#define VEOL     11
#define VREPRINT 12
#define VDISCARD 13
#define VWERASE  14
#define VLNEXT   15

/* c_iflag bits */
#define IGNBRK  0000001
#define BRKINT  0000002
#define IGNPAR  0000004
#define PARMRK  0000010
#define INPCK   0000020
#define ISTRIP  0000040
#define INLCR   0000100
#define IGNCR   0000200
#define ICRNL   0000400
#define IXON    0002000
#define IXOFF   0010000
#define IXANY   0020000
#define IMAXBEL 0020000

/* c_oflag bits */
#define OPOST   0000001
#define ONLCR   0000004

/* c_cflag bits */
#define CSIZE   0000060
#define CS5     0000000
#define CS6     0000020
#define CS7     0000040
#define CS8     0000060
#define CSTOPB  0000100
#define CREAD   0000200
#define PARENB  0000400
#define HUPCL   0002000
#define CLOCAL  0004000

/* c_lflag bits */
#define ISIG    0000001
#define ICANON  0000002
#define ECHO    0000010
#define ECHOE   0000020
#define ECHOK   0000040
#define ECHONL  0000100
#define NOFLSH  0000200
#define TOSTOP  0000400
#define ECHOCTL 0001000
#define ECHOKE  0004000
#define IEXTEN  0100000

/* tcsetattr actions */
#define TCSANOW   0
#define TCSADRAIN 1
#define TCSAFLUSH 2

/* tcflush queue selectors */
#define TCIFLUSH  0
#define TCOFLUSH  1
#define TCIOFLUSH 2

/* tcflow actions */
#define TCOOFF  0
#define TCOON   1
#define TCIOFF  2
#define TCION   3

/* Baud rates */
#define B0      0
#define B50     50
#define B75     75
#define B110    110
#define B134    134
#define B150    150
#define B200    200
#define B300    300
#define B600    600
#define B1200   1200
#define B1800   1800
#define B2400   2400
#define B4800   4800
#define B9600   9600
#define B19200  19200
#define B38400  38400
#define B57600  57600
#define B115200 115200

extern int   tcgetattr(int fd, struct termios *termios_p);
extern int   tcsetattr(int fd, int optional_actions,
                       const struct termios *termios_p);
extern int   tcdrain(int fd);
extern int   tcflush(int fd, int queue_selector);
extern int   tcsendbreak(int fd, int duration);
extern int   tcflow(int fd, int action);

extern speed_t cfgetospeed(const struct termios *termios_p);
extern speed_t cfgetispeed(const struct termios *termios_p);
extern int     cfsetospeed(struct termios *termios_p, speed_t speed);
extern int     cfsetispeed(struct termios *termios_p, speed_t speed);
extern void    cfmakeraw(struct termios *termios_p);

#endif /* __TERMIOS_H__ */
