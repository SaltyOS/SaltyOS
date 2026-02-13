/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SYS_SOCKET_H__
#define __SYS_SOCKET_H__

#include <sys/types.h>

#define AF_UNSPEC 0
#define AF_UNIX   1
#define AF_LOCAL  AF_UNIX
#define AF_INET   2

#define SOCK_STREAM    1
#define SOCK_DGRAM     2
#define SOCK_CLOEXEC   0x80000

#define SOL_SOCKET  1

#define SO_REUSEADDR 2
#define SO_ERROR     4
#define SO_KEEPALIVE 9

#define MSG_DONTWAIT 0x40

#define SHUT_RD   0
#define SHUT_WR   1
#define SHUT_RDWR 2

typedef unsigned int socklen_t;

struct sockaddr {
    unsigned short sa_family;
    char           sa_data[14];
};

#ifndef __SOCKADDR_UN_DEFINED__
#define __SOCKADDR_UN_DEFINED__
struct sockaddr_un {
    unsigned short sun_family;
    char           sun_path[108];
};
#endif

extern int socket(int domain, int type, int protocol);
extern int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
extern int listen(int sockfd, int backlog);
extern int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
extern int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
extern ssize_t send(int sockfd, const void *buf, size_t len, int flags);
extern ssize_t recv(int sockfd, void *buf, size_t len, int flags);
extern int shutdown(int sockfd, int how);
extern int socketpair(int domain, int type, int protocol, int sv[2]);
extern int getsockopt(int sockfd, int level, int optname,
                      void *optval, socklen_t *optlen);
extern int setsockopt(int sockfd, int level, int optname,
                      const void *optval, socklen_t optlen);
extern int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
extern int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

#endif /* __SYS_SOCKET_H__ */
