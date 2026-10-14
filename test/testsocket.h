#ifndef TESTSOCKET_H
#define TESTSOCKET_H


#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>

static inline int testsocket_init(void) {
    static int status = -1;
    if (status < 0) {
        WSADATA wd;
        status = (WSAStartup(MAKEWORD(2, 2), &wd) == 0) ? 1 : 0;
    }
    return status;
}

typedef SOCKET tst_sock;
#define tst_sock_bad INVALID_SOCKET
#define tst_sock_ok(s) ((s) != INVALID_SOCKET)

static inline int testsocketpair(int sv[2]) {
    SOCKET lsn, c, s;
    struct sockaddr_in addr;
    int one = 1;
    socklen_t al = (socklen_t)sizeof addr;
    if (!testsocket_init()) return -1;
    lsn = socket(AF_INET, SOCK_STREAM, 0);
    if (lsn == INVALID_SOCKET) return -1;
    setsockopt(lsn, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(lsn, (struct sockaddr *)&addr, (int)sizeof addr) != 0 ||
        getsockname(lsn, (struct sockaddr *)&addr, &al) != 0 ||
        listen(lsn, 1) != 0) {
        closesocket(lsn);
        return -1;
    }
    c = socket(AF_INET, SOCK_STREAM, 0);
    if (c == INVALID_SOCKET) { closesocket(lsn); return -1; }
    if (connect(c, (struct sockaddr *)&addr, (int)sizeof addr) != 0) {
        closesocket(lsn);
        closesocket(c);
        return -1;
    }
    s = accept(lsn, NULL, NULL);
    closesocket(lsn);
    if (s == INVALID_SOCKET) { closesocket(c); return -1; }
    sv[0] = (int)c;
    sv[1] = (int)s;
    return 0;
}

#define tst_fd_read(fd, buf, n)   recv((SOCKET)(intptr_t)(fd), (char *)(buf), (int)(n), 0)
#define tst_fd_write(fd, buf, n)  send((SOCKET)(intptr_t)(fd), (const char *)(buf), (int)(n), 0)
#define tst_fd_close(fd)          closesocket((SOCKET)(intptr_t)(fd))
#define tst_fd_shutdown_wr(fd)    shutdown((SOCKET)(intptr_t)(fd), SD_SEND)
#define tst_fd_shutdown_rw(fd)    shutdown((SOCKET)(intptr_t)(fd), SD_BOTH)

static inline void tst_ignore_sigpipe(void) { (void)0; }

#define tst_watchdog_arm(fn)    ((void)(fn))
#define tst_watchdog_cancel()   ((void)0)

#else /* POSIX */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

static inline int testsocket_init(void) { return 1; }

typedef int tst_sock;
#define tst_sock_bad (-1)
#define tst_sock_ok(s) ((s) >= 0)

static inline int testsocketpair(int sv[2]) {
    return socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
}

#define tst_fd_read(fd, buf, n)   read((fd), (buf), (n))
#define tst_fd_write(fd, buf, n)  write((fd), (buf), (n))
#define tst_fd_close(fd)          close((fd))
#define tst_fd_shutdown_wr(fd)    shutdown((fd), SHUT_WR)
#define tst_fd_shutdown_rw(fd)    shutdown((fd), SHUT_RDWR)

static inline void tst_ignore_sigpipe(void) { signal(SIGPIPE, SIG_IGN); }

#define tst_watchdog_arm(fn)    (signal(SIGALRM, (fn)), alarm(5))
#define tst_watchdog_cancel()   (alarm(0))

#endif

#endif /* TESTSOCKET_H */