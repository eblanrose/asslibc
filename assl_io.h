#ifndef ASSL_IO_H
#define ASSL_IO_H


#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>

static inline int assl_io_read(int fd, void *buf, size_t len) {
    if (len > (size_t)0x7FFFFFFF) len = (size_t)0x7FFFFFFF;
    return recv((SOCKET)(intptr_t)fd, (char *)buf, (int)len, 0);
}

static inline int assl_io_write(int fd, const void *buf, size_t len) {
    if (len > (size_t)0x7FFFFFFF) len = (size_t)0x7FFFFFFF;
    return send((SOCKET)(intptr_t)fd, (const char *)buf, (int)len, 0);
}

static inline int assl_io_close(int fd) {
    return closesocket((SOCKET)(intptr_t)fd);
}

static inline int assl_io_eintr(void) {
    return WSAGetLastError() == WSAEINTR;
}

#else

#include <unistd.h>
#include <errno.h>

static inline ssize_t assl_io_read(int fd, void *buf, size_t len) {
    return read(fd, buf, len);
}

static inline ssize_t assl_io_write(int fd, const void *buf, size_t len) {
    return write(fd, buf, len);
}

static inline int assl_io_close(int fd) {
    return close(fd);
}

static inline int assl_io_eintr(void) {
    return errno == EINTR;
}

#endif

#endif /* ASSL_IO_H */