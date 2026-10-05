#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <signal.h>
#include "ssl.h"

static uint16_t g_suite;
static int      g_with_sentinel;
static int      g_tls13_client;
static int      rogue_fd;

static void *rogue_server(void *arg) {
    (void)arg;
    int fd = rogue_fd;
    uint8_t buf[4096];
    if (read(fd, buf, sizeof buf) <= 5) { close(fd); return NULL; }

    uint8_t sh[128];
    size_t p = 0;
    sh[p++] = 0x03; sh[p++] = 0x03;
    uint8_t rnd[32];
    memset(rnd, 0xA5, sizeof rnd);
    if (g_with_sentinel) memcpy(rnd + 24, "DOWNGRD\x01", 8);
    memcpy(sh + p, rnd, 32); p += 32;
    sh[p++] = 0;
    sh[p++] = (uint8_t)(g_suite >> 8); sh[p++] = (uint8_t)g_suite;
    sh[p++] = 0;
    if (g_tls13_client) {
        sh[p++] = 0x00; sh[p++] = 0x06;
        sh[p++] = 0x00; sh[p++] = 0x2b;
        sh[p++] = 0x00; sh[p++] = 0x02;
        sh[p++] = 0x03; sh[p++] = 0x03;
    }
    uint8_t rec[192];
    size_t r = 0;
    rec[r++] = 22;
    rec[r++] = 0x03; rec[r++] = 0x03;
    rec[r++] = (uint8_t)((4 + p) >> 8); rec[r++] = (uint8_t)(4 + p);
    rec[r++] = 2;
    rec[r++] = 0; rec[r++] = (uint8_t)(p >> 8); rec[r++] = (uint8_t)p;
    memcpy(rec + r, sh, p); r += p;
    (void)!write(fd, rec, r);
    close(fd);
    return NULL;
}

static void run(const char *what, uint16_t suite, int with_sentinel, int tls13, int want_pass) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); return; }
    g_suite = suite; g_with_sentinel = with_sentinel; g_tls13_client = tls13;
    rogue_fd = sv[1];
    pthread_t t;
    pthread_create(&t, NULL, rogue_server, NULL);

    assl_ssl ssl;
    assl_ssl_init(&ssl, 1);
    assl_ssl_set_version(&ssl, tls13 ? TLS13_VERSION : TLS12_VERSION);
    (void)assl_ssl_handshake(&ssl, sv[0], sv[0]);
    int passed = (ssl.state == SSL3_STATE_SERVER_HELLO_RECEIVED);
    pthread_join(t, NULL);
    close(sv[0]);

    int ok = (passed == want_pass);
    printf("%-52s %-18s expected %-16s %s\n", what,
           passed ? "accepted" : "refused",
           want_pass ? "accepted" : "refused",
           ok ? "OK" : "*** FAIL ***");
    if (!ok) exit(1);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    run("TLS1.2 client, unoffered suite 0x1301", TLS13_CK_AES_128_GCM_SHA256, 0, 0, 0);
    run("TLS1.2 client, offered suite 0xC02F", TLS12_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0, 0, 1);
    run("TLS1.3 client, below 1.3, sentinel PRESENT", TLS13_CK_AES_128_GCM_SHA256, 1, 1, 0);
    run("TLS1.3 client, below 1.3, sentinel absent", TLS13_CK_AES_128_GCM_SHA256, 0, 1, 1);
    printf("all ServerHello probe expectations met\n");
    return 0;
}