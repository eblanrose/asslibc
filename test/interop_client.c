#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "asslibc.h"
#include "../ssl.h"

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <host> <port> <tls1.3|tls1.2>\n", argv[0]);
        return 2;
    }
    const char *host = argv[1];
    int port = atoi(argv[2]);
    uint16_t want_version = TLS13_VERSION;
    if (strcmp(argv[3], "tls1.2") == 0) want_version = TLS12_VERSION;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(host);
    sa.sin_port = htons(port);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) { perror("connect"); return 1; }

    assl_ssl ssl;
        assl_ssl_init(&ssl, 1);
    assl_ssl_set_verify(&ssl, 0, NULL);
    assl_ssl_set_version(&ssl, want_version);

    fprintf(stderr, "interop_client: handshaking as client...\n");
    int rc = assl_ssl_handshake(&ssl, fd, fd);
    if (rc < 0) {
        fprintf(stderr, "interop_client: HANDSHAKE FAILED\n");
        return 1;
    }
    fprintf(stderr, "interop_client: handshake OK version=0x%04x cipher=0x%04x\n",
            assl_ssl_get_version(&ssl), assl_ssl_get_cipher(&ssl));

    const char *req = "echo:hello from asslibc\n";
    rc = assl_ssl_write(&ssl, fd, req, strlen(req));
    if (rc < 0) { fprintf(stderr, "interop_client: write failed\n"); return 1; }
    fprintf(stderr, "interop_client: sent %d bytes\n", rc);

    char buf[4096];
    int n = assl_ssl_read(&ssl, fd, buf, sizeof buf - 1);
    if (n < 0) { fprintf(stderr, "interop_client: read failed\n"); return 1; }
    buf[n < 0 ? 0 : n] = 0;
    fprintf(stderr, "interop_client: got %d bytes: '%.*s'\n", n, n, buf);

    assl_ssl_write(&ssl, fd, "quit", 4);
    assl_ssl_shutdown(&ssl, fd);
    close(fd);
    return 0;
}