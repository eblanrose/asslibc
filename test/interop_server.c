#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "asslibc.h"
#include "../ssl.h"

static const char *k_n =
    "85aef7ed90484430ff6f7a64f0355efb959c54a3df918351311436a8b760f1fdf12d4fb9b9182a162655e279e5f1c20d1a1c5c4b82bce8bb340e53a8beb402a49e4a96efc15c4166dbb006a5d39d89a51642afc698fe08e1cd1d68d1d94f419b72b45f4a894c67cf3916f59e3b45949ce0add200c37f1b7cf8b97bb03f27d69ac175ffe71cdf9fcd7a4401dc7b481966d9d5636e3e380345d9fa685c9c45d0bd29a79269a2ac62fbf4367eefc1b4bd3dd07fa7d1ba3cdd751a4c72cb454c3335b835c7d24d578013a0b026a3c423ff6ad5f4fa2366c174d76877705322845a09de0a6f2662284bf14eb7b1d98b6e3cb78cc517af6b51114f2863d8c2a3f0b371";
static const char *k_e = "10001";
static const char *k_d =
    "6c90291badfe6212807e21a1734984773f8a9359f9a78c43155e5afd2cdef7e6c84389e9439d922026c5bc844deec52e2ab43967c12674c2028657fe43d0a00cdbd7ab37cd89843b69d14bb4c363be7268df832bfef6de73b1455ee87c57d6e9cc7f1a9bc7605b357821631a3afc48b215ec530cf7b673b64baf25f97d7076e041f1f17a866d4d9fa54e2ce82aec3d259fd5358246b26b7bba3d3c96b1df9a40b71ed92b5fac808a628b85a39bc8933d8b365e14fae756c4970b0296108fddb1455fb442bb8b6b58110c1a0062ed534b6d1b8a88a9d910a824259e910fb52c3c2c1277df44fa43bd27a9c1ddad0b22ceee94126da01db64b222139c7e4599539";
static const char *k_p =
    "f5b25944e4870317f07ffa2e1266f4c78e0cea7596d79812a2eeac3ed54fdd5eab0baa69cb4cd751c82dcac0a80d5839b0935efbe28b955df3a7a0bd95881cc1890eda7f75817371be629ad6b5f53782cf65dd3f98df00095d6dae048df927668b1bb2109d3174032116a760580f9d46bc4453b7181a35f010cdae2bde1b1c5b";
static const char *k_q =
    "8b4a1d12e9029947a244d9fbf7b4f52ac3652ae8250f45c20bb3e64597ad366dded73dd42490bb65334ea68c010df092f624b5ae18e558d9554d9b4ce77c5e68162c73631041d68cfcbf69f9750d3997c5e0ea0493f917034bc84cf04d5829de1c5d488298e810472ab82b7b9015854126606afece6e75828cba8565abd7e923";
static const char *k_dp =
    "dca375c1054c2d3e014e9bf765b5295a4f39500f9b0f2ed48596b9fd8f07b26f02416e9ea4dff378d0c036947e15c5c5c0c9070241f64183667c813fdf19a5613358b064c7bc2154e2b89ffdf2d72c2b7f5e25aaa7f8928ad668d95de3b4fc69fcc0394eec2aedd8a58d376fb0850d22e98c9e750ce2f4cf09f7fad21019de83";
static const char *k_dq =
    "a0fba75e93af4d385d72f5fd20ed23eda8a6e4502984dd3ac80bc3b7eaf56652d59a2efb60c765ce30de55deb9d9429297a915d1813490db9e9b73420ec8ced3bdcce20f3c5adb7d5720637accaddc426d90e4e7259e5dda915b8e90acd3988ffc7853b59cc3990ca772f3ce7b58640a48306778d75d12b32fb2e339fec22bd";
static const char *k_qi =
    "31dd749563f9b36e4228cbdf64a9eca0c6aec38f1246b5e4b9b2ca4d2a3bf8fd9364dbe177c4d1683b307a415936027bd79b6e7c5c55eaa0b774986e7e38ded7c91a36734a191cbe208aeb19c562fb14cf3007e842ee67aa2f484fc38e3e776e5bae9023c5defaa3b319677ae26993b872d7e0dc5bb67b5ff19d8d6823aea1b2";

static const uint8_t k_alpn[] = {
    0x08, 'h','t','t','p','/','1','.','1',
    0x0c, 'a','s','s','l','i','b','c','-','t','e','s','t'
};

static void setup_key(assl_rsa_key *k) {
    assl_rsa_init(k);
    assl_bn n, e, d, p, q, dp, dq, qi;
    assl_bn_init(&n); assl_bn_init(&e); assl_bn_init(&d);
    assl_bn_init(&p); assl_bn_init(&q);
    assl_bn_init(&dp); assl_bn_init(&dq); assl_bn_init(&qi);
    assl_bn_from_hex(&n, k_n); assl_bn_from_hex(&e, k_e); assl_bn_from_hex(&d, k_d);
    assl_bn_from_hex(&p, k_p); assl_bn_from_hex(&q, k_q);
    assl_bn_from_hex(&dp, k_dp); assl_bn_from_hex(&dq, k_dq); assl_bn_from_hex(&qi, k_qi);
    assl_rsa_set_key(k, &n, &e, &d, &p, &q, &dp, &dq, &qi);
    assl_bn_free(&n); assl_bn_free(&e); assl_bn_free(&d);
    assl_bn_free(&p); assl_bn_free(&q);
    assl_bn_free(&dp); assl_bn_free(&dq); assl_bn_free(&qi);
}

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(sz > 0 ? sz : 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, sz, f);
    fclose(f);
    *len = rd;
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <port> <tls1.3|tls1.2|any>\n", argv[0]);
        return 2;
    }
    int port = atoi(argv[1]);
    uint16_t want_version = TLS13_VERSION;
    if (strcmp(argv[2], "tls1.2") == 0) want_version = TLS12_VERSION;

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(port);
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) < 0) { perror("bind"); return 1; }
    if (listen(ls, 1) < 0) { perror("listen"); return 1; }
    fprintf(stderr, "interop_server: listening on 127.0.0.1:%d\n", port);

    int fd = accept(ls, NULL, NULL);
    if (fd < 0) { perror("accept"); return 1; }

    size_t cert_len = 0;
    uint8_t *cert = read_file("cert_0_0_0_0.der", &cert_len);
    if (!cert) { perror("cert_0_0_0_0.der"); return 1; }
    assl_rsa_key key;
    setup_key(&key);

    assl_ssl ssl;
        assl_ssl_init(&ssl, 0);
    assl_ssl_set_verify(&ssl, 0, NULL);
    assl_ssl_set_version(&ssl, want_version);
    assl_ssl_set_cert(&ssl, cert, cert_len, &key);
    if (assl_ssl_set_alpn(&ssl, k_alpn, sizeof k_alpn) != 0) {
        fprintf(stderr, "interop_server: bad ALPN list\n");
        return 1;
    }

    fprintf(stderr, "interop_server: handshaking as server...\n");
    int rc = assl_ssl_handshake(&ssl, fd, fd);
    if (rc < 0) {
        fprintf(stderr, "interop_server: HANDSHAKE FAILED\n");
        return 1;
    }
    fprintf(stderr, "interop_server: handshake OK version=0x%04x cipher=0x%04x alpn=%s sni=%s\n",
            assl_ssl_get_version(&ssl), assl_ssl_get_cipher(&ssl),
            assl_ssl_get_negotiated_alpn(&ssl) ? assl_ssl_get_negotiated_alpn(&ssl) : "(none)",
            assl_ssl_get_server_name(&ssl) ? assl_ssl_get_server_name(&ssl) : "(none)");

    char buf[4096];
    for (;;) {
        int n = assl_ssl_read(&ssl, fd, buf, sizeof buf - 1);
        if (n <= 0) break;
        buf[n] = 0;
        fprintf(stderr, "interop_server: recv %d bytes\n", n);
        if (strncmp(buf, "echo:", 5) == 0) {
            assl_ssl_write(&ssl, fd, buf + 5, n - 5);
            fprintf(stderr, "interop_server: echoed %d bytes\n", n - 5);
        } else if (strncmp(buf, "quit", 4) == 0) {
            break;
        } else {
            assl_ssl_write(&ssl, fd, buf, n);
        }
    }
    assl_ssl_shutdown(&ssl, fd);
    close(fd);
    close(ls);
    printf("OK\n");
    return 0;
}