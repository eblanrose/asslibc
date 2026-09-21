#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <signal.h>
#include "utest.h"
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

static const uint8_t dummy_cert[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };

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

typedef struct {
    int fd;
    assl_rsa_key *key;
    int version;
    int result;
} thread_arg;

static void *server_thread(void *arg) {
    thread_arg *ta = arg;
    assl_ssl ssl;
    assl_ssl_init(&ssl, 0);
    assl_ssl_set_version(&ssl, ta->version);
    assl_ssl_set_cert(&ssl, dummy_cert, sizeof dummy_cert, ta->key);
    ta->result = assl_ssl_handshake(&ssl, ta->fd, ta->fd);
    if (ta->result == 0) {
        char buf[64];
        int n = assl_ssl_read(&ssl, ta->fd, buf, sizeof buf);
        if (n > 0) assl_ssl_write(&ssl, ta->fd, buf, n);
    }
    close(ta->fd);
    return NULL;
}

static int test_version(uint16_t version, const char *name) {
    utest_begin(name);
    int sv[2];
    utest_bool(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    assl_rsa_key k;
    setup_key(&k);

    thread_arg ta = { .fd = sv[1], .key = &k, .version = version, .result = -1 };
    pthread_t tid;
    pthread_create(&tid, NULL, server_thread, &ta);

    assl_ssl client_ssl;
    assl_ssl_init(&client_ssl, 1);
    assl_ssl_set_version(&client_ssl, version);
    assl_ssl_set_cert(&client_ssl, dummy_cert, sizeof dummy_cert, &k);

    int cr = assl_ssl_handshake(&client_ssl, sv[0], sv[0]);
    utest_bool(cr == 0, "client_handshake");
    utest_bool(client_ssl.state == SSL3_STATE_CONNECTED, "client_connected");

    const char *msg = "Hello, TLS!";
    assl_ssl_write(&client_ssl, sv[0], msg, strlen(msg));
    char buf[64];
    int n = assl_ssl_read(&client_ssl, sv[0], buf, sizeof buf);
    utest_bool(n == (int)strlen(msg), "echo_len");
    utest_bool(n > 0 && memcmp(buf, msg, n) == 0, "echo_data");

    pthread_join(tid, NULL);
    utest_bool(ta.result == 0, "server_handshake");

    close(sv[0]);
    assl_rsa_free(&k);
    return utest_end();
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    int fails = 0;
    fails += test_version(TLS10_VERSION, "tls10-handshake");
    fails += test_version(TLS11_VERSION, "tls11-handshake");
    fails += test_version(TLS12_VERSION, "tls12-handshake");
    if (fails == 0) printf("ALL TLS 1.0/1.1/1.2 TESTS PASSED\n");
    return fails;
}
