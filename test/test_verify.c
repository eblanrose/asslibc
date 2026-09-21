#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "utest.h"
#include "asslibc.h"
#include "../ssl.h"
#include "x509.h"
#include "rsa_keygen.h"

static void setup_key(assl_rsa_key *k, unsigned bits) {
    assl_rsa_init(k);
    if (assl_rsa_keygen(k, bits) < 0) {
        fprintf(stderr, "keygen failed\n");
        exit(1);
    }
}

static void mk_dn(assl_x509_dn_pair *dn, const char *cn) {
    dn[0].attr = ASSL_X509_DN_CN;
    dn[0].value = (const uint8_t *)cn;
    dn[0].value_len = strlen(cn);
}

static uint8_t *gen_cert(assl_rsa_key *subject_key, assl_rsa_key *issuer_key,
                         const char *issuer_cn, const char *cn, int is_ca,
                         uint8_t serial, size_t *out_len) {
    assl_x509_dn_pair dn[1], idn[1];
    mk_dn(dn, cn);
    assl_x509_params p;
    memset(&p, 0, sizeof p);
    p.subject_attrs = dn;
    p.subject_attr_count = 1;
    if (issuer_cn) {
        mk_dn(idn, issuer_cn);
        p.issuer_attrs = idn;
        p.issuer_attr_count = 1;
    }
    p.serial = &serial;
    p.serial_len = 1;
    p.subject_key = subject_key;
    p.issuer_key = issuer_key;
    p.sig_algo = ASSL_X509_SIG_SHA256_RSA;
    p.is_ca = is_ca;
    p.validity.not_before = (assl_x509_time){2020, 1, 1, 0, 0, 0};
    p.validity.not_after = (assl_x509_time){2035, 1, 1, 0, 0, 0};

    uint8_t *der = NULL;
    size_t der_len = 0;
    if (assl_x509_generate(&p, &der, &der_len) < 0) {
        fprintf(stderr, "cert generate failed\n");
        exit(1);
    }
    *out_len = der_len;
    return der;
}

typedef struct {
    int rd_fd;
    int wr_fd;
    assl_rsa_key *key;
    const uint8_t *cert_der;
    size_t cert_len;
    int version;
    int result;
} srv_arg;

static void *run_server(void *vp) {
    srv_arg *a = vp;
    assl_ssl ssl;
    assl_ssl_init(&ssl, 0);
    assl_ssl_set_version(&ssl, a->version);
    assl_ssl_set_cert(&ssl, a->cert_der, a->cert_len, a->key);
    a->result = assl_ssl_handshake(&ssl, a->rd_fd, a->wr_fd);
    if (a->result == 0) {
        char buf[32];
        int n = assl_ssl_read(&ssl, a->rd_fd, buf, sizeof buf);
        if (n > 0) assl_ssl_write(&ssl, a->wr_fd, buf, n);
    }
    return NULL;
}

static void run_client(assl_rsa_key *server_key, const uint8_t *srv_der,
                       size_t srv_len, const uint8_t *root_der,
                       size_t root_len, int version, int verify,
                       const char *hostname, int expect_ok,
                       const char *name) {
    utest_begin(name);
    int c2s[2], s2c[2];
    utest_bool(pipe(c2s) == 0, "pipe_c2s");
    utest_bool(pipe(s2c) == 0, "pipe_s2c");

    srv_arg a = {
        .rd_fd = c2s[0], .wr_fd = s2c[1], .key = server_key,
        .cert_der = srv_der, .cert_len = srv_len, .version = version, .result = -1
    };
    pthread_t th;
    utest_bool(pthread_create(&th, NULL, run_server, &a) == 0, "pthread_create");

    assl_ssl ssl;
    assl_ssl_init(&ssl, 1);
    assl_ssl_set_version(&ssl, version);
    if (verify) {
        assl_ssl_set_verify(&ssl, 1, hostname);
        if (root_der) assl_ssl_add_trust(&ssl, root_der, root_len);
    }
    int rc = assl_ssl_handshake(&ssl, s2c[0], c2s[1]);
    if (rc == 0) {
        assl_ssl_write(&ssl, c2s[1], "ping", 4);
        char buf[16];
        int n = assl_ssl_read(&ssl, s2c[0], buf, sizeof buf);
        utest_bool(n == 4 && memcmp(buf, "ping", 4) == 0, "echo");
    }
    utest_bool((rc == 0) == expect_ok, "handshake_result");

    pthread_join(th, NULL);
    close(c2s[0]); close(c2s[1]); close(s2c[0]); close(s2c[1]);
    utest_end();
}

int main(void) {
    assl_rsa_key root_key, srv_key;
    setup_key(&root_key, 1024);
    setup_key(&srv_key, 1024);

    size_t root_len, srv_len;
    uint8_t *root_der = gen_cert(&root_key, &root_key, NULL, "test-root", 1, 1, &root_len);
    uint8_t *srv_der = gen_cert(&srv_key, &root_key, "test-root", "localhost", 0, 2, &srv_len);

    uint16_t versions[2] = { TLS12_VERSION, TLS13_VERSION };
    const char *vnames[2] = { "tls12", "tls13" };

    for (int v = 0; v < 2; v++) {
        char name[64];
        fprintf(stderr, "CASE %s-verify-valid\n", vnames[v]);
        snprintf(name, sizeof name, "%s-verify-valid", vnames[v]);
        run_client(&srv_key, srv_der, srv_len, root_der, root_len, versions[v], 1, "localhost", 1, name);
        fprintf(stderr, "CASE %s-verify-badhost\n", vnames[v]);
        snprintf(name, sizeof name, "%s-verify-badhost", vnames[v]);
        run_client(&srv_key, srv_der, srv_len, root_der, root_len, versions[v], 1, "evil.com", 0, name);
        fprintf(stderr, "CASE %s-verify-notrust\n", vnames[v]);
        snprintf(name, sizeof name, "%s-verify-notrust", vnames[v]);
        run_client(&srv_key, srv_der, srv_len, NULL, 0, versions[v], 1, "localhost", 0, name);
        fprintf(stderr, "CASE %s-noverify\n", vnames[v]);
        snprintf(name, sizeof name, "%s-noverify", vnames[v]);
        run_client(&srv_key, srv_der, srv_len, NULL, 0, versions[v], 0, NULL, 1, name);
    }

    free(root_der);
    free(srv_der);
    assl_rsa_free(&root_key);
    assl_rsa_free(&srv_key);
    return 0;
}