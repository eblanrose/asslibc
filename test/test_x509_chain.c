#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "utest.h"
#include "asslibc.h"
#include "x509.h"
#include "rsa_keygen.h"

static void gen_rsa_key(assl_rsa_key *k, unsigned bits) {
    assl_rsa_init(k);
    if (assl_rsa_keygen(k, bits) < 0) {
        fprintf(stderr, "rsa_keygen failed\n");
        exit(1);
    }
}

static void mk_dn(assl_x509_dn_pair *dn, const char *cn) {
    dn[0].attr = ASSL_X509_DN_CN;
    dn[0].value = (const uint8_t *)cn;
    dn[0].value_len = strlen(cn);
}

static uint8_t *gen_cert_p(const assl_rsa_key *subject_key,
                           const assl_rsa_key *issuer_key,
                           const char *issuer_cn,
                           const char *cn, int is_ca,
                           const uint8_t *serial, size_t serial_len,
                           int yr_from, int yr_to,
                           size_t *out_len) {
    assl_x509_dn_pair dn[1];
    mk_dn(dn, cn);
    assl_x509_dn_pair issuer_dn[1];
    if (issuer_cn) mk_dn(issuer_dn, issuer_cn);

    assl_x509_params p;
    memset(&p, 0, sizeof p);
    p.subject_attrs = dn;
    p.subject_attr_count = 1;
    if (issuer_cn) {
        p.issuer_attrs = issuer_dn;
        p.issuer_attr_count = 1;
    }
    p.serial = serial;
    p.serial_len = serial_len;
    p.subject_key = subject_key;
    p.issuer_key = issuer_key;
    p.sig_algo = ASSL_X509_SIG_SHA256_RSA;
    p.is_ca = is_ca;
    p.validity.not_before = (assl_x509_time){(int16_t)yr_from, 1, 1, 0, 0, 0};
    p.validity.not_after = (assl_x509_time){(int16_t)yr_to, 1, 1, 0, 0, 0};

    uint8_t *der = NULL;
    size_t der_len = 0;
    if (assl_x509_generate(&p, &der, &der_len) < 0) {
        fprintf(stderr, "cert generate failed\n");
        exit(1);
    }
    *out_len = der_len;
    return der;
}

static int g_checks = 0;

static void chain_case(const char *name, const uint8_t *const *chain,
                       const size_t *clen, size_t ccnt,
                       const assl_x509_trust_store *store,
                       const char *hostname, int expect) {
    int rc = assl_x509_verify_chain(chain, clen, ccnt, store, hostname, -1);
    printf("%-40s expect=%d got=%d\n", name, expect, rc);
    if ((rc >= 0) != expect) {
        fprintf(stderr, "FAIL %s\n", name);
        exit(1);
    }
    g_checks++;
}

int main(void) {
    assl_rsa_key root_key, mid_key, leaf_key;
    gen_rsa_key(&root_key, 1024);
    gen_rsa_key(&mid_key, 1024);
    gen_rsa_key(&leaf_key, 1024);

    uint8_t r1 = 1, r2 = 2, r3 = 3;

    size_t root_len, mid_len, leaf_len;
    uint8_t *root_der = gen_cert_p(&root_key, &root_key, NULL, "root-ca", 1,
                                   &r1, 1, 2020, 2030, &root_len);
    uint8_t *mid_der = gen_cert_p(&mid_key, &root_key, "root-ca", "mid-ca", 1,
                                  &r2, 1, 2020, 2030, &mid_len);
    uint8_t *leaf_der = gen_cert_p(&leaf_key, &mid_key, "mid-ca", "www.example.com", 0,
                                   &r3, 1, 2020, 2030, &leaf_len);

    assl_x509_trust_store store;
    memset(&store, 0, sizeof store);
    store.der[0] = root_der;
    store.len[0] = root_len;
    store.count = 1;

    {
        const uint8_t *chain[3] = {leaf_der, mid_der, root_der};
        size_t clen[3] = {leaf_len, mid_len, root_len};
        chain_case("full-chain ok", chain, clen, 3, &store, "www.example.com", 1);
        chain_case("full-chain bad-host", chain, clen, 3, &store, "other.example.com", 0);
    }

    {
        const uint8_t *chain[2] = {leaf_der, mid_der};
        size_t clen[2] = {leaf_len, mid_len};
        chain_case("leaf+mid (root in store)", chain, clen, 2, &store, "www.example.com", 1);
    }

    {
        const uint8_t *chain[1] = {leaf_der};
        size_t clen[1] = {leaf_len};
        chain_case("leaf-only (untrusted)", chain, clen, 1, &store, "www.example.com", 0);
    }

    {
        const uint8_t *chain[3] = {leaf_der, mid_der, root_der};
        size_t clen[3] = {leaf_len, mid_len, root_len};
        assl_x509_trust_store empty;
        memset(&empty, 0, sizeof empty);
        chain_case("empty store", chain, clen, 3, &empty, "www.example.com", 0);
    }

    printf("OK: %d chain checks passed\n", g_checks);

    free(root_der);
    free(mid_der);
    free(leaf_der);
    assl_rsa_free(&root_key);
    assl_rsa_free(&mid_key);
    assl_rsa_free(&leaf_key);
    return 0;
}