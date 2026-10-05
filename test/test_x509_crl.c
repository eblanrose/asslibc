#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "utest.h"
#include "asslibc.h"
#include "x509.h"

#define DIR "test/crl/"

static uint8_t *slurp(const char *name, size_t *len) {
    char path[256];
    snprintf(path, sizeof path, DIR "%s", name);
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "missing fixture %s\n", path); exit(1); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc((size_t)n);
    if (!b || fread(b, 1, (size_t)n, f) != (size_t)n) { fprintf(stderr, "read %s\n", path); exit(1); }
    fclose(f);
    *len = (size_t)n;
    return b;
}

static assl_x509_cert cert_of(uint8_t *der, size_t len) {
    assl_x509_cert c;
    if (assl_x509_parse(&c, der, len) < 0) { fprintf(stderr, "cert parse failed\n"); exit(1); }
    return c;
}

static void key_of(const assl_x509_cert *c, assl_rsa_key *k) {
    assl_rsa_init(k);
    assl_bn_init(&k->n);
    assl_bn_init(&k->e);
    if (assl_bn_copy(&k->n, &c->pubkey.n) || assl_bn_copy(&k->e, &c->pubkey.e)) {
        fprintf(stderr, "key copy failed\n");
        exit(1);
    }
    k->have_priv = 0;
}

int main(void) {
    size_t ca_len, other_len, good_len, bad_len;
    size_t crl_rev_len, crl_empty_len, crl_other_len;
    uint8_t *ca_der = slurp("ca.der", &ca_len);
    uint8_t *other_der = slurp("other.der", &other_len);
    uint8_t *good_der = slurp("good.der", &good_len);
    uint8_t *bad_der = slurp("bad.der", &bad_len);
    uint8_t *crl_rev = slurp("crl_revoked.der", &crl_rev_len);
    uint8_t *crl_empty = slurp("crl_empty.der", &crl_empty_len);
    uint8_t *crl_other = slurp("crl_other.der", &crl_other_len);

    assl_x509_cert ca = cert_of(ca_der, ca_len);
    assl_x509_cert other = cert_of(other_der, other_len);
    assl_x509_cert good = cert_of(good_der, good_len);
    assl_x509_cert bad = cert_of(bad_der, bad_len);

    assl_rsa_key ca_key, other_key;
    key_of(&ca, &ca_key);
    key_of(&other, &other_key);

    int64_t now = (int64_t)time(NULL);

    utest_begin("crl-parse");

    assl_x509_crl crl;
    utest_bool(assl_x509_crl_parse(&crl, crl_rev, crl_rev_len) == 0, "parse revoked CRL");
    utest_bool(crl.revoked_count == 1, "one entry");
    utest_bool(crl.has_next_update == 1, "nextUpdate present");
    utest_bool(crl.this_update <= now && now <= crl.next_update, "window covers now");
    utest_bool(crl.sig_algo == ASSL_X509_SIG_SHA256_RSA, "sig algo");
    utest_bool(assl_x509_dn_raw_eq(&crl.issuer, &ca.subject) != 0, "issuer is the CA");

    assl_x509_crl empty;
    utest_bool(assl_x509_crl_parse(&empty, crl_empty, crl_empty_len) == 0, "parse empty CRL");
    utest_bool(empty.revoked_count == 0, "no entries");

    utest_bool(assl_x509_crl_parse(&crl, crl_rev, 4) < 0, "short buffer refused");
    {
        uint8_t *copy = malloc(crl_rev_len);
        memcpy(copy, crl_rev, crl_rev_len);
        copy[crl_rev_len - 1] ^= 0xff;
        assl_x509_crl broken;
        utest_bool(assl_x509_crl_parse(&broken, copy, crl_rev_len) == 0, "parses despite bad sig");
        utest_bool(assl_x509_crl_check(&broken, &ca_key, &ca.subject, now) < 0,
                   "but signature check rejects it");
        free(copy);
    }

    utest_begin("crl-check");
    utest_bool(assl_x509_crl_check(&crl, &ca_key, &ca.subject, now) == 0, "valid CRL accepted");
    utest_bool(assl_x509_crl_check(&crl, &other_key, &ca.subject, now) < 0,
               "wrong key rejected");
    utest_bool(assl_x509_crl_check(&crl, &ca_key, &other.subject, now) < 0,
               "wrong issuer name rejected");
    utest_bool(assl_x509_crl_check(&crl, &ca_key, &ca.subject, crl.next_update + 1) < 0,
               "expired CRL rejected");
    utest_bool(assl_x509_crl_check(&crl, &ca_key, &ca.subject, crl.this_update - 1) < 0,
               "not-yet-valid CRL rejected");

    utest_begin("crl-lookup");
    utest_bool(assl_x509_crl_is_revoked(&crl, &good) == 0, "good cert not revoked");
    utest_bool(assl_x509_crl_is_revoked(&crl, &bad) == 1, "bad cert revoked");
    utest_bool(assl_x509_crl_is_revoked(&empty, &bad) == 0, "empty CRL revokes nothing");

    utest_begin("crl-chain");
    {
        assl_x509_trust_store st;
        memset(&st, 0, sizeof st);
        st.der[0] = ca_der; st.len[0] = ca_len; st.count = 1;

        const uint8_t *chain_good[1] = { good_der };
        size_t clen_good[1] = { good_len };
        const uint8_t *chain_bad[1] = { bad_der };
        size_t clen_bad[1] = { bad_len };

        utest_bool(assl_x509_verify_chain(chain_bad, clen_bad, 1, &st, NULL, now) == 0,
                   "revoked cert accepted when checking is off");

        st.check_revocation = 1;

        utest_bool(assl_x509_verify_chain(chain_good, clen_good, 1, &st, NULL, now) != 0,
                   "no CRL at all is refused");

        st.crl_der[0] = crl_empty; st.crl_len[0] = crl_empty_len; st.crl_count = 1;
        utest_bool(assl_x509_verify_chain(chain_good, clen_good, 1, &st, NULL, now) == 0,
                   "empty CRL accepts a good cert");

        st.crl_der[0] = crl_rev; st.crl_len[0] = crl_rev_len;
        utest_bool(assl_x509_verify_chain(chain_good, clen_good, 1, &st, NULL, now) == 0,
                   "listed-but-elsewhere CRL accepts a good cert");
        utest_bool(assl_x509_verify_chain(chain_bad, clen_bad, 1, &st, NULL, now) != 0,
                   "revoked cert refused");

        st.crl_der[0] = crl_other; st.crl_len[0] = crl_other_len;
        utest_bool(assl_x509_verify_chain(chain_good, clen_good, 1, &st, NULL, now) != 0,
                   "foreign CRL is refused");

        st.crl_der[0] = good_der; st.crl_len[0] = good_len;
        utest_bool(assl_x509_verify_chain(chain_good, clen_good, 1, &st, NULL, now) != 0,
                   "non-CRL blob is refused");

        st.crl_der[0] = crl_rev; st.crl_len[0] = crl_rev_len;
        utest_bool(assl_x509_verify_chain(chain_good, clen_good, 1, &st, NULL,
                                          crl.next_update + 1) != 0,
                   "expired CRL is refused");

        st.crl_der[0] = crl_other; st.crl_len[0] = crl_other_len;
        st.crl_der[1] = crl_rev;   st.crl_len[1] = crl_rev_len; st.crl_count = 2;
        utest_bool(assl_x509_verify_chain(chain_good, clen_good, 1, &st, NULL, now) == 0,
                   "picks the usable CRL out of several");
    }

    assl_bn_free(&ca_key.n); assl_bn_free(&ca_key.e);
    assl_bn_free(&other_key.n); assl_bn_free(&other_key.e);
    assl_x509_free(&ca); assl_x509_free(&other);
    assl_x509_free(&good); assl_x509_free(&bad);
    free(ca_der); free(other_der); free(good_der); free(bad_der);
    free(crl_rev); free(crl_empty); free(crl_other);

    int fails = utest_end();
    if (!fails) printf("ALL X509 CRL TESTS PASSED\n");
    return fails;
}