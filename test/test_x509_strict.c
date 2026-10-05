#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "utest.h"
#include "asslibc.h"
#include "x509.h"
#include "rsa_keygen.h"


typedef struct { uint8_t *b; size_t len, cap; } buf;

static void bput(buf *o, const void *d, size_t n) {
    if (!o->b || o->len + n > o->cap) {
        o->cap = (o->len + n) * 2;
        o->b = realloc(o->b, o->cap);
        if (!o->b) exit(1);
    }
    memcpy(o->b + o->len, d, n);
    o->len += n;
}

static void btaglen(buf *o, uint8_t tag, size_t len) {
    uint8_t t = tag;
    bput(o, &t, 1);
    if (len < 0x80) {
        uint8_t l = (uint8_t)len;
        bput(o, &l, 1);
    } else if (len < 0x100) {
        uint8_t t2[2] = { 0x81, (uint8_t)len };
        bput(o, t2, 2);
    } else {
        uint8_t t3[3] = { 0x82, (uint8_t)(len >> 8), (uint8_t)len };
        bput(o, t3, 3);
    }
}

static void wrap(buf *out, uint8_t tag, const uint8_t *content, size_t len) {
    btaglen(out, tag, len);
    bput(out, content, len);
}

static int rebuild(buf *out, const asn1_node *n, uint8_t inner_tag,
                   const uint8_t *replacement, size_t replacement_len) {
    buf body = {0};
    const uint8_t *p = n->value, *end = n->value + n->len;
    int done = 0;
    while (p < end) {
        asn1_node c;
        if (asn1_parse(p, (size_t)(end - p), &c) < 0) { free(body.b); return -1; }
        if (!done && c.tag == inner_tag) {
            wrap(&body, inner_tag, replacement, replacement_len);
            done = 1;
        } else {
            bput(&body, c.raw, (size_t)(c.end - c.raw));
        }
        p = c.end;
    }
    if (!done) { free(body.b); return -1; }
    wrap(out, n->tag, body.b, body.len);
    free(body.b);
    return 0;
}

static void unknown_ext(buf *out, int critical) {
    buf ext = {0}, fields = {0};
    const uint8_t oid[] = { 0x06, 0x03, 0x55, 0x1D, 0x20 };
    bput(&fields, oid, sizeof oid);
    if (critical) {
        const uint8_t boo[] = { 0x01, 0x01, 0xFF };
        bput(&fields, boo, sizeof boo);
    }
    const uint8_t inner[] = { 0x30, 0x00 };
    btaglen(&fields, 0x04, sizeof inner);
    bput(&fields, inner, sizeof inner);
    wrap(&ext, 0x30, fields.b, fields.len);
    bput(out, ext.b, ext.len);
    free(ext.b);
    free(fields.b);
}

static uint8_t *add_ext(const uint8_t *der, size_t der_len, int critical, size_t *out_len) {
    asn1_node outer, tbs, exts, extlist;
    if (asn1_parse(der, der_len, &outer) < 0) return NULL;
    if (asn1_parse(outer.value, outer.len, &tbs) < 0) return NULL;
    if (asn1_find(&tbs, ASN1_TAG_CTX3, &exts) < 0) return NULL;
    if (asn1_find(&exts, ASN1_TAG_SEQUENCE, &extlist) < 0) return NULL;

    buf list = {0}, newseq = {0}, new_tbs = {0}, new_outer = {0}, out = {0};
    bput(&list, extlist.value, extlist.len);
    unknown_ext(&list, critical);
    wrap(&newseq, ASN1_TAG_SEQUENCE, list.b, list.len);

    if (rebuild(&new_tbs, &tbs, ASN1_TAG_CTX3, newseq.b, newseq.len) < 0) goto fail;
    bput(&new_outer, new_tbs.b, new_tbs.len);
    bput(&new_outer, tbs.end, (size_t)(outer.end - tbs.end));
    wrap(&out, outer.tag, new_outer.b, new_outer.len);

    free(list.b); free(newseq.b); free(new_tbs.b); free(new_outer.b);
    *out_len = out.len;
    return out.b;
fail:
    free(list.b); free(newseq.b); free(new_tbs.b); free(new_outer.b); free(out.b);
    return NULL;
}


static uint8_t *make_cert(const assl_rsa_key *subj, const assl_rsa_key *iss,
                          const char *issuer_cn, const char *cn, size_t *len) {
    assl_x509_dn_pair dn[1], idn[1];
    dn[0].attr = ASSL_X509_DN_CN; dn[0].value = (const uint8_t *)cn; dn[0].value_len = strlen(cn);
    uint8_t serial = 7;
    assl_x509_params p;
    memset(&p, 0, sizeof p);
    p.subject_attrs = dn; p.subject_attr_count = 1;
    if (issuer_cn) {
        idn[0].attr = ASSL_X509_DN_CN;
        idn[0].value = (const uint8_t *)issuer_cn;
        idn[0].value_len = strlen(issuer_cn);
        p.issuer_attrs = idn;
        p.issuer_attr_count = 1;
    }
    p.serial = &serial; p.serial_len = 1;
    p.subject_key = subj; p.issuer_key = iss;
    p.sig_algo = ASSL_X509_SIG_SHA256_RSA;
    p.is_ca = 1;
    p.validity.not_before = (assl_x509_time){ 2020, 1, 1, 0, 0, 0 };
    p.validity.not_after  = (assl_x509_time){ 2030, 1, 1, 0, 0, 0 };
    uint8_t *der = NULL;
    if (assl_x509_generate(&p, &der, len) < 0) exit(1);
    return der;
}

int main(void) {
    assl_rsa_key root_key, leaf_key;
    assl_rsa_init(&root_key); assl_rsa_init(&leaf_key);
    if (assl_rsa_keygen(&root_key, 2048) < 0 || assl_rsa_keygen(&leaf_key, 2048) < 0) {
        fprintf(stderr, "rsa_keygen failed\n");
        return 1;
    }
    size_t root_len, leaf_len;
    uint8_t *root_der = make_cert(&root_key, &root_key, NULL, "root-ca", &root_len);
    uint8_t *leaf_der = make_cert(&leaf_key, &root_key, "root-ca", "leaf", &leaf_len);

    utest_begin("x509-unknown-critical");

    {
        assl_x509_cert c;
        utest_bool(assl_x509_parse(&c, root_der, root_len) == 0, "parse root");
        utest_bool(c.has_unknown_critical == 0, "generated cert has no unknown critical");
        assl_x509_free(&c);
    }

    size_t crit_len = 0, noncrit_len = 0;
    uint8_t *crit_der = add_ext(root_der, root_len, 1, &crit_len);
    uint8_t *noncrit_der = add_ext(root_der, root_len, 0, &noncrit_len);
    utest_bool(crit_der != NULL, "splice critical ext");
    utest_bool(noncrit_der != NULL, "splice non-critical ext");

    if (crit_der) {
        assl_x509_cert c;
        utest_bool(assl_x509_parse(&c, crit_der, crit_len) == 0, "parse spliced cert");
        utest_bool(c.has_unknown_critical == 1, "critical unknown extension flagged");
        utest_bool(c.has_basic_constraints == 1, "original extension still parsed");
        assl_x509_free(&c);
    }
    if (noncrit_der) {
        assl_x509_cert c;
        utest_bool(assl_x509_parse(&c, noncrit_der, noncrit_len) == 0, "parse non-critical");
        utest_bool(c.has_unknown_critical == 0, "non-critical unknown ignored");
        assl_x509_free(&c);
    }

    {
        assl_x509_trust_store strict;
        memset(&strict, 0, sizeof strict);
        strict.strict = 1;
        if (crit_der) {
            const uint8_t *chain[1] = { crit_der };
            size_t clen[1] = { crit_len };
            strict.der[0] = crit_der; strict.len[0] = crit_len; strict.count = 1;
            utest_bool(assl_x509_verify_chain(chain, clen, 1, &strict, NULL, -1) != 0,
                       "strict store refuses spliced anchor");
        }
    }

    free(crit_der);
    free(noncrit_der);
    free(root_der);
    free(leaf_der);
    assl_rsa_free(&root_key);
    assl_rsa_free(&leaf_key);

    int fails = utest_end();
    if (!fails) printf("ALL X509 STRICT TESTS PASSED\n");
    return fails;
}