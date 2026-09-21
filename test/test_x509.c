#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "utest.h"
#include "asslibc.h"
#include "asn1.h"
#include "x509.h"

static const uint8_t selfsigned_der[] = {
    0x30,0x82,0x01,0x8F,0x30,0x81,0xF9,0xA0,0x03,0x02,0x01,0x02,0x02,0x01,0x01,0x30,
    0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x05,0x05,0x00,0x30,0x0D,
    0x31,0x0B,0x30,0x09,0x06,0x03,0x55,0x04,0x03,0x0C,0x02,0x43,0x41,0x30,0x20,0x17,
    0x0D,0x31,0x33,0x30,0x39,0x31,0x35,0x31,0x35,0x33,0x35,0x30,0x32,0x5A,0x18,0x0F,
    0x32,0x31,0x31,0x33,0x30,0x39,0x32,0x32,0x31,0x35,0x33,0x35,0x30,0x32,0x5A,0x30,
    0x0D,0x31,0x0B,0x30,0x09,0x06,0x03,0x55,0x04,0x03,0x0C,0x02,0x43,0x41,0x30,0x81,
    0x9F,0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00,
    0x03,0x81,0x8D,0x00,0x30,0x81,0x89,0x02,0x81,0x81,0x00,0x8D,0x80,0xB5,0x8E,0x80,
    0x8E,0x94,0xD1,0x04,0x03,0x6A,0x45,0x1A,0x54,0x5E,0x7E,0xEE,0x6D,0x0C,0xCB,0x0B,
    0x82,0x03,0xF1,0x7D,0xC9,0x6F,0xED,0x52,0x02,0xB2,0x08,0xC3,0x48,0xD1,0x24,0x70,
    0xC3,0x50,0xC2,0x1C,0x40,0xBC,0xB5,0x9D,0xF8,0xE8,0xA8,0x41,0x16,0x7B,0x0B,0x34,
    0x1F,0x27,0x8D,0x32,0x2D,0x38,0xBA,0x18,0xA5,0x31,0xA9,0xE3,0x15,0x20,0x3D,0xE4,
    0x0A,0xDC,0xD8,0xCD,0x42,0xB0,0xE3,0x66,0x53,0x85,0x21,0x7C,0x90,0x13,0xE9,0xF9,
    0xC9,0x26,0x5A,0xF3,0xFF,0x8C,0xA8,0x92,0x25,0xCD,0x23,0x08,0x69,0xF4,0xA2,0xF8,
    0x7B,0xBF,0xCD,0x45,0xE8,0x19,0x33,0xF1,0xAA,0xE0,0x2B,0x92,0x31,0x22,0x34,0x60,
    0x27,0x2E,0xD7,0x56,0x04,0x8B,0x1B,0x59,0x64,0x77,0x5F,0x02,0x03,0x01,0x00,0x01,
    0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x05,0x05,0x00,0x03,
    0x81,0x81,0x00,0x0A,0x1C,0xED,0x77,0xF4,0x79,0xD5,0xEC,0x73,0x51,0x32,0x25,0x09,
    0x61,0xF7,0x00,0xC4,0x64,0x74,0x29,0x86,0x5B,0x67,0xF2,0x3D,0xA9,0x39,0x34,0x6B,
    0x3C,0xA9,0x92,0xB8,0xBF,0x07,0x13,0x0B,0xA0,0x9B,0xDF,0x41,0xE2,0x8A,0xF6,0xD3,
    0x17,0x53,0xE1,0xBA,0x7F,0xC0,0xD0,0xBC,0x10,0xB7,0x9B,0x63,0x4F,0x06,0xD0,0x7B,
    0xAC,0xC6,0xFB,0xCE,0x95,0xF7,0x8A,0x72,0xAA,0x10,0xEA,0xB0,0xD1,0x6D,0x74,0x69,
    0x5E,0x20,0x68,0x5D,0x1A,0x66,0x28,0xC5,0x59,0x33,0x43,0xDB,0xEE,0xDA,0x00,0x80,
    0x99,0x5E,0xDD,0x17,0xAC,0x43,0x36,0x1E,0xD0,0x5B,0x06,0x0F,0x8C,0x6C,0x82,0xD3,
    0xBB,0x3E,0x2B,0xA5,0xF1,0x94,0xFB,0x53,0x7B,0xB0,0x54,0x22,0x6F,0xF6,0x4C,0x18,
    0x1B,0x72,0x1C
};

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

static int test_asn1_parse(void) {
    utest_begin("asn1-parse");
    asn1_node n;
    utest_bool(asn1_parse(selfsigned_der, sizeof selfsigned_der, &n) == 0, "outer_seq");
    utest_bool(n.tag == ASN1_TAG_SEQUENCE, "outer_tag");
    utest_bool(n.len == 0x018F, "outer_len");

    asn1_node tbs;
    utest_bool(asn1_parse(n.value, n.len, &tbs) == 0, "tbs_parse");
    utest_bool(tbs.tag == ASN1_TAG_SEQUENCE, "tbs_tag");

    asn1_node ver;
    utest_bool(asn1_find(&tbs, ASN1_TAG_CTX0, &ver) == 0, "version_ext");
    asn1_node vi;
    utest_bool(asn1_find(&ver, ASN1_TAG_INTEGER, &vi) == 0, "version_int");
    uint8_t vbuf[4];
    int vlen = asn1_read_int(&vi, vbuf, sizeof vbuf);
    utest_bool(vlen == 1, "version_len");
    utest_bool(vbuf[0] == 2, "version_val");

    asn1_node seq;
    utest_bool(asn1_parse(tbs.value, tbs.len, &seq) == 0, "tbs_child0");
    asn1_node ser;
    utest_bool(asn1_next(&seq, (size_t)(tbs.value + tbs.len - seq.end), &ser) == 0, "serial_next");
    utest_bool(ser.tag == ASN1_TAG_INTEGER, "serial_tag");
    uint8_t sbuf[4];
    int slen = asn1_read_int(&ser, sbuf, sizeof sbuf);
    utest_bool(slen == 1 && sbuf[0] == 1, "serial_val");

    return utest_end();
}

static int test_x509_parse(void) {
    utest_begin("x509-parse");
    assl_x509_cert cert;
    utest_bool(assl_x509_parse(&cert, selfsigned_der, sizeof selfsigned_der) == 0, "parse");

    utest_bool(cert.version == 3, "version");
    utest_bool(cert.serial_len == 1 && cert.serial[0] == 0x01, "serial");
    utest_bool(cert.sig_algo == ASSL_X509_SIG_SHA1_RSA, "sig_algo");
    utest_bool(cert.hash_algo == ASSL_H_SHA1, "hash_algo");

    int found_issuer_cn = 0;
    for (size_t i = 0; i < cert.issuer_attr_count; i++) {
        if (cert.issuer_attrs[i].attr == ASSL_X509_DN_CN) {
            utest_bool(cert.issuer_attrs[i].value_len == 2, "issuer_cn_len");
            utest_bool(memcmp(cert.issuer_attrs[i].value, "CA", 2) == 0, "issuer_cn");
            found_issuer_cn = 1;
        }
    }
    utest_bool(found_issuer_cn, "issuer_has_cn");

    int found_subject_cn = 0;
    for (size_t i = 0; i < cert.subject_attr_count; i++) {
        if (cert.subject_attrs[i].attr == ASSL_X509_DN_CN) {
            utest_bool(cert.subject_attrs[i].value_len == 2, "subject_cn_len");
            utest_bool(memcmp(cert.subject_attrs[i].value, "CA", 2) == 0, "subject_cn");
            found_subject_cn = 1;
        }
    }
    utest_bool(found_subject_cn, "subject_has_cn");

    utest_bool(cert.validity.not_before.year == 2013, "nb_year");
    utest_bool(cert.validity.not_before.month == 9, "nb_month");
    utest_bool(cert.validity.not_before.day == 15, "nb_day");
    utest_bool(cert.validity.not_after.year == 2113, "na_year");
    utest_bool(cert.validity.not_after.month == 9, "na_month");
    utest_bool(cert.validity.not_after.day == 22, "na_day");

    utest_bool(cert.pk_algo == ASSL_X509_PK_RSA, "pk_algo");
    utest_bool(cert.pubkey.bits == 1024, "key_bits");

    {
        uint8_t ebuf[4];
        int ok = assl_bn_to_bin(&cert.pubkey.e, ebuf, sizeof ebuf);
        utest_bool(ok == 0 && ebuf[1] == 0x01 && ebuf[2] == 0x00 && ebuf[3] == 0x01, "exponent");
    }

    size_t nlen = assl_bn_bytes(&cert.pubkey.n);
    utest_bool(nlen == 128, "modulus_len");

    utest_bool(cert.tbs != NULL && cert.tbs_len > 0, "tbs_present");
    utest_bool(cert.signature != NULL && cert.sig_len > 0, "sig_present");

    assl_x509_free(&cert);
    return utest_end();
}

static int test_x509_verify_self(void) {
    utest_begin("x509-verify-self");
    assl_x509_cert cert;
    utest_bool(assl_x509_parse(&cert, selfsigned_der, sizeof selfsigned_der) == 0, "parse");
    utest_bool(assl_x509_verify_self(&cert) == 0, "verify_self_signed");
    assl_x509_free(&cert);
    return utest_end();
}

static int test_x509_fingerprint(void) {
    utest_begin("x509-fingerprint");
    uint8_t fp[20];
    assl_hash_one(ASSL_H_SHA1, selfsigned_der, sizeof selfsigned_der, fp);
    int nonzero = 0;
    for (int i = 0; i < 20; i++) if (fp[i]) nonzero = 1;
    utest_bool(nonzero, "fingerprint_nonzero");
    return utest_end();
}

static int test_x509_generate(void) {
    utest_begin("x509-generate");

    assl_rsa_key k;
    setup_key(&k);

    assl_x509_dn_pair dn[1];
    dn[0].attr = ASSL_X509_DN_CN;
    dn[0].value = (const uint8_t *)"TestCert";
    dn[0].value_len = 8;

    uint8_t serial = 0x42;

    assl_x509_params params = {0};
    params.subject_attrs = dn;
    params.subject_attr_count = 1;
    params.serial = &serial;
    params.serial_len = 1;
    params.validity.not_before.year = 2024;
    params.validity.not_before.month = 1;
    params.validity.not_before.day = 1;
    params.validity.not_before.hour = 0;
    params.validity.not_before.min = 0;
    params.validity.not_before.sec = 0;
    params.validity.not_after.year = 2034;
    params.validity.not_after.month = 12;
    params.validity.not_after.day = 31;
    params.validity.not_after.hour = 23;
    params.validity.not_after.min = 59;
    params.validity.not_after.sec = 59;
    params.subject_key = &k;
    params.sig_algo = ASSL_X509_SIG_SHA256_RSA;

    uint8_t *der = NULL;
    size_t der_len = 0;
    int rc = assl_x509_generate_self_signed(&params, &der, &der_len);
    utest_bool(rc == 0, "generate");
    utest_bool(der != NULL && der_len > 0, "der_nonempty");

    if (der) {
        assl_x509_cert cert;
        rc = assl_x509_parse(&cert, der, der_len);
        utest_bool(rc == 0, "parse_generated");

        int found_cn = 0;
        for (size_t i = 0; i < cert.subject_attr_count; i++) {
            if (cert.subject_attrs[i].attr == ASSL_X509_DN_CN &&
                cert.subject_attrs[i].value_len == 8 &&
                memcmp(cert.subject_attrs[i].value, "TestCert", 8) == 0)
                found_cn = 1;
        }
        utest_bool(found_cn, "subject_cn");

        utest_bool(cert.version == 3, "version");
        utest_bool(cert.serial_len == 1 && cert.serial[0] == 0x42, "serial");

        rc = assl_x509_verify_self(&cert);
        utest_bool(rc == 0, "verify_self");

        assl_x509_free(&cert);
        free(der);
    }

    assl_rsa_free(&k);
    return utest_end();
}

int main(void) {
    int fails = 0;
    fails += test_asn1_parse();
    fails += test_x509_parse();
    fails += test_x509_verify_self();
    fails += test_x509_fingerprint();
    fails += test_x509_generate();
    if (fails == 0) printf("ALL X509 TESTS PASSED\n");
    return fails;
}
