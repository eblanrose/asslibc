#include <stdio.h>
#include <string.h>
#include "utest.h"
#include "asslibc.h"

static int test_p256_init(void) {
    utest_begin("p256-init");
    utest_bool(assl_p256_init() == 0, "init");
    return utest_end();
}

static int test_p256_on_curve(void) {
    utest_begin("p256-on-curve");
    uint8_t g[64];
    assl_bn gx, gy;
    assl_bn_init(&gx); assl_bn_init(&gy);
    assl_bn_from_hex(&gx, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    assl_bn_from_hex(&gy, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    assl_bn_to_bin(&gx, g, 32);
    assl_bn_to_bin(&gy, g + 32, 32);
    utest_bool(assl_p256_on_curve(g) == 1, "generator_on_curve");
    assl_bn_free(&gx); assl_bn_free(&gy);
    return utest_end();
}

static int test_p256_mul_base(void) {
    utest_begin("p256-mul-base");
    uint8_t k[32], pt[64];
    memset(k, 0, 32);
    k[31] = 1; 
    utest_bool(assl_p256_mul_base(k, pt) == 0, "mul_base_1");
    utest_bool(assl_p256_on_curve(pt) == 1, "on_curve");
    uint8_t gx[32], gy[32];
    assl_bn gxn, gyn;
    assl_bn_init(&gxn); assl_bn_init(&gyn);
    assl_bn_from_hex(&gxn, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    assl_bn_from_hex(&gyn, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    assl_bn_to_bin(&gxn, gx, 32);
    assl_bn_to_bin(&gyn, gy, 32);
    utest_bool(memcmp(pt, gx, 32) == 0 && memcmp(pt + 32, gy, 32) == 0, "equals_G");
    assl_bn_free(&gxn); assl_bn_free(&gyn);
    return utest_end();
}

static int test_p256_keygen(void) {
    utest_begin("p256-keygen");
    uint8_t d[32], q[64];
    utest_bool(assl_p256_keygen(d, q) == 0, "keygen");
    utest_bool(assl_p256_on_curve(q) == 1, "pubkey_on_curve");
    int nonzero = 0;
    for (int i = 0; i < 32; i++) if (d[i]) nonzero = 1;
    utest_bool(nonzero, "privkey_nonzero");
    return utest_end();
}

static int test_p256_ecdh(void) {
    utest_begin("p256-ecdh");
    uint8_t d1[32], q1[64], d2[32], q2[64], s1[32], s2[32];
    utest_bool(assl_p256_keygen(d1, q1) == 0, "keygen1");
    utest_bool(assl_p256_keygen(d2, q2) == 0, "keygen2");
    utest_bool(assl_p256_ecdh(d1, q2, s1) == 0, "ecdh1");
    utest_bool(assl_p256_ecdh(d2, q1, s2) == 0, "ecdh2");
    utest_bool(memcmp(s1, s2, 32) == 0, "shared_equal");
    return utest_end();
}

static int test_p256_ecdsa(void) {
    utest_begin("p256-ecdsa");
    uint8_t d[32], q[64], digest[32], r[32], s[32];
    utest_bool(assl_p256_keygen(d, q) == 0, "keygen");
    memset(digest, 0xAB, 32);
    utest_bool(assl_p256_sign(d, digest, r, s) == 0, "sign");
    utest_bool(assl_p256_verify(q, digest, r, s) == 1, "verify");
    uint8_t bad[32];
    memset(bad, 0xCD, 32);
    utest_bool(assl_p256_verify(q, bad, r, s) == 0, "verify_wrong_digest");
    return utest_end();
}

int main(void) {
    int fails = 0;
    fails += test_p256_init();
    fails += test_p256_on_curve();
    fails += test_p256_mul_base();
    fails += test_p256_keygen();
    fails += test_p256_ecdh();
    fails += test_p256_ecdsa();
    if (fails == 0) printf("ALL ECC TESTS PASSED\n");
    return fails;
}
