#include <stdio.h>
#include <string.h>
#include "utest.h"
#include "asslibc.h"
#include "test_dh_vectors.h"

static int dh_group_vectors(int grp, const char *privA, const char *privB,
                            const char *pubA, const char *pubB, const char *shared) {
    char name[16];
    snprintf(name, sizeof name, "dh-%s", grp == ASSL_DH_FFDHE2048 ? "2048" : "3072");
    utest_begin(name);
    assl_bn p, g, a, b, pa, pb, s, t;
    assl_bn_init(&p); assl_bn_init(&g); assl_bn_init(&a); assl_bn_init(&b);
    assl_bn_init(&pa); assl_bn_init(&pb); assl_bn_init(&s); assl_bn_init(&t);
    utest_bool(assl_dh_group(grp, &p, &g) == 0, "group_ok");
    utest_bool(assl_bn_is_one(&g) == 0, "g_is_2");
    utest_bool(assl_bn_from_hex(&a, privA) == 0, "privA_hex");
    utest_bool(assl_bn_from_hex(&b, privB) == 0, "privB_hex");
    utest_bool(assl_dh_pub(&p, &g, &a, &pa) == 0, "pubA");
    {
        assl_bn exp;
        assl_bn_init(&exp);
        utest_bool(assl_bn_from_hex(&exp, pubA) == 0, "pubA_expect");
        utest_bool(assl_bn_cmp(&pa, &exp) == 0, "pubA_knows");
        utest_bool(assl_dh_pub(&p, &g, &b, &pb) == 0, "pubB");
        utest_bool(assl_bn_from_hex(&exp, pubB) == 0, "pubB_expect");
        utest_bool(assl_bn_cmp(&pb, &exp) == 0, "pubB_knows");
        assl_bn_free(&exp);
    }
    utest_bool(assl_dh_shared(&p, &a, &pb, &s) == 0, "shared_AB");
    utest_bool(assl_dh_shared(&p, &b, &pa, &t) == 0, "shared_BA");
    {
        assl_bn exp;
        assl_bn_init(&exp);
        utest_bool(assl_bn_from_hex(&exp, shared) == 0, "shared_expect");
        utest_bool(assl_bn_cmp(&s, &exp) == 0, "shared_knows");
        utest_bool(assl_bn_cmp(&s, &t) == 0, "shared_sym");
        assl_bn_free(&exp);
    }
    {
        assl_bn ka, kb, kpa, kpb, sh_a, sh_b;
        assl_bn_init(&ka); assl_bn_init(&kb); assl_bn_init(&kpa); assl_bn_init(&kpb);
        assl_bn_init(&sh_a); assl_bn_init(&sh_b);
        utest_bool(assl_dh_keygen(&p, &g, &ka, &kpa) == 0, "keygen_A");
        utest_bool(assl_dh_keygen(&p, &g, &kb, &kpb) == 0, "keygen_B");
        utest_bool(assl_bn_cmp(&ka, &kb) != 0, "keys_distinct");
        utest_bool(assl_bn_cmp(&kpa, &p) < 0, "pub_in_range");
        utest_bool(assl_bn_is_zero(&kpa) == 0 && assl_bn_is_one(&kpa) == 0, "pub_nontrivial");
        utest_bool(assl_dh_shared(&p, &ka, &kpb, &sh_a) == 0, "agree_A");
        utest_bool(assl_dh_shared(&p, &kb, &kpa, &sh_b) == 0, "agree_B");
        utest_bool(assl_bn_cmp(&sh_a, &sh_b) == 0, "agree_equal");
        assl_bn_free(&ka); assl_bn_free(&kb); assl_bn_free(&kpa); assl_bn_free(&kpb);
        assl_bn_free(&sh_a); assl_bn_free(&sh_b); }
    assl_bn_free(&p); assl_bn_free(&g); assl_bn_free(&a); assl_bn_free(&b);
    assl_bn_free(&pa); assl_bn_free(&pb); assl_bn_free(&s); assl_bn_free(&t);
    return utest_end();
}

static int dh_reject_degenerate(void) {
    utest_begin("dh-reject-degenerate");
    assl_bn p, g, priv, pub, sh;
    assl_bn_init(&p); assl_bn_init(&g); assl_bn_init(&priv);
    assl_bn_init(&pub); assl_bn_init(&sh);
    utest_bool(assl_dh_group(ASSL_DH_FFDHE2048, &p, &g) == 0, "group");

    assl_bn one, pm1;
    assl_bn_init(&one); assl_bn_init(&pm1);
    assl_bn_set_u32(&one, 1);
    assl_bn_sub(&p, &one, &pm1);

    utest_bool(assl_bn_set_u32(&priv, 0x1234567) == 0, "priv");

    assl_bn_set_u32(&pub, 0);
    utest_bool(assl_dh_shared(&p, &priv, &pub, &sh) != 0, "reject_pub_0");
    assl_bn_set_u32(&pub, 1);
    utest_bool(assl_dh_shared(&p, &priv, &pub, &sh) != 0, "reject_pub_1");
    assl_bn_copy(&pub, &pm1);
    utest_bool(assl_dh_shared(&p, &priv, &pub, &sh) != 0, "reject_pub_p_minus_1");
    assl_bn_copy(&pub, &p);
    utest_bool(assl_dh_shared(&p, &priv, &pub, &sh) != 0, "reject_pub_above_p");
    assl_bn_copy(&pub, &pm1);
    assl_bn_sub(&pub, &one, &pub);
    utest_bool(assl_bn_cmp(&pub, &p) < 0, "boundary_value_below_p");
    utest_bool(assl_dh_shared(&p, &priv, &pub, &sh) == 0, "accept_pub_p_minus_2");

    assl_bn ka, kpa;
    assl_bn_init(&ka); assl_bn_init(&kpa);
    utest_bool(assl_dh_keygen(&p, &g, &ka, &kpa) == 0, "keygen_ok");
    utest_bool(assl_dh_shared(&p, &ka, &kpa, &sh) == 0, "valid_peer_accepted");
    assl_bn_free(&ka); assl_bn_free(&kpa);

    assl_bn_free(&one); assl_bn_free(&pm1);
    assl_bn_free(&p); assl_bn_free(&g); assl_bn_free(&priv);
    assl_bn_free(&pub); assl_bn_free(&sh);
    return utest_end();
}

int main(void) {
    int fails = 0;
    fails += dh_group_vectors(ASSL_DH_FFDHE2048, DH_2048_PRIV_A, DH_2048_PRIV_B,
                              DH_2048_PUB_A, DH_2048_PUB_B, DH_2048_SHARED);
    fails += dh_group_vectors(ASSL_DH_FFDHE3072, DH_3072_PRIV_A, DH_3072_PRIV_B,
                              DH_3072_PUB_A, DH_3072_PUB_B, DH_3072_SHARED);
    fails += dh_reject_degenerate();
    if (fails == 0) printf("ALL DH TESTS PASSED\n");
    return fails;
}
