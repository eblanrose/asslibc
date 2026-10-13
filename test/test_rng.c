#include <stdio.h>
#include <string.h>
#include "utest.h"
#include "asslibc.h"

static int all_zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) if (p[i]) return 0;
    return 1;
}

static int test_rng_secure(void) {
    utest_begin("rng-secure");
    utest_bool(assl_rng_is_secure() == 1, "is_secure");

    uint8_t a[32], b[32];
    utest_bool(assl_rng_bytes_checked(a, sizeof a) == 0, "checked_bytes");
    utest_bool(!all_zero(a, sizeof a), "bytes_nonzero");
    utest_bool(assl_rng_bytes_checked(b, sizeof b) == 0, "checked_bytes2");
    utest_bool(memcmp(a, b, sizeof a) != 0, "distinct_blocks");

    uint8_t nz[16];
    utest_bool(assl_rng_bytes_nonzero(nz, sizeof nz) == 0, "nonzero_ok");
    utest_bool(!all_zero(nz, sizeof nz), "nonzero_nonzero");
    return utest_end();
}

static int test_rng_seed_recovers(void) {
    utest_begin("rng-seed-recovers");
    assl_rng_seed(0x123456789abcdef0ULL);
    utest_bool(assl_rng_is_secure() == 1, "secure_after_seed");

    uint8_t buf[24];
    utest_bool(assl_rng_bytes_checked(buf, sizeof buf) == 0, "bytes_after_seed");
    utest_bool(!all_zero(buf, sizeof buf), "bytes_after_seed_nonzero");

    assl_rng_seed(1);
    utest_bool(assl_rng_is_secure() == 1, "secure_after_reseed");
    utest_bool(assl_rng_bytes_checked(buf, sizeof buf) == 0, "bytes_after_reseed");
    return utest_end();
}

int main(void) {
    int fails = 0;
    fails += test_rng_secure();
    fails += test_rng_seed_recovers();
    if (fails == 0) printf("ALL RNG TESTS PASSED\n");
    return fails;
}
