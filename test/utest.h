#ifndef UTEST_H
#define UTEST_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static int utest_total_failures;
static int utest_total_checks;
static int utest_failures;
static int utest_checks;
static const char *utest_cur;

static void utest_begin(const char *name) {
    utest_cur = name;
    utest_failures = 0;
    utest_checks = 0;
    printf("[==] %s\n", name);
    fflush(stdout);
}

static void utest_hex(const uint8_t *in, size_t len, char *out) {
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = d[in[i] >> 4];
        out[i * 2 + 1] = d[in[i] & 0xf];
    }
    out[len * 2] = 0;
}

static int utest_hexbytes(const char *hex, uint8_t *out, size_t maxlen) {
    size_t n = strlen(hex) / 2;
    if (n > maxlen) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return (int)n;
}

static void utest_fail(void) {
    utest_failures++;
    utest_total_failures++;
}

static void utest_eq(const uint8_t *got, const uint8_t *want, size_t len, const char *what) {
    utest_checks++;
    utest_total_checks++;
    if (memcmp(got, want, len) != 0) {
        char *g = malloc(len * 2 + 1), *w = malloc(len * 2 + 1);
        if (g && w) {
            utest_hex(got, len, g);
            utest_hex(want, len, w);
            printf("    FAIL %s (%s):\n      got  %s\n      want %s\n", utest_cur, what, g, w);
        } else {
            printf("    FAIL %s (%s): %zu bytes differ\n", utest_cur, what, len);
        }
        free(g); free(w);
        utest_fail();
    }
}

static void utest_bool(int cond, const char *what) {
    utest_checks++;
    utest_total_checks++;
    if (!cond) {
        printf("    FAIL %s (%s)\n", utest_cur, what);
        utest_fail();
    }
}

static int utest_end(void) {
    if (utest_failures == 0) {
        printf("[OK] %s (%d checks)\n", utest_cur, utest_checks);
    } else {
        printf("[!!] %s: %d checks, %d failures\n", utest_cur, utest_checks, utest_failures);
    }
    fflush(stdout);
    return utest_failures;
}

static int utest_finish(const char *suite) {
    if (utest_total_failures) {
        printf("FAILURES: %s: %d failure(s) out of %d checks\n",
               suite, utest_total_failures, utest_total_checks);
        return 1;
    }
    printf("ALL %s TESTS PASSED (%d checks)\n", suite, utest_total_checks);
    return 0;
}

static int __attribute__((unused)) utest_need_rng(void) {
    FILE *f = fopen("/dev/urandom", "rb");
    int ok = f != NULL;
    if (f) fclose(f);
    return ok;
}

#endif