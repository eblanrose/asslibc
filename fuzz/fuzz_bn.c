
#include "asslibc.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    enum { L = 1 + 4 * 16 + 4 * 16 + 4 * 16 + 12 };
    uint8_t buf[L];
    size_t n = size < L ? size : L;
    memset(buf, 0, sizeof buf);
    memcpy(buf, data, n);

    unsigned s = buf[0] & 0x0f;
    if (s < 1) s = 1;
    if (s > 16) s = 16;

    assl_bn m, a, b, e, ar, br, cl, ct, t;
    assl_bn_init(&m); assl_bn_init(&a); assl_bn_init(&b);
    assl_bn_init(&e); assl_bn_init(&ar); assl_bn_init(&br);
    assl_bn_init(&cl); assl_bn_init(&ct); assl_bn_init(&t);

    if (assl_bn_from_bin(&m, buf + 1, 4 * s)) goto done;
    if (assl_bn_from_bin(&a, buf + 1 + 4 * s, 4 * s)) goto done;
    if (assl_bn_from_bin(&b, buf + 1 + 8 * s, 4 * s)) goto done;
    if (assl_bn_from_bin(&e, buf + 1 + 12 * s, 12)) goto done;
    if (assl_bn_is_zero(&m)) { assl_bn_set_u32(&m, 3); }
    if (!assl_bn_is_odd(&m)) { assl_bn_set_u32(&t, 1); assl_bn_add(&m, &t, &m); }

    if (assl_bn_cmp(&a, &m) >= 0) assl_bn_mod(&a, &m, &ar);
    if (assl_bn_cmp(&b, &m) >= 0) assl_bn_mod(&b, &m, &br);
    if (assl_bn_is_zero(&ar)) assl_bn_set_u32(&ar, 1);
    if (assl_bn_is_zero(&br)) assl_bn_set_u32(&br, 1);

    assl_bn_modmul(&ar, &br, &m, &cl);
    if (assl_bn_modmul_ct(&ar, &br, &m, &ct)) abort();
    if (assl_bn_cmp(&cl, &ct)) abort();

    if (assl_bn_bitlen(&m) > 32) {
        assl_bn xu, yu, k;
        assl_bn_init(&xu); assl_bn_init(&yu); assl_bn_init(&k);
        assl_bn_set_u32(&xu, (uint32_t)((buf[L - 2] << 8) | buf[L - 1]));
        assl_bn_set_u32(&yu, (uint32_t)((buf[L - 4] << 8) | buf[L - 3]));
        assl_bn_mod(&br, &m, &k);
        assl_bn_modmul(&xu, &yu, &m, &cl);
        assl_bn_modadd(&cl, &k, &m, &cl);          
        if (assl_bn_modmuladd_ct(&xu, &yu, &k, &m, &ct)) abort();
        if (assl_bn_cmp(&cl, &ct)) abort();
        assl_bn_free(&xu); assl_bn_free(&yu); assl_bn_free(&k);
    }

    assl_bn_modadd(&ar, &br, &m, &cl);
    if (assl_bn_modadd_ct(&ar, &br, &m, &ct)) abort();
    if (assl_bn_cmp(&cl, &ct)) abort();
    assl_bn_modsub(&ar, &br, &m, &cl);
    if (assl_bn_modsub_ct(&ar, &br, &m, &ct)) abort();
    if (assl_bn_cmp(&cl, &ct)) abort();

    assl_bn_mod(&e, &m, &e);
    assl_bn_modpow(&a, &e, &m, &cl);
    if (assl_bn_modpow_ct(&a, &e, &m, &ct)) abort();
    if (assl_bn_cmp(&cl, &ct)) abort();
    assl_bn_modpow(&ar, &e, &m, &cl);
    if (assl_bn_modpow_ct(&ar, &e, &m, &ct)) abort();
    if (assl_bn_cmp(&cl, &ct)) abort();

    {
        uint8_t o1[128], o2[128];
        size_t olen = 1 + (buf[L - 1] % 120);
        memset(o1, 0x11, sizeof o1);
        memset(o2, 0x22, sizeof o2);
        if (assl_bn_to_bin(&ar, o1, olen)) goto done2;
        if (assl_bn_to_bin_ct(&ar, o2, olen)) abort();
        if (memcmp(o1, o2, olen)) abort();
        goto done2;
    }
done2:
done:
    assl_bn_free(&m); assl_bn_free(&a); assl_bn_free(&b);
    assl_bn_free(&e); assl_bn_free(&ar); assl_bn_free(&br);
    assl_bn_free(&cl); assl_bn_free(&ct); assl_bn_free(&t);
    return 0;
}

#ifdef ASSL_FUZZ_STANDALONE
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s FILE [FILE...]\n", argv[0]);
        return 2;
    }
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) { perror(argv[i]); return 2; }
        static uint8_t buf[1 << 20];
        size_t got = fread(buf, 1, sizeof buf, f);
        fclose(f);
        LLVMFuzzerTestOneInput(buf, got);
        printf("ok: %s\n", argv[i]);
    }
    return 0;
}
#endif