#include "../asslibc.h"
#include "utest.h"
#include "aes_vectors.h"

static int hexlen(const char *h) {
    return (int)(strlen(h) / 2);
}

static void test_ecb(void) {
    utest_begin("aes-ecb");
    {
        uint8_t key[32], pt[16], want[16], got[16];
        assl_aes_ctx c;
        int n = hexlen(ecb_128_k);
        utest_hexbytes(ecb_128_k, key, 32);
        utest_hexbytes(ecb_pt, pt, 16);
        utest_hexbytes(ecb_128_ct, want, 16);
        assl_aes_setkey_enc(&c, key, n * 8);
        assl_aes_encrypt(&c, pt, got);
        utest_eq(got, want, 16, "aes-128-encrypt");
        assl_aes_setkey_dec(&c, key, n * 8);
        assl_aes_decrypt(&c, got, got);
        utest_eq(got, pt, 16, "aes-128-roundtrip");
    }
    {
        uint8_t key[32], pt[16], want[16], got[16];
        assl_aes_ctx c;
        int n = hexlen(ecb_192_k);
        utest_hexbytes(ecb_192_k, key, 32);
        utest_hexbytes(ecb_pt, pt, 16);
        utest_hexbytes(ecb_192_ct, want, 16);
        assl_aes_setkey_enc(&c, key, n * 8);
        assl_aes_encrypt(&c, pt, got);
        utest_eq(got, want, 16, "aes-192-encrypt");
        assl_aes_setkey_dec(&c, key, n * 8);
        assl_aes_decrypt(&c, got, got);
        utest_eq(got, pt, 16, "aes-192-roundtrip");
    }
    {
        uint8_t key[32], pt[16], want[16], got[16];
        assl_aes_ctx c;
        int n = hexlen(ecb_256_k);
        utest_hexbytes(ecb_256_k, key, 32);
        utest_hexbytes(ecb_pt, pt, 16);
        utest_hexbytes(ecb_256_ct, want, 16);
        assl_aes_setkey_enc(&c, key, n * 8);
        assl_aes_encrypt(&c, pt, got);
        utest_eq(got, want, 16, "aes-256-encrypt");
        assl_aes_setkey_dec(&c, key, n * 8);
        assl_aes_decrypt(&c, got, got);
        utest_eq(got, pt, 16, "aes-256-roundtrip");
    }
    utest_bool(utest_end() == 0, "all aes-ecb cases");
}

static void test_cbc(void) {
    utest_begin("aes-cbc");
    {
        uint8_t key[32], iv[16], pt[64], want[64], got[64];
        utest_hexbytes(cbc_128_k, key, 32);
        utest_hexbytes(cbc_iv, iv, 16);
        utest_hexbytes(pt4, pt, 64);
        utest_hexbytes(cbc_128_ct, want, 64);
        assl_aes_cbc_encrypt(key, 128, iv, pt, 64, got);
        utest_eq(got, want, 64, "aes-128-cbc-encrypt");
        assl_aes_cbc_decrypt(key, 128, iv, got, 64, got);
        utest_eq(got, pt, 64, "aes-128-cbc-roundtrip");
    }
    {
        uint8_t key[32], iv[16], pt[64], want[64], got[64];
        utest_hexbytes(cbc_256_k, key, 32);
        utest_hexbytes(cbc_iv, iv, 16);
        utest_hexbytes(pt4, pt, 64);
        utest_hexbytes(cbc_256_ct, want, 64);
        assl_aes_cbc_encrypt(key, 256, iv, pt, 64, got);
        utest_eq(got, want, 64, "aes-256-cbc-encrypt");
        assl_aes_cbc_decrypt(key, 256, iv, got, 64, got);
        utest_eq(got, pt, 64, "aes-256-cbc-roundtrip");
    }
    utest_bool(utest_end() == 0, "all aes-cbc cases");
}

static void test_ctr(void) {
    utest_begin("aes-ctr");
    {
        uint8_t key[32], iv[16], pt[64], ks[64], want_ks[64], mixed[64], ci[64];
        utest_hexbytes(ctr_128_k, key, 32);
        utest_hexbytes(ctr_iv, iv, 16);
        utest_hexbytes(pt4, pt, 64);
        utest_hexbytes(ctr_128_ks, want_ks, 64);
        assl_aes_ctr_stream(key, 128, iv, 4, NULL, ks);
        utest_eq(ks, want_ks, 64, "aes-128-ctr-keystream");
        assl_aes_ctr_stream(key, 128, iv, 4, pt, mixed);
        for (int i = 0; i < 64; i++) ci[i] = (uint8_t)(pt[i] ^ want_ks[i]);
        utest_eq(mixed, ci, 64, "aes-128-ctr-encrypt");
    }
    {
        uint8_t key[32], iv[16], pt[64], ks[64], want_ks[64], mixed[64], ci[64];
        utest_hexbytes(ctr_256_k, key, 32);
        utest_hexbytes(ctr_iv, iv, 16);
        utest_hexbytes(pt4, pt, 64);
        utest_hexbytes(ctr_256_ks, want_ks, 64);
        assl_aes_ctr_stream(key, 256, iv, 4, NULL, ks);
        utest_eq(ks, want_ks, 64, "aes-256-ctr-keystream");
        assl_aes_ctr_stream(key, 256, iv, 4, pt, mixed);
        for (int i = 0; i < 64; i++) ci[i] = (uint8_t)(pt[i] ^ want_ks[i]);
        utest_eq(mixed, ci, 64, "aes-256-ctr-encrypt");
    }
    utest_bool(utest_end() == 0, "all aes-ctr cases");
}

static void test_gcm(void) {
    utest_begin("gcm");
    {
        uint8_t key[32], iv[64], pt[128], aad[128], ct[128], tag[16], wantct[128], wanttag[16];
        int n;

        utest_hexbytes(gcm_k, key, 32);
        utest_hexbytes(gcm_iv3, iv, 64);
        n = hexlen(gcm_p64);
        utest_hexbytes(gcm_p64, pt, 128);
        utest_hexbytes(gcm_c3, wantct, 128);
        utest_hexbytes(gcm_t3, wanttag, 16);
        assl_gcm_seal(key, 128, iv, hexlen(gcm_iv3), NULL, 0, pt, n, ct, tag);
        utest_eq(ct, wantct, n, "gcm-seal-no-aad");
        utest_eq(tag, wanttag, 16, "gcm-tag-no-aad");
        utest_bool(assl_gcm_open(key, 128, iv, hexlen(gcm_iv3), NULL, 0, ct, n, tag, ct) == 0,
                   "gcm-open-no-aad");
        utest_eq(ct, pt, n, "gcm-open-plaintext");

        utest_hexbytes(gcm_a4, aad, 128);
        utest_hexbytes(gcm_c4, wantct, 128);
        utest_hexbytes(gcm_t4, wanttag, 16);
        assl_gcm_seal(key, 128, iv, hexlen(gcm_iv3), aad, hexlen(gcm_a4), pt, n, ct, tag);
        utest_eq(ct, wantct, n, "gcm-ct-with-aad");
        utest_eq(tag, wanttag, 16, "gcm-tag-with-aad");
        utest_bool(assl_gcm_open(key, 128, iv, hexlen(gcm_iv3), aad, hexlen(gcm_a4), ct, n, tag, ct) == 0,
                   "gcm-open-with-aad");

        tag[0] ^= 1;
        utest_bool(assl_gcm_open(key, 128, iv, hexlen(gcm_iv3), aad, hexlen(gcm_a4), ct, n, tag, ct) != 0,
                   "gcm-open-bad-tag");
        tag[0] ^= 1;
        ct[0] ^= 1;
        utest_bool(assl_gcm_open(key, 128, iv, hexlen(gcm_iv3), aad, hexlen(gcm_a4), ct, n, tag, ct) != 0,
                   "gcm-open-bad-ct");
    }
    {
        uint8_t key[32], iv[64], pt[128], ct[128], tag[16], wantct[128], wanttag[16];
        int n;
        utest_hexbytes(gcm_k, key, 32);
        utest_hexbytes(gcm_iv5, iv, 64);
        n = hexlen(gcm_p60);
        utest_hexbytes(gcm_p60, pt, 128);
        utest_hexbytes(gcm_c5, wantct, 128);
        utest_hexbytes(gcm_t5, wanttag, 16);
        assl_gcm_seal(key, 128, iv, hexlen(gcm_iv5), NULL, 0, pt, n, ct, tag);
        utest_eq(ct, wantct, n, "gcm-iv8-seal");
        utest_eq(tag, wanttag, 16, "gcm-iv8-tag");
    }
    {
        uint8_t key[32], iv[64], pt[128], ct[128], tag[16], wantct[128], wanttag[16];
        int n;
        utest_hexbytes(gcm_k, key, 32);
        utest_hexbytes(gcm_iv6, iv, 64);
        n = hexlen(gcm_p60);
        utest_hexbytes(gcm_p60, pt, 128);
        utest_hexbytes(gcm_c6, wantct, 128);
        utest_hexbytes(gcm_t6, wanttag, 16);
        assl_gcm_seal(key, 128, iv, hexlen(gcm_iv6), NULL, 0, pt, n, ct, tag);
        utest_eq(ct, wantct, n, "gcm-iv60-seal");
        utest_eq(tag, wanttag, 16, "gcm-iv60-tag");
    }
    {
        uint8_t key[32], iv[16], pt[80], aad[16], ct[80], tag[16], wantct[80], wanttag[16];
        int n;
        utest_hexbytes(g256_k, key, 32);
        utest_hexbytes(g256_iv, iv, 16);
        n = hexlen(g256_pt);
        utest_hexbytes(g256_pt, pt, 80);
        utest_hexbytes(g256_aad, aad, 16);
        utest_hexbytes(g256_ct, wantct, 80);
        utest_hexbytes(g256_t, wanttag, 16);
        assl_gcm_seal(key, 256, iv, hexlen(g256_iv), aad, hexlen(g256_aad), pt, n, ct, tag);
        utest_eq(ct, wantct, n, "gcm-256-seal");
        utest_eq(tag, wanttag, 16, "gcm-256-tag");
        utest_bool(assl_gcm_open(key, 256, iv, hexlen(g256_iv), aad, hexlen(g256_aad), ct, n, tag, ct) == 0,
                   "gcm-256-open");
    }
    {
        uint8_t key[32], iv[16], tag[16], wanttag[16];
        utest_hexbytes(g0_k, key, 32);
        utest_hexbytes(g0_iv, iv, 16);
        utest_hexbytes(g0_t, wanttag, 16);
        assl_gcm_seal(key, 128, iv, 12, NULL, 0, NULL, 0, NULL, tag);
        utest_eq(tag, wanttag, 16, "gcm-empty-tag");
        utest_bool(assl_gcm_open(key, 128, iv, 12, NULL, 0, NULL, 0, tag, NULL) == 0,
                   "gcm-empty-open");
    }
    utest_bool(utest_end() == 0, "all gcm cases");
}

static void test_ccm(void) {
    utest_begin("ccm");
    {
        const char *const ks[] = { ccm0_k, ccm1_k, ccm2_k, ccm3_k, ccm4_k, ccm5_k };
        const char *const ns[] = { ccm0_n, ccm1_n, ccm2_n, ccm3_n, ccm4_n, ccm5_n };
        const char *const as[] = { ccm0_a, ccm1_a, ccm2_a, ccm3_a, ccm4_a, ccm5_a };
        const char *const ps[] = { ccm0_p, ccm1_p, ccm2_p, ccm3_p, ccm4_p, ccm5_p };
        const char *const cs[] = { ccm0_c, ccm1_c, ccm2_c, ccm3_c, ccm4_c, ccm5_c };
        const char *const ts[] = { ccm0_t, ccm1_t, ccm2_t, ccm3_t, ccm4_t, ccm5_t };
        for (int i = 0; i < 6; i++) {
            uint8_t key[32], nonce[16], aad[64], pt[128], ct[128], tag[16];
            uint8_t wantct[128], wanttag[16], tmp[128];
            int asz = hexlen(as[i]);
            int tsz = hexlen(ts[i]);
            int psz = hexlen(ps[i]);
            char what[64];
            utest_hexbytes(ks[i], key, 32);
            utest_hexbytes(ns[i], nonce, 16);
            utest_hexbytes(as[i], aad, 64);
            utest_hexbytes(ps[i], pt, 128);
            utest_hexbytes(cs[i], wantct, 128);
            utest_hexbytes(ts[i], wanttag, 16);
            assl_ccm_seal(key, hexlen(ks[i]) * 8, nonce, hexlen(ns[i]),
                          asz ? aad : NULL, asz, pt, psz, ct, tag, tsz);
            snprintf(what, sizeof what, "ccm%d-seal", i);
            utest_eq(ct, wantct, psz, what);
            snprintf(what, sizeof what, "ccm%d-tag", i);
            utest_eq(tag, wanttag, tsz, what);
            snprintf(what, sizeof what, "ccm%d-open", i);
            utest_bool(assl_ccm_open(key, hexlen(ks[i]) * 8, nonce, hexlen(ns[i]),
                                     asz ? aad : NULL, asz, ct, psz, tag, tsz, tmp) == 0, what);
            if (psz) {
                ct[0] ^= 1;
                snprintf(what, sizeof what, "ccm%d-open-bad-ct", i);
                utest_bool(assl_ccm_open(key, hexlen(ks[i]) * 8, nonce, hexlen(ns[i]),
                                         asz ? aad : NULL, asz, ct, psz, tag, tsz, tmp) != 0, what);
                ct[0] ^= 1;
            }
            tag[0] ^= 1;
            snprintf(what, sizeof what, "ccm%d-open-bad-tag", i);
            utest_bool(assl_ccm_open(key, hexlen(ks[i]) * 8, nonce, hexlen(ns[i]),
                                     asz ? aad : NULL, asz, ct, psz, tag, tsz, tmp) != 0, what);
            tag[0] ^= 1;
        }
    }
    utest_bool(utest_end() == 0, "all ccm cases");
}

static void test_chacha20(void) {
    utest_begin("chacha20");
    {
        uint8_t key[32], nonce[12], ks[192], blk[192], zero[192];
        memset(zero, 0, sizeof zero);
        utest_hexbytes(chacha_k, key, 32);
        utest_hexbytes(chacha_n, nonce, 12);
        utest_hexbytes(chacha_ks, ks, 192);
        assl_chacha20_block(key, nonce, 1, blk);
        utest_eq(blk, ks, 64, "chacha20-counter1");
        assl_chacha20_block(key, nonce, 2, blk);
        utest_eq(blk, ks + 64, 64, "chacha20-counter2");
        assl_chacha20_block(key, nonce, 3, blk);
        utest_eq(blk, ks + 128, 64, "chacha20-counter3");
        assl_chacha20_xor(key, nonce, 1, zero, 160, blk);
        utest_eq(blk, ks, 160, "chacha20-xor-full");
        assl_chacha20_xor(key, nonce, 1, zero, 130, blk);
        utest_eq(blk, ks, 130, "chacha20-xor-partial");
    }
    utest_bool(utest_end() == 0, "all chacha20 cases");
}

static void test_poly1305(void) {
    utest_begin("poly1305");
    {
        uint8_t key[32], msg[34], tag[16], want[16];
        utest_hexbytes(poly_k, key, 32);
        utest_hexbytes(poly_a5, msg, 34);
        utest_hexbytes(poly_t5, want, 16);
        assl_poly1305_mac(key, msg, 34, tag);
        utest_eq(tag, want, 16, "poly1305-a5");
    }
    {
        uint8_t key[32], tag[16], want[16];
        utest_hexbytes(poly_k, key, 32);
        utest_hexbytes(poly_t0, want, 16);
        assl_poly1305_mac(key, NULL, 0, tag);
        utest_eq(tag, want, 16, "poly1305-empty");
    }
    {
        uint8_t key[32], msg[15], tag[16], want[16];
        utest_hexbytes(poly_k, key, 32);
        for (int i = 0; i < 15; i++) msg[i] = (uint8_t)i;
        utest_hexbytes(poly15_t, want, 16);
        assl_poly1305_mac(key, msg, 15, tag);
        utest_eq(tag, want, 16, "poly1305-15");
    }
    {
        uint8_t key[32], msg[16], tag[16], want[16];
        utest_hexbytes(poly_k, key, 32);
        utest_hexbytes("43727970746f6772617068696320466f", msg, 16);
        utest_hexbytes(poly16_t, want, 16);
        assl_poly1305_mac(key, msg, 16, tag);
        utest_eq(tag, want, 16, "poly1305-16");
    }
    {
        uint8_t key[32], msg[17], tag[16], want[16];
        const char *m = "12345678901234567";
        utest_hexbytes(poly_k, key, 32);
        memcpy(msg, m, 17);
        utest_hexbytes(poly17_t, want, 16);
        assl_poly1305_mac(key, msg, 17, tag);
        utest_eq(tag, want, 16, "poly1305-17");
    }
    {
        uint8_t key[32], msg[768], tag[16], want[16];
        utest_hexbytes(poly3_k, key, 32);
        for (int i = 0; i < 768; i++) msg[i] = (uint8_t)(i % 256);
        utest_hexbytes(poly_long_t, want, 16);
        assl_poly1305_mac(key, msg, 768, tag);
        utest_eq(tag, want, 16, "poly1305-long");
    }
    utest_bool(utest_end() == 0, "all poly1305 cases");
}

static void test_chachapoly(void) {
    utest_begin("chacha20-poly1305");
    {
        uint8_t key[32], nonce[12], aad[16], pt[128], ct[128], tag[16];
        uint8_t wantct[128], wanttag[16];
        int n = hexlen(aead_p);
        utest_hexbytes(aead_k, key, 32);
        utest_hexbytes(aead_n, nonce, 12);
        utest_hexbytes(aead_a, aad, 16);
        utest_hexbytes(aead_p, pt, 128);
        utest_hexbytes(aead_ct, wantct, 128);
        utest_hexbytes(aead_t, wanttag, 16);
        assl_chacha20_poly1305_seal(key, nonce, aad, hexlen(aead_a), pt, n, ct, tag);
        utest_eq(ct, wantct, n, "aead-seal");
        utest_eq(tag, wanttag, 16, "aead-tag");
        utest_bool(assl_chacha20_poly1305_open(key, nonce, aad, hexlen(aead_a), ct, n, tag, ct) == 0,
                   "aead-open");
        utest_eq(ct, pt, n, "aead-open-plaintext");
        tag[0] ^= 1;
        utest_bool(assl_chacha20_poly1305_open(key, nonce, aad, hexlen(aead_a), ct, n, tag, ct) != 0,
                   "aead-open-bad-tag");
        tag[0] ^= 1;
        ct[0] ^= 1;
        utest_bool(assl_chacha20_poly1305_open(key, nonce, aad, hexlen(aead_a), ct, n, tag, ct) != 0,
                   "aead-open-bad-ct");
    }
    {
        uint8_t key[32], nonce[12], aad[16], tag[16], wanttag[16];
        utest_hexbytes(aead_k, key, 32);
        utest_hexbytes(aead_n, nonce, 12);
        utest_hexbytes(xac_a, aad, 16);
        utest_hexbytes(xac_t, wanttag, 16);
        assl_chacha20_poly1305_seal(key, nonce, aad, hexlen(xac_a), NULL, 0, NULL, tag);
        utest_eq(tag, wanttag, 16, "aead-empty-tag");
        utest_bool(assl_chacha20_poly1305_open(key, nonce, aad, hexlen(xac_a), NULL, 0, tag, NULL) == 0,
                   "aead-empty-open");
    }
    utest_bool(utest_end() == 0, "all chacha20-poly1305 cases");
}

int main(void) {
    int n = 0;
    test_ecb();
    test_cbc();
    test_ctr();
    test_gcm();
    test_ccm();
    test_chacha20();
    test_poly1305();
    test_chachapoly();
    n += utest_failures;
    if (n == 0) printf("ALL AES TESTS PASSED\n");
    return n ? 1 : 0;
}