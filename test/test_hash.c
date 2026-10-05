#define ASSLIBC_IMPLEMENTATION
#include "../asslibc.h"
#include "utest.h"

static void test_md5(void) {
    utest_begin("md5");
    {
        const char *v = "abc";
        uint8_t want[16], got[16];
        utest_hexbytes("900150983cd24fb0d6963f7d28e17f72", want, 16);
        assl_hash_one(ASSL_H_MD5, v, strlen(v), got);
        utest_eq(got, want, 16, "md5(abc)");
    }
    {
        const char *v = "";
        uint8_t want[16], got[16];
        utest_hexbytes("d41d8cd98f00b204e9800998ecf8427e", want, 16);
        assl_hash_one(ASSL_H_MD5, v, strlen(v), got);
        utest_eq(got, want, 16, "md5(empty)");
    }
    {
        const char *v = "The quick brown fox jumps over the lazy dog";
        uint8_t want[16], got[16];
        utest_hexbytes("9e107d9d372bb6826bd81d3542a419d6", want, 16);
        assl_hash_one(ASSL_H_MD5, v, strlen(v), got);
        utest_eq(got, want, 16, "md5(fox)");
    }
    {
        uint8_t want[16], got[16];
        utest_hexbytes("7707d6ae4e027c70eea2a935c2296f21", want, 16);
        {
            assl_md5_ctx c;
            uint8_t chunk[1000];
            memset(chunk, 'a', 1000);
            assl_md5_init(&c);
            for (int i = 0; i < 1000; i++) assl_md5_update(&c, chunk, 1000);
            assl_md5_final(&c, got);
        }
        utest_eq(got, want, 16, "md5(1e6 a's)");
    }
    utest_bool(utest_end() == 0, "all md5 cases");
}

static void test_sha1(void) {
    utest_begin("sha1");
    {
        const char *v = "abc";
        uint8_t want[20], got[20];
        utest_hexbytes("a9993e364706816aba3e25717850c26c9cd0d89d", want, 20);
        assl_hash_one(ASSL_H_SHA1, v, strlen(v), got);
        utest_eq(got, want, 20, "sha1(abc)");
    }
    {
        const char *v = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        uint8_t want[20], got[20];
        utest_hexbytes("84983e441c3bd26ebaae4aa1f95129e5e54670f1", want, 20);
        assl_hash_one(ASSL_H_SHA1, v, strlen(v), got);
        utest_eq(got, want, 20, "sha1(big)");
    }
    {
        uint8_t want[20], got[20];
        utest_hexbytes("34aa973cd4c4daa4f61eeb2bdbad27316534016f", want, 20);
        {
            assl_sha1_ctx c;
            uint8_t block[64];
            memset(block, 'a', 64);
            assl_sha1_init(&c);
            for (int i = 0; i < 15625; i++) assl_sha1_update(&c, block, 64);
            assl_sha1_final(&c, got);
        }
        utest_eq(got, want, 20, "sha1(1e6 a's)");
    }
    utest_bool(utest_end() == 0, "all sha1 cases");
}

static void test_sha256(void) {
    utest_begin("sha256");
    {
        const char *v = "abc";
        uint8_t want[32], got[32];
        utest_hexbytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", want, 32);
        assl_hash_one(ASSL_H_SHA256, v, strlen(v), got);
        utest_eq(got, want, 32, "sha256(abc)");
    }
    {
        const char *v = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        uint8_t want[32], got[32];
        utest_hexbytes("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", want, 32);
        assl_hash_one(ASSL_H_SHA256, v, strlen(v), got);
        utest_eq(got, want, 32, "sha256(big)");
    }
    {
        uint8_t want[32], got[32];
        utest_hexbytes("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", want, 32);
        {
            assl_sha256_ctx c;
            uint8_t block[64];
            memset(block, 'a', 64);
            assl_sha256_init(&c);
            for (int i = 0; i < 15625; i++) assl_sha256_update(&c, block, 64);
            assl_sha256_final(&c, got);
        }
        utest_eq(got, want, 32, "sha256(1e6 a's)");
    }
    {
        const char *v = "a";
        uint8_t want[32], got[32];
        utest_hexbytes("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", want, 32);
        assl_hash_one(ASSL_H_SHA256, v, 1, got);
        utest_eq(got, want, 32, "sha256(a)");
    }
    utest_bool(utest_end() == 0, "all sha256 cases");
}

static void test_sha512(void) {
    utest_begin("sha512");
    {
        const char *v = "abc";
        uint8_t want[64], got[64];
        utest_hexbytes("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                       "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", want, 64);
        assl_hash_one(ASSL_H_SHA512, v, strlen(v), got);
        utest_eq(got, want, 64, "sha512(abc)");
    }
    {
        const char *v = ""; {
            uint8_t want[64], got[64];
            utest_hexbytes("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                           "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", want, 64);
            assl_hash_one(ASSL_H_SHA512, v, 0, got);
            utest_eq(got, want, 64, "sha512(empty)");
        }
    }
    utest_bool(utest_end() == 0, "all sha512 cases");
}

static void test_sha384(void) {
    utest_begin("sha384");
    {
        const char *v = "abc";
        uint8_t want[48], got[48];
        utest_hexbytes("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                       "8086072ba1e7cc2358baeca134c825a7", want, 48);
        assl_hash_one(ASSL_H_SHA384, v, strlen(v), got);
        utest_eq(got, want, 48, "sha384(abc)");
    }
    {
        const char *v = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        uint8_t want[48], got[48];
        utest_hexbytes("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
                       "fcc7c71a557e2db966c3e9fa91746039", want, 48);
        assl_hash_one(ASSL_H_SHA384, v, strlen(v), got);
        utest_eq(got, want, 48, "sha384(big)");
    }
    utest_bool(utest_end() == 0, "all sha384 cases");
}

static void test_hmac(void) {
    utest_begin("hmac");
    {
        uint8_t key[20], data[50];
        uint8_t want[32], got[32];
        for (int i = 0; i < 20; i++) key[i] = 0x0b;
        memcpy(data, "Hi There", 8);
        utest_hexbytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", want, 32);
        assl_hmac(ASSL_H_SHA256, key, 20, data, 8, got);
        utest_eq(got, want, 32, "sha256-hmac rfc4231 tc1");
    }
    {
        uint8_t key[4] = {0x4a,0x65,0x66,0x65};
        const char *data = "what do ya want for nothing?";
        uint8_t want[16], got[16];
        utest_hexbytes("750c783e6ab0b503eaa86e310a5db738", want, 16);
        assl_hmac(ASSL_H_MD5, key, 4, data, strlen(data), got);
        utest_eq(got, want, 16, "md5-hmac rfc2202 tc2");
    }
    {
        uint8_t key[20];
        uint8_t data[50];
        uint8_t want[20], got[20];
        for (int i = 0; i < 20; i++) key[i] = 0xaa;
        for (int i = 0; i < 50; i++) data[i] = 0xdd;
        utest_hexbytes("125d7342b9ac11cd91a39af48aa17b4f63f175d3", want, 20);
        assl_hmac(ASSL_H_SHA1, key, 20, data, 50, got);
        utest_eq(got, want, 20, "sha1-hmac rfc2202 tc4");
    }
    utest_bool(utest_end() == 0, "all hmac cases");
}

static void test_hkdf(void) {
    utest_begin("hkdf");
    {
        uint8_t ikm[22], salt[13], info[10];
        uint8_t got[42], want[42];
        utest_hexbytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", ikm, 22);
        utest_hexbytes("000102030405060708090a0b0c", salt, 13);
        utest_hexbytes("f0f1f2f3f4f5f6f7f8f9", info, 10);
        utest_hexbytes("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                       "34007208d5b887185865", want, 42);
        assl_hkdf(ASSL_H_SHA256, ikm, 22, salt, 13, info, 10, got, 42);
        utest_eq(got, want, 42, "hkdf-sha256 rfc5869 tc1");
    }
    {
        uint8_t ikm[80], salt[80], info[80];
        uint8_t got[82], want[82];
        for (int i = 0; i < 80; i++) {
            ikm[i] = (uint8_t)(0x00 + i);
            salt[i] = (uint8_t)(0x60 + i);
            info[i] = (uint8_t)(0xb0 + i);
        }
        utest_hexbytes("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
                       "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
                       "cc30c58179ec3e87c14c01d5c1f3434f1d87", want, 82);
        assl_hkdf(ASSL_H_SHA256, ikm, 80, salt, 80, info, 80, got, 82);
        utest_eq(got, want, 82, "hkdf-sha256 rfc5869 tc3");
    }
    utest_bool(utest_end() == 0, "all hkdf cases");
}

static void test_tls13_label(void) {
    utest_begin("tls13-hkdf-label");
    {
        uint8_t secret[32];
        uint8_t got[32], want[32];
        for (int i = 0; i < 32; i++) secret[i] = 0x9e ^ (uint8_t)i;
        utest_hexbytes("6a7e64cead3d1037c27d546ab0a548089776baeda35a579a7f0931973b7f2076", want, 32);
        assl_tls13_hkdf_expand_label(ASSL_H_SHA256, secret, 32, "derived", 7, NULL, 0, got, 32);
        utest_eq(got, want, 32, "tls13 expand label 'derived'");
    }
    {
        uint8_t secret[32], ctx[8];
        uint8_t got[32], want[32];
        for (int i = 0; i < 32; i++) secret[i] = 0xa1;
        utest_hexbytes("53c2c17cbe0c8c2880dce8e1d0d176dca066e646ccfbc43879506fcdce2fe086", want, 32);
        for (int i = 0; i < 8; i++) ctx[i] = (uint8_t)(0x0102030405060708ull >> (8 * (7 - i)));
        assl_tls13_hkdf_expand_label(ASSL_H_SHA256, secret, 32, "c hs traffic", 12, ctx, 8, got, 32);
        utest_eq(got, want, 32, "tls13 expand label with ctx");
    }
    utest_bool(utest_end() == 0, "all tls13 label cases");
}

static void test_prf(void) {
    utest_begin("prf");
    {
        uint8_t secret[48], seed[8], got[48];
        for (int i = 0; i < 48; i++) secret[i] = (uint8_t)i;
        for (int i = 0; i < 8; i++) seed[i] = (uint8_t)(0x80 + i);
        assl_tls_prf_md5sha1(secret, 48, seed, 8, got, 48);
        {
            uint8_t half1[24], half2[24];
            uint8_t o1[48], o2[48];
            memcpy(half1, secret, 24);
            memcpy(half2, secret + 24, 24);
            assl_p_hash(ASSL_H_MD5, half1, 24, seed, 8, o1, 48);
            assl_p_hash(ASSL_H_SHA1, half2, 24, seed, 8, o2, 48);
            for (int i = 0; i < 48; i++) {
                utest_bool(got[i] == (uint8_t)(o1[i] ^ o2[i]), "prf is XOR of two p_hash");
            }
        }
    }
    {
        uint8_t secret[48], seed[64], got[104], ref[104];
        for (int i = 0; i < 48; i++) secret[i] = (uint8_t)(100 + i);
        for (int i = 0; i < 64; i++) seed[i] = (uint8_t)(i * 3);
        assl_tls_prf12(secret, 48, "key expansion", seed, 64, got, 104);
        {
            uint8_t combined[64 + 13];
            memcpy(combined, "key expansion", 13);
            memcpy(combined + 13, seed, 64);
            assl_p_hash(ASSL_H_SHA256, secret, 48, combined, 77, ref, 104);
        }
        utest_eq(got, ref, 104, "prf12 == p_hash(sha256)");
    }
    utest_bool(utest_end() == 0, "all prf cases");
}

int main(void) {
    test_md5();
    test_sha1();
    test_sha256();
    test_sha512();
    test_sha384();
    test_hmac();
    test_hkdf();
    test_tls13_label();
    test_prf();
    return utest_finish("HASH");
}