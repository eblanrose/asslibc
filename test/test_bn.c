#include <stdio.h>
#include <string.h>
#include "asslibc.h"
#include "utest.h"

static uint64_t seed_ = 0x9e3779b97f4a7c15ull;
static uint64_t xrng(void) {
    seed_ ^= seed_ >> 12;
    seed_ ^= seed_ << 25;
    seed_ ^= seed_ >> 27;
    return seed_ * 0x2545f4914f6cdd1dull;
}

static void t_hex(const char *what, assl_bn *a, const char *want) {
    char got[16384];
    if (assl_bn_to_hex(a, got, sizeof got) < 0) {
        printf("    FAIL %s (to_hex)\n", what);
        utest_fail();
        utest_checks++; utest_total_checks++;
    } else if (strcmp(got, want) != 0) {
        printf("    FAIL %s: got %s want %s\n", what, got, want);
        utest_fail();
        utest_checks++; utest_total_checks++;
    } else {
        utest_checks++; utest_total_checks++;
    }
}

static void rnd_bn(assl_bn *a, unsigned bits) {
    uint32_t v[128];
    unsigned n = (bits + 31) / 32;
    unsigned keep = bits % 32;
    if (!keep) keep = 32;
    for (unsigned i = 0; i < n; i++) v[i] = (uint32_t)xrng();
    v[n - 1] &= (keep == 32) ? 0xffffffffu : ((1u << keep) - 1);
    while (n > 1 && v[n - 1] == 0) n--;
    assl_bn_reserve(a, n);
    memcpy(a->d, v, n * 4);
    a->len = n;
    if (a->len == 1 && a->d[0] == 0) a->d[0] = 1;
}

static void test_bn_basic(void) {
    utest_begin("bn-basic");
    {
        assl_bn a, b;
        char buf[64];
        uint8_t bin[16];
        assl_bn_init(&a);
        assl_bn_init(&b);
        utest_bool(assl_bn_from_hex(&a, "0x0a1b2c") == 0, "from_hex 0x");
        t_hex("from_hex", &a, "a1b2c");
        utest_bool(assl_bn_from_hex(&b, "5") == 0, "from_hex odd-nibble");
        t_hex("odd-nibble", &b, "5");
        utest_bool(assl_bn_from_hex(&a, "00ff80001a2b3c") == 0, "from_hex lz");
        t_hex("leading-zero", &a, "ff80001a2b3c");
        assl_bn_set_u32(&a, 0);
        t_hex("zero", &a, "0");
        utest_bool(assl_bn_is_zero(&a), "is_zero");
        assl_bn_set_u64(&a, 0x1122334455667788ull);
        t_hex("set_u64", &a, "1122334455667788");
        assl_bn_set_u32(&a, 0x80000001u);
        utest_bool(assl_bn_is_odd(&a), "is_odd");
        utest_bool(assl_bn_bitlen(&a) == 32, "bitlen");
        assl_bn_from_hex(&a, "1234567890abcdef1234567890abcdef");
        utest_bool(assl_bn_bitlen(&a) == 125, "bitlen2");
        utest_bool(assl_bn_bytes(&a) == 16, "bytes");
        utest_bool(assl_bn_to_bin(&a, bin, sizeof bin) == 0, "to_bin");
        utest_bool(assl_bn_from_bin(&b, bin, sizeof bin) == 0, "from_bin");
        t_hex("bin roundtrip", &b, "1234567890abcdef1234567890abcdef");
        assl_bn_to_hex(&a, buf, sizeof buf);
        utest_bool(strlen(buf) == 32, "to_hex len");
        assl_bn_free(&a);
        assl_bn_free(&b);
    }
    utest_bool(utest_end() == 0, "all bn-basic");
}

static void test_bn_arith(void) {
    utest_begin("bn-arith");
    {
        assl_bn a, b, r, f;
        assl_bn_init(&a);
        assl_bn_init(&b);
        assl_bn_init(&r);
        assl_bn_init(&f);
        assl_bn_from_hex(&a, "123456789abcdef01");
        assl_bn_from_hex(&b, "fedcba987654321");
        assl_bn_add(&a, &b, &r);
        t_hex("add", &r, "13333333333333222");
        assl_bn_sub(&a, &b, &r);
        t_hex("sub", &r, "113579be02468abe0");
        assl_bn_from_hex(&a, "1234456abcdef");
        assl_bn_from_hex(&b, "456");
        assl_bn_mul(&a, &b, &r);
        t_hex("mul", &r, "4eeea4fcceeea4a");
        assl_bn_mul_word(&a, 0x456, &r);
        t_hex("mul_word", &r, "4eeea4fcceeea4a");
        assl_bn_from_hex(&a, "123456789abcdef01");
        assl_bn_from_hex(&b, "fedcba987654321");
        assl_bn_mul(&a, &b, &r);
        t_hex("mul big", &r, "121fa00ad77d7422335b54a7dd7e1221");
        assl_bn_from_hex(&a, "123456789abcdef01");
        assl_bn_from_hex(&b, "fedcba987654321");
        assl_bn_div(&a, &b, &r, &f);
        t_hex("div q", &r, "12");
        t_hex("div r", &f, "48d159e26af36af");
        assl_bn_free(&f);
        assl_bn_free(&a);
        assl_bn_free(&b);
        assl_bn_free(&r);
    }
    utest_bool(utest_end() == 0, "all bn-arith");
}static const char *p127_ = "7fffffffffffffffffffffffffffffff";
static const char *pmul_a_ = "deadbeef1234567890abcdef";
static const char *pmul_b_ = "badc0ffee0d15bad5a5";
static const char *pmul_ab_ = "741bba7ab5a35f127263fc40a0b80b64";
static const char *pinv127_ = "23d642028a597cd299e9020ed3104a54";
static const char *modpow_m_ = "10001";
static const char *modpow_o_ = "6a79";

static const char *M512_ =
    "79cb9e86830c71c2cdcc69292f45e678309d6b79965eda32dae445508201e2bd7"
    "3ab48767734d7c1c7fde805ec99108ddb5b5fab8f4d3e27dda1494c73cf256d";
static const char *A512_ =
    "986e80ab8ab67a26b7f62b1852f27e3eff9c0cf44dd3f89e7d15f17362f25244c"
    "af9c4dabb4817253edc6181879932fa91425cb0088539d2c67eda13ffe79";
static const char *B512_ =
    "92080f3ebdd3102b938b8743feb6d4ea65d003d716849f8558a628518867a66b0"
    "d389d95847ebd299753a767779673f778aaf6fa5db8656abd72fb710734";
static const char *AB512_ =
    "3dfc80e35d585918e63afceca8475c2a855787f7ee84b9f4415499cf28591002"
    "1ee5c7e442fdc2e80275264d2d2a1ff68b4b8553720c3dd11b263a8fe33fdace";
static const char *E512_ =
    "84e5320094ead7a94ded97491e2370c6a5b85387f61376c468aec7321cc007b3"
    "7e14998092253deffa38e12b2b8f30b17d0b";
static const char *POW512_ =
    "1cdb0fbecd0fdf0ead1e807706960be9d33918bae03d0a78117e9ca1270564493"
    "053cb52e09b2f197a76919096ba1098ed03711a848a079a4f41a49b8b5fc499";
static const char *INV512_ =
    "4db505cb4ba8c609807c14b9d6e718cf5c81c568eab68617ac23f03176ea24bcc"
    "da966ee16d7587e125d372160ab37fd6f15a44c4fb2230e235f7d1a02f1804a";
static const char *X512_ =
    "473a7a114907513923715c1d2dfa9964aef012d0ea67ff122294b4d8474a3ea2"
    "84d3bd03346";
static const char *Y512_ =
    "50b4105cca7b53302fc154cd2aad7185ddaee82ec3ffee5a5b28d1fe1daff6665"
    "896822a6b2";
static const char *SUB512_ =
    "79cb9e86830c71c2cdcc69292f45e678309d6b79965eda32dae444b8e89d2aa63"
    "38bd7b177a9d7f69a7bd519ff4332f45c66dc224d7ae0c182250c10477cb201";

static void test_bn_mod(void) {
    utest_begin("bn-mod");
    {
        assl_bn m, a, b, r;
        assl_bn_init(&m);
        assl_bn_init(&a);
        assl_bn_init(&b);
        assl_bn_init(&r);
        assl_bn_from_hex(&m, p127_);
        assl_bn_from_hex(&a, pmul_a_);
        assl_bn_from_hex(&b, pmul_b_);
        utest_bool(assl_bn_modmul(&a, &b, &m, &r) == 0, "modmul ok");
        t_hex("modmul p127", &r, pmul_ab_);
        assl_bn_free(&m);
        assl_bn_free(&a);
        assl_bn_free(&b);
        assl_bn_free(&r);
    }
    {
        assl_bn m, a, b, r;
        assl_bn_init(&m);
        assl_bn_init(&a);
        assl_bn_init(&b);
        assl_bn_init(&r);
        assl_bn_from_hex(&m, M512_);
        assl_bn_from_hex(&a, A512_);
        assl_bn_from_hex(&b, B512_);
        assl_bn_modmul(&a, &b, &m, &r);
        t_hex("modmul 512", &r, AB512_);
        assl_bn_from_hex(&b, E512_);
        assl_bn_modpow(&a, &b, &m, &r);
        t_hex("modpow 512", &r, POW512_);
        assl_bn_modinv(&a, &m, &r);
        t_hex("modinv 512", &r, INV512_);
        assl_bn_from_hex(&a, X512_);
        assl_bn_from_hex(&b, Y512_);
        assl_bn_modsub(&a, &b, &m, &r);
        t_hex("modsub 512", &r, SUB512_);
        assl_bn_modsub(&a, &a, &m, &r);
        t_hex("modsub self", &r, "0");
        assl_bn_free(&m);
        assl_bn_free(&a);
        assl_bn_free(&b);
        assl_bn_free(&r);
    }
    {
        assl_bn a, b, m, r;
        assl_bn_init(&a);
        assl_bn_init(&b);
        assl_bn_init(&m);
        assl_bn_init(&r);
        assl_bn_from_hex(&a, pmul_a_);
        assl_bn_from_hex(&b, pmul_b_);
        assl_bn_from_hex(&m, modpow_m_);
        assl_bn_modpow(&a, &b, &m, &r);
        t_hex("modpow small", &r, modpow_o_);
        assl_bn_gcd(&m, &m, &r);
        t_hex("gcd self", &r, "10001");
        assl_bn_from_hex(&m, "3c");
        assl_bn_from_hex(&a, "2a");
        assl_bn_gcd(&a, &m, &r);
        t_hex("gcd", &r, "6");
        assl_bn_from_hex(&m, p127_);
        assl_bn_from_hex(&a, pmul_a_);
        assl_bn_modinv(&a, &m, &r);
        t_hex("modinv p127", &r, pinv127_);
        assl_bn_free(&a);
        assl_bn_free(&b);
        assl_bn_free(&m);
        assl_bn_free(&r);
    }
    utest_bool(utest_end() == 0, "all bn-mod");
}static const char *rsa_p_ =
    "e476f3c1a2e2813f4977eb0ba38a0f8d703f75617abb86542dae8cb3a90e3a47"
    "927c53bd7f7c49be82111054fc83a2a860135ff2ebd41c6e5c45c81b09612b4"
    "49abdfa802372d133ade01da4710727b80c8d490c7898d8b1bc06ab6fce659c7"
    "19a0c146667d2e4f04e25820d78293c2ff6fbb335c65d96548b244491c7b0d773";
static const char *rsa_q_ =
    "53ee6cbb882a97011b3bae1af7b55c2105424d6677a025674e3d28a700650120"
    "e9bf73c8ce8e63d0ff94dae6ffbdd778ce3cde1858de4c53b651518013c5e4e9"
    "8ce4989bbc0c7f2aa237f2519be27ec01254c5035e6c94eaa1e0bdee4d6dfade"
    "37cb2e1939d4bb514bb3f23b4a5df58af95897a2b561b22250191a5634e349b";
static const char *rsa_n_ =
    "4ae758a7f113d16b3a7c521321c36bbc2212d9c9518f776e1ce6cbec481179cf"
    "055728c2d79bd0e712c0dfd7e88c86c984d00947945d60067e392328642bd04"
    "e6cd9b5042e4959744fe7426a6abb68d9a6699d9b45d03d69be466a0f7b434b"
    "f9b4c7527ea82eee1e1ab44c0ff88582e9a5a7dbaf013f2b8a9d6c3147d7ac0"
    "c9bbb854f00663c62b9a7beb50ecfb29b3f221227d2919a0b2fa8edf075fb2"
    "54bc2b1d71ea6bee09678c26ab2876880f990ace66ebc511df980c5f39c1ec9"
    "8255e3385a29fdf37d11a0051a7822c6ad479f474714cc287edfe8f17b30d36"
    "acca8694955834241dff09891b32d5dae9ccfe5fe01cae0a41763036fd5c25f1dfcea1";
static const char *rsa_e_ = "10001";
static const char *rsa_d_ =
    "34d114ceb74b862bda3db7920e08c27b127bc05e18c8d52a2bef0274460d2c9b"
    "31e4d7b52c5b8edea176a760937623c50d85b44568f4beb55563ecca9a77da96"
    "b2628125c58dab2a3cfd90f380f74d63cbd8456e2bb83ed5c579d967b93f26df"
    "98fdc3c9d3c5e3da0e727bfff6fa0de9bb09b5fa9d22720d781bc654265c072d"
    "ac32c914e89e211a6836faa5ff1d0de12c3fe06fb89f2f84f3298d8d0968b131"
    "8c7b14165dc1593f1f4eae0e7464a04d969ddb3f92ad5e277f8861baa75104e"
    "005952bcea9e0ee61d138ab3ce27ec96f7f452a5e33a467b9d5c58ef69b7535"
    "1960b2255a4098ab34bd18238e11ba96e9d906499c3ae93bd4ebbc29130636451";
static const char *rsa_dp_ =
    "9fd86e1193c24045a44487aa3c00d382d4ff41443397d29340e6f840974e820"
    "e237a63289972bf31d054da056c2b3979eec67f8239e7cd009604a8cde9d1177"
    "1c78696266326e921ec4c7ad0dbd7f2bd3de2f832068a824a5050a64ff2ab7b"
    "3aac5a3947b0ea880d6dcfa65f802bf195698b8f465784913293ab8b6227c21deb";
static const char *rsa_dq_ =
    "e50126ac885baca8d8257e6716794166d77290bd84a8f1656d9471d738bc5ed"
    "7eef0f27a751d0e3cb31ef42854a327c7f6f11d0c516e39d42f20b1bf443430"
    "e30e0aac5a403dd8bbfae1abca000b7ecb9338b854f8ce4b83e72bcf0ee735a"
    "dc9a5723bd5987558a3f86a840442651c129545a477cf6f411b5e711feb176311";
static const char *rsa_qinv_ =
    "daf66383a2bc39c68fa4f02d8389844d33259819e9d8e4655aa10cf4b9e873d"
    "247c4985255d34aeb20a74b60dff0f183382492ba47de9be31556e7771c84c3"
    "018f3be9b0402e14f025bcfd4ddc8ce1dd1ff025968a60440278c7b6be39482"
    "193e5043609faf722eee6a8ac2ea19566c4231ba24dc2deb5a8cd02b23a6ac12ab7";
static const char *rsa_msg_ =
    "809781b64ce4228c38fb2918f135d25f557203301850c5a38fd547923a736994"
    "e3bf911a61dbe22e44158bae97ba94d0eda82f8f6d05584ef8aa38922766581"
    "e27a1c08a6a63ec24ede6a46b4cb2424a23d5962217beaddbc496cb8e81973e"
    "0becd7b03898d190f9ebdacc0cb1e29c658cda1495e60af593bd04cf0fd630f"
    "1f29d0da9953f48f1a09f76b5a170b33839263059f28c105d1fb17c2390c192c"
    "fd3ac94af0f21ddb66cad4a268d116ece1738f7d93d9c172411e20b8f6b0d54"
    "9b6f03675a1600a35a099950d836f675cc81e74ef5e8e25d940ed904759531985"
    "d5d9dc9f81818e811892f902bd23f0824128b2f330c5c7fd0a6a3a45065132710";
static const char *rsa_ct_ =
    "2dcad13247962c15ee6c4fe3e81148e01d3be1adba1c4fdba1c651ac2af4610"
    "b7de319e4941e4d99d77cafa6a08175f676a3cb5169cb1be17032753c01406d"
    "08ae574c139279839f258fe0d77db6dd71e97f2e04f84de5cf6f6ac3871dba9"
    "780378aa4e54428bd5c7e68764b1af4174f9596319614d8631b19dc5623d421e"
    "76aa1d2daecc4b4671ef10cb2ae394ea3acfcea1472406e0b1587ef0f837f7f"
    "6adfa38354cd40509b7355988f85fee66404d8e9e7cf66adbf12768d2b52b69d"
    "7a1611e6711f531e19bf64f5175f851d39c31abef8004012c7598aaac94c79e"
    "91f310b80a6bce21ba931407223a3ef3273c7166921ce541eee8736162f58f19248b";

static void t_eq_bn(const char *what, assl_bn *a, assl_bn *b) {
    if (assl_bn_cmp(a, b) != 0) {
        char ha[16384], hb[16384];
        assl_bn_to_hex(a, ha, sizeof ha);
        assl_bn_to_hex(b, hb, sizeof hb);
        printf("    FAIL %s: got %s want %s\n", what, ha, hb);
        utest_fail();
    }
    utest_checks++;
}

static void test_bn_rsa(void) {
    utest_begin("bn-rsa");
    {
        assl_bn p, q, n, e, d, dp, dq, qi, msg, ct, r, h, m1, m2;
        assl_bn_init(&p);
        assl_bn_init(&q);
        assl_bn_init(&n);
        assl_bn_init(&e);
        assl_bn_init(&d);
        assl_bn_init(&dp);
        assl_bn_init(&dq);
        assl_bn_init(&qi);
        assl_bn_init(&msg);
        assl_bn_init(&ct);
        assl_bn_init(&r);
        assl_bn_init(&h);
        assl_bn_init(&m1);
        assl_bn_init(&m2);
        assl_bn_from_hex(&p, rsa_p_);
        assl_bn_from_hex(&q, rsa_q_);
        assl_bn_from_hex(&n, rsa_n_);
        assl_bn_from_hex(&e, rsa_e_);
        assl_bn_from_hex(&d, rsa_d_);
        assl_bn_from_hex(&dp, rsa_dp_);
        assl_bn_from_hex(&dq, rsa_dq_);
        assl_bn_from_hex(&qi, rsa_qinv_);
        assl_bn_from_hex(&msg, rsa_msg_);
        assl_bn_from_hex(&ct, rsa_ct_);
        assl_bn_modpow(&msg, &e, &n, &r);
        t_eq_bn("encrypt", &r, &ct);
        assl_bn_modpow(&ct, &d, &n, &r);
        t_eq_bn("decrypt", &r, &msg);
        assl_bn_modpow(&ct, &dp, &p, &m1);
        assl_bn_modpow(&ct, &dq, &q, &m2);
        assl_bn_modsub(&m1, &m2, &p, &h);
        assl_bn_modmul(&qi, &h, &p, &h);
        assl_bn_mul(&h, &q, &r);
        assl_bn_add(&r, &m2, &r);
        assl_bn_mod(&r, &n, &r);
        t_eq_bn("crt", &r, &msg);
        assl_bn_free(&p);
        assl_bn_free(&q);
        assl_bn_free(&n);
        assl_bn_free(&e);
        assl_bn_free(&d);
        assl_bn_free(&dp);
        assl_bn_free(&dq);
        assl_bn_free(&qi);
        assl_bn_free(&msg);
        assl_bn_free(&ct);
        assl_bn_free(&r);
        assl_bn_free(&h);
        assl_bn_free(&m1);
        assl_bn_free(&m2);
    }
    utest_bool(utest_end() == 0, "all bn-rsa");
}

static void test_bn_random(void) {
    utest_begin("bn-random");
    {
        assl_bn m, a, b, c, d, q, rr, t;
        assl_bn_init(&m);
        assl_bn_init(&a);
        assl_bn_init(&b);
        assl_bn_init(&c);
        assl_bn_init(&d);
        assl_bn_init(&q);
        assl_bn_init(&rr);
        assl_bn_init(&t);
        for (int i = 0; i < 200; i++) {
            unsigned mb = 8 + (unsigned)(xrng() % 504);
            rnd_bn(&m, mb);
            if (!assl_bn_is_odd(&m)) {
                assl_bn_set_u32(&t, 1);
                assl_bn_add(&m, &t, &m);
            }
            rnd_bn(&a, mb - 1);
            rnd_bn(&b, mb - 1);
            if (assl_bn_cmp(&a, &m) >= 0) assl_bn_mod(&a, &m, &a);
            if (assl_bn_cmp(&b, &m) >= 0) assl_bn_mod(&b, &m, &b);
            assl_bn_mul(&a, &b, &c);
            assl_bn_mod(&c, &m, &c);
            assl_bn_modmul(&a, &b, &m, &d);
            t_eq_bn("modmul==mulmod", &c, &d);
            assl_bn_add(&a, &b, &c);
            assl_bn_mod(&c, &m, &c);
            assl_bn_modadd(&a, &b, &m, &d);
            t_eq_bn("modadd==addmod", &c, &d);
            assl_bn_modsub(&a, &b, &m, &c);
            assl_bn_modadd(&c, &b, &m, &d);
            t_eq_bn("modsub roundtrip", &d, &a);
            assl_bn_mul_word(&a, 0xfedcba98u, &c);
            assl_bn_set_u32(&d, 0xfedcba98u);
            assl_bn_mul(&a, &d, &d);
            t_eq_bn("mul_word==mul", &c, &d);
            assl_bn_div(&a, &b, &c, &d);
            assl_bn_mul(&c, &b, &q);
            assl_bn_add(&q, &d, &q);
            t_eq_bn("div identity", &q, &a);
            if (assl_bn_cmp(&d, &b) >= 0) {
                utest_bool(0, "div remainder < b");
            } else {
                utest_checks++;
            }
            assl_bn_set_u32(&t, 1);
            assl_bn_mod(&a, &m, &c);
            assl_bn_modpow(&c, &t, &m, &d);
            t_eq_bn("pow ^1", &d, &c);
            assl_bn_set_u32(&t, 0);
            assl_bn_modpow(&c, &t, &m, &d);
            assl_bn_set_u32(&t, 1);
            t_eq_bn("pow ^0", &d, &t);
            assl_bn_gcd(&a, &m, &c);
            if (assl_bn_is_one(&c)) {
                assl_bn_modinv(&a, &m, &d);
                assl_bn_modmul(&a, &d, &m, &q);
                assl_bn_set_u32(&t, 1);
                t_eq_bn("inv invert", &q, &t);
            } else {
                utest_checks++;
            }
            assl_bn_from_hex(&a, "0");
            assl_bn_from_hex(&b, "1");
            assl_bn_modpow(&a, &b, &m, &d);
            t_eq_bn("pow 0^1", &d, &a);
        }
        assl_bn_free(&m);
        assl_bn_free(&a);
        assl_bn_free(&b);
        assl_bn_free(&c);
        assl_bn_free(&d);
        assl_bn_free(&q);
        assl_bn_free(&rr);
        assl_bn_free(&t);
    }
    utest_bool(utest_end() == 0, "all bn-random");
}

static void test_bn_ct(void) {
    utest_begin("bn-ct");
    {
        assl_bn m, a, b, e, cl, ct, t;
        assl_bn_init(&m); assl_bn_init(&a); assl_bn_init(&b);
        assl_bn_init(&e); assl_bn_init(&cl); assl_bn_init(&ct); assl_bn_init(&t);
        for (int i = 0; i < 200; i++) {
            unsigned mb = 8 + (unsigned)(xrng() % 504);
            rnd_bn(&m, mb);
            if (!assl_bn_is_odd(&m)) {
                assl_bn_set_u32(&t, 1);
                assl_bn_add(&m, &t, &m);
            }
            rnd_bn(&a, mb - 1);
            rnd_bn(&b, mb - 1);
            if (assl_bn_cmp(&a, &m) >= 0) assl_bn_mod(&a, &m, &a);
            if (assl_bn_cmp(&b, &m) >= 0) assl_bn_mod(&b, &m, &b);
            assl_bn_modmul(&a, &b, &m, &cl);
            utest_bool(assl_bn_modmul_ct(&a, &b, &m, &ct) == 0, "ct modmul rc");
            t_eq_bn("ct modmul==modmul", &ct, &cl);
            rnd_bn(&e, (mb / 2) + 2);
            assl_bn_modpow(&a, &e, &m, &cl);
            utest_bool(assl_bn_modpow_ct(&a, &e, &m, &ct) == 0, "ct modpow rc");
            t_eq_bn("ct modpow==modpow", &ct, &cl);
            rnd_bn(&a, mb + 8);
            assl_bn_modpow(&a, &e, &m, &cl);
            utest_bool(assl_bn_modpow_ct(&a, &e, &m, &ct) == 0, "ct modpow big base rc");
            t_eq_bn("ct modpow big base==modpow", &ct, &cl);
            rnd_bn(&a, mb - 1);
            rnd_bn(&b, mb - 1);
            if (assl_bn_cmp(&a, &m) >= 0) assl_bn_mod(&a, &m, &a);
            if (assl_bn_cmp(&b, &m) >= 0) assl_bn_mod(&b, &m, &b);
            assl_bn_modadd(&a, &b, &m, &cl);
            utest_bool(assl_bn_modadd_ct(&a, &b, &m, &ct) == 0, "ct modadd rc");
            t_eq_bn("ct modadd==modadd", &ct, &cl);
            assl_bn_modsub(&a, &b, &m, &cl);
            utest_bool(assl_bn_modsub_ct(&a, &b, &m, &ct) == 0, "ct modsub rc");
            t_eq_bn("ct modsub==modsub", &ct, &cl);
            if (assl_bn_bitlen(&m) > 33) {
            assl_bn_set_u32(&a, (uint32_t)(xrng() % 0x10000));
            assl_bn_set_u32(&b, (uint32_t)(xrng() % 0x10000));
            assl_bn_set_u32(&t, 0);
            assl_bn_modmul(&a, &b, &m, &cl);          
            utest_bool(assl_bn_modmuladd_ct(&a, &b, &t, &m, &ct) == 0, "ct modmuladd rc");
            t_eq_bn("ct modmuladd==muladd", &ct, &cl);
            }
        }
        for (int i = 0; i < 64; i++) {
            size_t len = 8 + (size_t)(xrng() % 120);
            uint8_t out1[128], out2[128];
            memset(out1, 0xAA, sizeof out1);
            memset(out2, 0xBB, sizeof out2);
            rnd_bn(&a, 1 + (unsigned)(xrng() % (8 * len - 1)));
            assl_bn_to_bin(&a, out1, len);
            int crc = assl_bn_to_bin_ct(&a, out2, len);
            utest_bool(crc == 0, "ct to_bin rc");
            if (crc == 0 && memcmp(out1, out2, len) != 0) {
                char got[768];
                assl_bn_to_hex(&a, got, sizeof got);
                printf("    FAIL ct to_bin==to_bin: a=%s len=%zu\n", got, len);
                utest_fail();
            }
            utest_checks++;
        }
        assl_bn_free(&m); assl_bn_free(&a); assl_bn_free(&b);
        assl_bn_free(&e); assl_bn_free(&cl); assl_bn_free(&ct); assl_bn_free(&t);
    }
    utest_bool(utest_end() == 0, "all bn-ct");
}

int main(void) {
    int n = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    test_bn_basic();
    test_bn_arith();
    test_bn_mod();
    test_bn_rsa();
    test_bn_random();
    test_bn_ct();
    (void)n;
    return utest_finish("BN");
}