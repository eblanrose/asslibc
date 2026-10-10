#ifndef ASSLIBC_H
#define ASSLIBC_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#if defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__)
#include <sys/random.h>
#endif

#define ASSL_VERSION_SSL30 0x0300
#define ASSL_VERSION_TLS10 0x0301
#define ASSL_VERSION_TLS11 0x0302
#define ASSL_VERSION_TLS12 0x0303
#define ASSL_VERSION_TLS13 0x0304

typedef enum {
    ASSL_H_MD5 = 0,
    ASSL_H_SHA1,
    ASSL_H_SHA256,
    ASSL_H_SHA384,
    ASSL_H_SHA512,
    ASSL_H_COUNT
} assl_hash_t;

typedef struct {
    uint32_t state[4];
    uint64_t bits;
    uint8_t buf[64];
    size_t len;
} assl_md5_ctx;

typedef struct {
    uint32_t state[5];
    uint64_t bits;
    uint8_t buf[64];
    size_t len;
} assl_sha1_ctx;

typedef struct {
    uint32_t state[8];
    uint64_t bits;
    uint8_t buf[64];
    size_t len;
} assl_sha256_ctx;

typedef struct {
    uint64_t state[8];
    uint64_t bits_hi, bits_lo;
    uint8_t buf[128];
    size_t len;
} assl_sha512_ctx;

typedef union {
    assl_md5_ctx md5;
    assl_sha1_ctx sha1;
    assl_sha256_ctx sha256;
    assl_sha512_ctx sha512;
} assl_hctx;

typedef struct {
    unsigned block_size;
    unsigned out_size;
    void (*init)(void *);
    void (*update)(void *, const void *, size_t);
    void (*final)(void *, void *);
} assl_hash_ops;

void assl_md5_init(assl_md5_ctx *c);
void assl_md5_update(assl_md5_ctx *c, const void *data, size_t len);
void assl_md5_final(assl_md5_ctx *c, uint8_t out[16]);

void assl_sha1_init(assl_sha1_ctx *c);
void assl_sha1_update(assl_sha1_ctx *c, const void *data, size_t len);
void assl_sha1_final(assl_sha1_ctx *c, uint8_t out[20]);

void assl_sha256_init(assl_sha256_ctx *c);
void assl_sha256_update(assl_sha256_ctx *c, const void *data, size_t len);
void assl_sha256_final(assl_sha256_ctx *c, uint8_t out[32]);

void assl_sha384_init(assl_sha512_ctx *c);
void assl_sha512_init(assl_sha512_ctx *c);
void assl_sha512_update(assl_sha512_ctx *c, const void *data, size_t len);
void assl_sha512_final(assl_sha512_ctx *c, uint8_t out[64]);
void assl_sha384_final(assl_sha512_ctx *c, uint8_t out[48]);

const assl_hash_ops *assl_hash_ops_of(assl_hash_t h);
unsigned assl_hash_block_size(assl_hash_t h);
unsigned assl_hash_size(assl_hash_t h);
void assl_hash_one(assl_hash_t h, const void *data, size_t len, uint8_t *out);

typedef struct {
    const assl_hash_ops *ops;
    assl_hctx inner;
    assl_hctx outer;
    uint8_t pad[128];
} assl_hmac_ctx;

void assl_hmac_init(assl_hmac_ctx *c, assl_hash_t h, const void *key, size_t keylen);
void assl_hmac_update(assl_hmac_ctx *c, const void *data, size_t len);
void assl_hmac_final(assl_hmac_ctx *c, uint8_t *out);
void assl_hmac(assl_hash_t h, const void *key, size_t keylen,
               const void *data, size_t datalen, uint8_t *out);

void assl_tls_prf_md5sha1(const void *secret, size_t secretlen,
                          const uint8_t *seed, size_t seedlen,
                          uint8_t *out, size_t outlen);
size_t assl_p_hash(assl_hash_t h, const void *secret, size_t secretlen,
                   const uint8_t *seed, size_t seedlen, uint8_t *out, size_t outlen);
void assl_tls_prf12(const void *secret, size_t secretlen,
                    const char *label, const uint8_t *seed, size_t seedlen,
                    uint8_t *out, size_t outlen);

void assl_hkdf_extract(assl_hash_t h, const void *ikm, size_t ikmlen,
                       const void *salt, size_t saltlen, uint8_t *prk);
void assl_hkdf_expand(assl_hash_t h, const void *prk, size_t prklen,
                      const uint8_t *info, size_t infolen,
                      uint8_t *out, size_t outlen);
void assl_hkdf(assl_hash_t h, const void *ikm, size_t ikmlen,
               const void *salt, size_t saltlen,
               const uint8_t *info, size_t infolen,
               uint8_t *out, size_t outlen);
void assl_tls13_hkdf_expand_label(assl_hash_t h, const uint8_t *secret, size_t secretlen,
                                  const char *label, size_t labellen,
                                  const uint8_t *ctx, size_t ctxlen,
                                  uint8_t *out, size_t outlen);

typedef struct {
    uint32_t rk[60];
    int rounds;
} assl_aes_ctx;

void assl_aes_setkey_enc(assl_aes_ctx *c, const uint8_t *key, size_t bits);
void assl_aes_setkey_dec(assl_aes_ctx *c, const uint8_t *key, size_t bits);
void assl_aes_encrypt(const assl_aes_ctx *c, const uint8_t in[16], uint8_t out[16]);
void assl_aes_decrypt(const assl_aes_ctx *c, const uint8_t in[16], uint8_t out[16]);
void assl_aes_cbc_encrypt(const uint8_t *key, size_t keybits,
                          const uint8_t iv[16], const uint8_t *in, size_t len, uint8_t *out);
void assl_aes_cbc_decrypt(const uint8_t *key, size_t keybits,
                          const uint8_t iv[16], const uint8_t *in, size_t len, uint8_t *out);
void assl_aes_ctr_stream(const uint8_t *key, size_t keybits,
                         const uint8_t counter[16], size_t blocks,
                         const uint8_t *in, uint8_t *out);

void assl_gcm_seal(const uint8_t *key, size_t keybits,
                   const uint8_t *iv, size_t ivlen,
                   const uint8_t *aad, size_t aadlen,
                   const uint8_t *pt, size_t ptlen,
                   uint8_t *ct, uint8_t tag[16]);
int assl_gcm_open(const uint8_t *key, size_t keybits,
                  const uint8_t *iv, size_t ivlen,
                  const uint8_t *aad, size_t aadlen,
                  const uint8_t *ct, size_t ctlen,
                  const uint8_t tag[16], uint8_t *pt);

void assl_ccm_seal(const uint8_t *key, size_t keybits,
                   const uint8_t *nonce, size_t noncelen,
                   const uint8_t *aad, size_t aadlen,
                   const uint8_t *pt, size_t ptlen,
                   uint8_t *ct, uint8_t *tag, size_t taglen);
int assl_ccm_open(const uint8_t *key, size_t keybits,
                  const uint8_t *nonce, size_t noncelen,
                  const uint8_t *aad, size_t aadlen,
                  const uint8_t *ct, size_t ctlen,
                  const uint8_t *tag, size_t taglen, uint8_t *pt);

void assl_chacha20_block(const uint8_t key[32], const uint8_t nonce[12],
                         uint32_t counter, uint8_t out[64]);
void assl_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                       uint32_t counter, const uint8_t *in, size_t len, uint8_t *out);
void assl_poly1305_mac(const uint8_t key[32], const uint8_t *msg, size_t msglen,
                       uint8_t tag[16]);
void assl_chacha20_poly1305_seal(const uint8_t key[32], const uint8_t nonce[12],
                                 const uint8_t *aad, size_t aadlen,
                                 const uint8_t *pt, size_t ptlen,
                                 uint8_t *ct, uint8_t tag[16]);
int assl_chacha20_poly1305_open(const uint8_t key[32], const uint8_t nonce[12],
                                const uint8_t *aad, size_t aadlen,
                                const uint8_t *ct, size_t ctlen,
                                const uint8_t tag[16], uint8_t *pt);

typedef struct assl_bn {
    size_t cap;
    size_t len;
    uint32_t *d;
} assl_bn;

void assl_bn_init(assl_bn *a);
void assl_bn_free(assl_bn *a);
void assl_bn_zero(assl_bn *a);
int assl_bn_reserve(assl_bn *a, size_t n);
int assl_bn_set_u32(assl_bn *a, uint32_t v);
int assl_bn_set_u64(assl_bn *a, uint64_t v);
int assl_bn_copy(assl_bn *dst, const assl_bn *src);
int assl_bn_from_bin(assl_bn *a, const uint8_t *bin, size_t len);
int assl_bn_to_bin(const assl_bn *a, uint8_t *bin, size_t len);
int assl_bn_from_hex(assl_bn *a, const char *hex);
int assl_bn_to_hex(const assl_bn *a, char *buf, size_t buflen);
size_t assl_bn_bitlen(const assl_bn *a);
size_t assl_bn_bytes(const assl_bn *a);
int assl_bn_is_zero(const assl_bn *a);
int assl_bn_is_one(const assl_bn *a);
int assl_bn_is_odd(const assl_bn *a);
int assl_bn_cmp(const assl_bn *a, const assl_bn *b);
int assl_bn_add(const assl_bn *a, const assl_bn *b, assl_bn *c);
int assl_bn_sub(const assl_bn *a, const assl_bn *b, assl_bn *c);
int assl_bn_mul_word(const assl_bn *a, uint32_t w, assl_bn *c);
int assl_bn_mul(const assl_bn *a, const assl_bn *b, assl_bn *c);
int assl_bn_div(const assl_bn *a, const assl_bn *b, assl_bn *q, assl_bn *r);
int assl_bn_mod(const assl_bn *a, const assl_bn *m, assl_bn *r);
int assl_bn_modadd(const assl_bn *a, const assl_bn *b, const assl_bn *m, assl_bn *r);
int assl_bn_modsub(const assl_bn *a, const assl_bn *b, const assl_bn *m, assl_bn *r);
int assl_bn_modmul(const assl_bn *a, const assl_bn *b, const assl_bn *m, assl_bn *r);
int assl_bn_modpow(const assl_bn *a, const assl_bn *e, const assl_bn *m, assl_bn *r);
int assl_bn_modinv(const assl_bn *a, const assl_bn *m, assl_bn *r);
int assl_bn_gcd(const assl_bn *a, const assl_bn *b, assl_bn *r);

int assl_bn_modmul_ct(const assl_bn *a, const assl_bn *b, const assl_bn *m, assl_bn *r);
int assl_bn_modpow_ct(const assl_bn *base, const assl_bn *exp, const assl_bn *m, assl_bn *r);
int assl_bn_modadd_ct(const assl_bn *a, const assl_bn *b, const assl_bn *m, assl_bn *r);
int assl_bn_modsub_ct(const assl_bn *a, const assl_bn *b, const assl_bn *m, assl_bn *r);
int assl_bn_modmuladd_ct(const assl_bn *x, const assl_bn *y, const assl_bn *a,
                         const assl_bn *m, assl_bn *r);
int assl_bn_to_bin_ct(const assl_bn *a, uint8_t *bin, size_t len);

void assl_rng_seed(uint64_t seed);
uint64_t assl_rng_next(void);
void assl_rng_bytes(uint8_t *out, size_t len);
int assl_rng_bytes_nonzero(uint8_t *out, size_t len);
int assl_rng_is_secure(void);

int assl_rng_bytes_checked(uint8_t *out, size_t len);
int assl_bn_rand(assl_bn *r, unsigned bits);

#define ASSL_DH_FFDHE2048 0
#define ASSL_DH_FFDHE3072 1
int assl_dh_group(int group, assl_bn *p, assl_bn *g);
int assl_dh_pub(const assl_bn *p, const assl_bn *g, const assl_bn *priv, assl_bn *pub);
int assl_dh_keygen(const assl_bn *p, const assl_bn *g, assl_bn *priv, assl_bn *pub);
int assl_dh_shared(const assl_bn *p, const assl_bn *priv, const assl_bn *peer_pub, assl_bn *shared);

int assl_p256_init(void);
int assl_p256_on_curve(const uint8_t pt[64]);
int assl_p256_add_pt(const uint8_t a[64], const uint8_t b[64], uint8_t out[64]);
int assl_p256_mul_base(const uint8_t k[32], uint8_t out[64]);
int assl_p256_point_mul(const uint8_t k[32], const uint8_t pt[64], uint8_t out[64]);
int assl_p256_ecdh(const uint8_t priv[32], const uint8_t peer[64], uint8_t out[32]);
int assl_p256_keygen(uint8_t d[32], uint8_t q[64]);
int assl_p256_sign(const uint8_t d[32], const uint8_t digest[32], uint8_t r[32], uint8_t s[32]);
int assl_p256_verify(const uint8_t q[64], const uint8_t digest[32], const uint8_t r[32], const uint8_t s[32]);

typedef struct assl_rsa_key {
    assl_bn n, e, d;
    assl_bn p, q, dp, dq, qinv;
    int have_priv;
    int have_crt;
} assl_rsa_key;

void assl_rsa_init(assl_rsa_key *k);
void assl_rsa_free(assl_rsa_key *k);
size_t assl_rsa_key_size(const assl_rsa_key *k);
int assl_rsa_set_key(assl_rsa_key *k,
                     const assl_bn *n, const assl_bn *e, const assl_bn *d,
                     const assl_bn *p, const assl_bn *q,
                     const assl_bn *dp, const assl_bn *dq, const assl_bn *qinv);
int assl_rsa_public(const assl_rsa_key *k, const uint8_t *in, size_t inlen, uint8_t *out);
int assl_rsa_private(const assl_rsa_key *k, const uint8_t *in, size_t inlen, uint8_t *out);
int assl_rsa_encrypt(const assl_rsa_key *k, const uint8_t *in, size_t inlen, uint8_t *out);
int assl_rsa_decrypt(const assl_rsa_key *k, const uint8_t *in, size_t inlen,
                     uint8_t *out, size_t outcap, size_t *outlen);
int assl_rsa_sign(const assl_rsa_key *k, assl_hash_t h, const uint8_t *digest, uint8_t *sig);
int assl_rsa_verify(const assl_rsa_key *k, assl_hash_t h, const uint8_t *digest, const uint8_t *sig, size_t siglen);
int assl_rsa_sign_pss(const assl_rsa_key *k, assl_hash_t h, const uint8_t *digest, size_t saltlen, uint8_t *sig);
int assl_rsa_verify_pss(const assl_rsa_key *k, assl_hash_t h, const uint8_t *digest, size_t saltlen, const uint8_t *sig, size_t siglen);

static inline uint32_t assl_rd32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static inline uint64_t assl_rd64_be(const uint8_t *p) {
    return ((uint64_t)assl_rd32_be(p) << 32) | assl_rd32_be(p + 4);
}

static inline uint32_t assl_rd32_le(const uint8_t *p) {
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[1] << 8) | p[0];
}

static inline void assl_wr32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline void assl_wr64_be(uint8_t *p, uint64_t v) {
    assl_wr32_be(p, (uint32_t)(v >> 32));
    assl_wr32_be(p + 4, (uint32_t)v);
}

static inline void assl_wr32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline void assl_wr64_le(uint8_t *p, uint64_t v) {
    assl_wr32_le(p, (uint32_t)v);
    assl_wr32_le(p + 4, (uint32_t)(v >> 32));
}

#endif