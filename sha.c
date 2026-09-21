#include "asslibc.h"

static void assl_md5_compress(assl_md5_ctx *c, const uint8_t block[64]) {
    static const uint32_t K[64] = {
        0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,
        0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
        0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
        0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
        0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,
        0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x04881d05u,0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
        0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
        0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u
    };
    static const uint8_t S[64] = {
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
    };
    uint32_t M[16];
    uint32_t a = c->state[0], b = c->state[1], cc = c->state[2], d = c->state[3];
    uint32_t f, temp;

    for (int i = 0; i < 16; i++) M[i] = assl_rd32_le(block + i * 4);

#define MD5_F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | ~(z)))
#define MD5_ROT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

    for (int i = 0; i < 16; i++) {
        f = MD5_F(b, cc, d);
        temp = d; d = cc; cc = b;
        b += MD5_ROT(a + f + K[i] + M[i], S[i]);
        a = temp;
    }
    for (int i = 0; i < 16; i++) {
        f = MD5_G(b, cc, d);
        temp = d; d = cc; cc = b;
        b += MD5_ROT(a + f + K[i + 16] + M[(5 * i + 1) % 16], S[i + 16]);
        a = temp;
    }
    for (int i = 0; i < 16; i++) {
        f = MD5_H(b, cc, d);
        temp = d; d = cc; cc = b;
        b += MD5_ROT(a + f + K[i + 32] + M[(3 * i + 5) % 16], S[i + 32]);
        a = temp;
    }
    for (int i = 0; i < 16; i++) {
        f = MD5_I(b, cc, d);
        temp = d; d = cc; cc = b;
        b += MD5_ROT(a + f + K[i + 48] + M[(7 * i) % 16], S[i + 48]);
        a = temp;
    }
#undef MD5_F
#undef MD5_G
#undef MD5_H
#undef MD5_I
#undef MD5_ROT

    c->state[0] += a;
    c->state[1] += b;
    c->state[2] += cc;
    c->state[3] += d;
}

void assl_md5_init(assl_md5_ctx *c) {
    c->state[0] = 0x67452301u;
    c->state[1] = 0xefcdab89u;
    c->state[2] = 0x98badcfeu;
    c->state[3] = 0x10325476u;
    c->bits = 0;
    c->len = 0;
}

void assl_md5_update(assl_md5_ctx *c, const void *data, size_t len) {
    const uint8_t *p = data;
    c->bits += (uint64_t)len * 8;
    while (len > 0) {
        size_t take = 64 - c->len;
        if (take > len) take = len;
        memcpy(c->buf + c->len, p, take);
        c->len += take;
        p += take;
        len -= take;
        if (c->len == 64) {
            assl_md5_compress(c, c->buf);
            c->len = 0;
        }
    }
}

void assl_md5_final(assl_md5_ctx *c, uint8_t out[16]) {
    uint64_t bits = c->bits;
    uint8_t lenb[8];
    uint8_t pad = 0x80;
    assl_md5_update(c, &pad, 1);
    while ((c->len % 64) != 56) {
        assl_md5_update(c, "\0", 1);
    }
    for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (i * 8));
    assl_md5_update(c, lenb, 8);
    for (int i = 0; i < 4; i++) assl_wr32_le(out + i * 4, c->state[i]);
}

static void assl_sha1_compress(assl_sha1_ctx *c, const uint8_t block[64]) {
    static const uint32_t K[4] = { 0x5a827999u, 0x6ed9eba1u, 0x8f1bbcdcu, 0xca62c1d6u };
    uint32_t w[80];
    uint32_t a, b, cc, d, e, f, k, tmp;

    for (int i = 0; i < 16; i++) w[i] = assl_rd32_be(block + i * 4);
    for (int i = 16; i < 80; i++) {
        tmp = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = (tmp << 1) | (tmp >> 31);
    }
    a = c->state[0];
    b = c->state[1];
    cc = c->state[2];
    d = c->state[3];
    e = c->state[4];

    for (int i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & cc) | ((~b) & d);
            k = K[0];
        } else if (i < 40) {
            f = b ^ cc ^ d;
            k = K[1];
        } else if (i < 60) {
            f = (b & cc) | (b & d) | (cc & d);
            k = K[2];
        } else {
            f = b ^ cc ^ d;
            k = K[3];
        }
        tmp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
        e = d;
        d = cc;
        cc = (b << 30) | (b >> 2);
        b = a;
        a = tmp;
    }

    c->state[0] += a;
    c->state[1] += b;
    c->state[2] += cc;
    c->state[3] += d;
    c->state[4] += e;
}

void assl_sha1_init(assl_sha1_ctx *c) {
    c->state[0] = 0x67452301u;
    c->state[1] = 0xefcdab89u;
    c->state[2] = 0x98badcfeu;
    c->state[3] = 0x10325476u;
    c->state[4] = 0xc3d2e1f0u;
    c->bits = 0;
    c->len = 0;
}

void assl_sha1_update(assl_sha1_ctx *c, const void *data, size_t len) {
    const uint8_t *p = data;
    c->bits += (uint64_t)len * 8;
    while (len > 0) {
        size_t take = 64 - c->len;
        if (take > len) take = len;
        memcpy(c->buf + c->len, p, take);
        c->len += take;
        p += take;
        len -= take;
        if (c->len == 64) {
            assl_sha1_compress(c, c->buf);
            c->len = 0;
        }
    }
}

void assl_sha1_final(assl_sha1_ctx *c, uint8_t out[20]) {
    uint64_t bits = c->bits;
    uint8_t lenb[8];
    uint8_t pad = 0x80;
    assl_sha1_update(c, &pad, 1);
    while ((c->len % 64) != 56) {
        assl_sha1_update(c, "\0", 1);
    }
    assl_wr64_be(lenb, bits);
    assl_sha1_update(c, lenb, 8);
    for (int i = 0; i < 5; i++) assl_wr32_be(out + i * 4, c->state[i]);
}

#define RR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void assl_sha256_compress(assl_sha256_ctx *c, const uint8_t block[64]) {
    static const uint32_t K[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };
    uint32_t w[64];
    uint32_t a, b, cc, d, e, f, g, h;
    uint32_t s0, s1, S1, ch, t1, t2, maj;

    for (int i = 0; i < 16; i++) w[i] = assl_rd32_be(block + i * 4);
    for (int i = 16; i < 64; i++) {
        s0 = RR(w[i - 15], 7) ^ RR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        s1 = RR(w[i - 2], 17) ^ RR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = c->state[0];
    b = c->state[1];
    cc = c->state[2];
    d = c->state[3];
    e = c->state[4];
    f = c->state[5];
    g = c->state[6];
    h = c->state[7];

    for (int i = 0; i < 64; i++) {
        S1 = RR(e, 6) ^ RR(e, 11) ^ RR(e, 25);
        ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + K[i] + w[i];
        maj = (a & b) ^ (a & cc) ^ (b & cc);
        s0 = RR(a, 2) ^ RR(a, 13) ^ RR(a, 22);
        t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = cc;
        cc = b;
        b = a;
        a = t1 + t2;
    }

    c->state[0] += a;
    c->state[1] += b;
    c->state[2] += cc;
    c->state[3] += d;
    c->state[4] += e;
    c->state[5] += f;
    c->state[6] += g;
    c->state[7] += h;
}

#undef RR

void assl_sha256_init(assl_sha256_ctx *c) {
    c->state[0] = 0x6a09e667u;
    c->state[1] = 0xbb67ae85u;
    c->state[2] = 0x3c6ef372u;
    c->state[3] = 0xa54ff53au;
    c->state[4] = 0x510e527fu;
    c->state[5] = 0x9b05688cu;
    c->state[6] = 0x1f83d9abu;
    c->state[7] = 0x5be0cd19u;
    c->bits = 0;
    c->len = 0;
}

void assl_sha256_update(assl_sha256_ctx *c, const void *data, size_t len) {
    const uint8_t *p = data;
    c->bits += (uint64_t)len * 8;
    while (len > 0) {
        size_t take = 64 - c->len;
        if (take > len) take = len;
        memcpy(c->buf + c->len, p, take);
        c->len += take;
        p += take;
        len -= take;
        if (c->len == 64) {
            assl_sha256_compress(c, c->buf);
            c->len = 0;
        }
    }
}

void assl_sha256_final(assl_sha256_ctx *c, uint8_t out[32]) {
    uint64_t bits = c->bits;
    uint8_t lenb[8];
    uint8_t pad = 0x80;
    assl_sha256_update(c, &pad, 1);
    while ((c->len % 64) != 56) {
        assl_sha256_update(c, "\0", 1);
    }
    assl_wr64_be(lenb, bits);
    assl_sha256_update(c, lenb, 8);
    for (int i = 0; i < 8; i++) assl_wr32_be(out + i * 4, c->state[i]);
}

#define SHR64(x, n) ((x) >> (n))
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static void assl_sha512_compress(assl_sha512_ctx *c, const uint8_t block[128]) {
    static const uint64_t K[80] = {
        0x428a2f98d728ae22ull,0x7137449123ef65cdull,0xb5c0fbcfec4d3b2full,0xe9b5dba58189dbbcull,
        0x3956c25bf348b538ull,0x59f111f1b605d019ull,0x923f82a4af194f9bull,0xab1c5ed5da6d8118ull,
        0xd807aa98a3030242ull,0x12835b0145706fbeull,0x243185be4ee4b28cull,0x550c7dc3d5ffb4e2ull,
        0x72be5d74f27b896full,0x80deb1fe3b1696b1ull,0x9bdc06a725c71235ull,0xc19bf174cf692694ull,
        0xe49b69c19ef14ad2ull,0xefbe4786384f25e3ull,0x0fc19dc68b8cd5b5ull,0x240ca1cc77ac9c65ull,
        0x2de92c6f592b0275ull,0x4a7484aa6ea6e483ull,0x5cb0a9dcbd41fbd4ull,0x76f988da831153b5ull,
        0x983e5152ee66dfabul,0xa831c66d2db43210ull,0xb00327c898fb213full,0xbf597fc7beef0ee4ull,
        0xc6e00bf33da88fc2ull,0xd5a79147930aa725ull,0x06ca6351e003826full,0x142929670a0e6e70ull,
        0x27b70a8546d22ffcull,0x2e1b21385c26c926ull,0x4d2c6dfc5ac42aedull,0x53380d139d95b3dfull,
        0x650a73548baf63deull,0x766a0abb3c77b2a8ull,0x81c2c92e47edaee6ull,0x92722c851482353bull,
        0xa2bfe8a14cf10364ull,0xa81a664bbc423001ull,0xc24b8b70d0f89791ull,0xc76c51a30654be30ull,
        0xd192e819d6ef5218ull,0xd69906245565a910ull,0xf40e35855771202aull,0x106aa07032bbd1b8ull,
        0x19a4c116b8d2d0c8ull,0x1e376c085141ab53ull,0x2748774cdf8eeb99ull,0x34b0bcb5e19b48a8ull,
        0x391c0cb3c5c95a63ull,0x4ed8aa4ae3418acbull,0x5b9cca4f7763e373ull,0x682e6ff3d6b2b8a3ull,
        0x748f82ee5defb2fcull,0x78a5636f43172f60ull,0x84c87814a1f0ab72ull,0x8cc702081a6439ecull,
        0x90befffa23631e28ull,0xa4506cebde82bde9ull,0xbef9a3f7b2c67915ull,0xc67178f2e372532bull,
        0xca273eceea26619cull,0xd186b8c721c0c207ull,0xeada7dd6cde0eb1eull,0xf57d4f7fee6ed178ull,
        0x06f067aa72176fbaull,0x0a637dc5a2c898a6ull,0x113f9804bef90daeull,0x1b710b35131c471bull,
        0x28db77f523047d84ull,0x32caab7b40c72493ull,0x3c9ebe0a15c9bebcull,0x431d67c49c100d4cull,
        0x4cc5d4becb3e42b6ull,0x597f299cfc657e2aull,0x5fcb6fab3ad6faecull,0x6c44198c4a475817ull
    };
    uint64_t w[80];
    uint64_t a, b, cc, d, e, f, g, h;
    uint64_t s0, s1, S1, ch, t1, t2, maj;

    for (int i = 0; i < 16; i++) w[i] = assl_rd64_be(block + i * 8);
    for (int i = 16; i < 80; i++) {
        s0 = ROTR64(w[i - 15], 1) ^ ROTR64(w[i - 15], 8) ^ SHR64(w[i - 15], 7);
        s1 = ROTR64(w[i - 2], 19) ^ ROTR64(w[i - 2], 61) ^ SHR64(w[i - 2], 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = c->state[0];
    b = c->state[1];
    cc = c->state[2];
    d = c->state[3];
    e = c->state[4];
    f = c->state[5];
    g = c->state[6];
    h = c->state[7];

    for (int i = 0; i < 80; i++) {
        S1 = ROTR64(e, 14) ^ ROTR64(e, 18) ^ ROTR64(e, 41);
        ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + K[i] + w[i];
        maj = (a & b) ^ (a & cc) ^ (b & cc);
        s0 = ROTR64(a, 28) ^ ROTR64(a, 34) ^ ROTR64(a, 39);
        t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = cc;
        cc = b;
        b = a;
        a = t1 + t2;
    }

    c->state[0] += a;
    c->state[1] += b;
    c->state[2] += cc;
    c->state[3] += d;
    c->state[4] += e;
    c->state[5] += f;
    c->state[6] += g;
    c->state[7] += h;
}

#undef SHR64
#undef ROTR64

void assl_sha512_init(assl_sha512_ctx *c) {
    c->state[0] = 0x6a09e667f3bcc908ull;
    c->state[1] = 0xbb67ae8584caa73bull;
    c->state[2] = 0x3c6ef372fe94f82bull;
    c->state[3] = 0xa54ff53a5f1d36f1ull;
    c->state[4] = 0x510e527fade682d1ull;
    c->state[5] = 0x9b05688c2b3e6c1full;
    c->state[6] = 0x1f83d9abfb41bd6bull;
    c->state[7] = 0x5be0cd19137e2179ull;
    c->bits_hi = 0;
    c->bits_lo = 0;
    c->len = 0;
}

void assl_sha384_init(assl_sha512_ctx *c) {
    c->state[0] = 0xcbbb9d5dc1059ed8ull;
    c->state[1] = 0x629a292a367cd507ull;
    c->state[2] = 0x9159015a3070dd17ull;
    c->state[3] = 0x152fecd8f70e5939ull;
    c->state[4] = 0x67332667ffc00b31ull;
    c->state[5] = 0x8eb44a8768581511ull;
    c->state[6] = 0xdb0c2e0d64f98fa7ull;
    c->state[7] = 0x47b5481dbefa4fa4ull;
    c->bits_hi = 0;
    c->bits_lo = 0;
    c->len = 0;
}

void assl_sha512_update(assl_sha512_ctx *c, const void *data, size_t len) {
    const uint8_t *p = data;
    uint64_t lo = (uint64_t)(len << 3);
    uint64_t hi = (uint64_t)(len >> 61);
    uint64_t old = c->bits_lo;
    c->bits_lo += lo;
    c->bits_hi += hi + (c->bits_lo < old ? 1 : 0);
    while (len > 0) {
        size_t take = 128 - c->len;
        if (take > len) take = len;
        memcpy(c->buf + c->len, p, take);
        c->len += take;
        p += take;
        len -= take;
        if (c->len == 128) {
            assl_sha512_compress(c, c->buf);
            c->len = 0;
        }
    }
}

void assl_sha512_final(assl_sha512_ctx *c, uint8_t out[64]) {
    uint8_t lenb[16];
    uint8_t pad = 0x80;
    uint64_t lo = c->bits_lo, hi = c->bits_hi;
    assl_sha512_update(c, &pad, 1);
    while ((c->len % 128) != 112) {
        assl_sha512_update(c, "\0", 1);
    }
    assl_wr64_be(lenb, hi);
    assl_wr64_be(lenb + 8, lo);
    assl_sha512_update(c, lenb, 16);
    for (int i = 0; i < 8; i++) assl_wr64_be(out + i * 8, c->state[i]);
}

void assl_sha384_final(assl_sha512_ctx *c, uint8_t out[48]) {
    uint8_t all[64];
    assl_sha512_final(c, all);
    memcpy(out, all, 48);
}

static assl_hash_ops assl_hash_ops_table[ASSL_H_COUNT];
static int assl_hash_ops_ready;

static void assl_hash_ops_ensure(void) {
    if (assl_hash_ops_ready) return;
    assl_hash_ops_table[ASSL_H_MD5].init = (void (*)(void *))assl_md5_init;
    assl_hash_ops_table[ASSL_H_MD5].update = (void (*)(void *, const void *, size_t))assl_md5_update;
    assl_hash_ops_table[ASSL_H_MD5].final = (void (*)(void *, void *))assl_md5_final;
    assl_hash_ops_table[ASSL_H_MD5].block_size = 64;
    assl_hash_ops_table[ASSL_H_MD5].out_size = 16;

    assl_hash_ops_table[ASSL_H_SHA1].init = (void (*)(void *))assl_sha1_init;
    assl_hash_ops_table[ASSL_H_SHA1].update = (void (*)(void *, const void *, size_t))assl_sha1_update;
    assl_hash_ops_table[ASSL_H_SHA1].final = (void (*)(void *, void *))assl_sha1_final;
    assl_hash_ops_table[ASSL_H_SHA1].block_size = 64;
    assl_hash_ops_table[ASSL_H_SHA1].out_size = 20;

    assl_hash_ops_table[ASSL_H_SHA256].init = (void (*)(void *))assl_sha256_init;
    assl_hash_ops_table[ASSL_H_SHA256].update = (void (*)(void *, const void *, size_t))assl_sha256_update;
    assl_hash_ops_table[ASSL_H_SHA256].final = (void (*)(void *, void *))assl_sha256_final;
    assl_hash_ops_table[ASSL_H_SHA256].block_size = 64;
    assl_hash_ops_table[ASSL_H_SHA256].out_size = 32;

    assl_hash_ops_table[ASSL_H_SHA384].init = (void (*)(void *))assl_sha384_init;
    assl_hash_ops_table[ASSL_H_SHA384].update = (void (*)(void *, const void *, size_t))assl_sha512_update;
    assl_hash_ops_table[ASSL_H_SHA384].final = (void (*)(void *, void *))assl_sha384_final;
    assl_hash_ops_table[ASSL_H_SHA384].block_size = 128;
    assl_hash_ops_table[ASSL_H_SHA384].out_size = 48;

    assl_hash_ops_table[ASSL_H_SHA512].init = (void (*)(void *))assl_sha512_init;
    assl_hash_ops_table[ASSL_H_SHA512].update = (void (*)(void *, const void *, size_t))assl_sha512_update;
    assl_hash_ops_table[ASSL_H_SHA512].final = (void (*)(void *, void *))assl_sha512_final;
    assl_hash_ops_table[ASSL_H_SHA512].block_size = 128;
    assl_hash_ops_table[ASSL_H_SHA512].out_size = 64;

    assl_hash_ops_ready = 1;
}

const assl_hash_ops *assl_hash_ops_of(assl_hash_t h) {
    if ((int)h < 0 || (int)h >= ASSL_H_COUNT) return NULL;
    assl_hash_ops_ensure();
    return &assl_hash_ops_table[(int)h];
}

unsigned assl_hash_block_size(assl_hash_t h) {
    const assl_hash_ops *ops = assl_hash_ops_of(h);
    return ops ? ops->block_size : 0;
}

unsigned assl_hash_size(assl_hash_t h) {
    const assl_hash_ops *ops = assl_hash_ops_of(h);
    return ops ? ops->out_size : 0;
}

void assl_hash_one(assl_hash_t h, const void *data, size_t len, uint8_t *out) {
    const assl_hash_ops *ops = assl_hash_ops_of(h);
    assl_hctx ctx;
    if (!ops) return;
    memset(&ctx, 0, sizeof(ctx));
    ops->init(&ctx);
    ops->update(&ctx, data, len);
    ops->final(&ctx, out);
}

void assl_hmac_init(assl_hmac_ctx *c, assl_hash_t h, const void *key, size_t keylen) {
    const assl_hash_ops *ops = assl_hash_ops_of(h);
    const uint8_t *k = key;
    uint8_t keybuf[128];

    if (!ops) {
        memset(c, 0, sizeof *c);
        return;
    }
    c->ops = ops;
    memset(c->pad, 0, sizeof(c->pad));
    if (keylen > ops->block_size) {
        assl_hash_one(h, key, keylen, keybuf);
        memcpy(c->pad, keybuf, ops->out_size);
    } else {
        memcpy(c->pad, k, keylen);
    }
    memset(&c->inner, 0, sizeof(c->inner));
    memset(&c->outer, 0, sizeof(c->outer));
    for (size_t i = 0; i < ops->block_size; i++) c->pad[i] ^= 0x36;
    ops->init(&c->inner);
    ops->update(&c->inner, c->pad, ops->block_size);
    for (size_t i = 0; i < ops->block_size; i++) c->pad[i] ^= (0x36 ^ 0x5c);
    ops->init(&c->outer);
    ops->update(&c->outer, c->pad, ops->block_size);
}

void assl_hmac_update(assl_hmac_ctx *c, const void *data, size_t len) {
    c->ops->update(&c->inner, data, len);
}

void assl_hmac_final(assl_hmac_ctx *c, uint8_t *out) {
    uint8_t inner_hash[64];
    c->ops->final(&c->inner, inner_hash);
    c->ops->update(&c->outer, inner_hash, c->ops->out_size);
    c->ops->final(&c->outer, out);
}

void assl_hmac(assl_hash_t h, const void *key, size_t keylen,
               const void *data, size_t datalen, uint8_t *out) {
    assl_hmac_ctx c;
    assl_hmac_init(&c, h, key, keylen);
    assl_hmac_update(&c, data, datalen);
    assl_hmac_final(&c, out);
}

size_t assl_p_hash(assl_hash_t h, const void *secret, size_t secretlen,
                   const uint8_t *seed, size_t seedlen, uint8_t *out, size_t outlen) {
    size_t hlen = assl_hash_size(h);
    size_t alen = seedlen;
    size_t produced = 0;
    size_t asz = hlen > seedlen ? hlen : seedlen;
    uint8_t *a = malloc(asz);
    uint8_t *mac = malloc(hlen);
    uint8_t *buf = malloc(hlen + seedlen);

    if (!a || !mac || !buf) {
        free(a); free(mac); free(buf);
        return 0;
    }
    memcpy(a, seed, seedlen);
    while (produced < outlen) {
        assl_hmac(h, secret, secretlen, a, alen, mac);
        alen = hlen;
        memcpy(a, mac, hlen);
        memcpy(buf, mac, hlen);
        memcpy(buf + hlen, seed, seedlen);
        assl_hmac(h, secret, secretlen, buf, hlen + seedlen, mac);
        for (size_t i = 0; i < hlen && produced < outlen; i++) {
            out[produced++] = mac[i];
        }
    }
    free(a);
    free(mac);
    free(buf);
    return produced;
}

void assl_tls_prf_md5sha1(const void *secret, size_t secretlen,
                          const uint8_t *seed, size_t seedlen,
                          uint8_t *out, size_t outlen) {
    const uint8_t *s = secret;
    size_t half = secretlen / 2;
    uint8_t *outmd5 = malloc(outlen);
    uint8_t *outsha = malloc(outlen);

    assl_p_hash(ASSL_H_MD5, s, half, seed, seedlen, outmd5, outlen);
    assl_p_hash(ASSL_H_SHA1, s + secretlen - half, half, seed, seedlen, outsha, outlen);
    for (size_t i = 0; i < outlen; i++) out[i] = outmd5[i] ^ outsha[i];
    free(outmd5);
    free(outsha);
}

void assl_tls_prf12(const void *secret, size_t secretlen,
                    const char *label, const uint8_t *seed, size_t seedlen,
                    uint8_t *out, size_t outlen) {
    size_t labelen = strlen(label);
    uint8_t *combined = malloc(labelen + seedlen);
    memcpy(combined, label, labelen);
    memcpy(combined + labelen, seed, seedlen);
    assl_p_hash(ASSL_H_SHA256, secret, secretlen, combined, labelen + seedlen, out, outlen);
    free(combined);
}

void assl_hkdf_extract(assl_hash_t h, const void *ikm, size_t ikmlen,
                       const void *salt, size_t saltlen, uint8_t *prk) {
    unsigned hlen = assl_hash_size(h);
    uint8_t zerosalt[128];
    if (salt == NULL || saltlen == 0) {
        memset(zerosalt, 0, hlen);
        assl_hmac(h, zerosalt, hlen, ikm, ikmlen, prk);
    } else {
        assl_hmac(h, salt, saltlen, ikm, ikmlen, prk);
    }
}

void assl_hkdf_expand(assl_hash_t h, const void *prk, size_t prklen,
                      const uint8_t *info, size_t infolen,
                      uint8_t *out, size_t outlen) {
    unsigned hlen = assl_hash_size(h);
    size_t tlen = 0;
    size_t pos = 0;
    uint8_t t[64];
    uint8_t *block = malloc(hlen + infolen + 1);
    uint8_t counter = 1;

    if (!block) return;
    while (pos < outlen) {
        size_t n = 0;
        if (tlen) {
            memcpy(block, t, tlen);
            n = tlen;
        }
        memcpy(block + n, info, infolen);
        n += infolen;
        block[n++] = counter;
        assl_hmac(h, prk, prklen, block, n, t);
        tlen = hlen;
        for (size_t i = 0; i < hlen && pos < outlen; i++) out[pos++] = t[i];
        counter++;
    }
    free(block);
}

void assl_hkdf(assl_hash_t h, const void *ikm, size_t ikmlen,
               const void *salt, size_t saltlen,
               const uint8_t *info, size_t infolen,
               uint8_t *out, size_t outlen) {
    uint8_t prk[64];
    assl_hkdf_extract(h, ikm, ikmlen, salt, saltlen, prk);
    assl_hkdf_expand(h, prk, assl_hash_size(h), info, infolen, out, outlen);
}

void assl_tls13_hkdf_expand_label(assl_hash_t h, const uint8_t *secret, size_t secretlen,
                                  const char *label, size_t labellen,
                                  const uint8_t *ctx, size_t ctxlen,
                                  uint8_t *out, size_t outlen) {
    uint8_t buf[512];
    size_t n = 0;
    const char *prefix = "tls13 ";
    size_t plen = 6;
    if (labellen > 255 || ctxlen > 255) return;
    buf[n++] = (uint8_t)(outlen >> 8);
    buf[n++] = (uint8_t)outlen;
    buf[n++] = (uint8_t)(plen + labellen);
    memcpy(buf + n, prefix, plen);
    n += plen;
    memcpy(buf + n, label, labellen);
    n += labellen;
    buf[n++] = (uint8_t)ctxlen;
    if (ctxlen) memcpy(buf + n, ctx, ctxlen);
    n += ctxlen;
    assl_hkdf_expand(h, secret, secretlen, buf, n, out, outlen);
}