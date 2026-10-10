#include "asslibc.h"



static uint32_t assl_aes_xtime(uint32_t x) {
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b)) & 0xff;
}

static uint8_t aes_gf_xt(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static uint8_t aes_gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t bit = (uint8_t)((b >> i) & 1);
        uint8_t mask = (uint8_t)(0u - bit);
        p ^= (uint8_t)(a & mask);
        a = aes_gf_xt(a);
    }
    return p;
}

static uint8_t aes_gf_sq(uint8_t x) { return aes_gf_mul(x, x); }

static uint8_t aes_gf_inv(uint8_t x) {
    uint8_t r = 1;
    for (int i = 7; i >= 0; i--) {
        r = aes_gf_sq(r);
        if (254 & (1u << i)) r = aes_gf_mul(r, x);
    }
    return r;
}

static uint8_t aes_rotl8(uint8_t x, int n) {
    return (uint8_t)((x << n) | (x >> (8 - n)));
}

static uint8_t aes_sbox_ct(uint8_t x) {
    uint8_t y = aes_gf_inv(x);
    return (uint8_t)(y ^ aes_rotl8(y, 1) ^ aes_rotl8(y, 2) ^ aes_rotl8(y, 3) ^
                     aes_rotl8(y, 4) ^ 0x63);
}

static uint8_t aes_isbox_ct(uint8_t x) {
    uint8_t t = (uint8_t)(x ^ 0x63);
    uint8_t y = (uint8_t)(aes_rotl8(t, 1) ^ aes_rotl8(t, 3) ^ aes_rotl8(t, 6));
    return aes_gf_inv(y);
}

static uint32_t assl_aes_sub(uint32_t x) {
    return (uint32_t)aes_sbox_ct((uint8_t)x) |
           ((uint32_t)aes_sbox_ct((uint8_t)(x >> 8)) << 8) |
           ((uint32_t)aes_sbox_ct((uint8_t)(x >> 16)) << 16) |
           ((uint32_t)aes_sbox_ct((uint8_t)(x >> 24)) << 24);
}

static uint32_t assl_aes_rot8(uint32_t x) {
    return (x << 8) | (x >> 24);
}

void assl_aes_setkey_enc(assl_aes_ctx *c, const uint8_t *key, size_t bits) {
    static const uint32_t rcon[11] = {
        0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };
    uint32_t *rk = c->rk;
    int nk = (int)bits / 32;
    int nr = nk + 6;
    int i = 0;
    uint32_t temp;

    c->rounds = nr;
    for (i = 0; i < nk; i++) {
        rk[i] = ((uint32_t)key[i * 4] << 24) | ((uint32_t)key[i * 4 + 1] << 16) |
                ((uint32_t)key[i * 4 + 2] << 8) | key[i * 4 + 3];
    }
    for (i = nk; i < 4 * (nr + 1); i++) {
        temp = rk[i - 1];
        if (i % nk == 0) {
            temp = assl_aes_sub(assl_aes_rot8(temp)) ^ (rcon[i / nk] << 24);
        } else if (nk > 6 && i % nk == 4) {
            temp = assl_aes_sub(temp);
        }
        rk[i] = rk[i - nk] ^ temp;
    }
}

void assl_aes_setkey_dec(assl_aes_ctx *c, const uint8_t *key, size_t bits) {
    assl_aes_setkey_enc(c, key, bits);
}

static void assl_aes_addround(uint8_t *s, const uint32_t *rk) {
    for (int c = 0; c < 4; c++) {
        uint32_t w = rk[c];
        s[c * 4 + 0] ^= (uint8_t)(w >> 24);
        s[c * 4 + 1] ^= (uint8_t)(w >> 16);
        s[c * 4 + 2] ^= (uint8_t)(w >> 8);
        s[c * 4 + 3] ^= (uint8_t)w;
    }
}

static void assl_aes_subbytes(uint8_t *s) {
    for (int i = 0; i < 16; i++) s[i] = aes_sbox_ct(s[i]);
}

static void assl_aes_invsubbytes(uint8_t *s) {
    for (int i = 0; i < 16; i++) s[i] = aes_isbox_ct(s[i]);
}

static void assl_aes_shiftrows(uint8_t *s) {
    uint8_t t;

    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t;
}

static void assl_aes_invshiftrows(uint8_t *s) {
    uint8_t t;

    t = s[1]; s[1] = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = t;
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

static void assl_aes_mixcolumns(uint8_t *s) {
    for (int c = 0; c < 4; c++) {
        uint8_t a0 = s[c * 4 + 0], a1 = s[c * 4 + 1];
        uint8_t a2 = s[c * 4 + 2], a3 = s[c * 4 + 3];
        uint8_t b0 = assl_aes_xtime(a0) ^ assl_aes_xtime(a1) ^ a1 ^ a2 ^ a3;
        uint8_t b1 = a0 ^ assl_aes_xtime(a1) ^ assl_aes_xtime(a2) ^ a2 ^ a3;
        uint8_t b2 = a0 ^ a1 ^ assl_aes_xtime(a2) ^ assl_aes_xtime(a3) ^ a3;
        uint8_t b3 = assl_aes_xtime(a0) ^ a0 ^ a1 ^ a2 ^ assl_aes_xtime(a3);
        s[c * 4 + 0] = b0;
        s[c * 4 + 1] = b1;
        s[c * 4 + 2] = b2;
        s[c * 4 + 3] = b3;
    }
}

static void assl_aes_invmixcolumns(uint8_t *s) {
    for (int c = 0; c < 4; c++) {
        uint8_t a0 = s[c * 4 + 0], a1 = s[c * 4 + 1];
        uint8_t a2 = s[c * 4 + 2], a3 = s[c * 4 + 3];
        uint8_t t2 = assl_aes_xtime(a0), t4 = assl_aes_xtime(t2), t8 = assl_aes_xtime(t4);
        uint8_t m14 = (uint8_t)(t8 ^ t4 ^ t2), m11 = (uint8_t)(t8 ^ t2 ^ a0), m13 = (uint8_t)(t8 ^ t4 ^ a0), m9 = (uint8_t)(t8 ^ a0);
        uint8_t u2 = assl_aes_xtime(a1), u4 = assl_aes_xtime(u2), u8 = assl_aes_xtime(u4);
        uint8_t n14 = (uint8_t)(u8 ^ u4 ^ u2), n11 = (uint8_t)(u8 ^ u2 ^ a1), n13 = (uint8_t)(u8 ^ u4 ^ a1), n9 = (uint8_t)(u8 ^ a1);
        uint8_t v2 = assl_aes_xtime(a2), v4 = assl_aes_xtime(v2), v8 = assl_aes_xtime(v4);
        uint8_t o14 = (uint8_t)(v8 ^ v4 ^ v2), o11 = (uint8_t)(v8 ^ v2 ^ a2), o13 = (uint8_t)(v8 ^ v4 ^ a2), o9 = (uint8_t)(v8 ^ a2);
        uint8_t w2 = assl_aes_xtime(a3), w4 = assl_aes_xtime(w2), w8 = assl_aes_xtime(w4);
        uint8_t p14 = (uint8_t)(w8 ^ w4 ^ w2), p11 = (uint8_t)(w8 ^ w2 ^ a3), p13 = (uint8_t)(w8 ^ w4 ^ a3), p9 = (uint8_t)(w8 ^ a3);
        s[c * 4 + 0] = (uint8_t)(m14 ^ n11 ^ o13 ^ p9);
        s[c * 4 + 1] = (uint8_t)(m9 ^ n14 ^ o11 ^ p13);
        s[c * 4 + 2] = (uint8_t)(m13 ^ n9 ^ o14 ^ p11);
        s[c * 4 + 3] = (uint8_t)(m11 ^ n13 ^ o9 ^ p14);
    }
}

void assl_aes_encrypt(const assl_aes_ctx *c, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    int round;

    memcpy(s, in, 16);
    assl_aes_addround(s, c->rk);
    for (round = 1; round < c->rounds; round++) {
        assl_aes_subbytes(s);
        assl_aes_shiftrows(s);
        assl_aes_mixcolumns(s);
        assl_aes_addround(s, c->rk + round * 4);
    }
    assl_aes_subbytes(s);
    assl_aes_shiftrows(s);
    assl_aes_addround(s, c->rk + c->rounds * 4);
    memcpy(out, s, 16);
}

void assl_aes_decrypt(const assl_aes_ctx *c, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    int round;

    memcpy(s, in, 16);
    assl_aes_addround(s, c->rk + c->rounds * 4);
    for (round = c->rounds - 1; round >= 1; round--) {
        assl_aes_invshiftrows(s);
        assl_aes_invsubbytes(s);
        assl_aes_addround(s, c->rk + round * 4);
        assl_aes_invmixcolumns(s);
    }
    assl_aes_invshiftrows(s);
    assl_aes_invsubbytes(s);
    assl_aes_addround(s, c->rk);
    memcpy(out, s, 16);
}

void assl_aes_cbc_encrypt(const uint8_t *key, size_t keybits,
                          const uint8_t iv[16], const uint8_t *in, size_t len, uint8_t *out) {
    assl_aes_ctx c;
    uint8_t cur[16];
    size_t n = len / 16;

    assl_aes_setkey_enc(&c, key, keybits);
    memcpy(cur, iv, 16);
    for (size_t i = 0; i < n; i++) {
        for (int j = 0; j < 16; j++) cur[j] ^= in[i * 16 + j];
        assl_aes_encrypt(&c, cur, out + i * 16);
        memcpy(cur, out + i * 16, 16);
    }
}

void assl_aes_cbc_decrypt(const uint8_t *key, size_t keybits,
                          const uint8_t iv[16], const uint8_t *in, size_t len, uint8_t *out) {
    assl_aes_ctx c;
    uint8_t prev[16];
    size_t n = len / 16;

    assl_aes_setkey_dec(&c, key, keybits);
    memcpy(prev, iv, 16);
    for (size_t i = 0; i < n; i++) {
        uint8_t keep[16];
        memcpy(keep, in + i * 16, 16);
        assl_aes_decrypt(&c, in + i * 16, out + i * 16);
        for (int j = 0; j < 16; j++) out[i * 16 + j] ^= prev[j];
        memcpy(prev, keep, 16);
    }
}

void assl_aes_ctr_stream(const uint8_t *key, size_t keybits,
                         const uint8_t counter[16], size_t blocks,
                         const uint8_t *in, uint8_t *out) {
    assl_aes_ctx c;
    uint8_t ctr[16];
    uint8_t enc[16];

    assl_aes_setkey_enc(&c, key, keybits);
    memcpy(ctr, counter, 16);
    for (size_t i = 0; i < blocks; i++) {
        assl_aes_encrypt(&c, ctr, enc);
        for (int j = 0; j < 16; j++) out[i * 16 + j] = in ? in[i * 16 + j] ^ enc[j] : enc[j];
        for (int j = 15; j >= 0; j--) {
            if (++ctr[j] != 0) break;
        }
    }
}

static void assl_gcm_mul(uint8_t out[16], const uint8_t x[16], const uint8_t y[16]) {
    uint64_t z[2] = {0, 0};
    uint64_t v[2];

    v[0] = assl_rd64_be(y);
    v[1] = assl_rd64_be(y + 8);
    for (int i = 0; i < 128; i++) {
        uint8_t xb = x[i >> 3];
        uint64_t lsb;
        if (xb & (0x80 >> (i & 7))) {
            z[0] ^= v[0];
            z[1] ^= v[1];
        }
        lsb = v[1] & 1;
        v[1] = (v[1] >> 1) | (v[0] << 63);
        v[0] = v[0] >> 1;
        if (lsb) v[0] ^= 0xe100000000000000ull;
    }
    assl_wr64_be(out, z[0]);
    assl_wr64_be(out + 8, z[1]);
}

static void assl_gcm_ghash(uint8_t s[16], const uint8_t h[16],
                           const uint8_t *data, size_t len) {
    size_t n = len / 16;

    for (size_t i = 0; i < n; i++) {
        for (int j = 0; j < 16; j++) s[j] ^= data[i * 16 + j];
        assl_gcm_mul(s, s, h);
    }
}

static void assl_gcm_ghash_len(uint8_t s[16], const uint8_t h[16],
                               uint64_t abitlen, uint64_t cbitlen) {
    uint8_t blk[16];
    assl_wr64_be(blk, abitlen);
    assl_wr64_be(blk + 8, cbitlen);
    for (int j = 0; j < 16; j++) s[j] ^= blk[j];
    assl_gcm_mul(s, s, h);
}

static void assl_gcm_init_j0(const uint8_t *key, size_t keybits,
                             const uint8_t *iv, size_t ivlen, uint8_t j0[16]) {
    assl_aes_ctx c;
    uint8_t h[16];
    uint8_t zero[16] = {0};

    assl_aes_setkey_enc(&c, key, keybits);
    assl_aes_encrypt(&c, zero, h);
    if (ivlen == 12) {
        memcpy(j0, iv, 12);
        j0[12] = j0[13] = j0[14] = 0;
        j0[15] = 1;
    } else {
        uint8_t s[16] = {0};
        size_t pos = 0;
        uint8_t pad[16] = {0};
        while (pos + 16 <= ivlen) {
            assl_gcm_ghash(s, h, iv + pos, 16);
            pos += 16;
        }
        if (pos < ivlen) {
            memset(pad, 0, 16);
            memcpy(pad, iv + pos, ivlen - pos);
            assl_gcm_ghash(s, h, pad, 16);
        }
        assl_gcm_ghash_len(s, h, 0, (uint64_t)ivlen * 8);
        memcpy(j0, s, 16);
    }
}

static void assl_gcm_inc32(uint8_t ctr[16]) {
    for (int i = 15; i >= 12; i--) {
        if (++ctr[i] != 0) break;
    }
}

void assl_gcm_seal(const uint8_t *key, size_t keybits,
                   const uint8_t *iv, size_t ivlen,
                   const uint8_t *aad, size_t aadlen,
                   const uint8_t *pt, size_t ptlen,
                   uint8_t *ct, uint8_t tag[16]) {
    assl_aes_ctx c;
    uint8_t h[16];
    uint8_t zero[16] = {0};
    uint8_t j0[16];
    uint8_t ctr[16];
    uint8_t s[16] = {0};
    uint8_t e[16];
    uint8_t pad[16] = {0};
    size_t n;

    assl_aes_setkey_enc(&c, key, keybits);
    assl_aes_encrypt(&c, zero, h);
    assl_gcm_init_j0(key, keybits, iv, ivlen, j0);

    n = ptlen / 16;
    memcpy(ctr, j0, 16);
    assl_gcm_inc32(ctr);
    if (pt && ct) {
        assl_aes_ctr_stream(key, keybits, ctr, n, pt, ct);
    }
    if (ptlen % 16) {
        uint8_t last[16] = {0};
        for (size_t k = 0; k < n; k++) assl_gcm_inc32(ctr);
        memcpy(last, pt + n * 16, ptlen % 16);
        assl_aes_ctr_stream(key, keybits, ctr, 1, last, last);
        memcpy(ct + n * 16, last, ptlen % 16);
    }

    if (aadlen) {
        n = aadlen / 16;
        if (n) assl_gcm_ghash(s, h, aad, n * 16);
        if (aadlen % 16) {
            memset(pad, 0, 16);
            memcpy(pad, aad + n * 16, aadlen % 16);
            assl_gcm_ghash(s, h, pad, 16);
        }
    }
    if (ptlen) {
        n = ptlen / 16;
        if (n) assl_gcm_ghash(s, h, ct, n * 16);
        if (ptlen % 16) {
            memset(pad, 0, 16);
            memcpy(pad, ct + n * 16, ptlen % 16);
            assl_gcm_ghash(s, h, pad, 16);
        }
    }
    assl_gcm_ghash_len(s, h, (uint64_t)aadlen * 8, (uint64_t)ptlen * 8);

    assl_aes_encrypt(&c, j0, e);
    for (size_t i = 0; i < 16; i++) tag[i] = s[i] ^ e[i];
}

int assl_gcm_open(const uint8_t *key, size_t keybits,
                  const uint8_t *iv, size_t ivlen,
                  const uint8_t *aad, size_t aadlen,
                  const uint8_t *ct, size_t ctlen,
                  const uint8_t tag[16], uint8_t *pt) {
    assl_aes_ctx c;
    uint8_t h[16];
    uint8_t zero[16] = {0};
    uint8_t j0[16];
    uint8_t ctr[16];
    uint8_t s[16] = {0};
    uint8_t e[16];
    uint8_t pad[16] = {0};
    uint32_t bad = 0;
    size_t n = 0;

    assl_aes_setkey_enc(&c, key, keybits);
    assl_aes_encrypt(&c, zero, h);
    assl_gcm_init_j0(key, keybits, iv, ivlen, j0);
    if (aadlen) {
        n = aadlen / 16;
        if (n) assl_gcm_ghash(s, h, aad, n * 16);
        if (aadlen % 16) {
            memset(pad, 0, 16);
            memcpy(pad, aad + n * 16, aadlen % 16);
            assl_gcm_ghash(s, h, pad, 16);
        }
    }
    if (ctlen) {
        n = ctlen / 16;
        if (n) assl_gcm_ghash(s, h, ct, n * 16);
        if (ctlen % 16) {
            memset(pad, 0, 16);
            memcpy(pad, ct + n * 16, ctlen % 16);
            assl_gcm_ghash(s, h, pad, 16);
        }
    }
    assl_gcm_ghash_len(s, h, (uint64_t)aadlen * 8, (uint64_t)ctlen * 8);
    assl_aes_encrypt(&c, j0, e);
    for (int i = 0; i < 16; i++) bad |= (uint32_t)(s[i] ^ e[i] ^ tag[i]);
    if (bad) return -1;

    memcpy(ctr, j0, 16);
    assl_gcm_inc32(ctr);
    if (pt && ct) {
        assl_aes_ctr_stream(key, keybits, ctr, ctlen / 16, ct, pt);
    }
    if (ctlen % 16) {
        uint8_t last[16] = {0};
        for (size_t k = 0; k < n; k++) assl_gcm_inc32(ctr);
        memcpy(last, ct + n * 16, ctlen % 16);
        assl_aes_ctr_stream(key, keybits, ctr, 1, last, last);
        memcpy(pt + n * 16, last, ctlen % 16);
    }
    return 0;
}

static void assl_ccm_ctr_xor(const uint8_t *key, size_t keybits, uint8_t ctr[16],
                             const uint8_t *in, size_t len, uint8_t *out) {
    assl_aes_ctx c;
    uint8_t enc[16];
    size_t i = 0;

    assl_aes_setkey_enc(&c, key, keybits);
    while (i < len) {
        assl_aes_encrypt(&c, ctr, enc);
        for (size_t j = 0; j < 16 && i < len; j++, i++) {
            out[i] = in[i] ^ enc[j];
        }
        for (int j = 15; j >= 0; j--) {
            if (++ctr[j] != 0) break;
        }
    }
}

static void assl_ccm_mac(assl_aes_ctx *c, const uint8_t *aad, size_t aadlen,
                         const uint8_t *m, size_t mlen, uint8_t cbc[16]) {
    uint8_t blk[16];
    size_t pos;
    if (aadlen) {
        size_t nlen;
        uint8_t nbuf[6];
        if (aadlen < 0xff00) {
            nbuf[0] = (uint8_t)(aadlen >> 8);
            nbuf[1] = (uint8_t)aadlen;
            nlen = 2;
        } else {
            nbuf[0] = 0xff;
            nbuf[1] = 0xfe;
            nbuf[2] = (uint8_t)((aadlen >> 24) & 0xff);
            nbuf[3] = (uint8_t)((aadlen >> 16) & 0xff);
            nbuf[4] = (uint8_t)((aadlen >> 8) & 0xff);
            nbuf[5] = (uint8_t)aadlen;
            nlen = 6;
        }
        memset(blk, 0, 16);
        memcpy(blk, nbuf, nlen);
        if (aadlen + nlen < 16) {
            memcpy(blk + nlen, aad, aadlen);
            for (int i = 0; i < 16; i++) cbc[i] ^= blk[i];
            assl_aes_encrypt(c, cbc, cbc);
        } else {
            size_t take = 16 - nlen;
            memcpy(blk + nlen, aad, take);
            for (int i = 0; i < 16; i++) cbc[i] ^= blk[i];
            assl_aes_encrypt(c, cbc, cbc);
            pos = take;
            while (pos < aadlen) {
                size_t t2 = (aadlen - pos) > 16 ? 16 : (aadlen - pos);
                memcpy(blk, aad + pos, t2);
                for (size_t j = t2; j < 16; j++) blk[j] = 0;
                for (int i = 0; i < 16; i++) cbc[i] ^= blk[i];
                assl_aes_encrypt(c, cbc, cbc);
                pos += t2;
            }
        }
    }
    pos = 0;
    while (pos < mlen) {
        size_t t2 = (mlen - pos) > 16 ? 16 : (mlen - pos);
        memcpy(blk, m + pos, t2);
        for (size_t j = t2; j < 16; j++) blk[j] = 0;
        for (int i = 0; i < 16; i++) cbc[i] ^= blk[i];
        assl_aes_encrypt(c, cbc, cbc);
        pos += t2;
    }
}

static void assl_ccm_b0(uint8_t b0[16], size_t hasaad, size_t m, size_t l,
                        const uint8_t *nonce, size_t noncelen, size_t q) {
    memset(b0, 0, 16);
    if (hasaad) b0[0] |= 0x40;
    b0[0] |= (uint8_t)(((m - 2) / 2) << 3);
    b0[0] |= (uint8_t)(l - 1);
    memcpy(b0 + 1, nonce, noncelen);
    for (size_t i = 0; i < l; i++) {
        b0[16 - 1 - i] = (uint8_t)(q >> (8 * i));
    }
}

void assl_ccm_seal(const uint8_t *key, size_t keybits,
                   const uint8_t *nonce, size_t noncelen,
                   const uint8_t *aad, size_t aadlen,
                   const uint8_t *pt, size_t ptlen,
                   uint8_t *ct, uint8_t *tag, size_t taglen) {
    uint8_t b0[16];
    uint8_t s0[16];
    uint8_t ctr[16];
    uint8_t cbc[16];
    uint8_t blk[16];
    assl_aes_ctx c;
    size_t l = 15 - noncelen;
    size_t m = taglen;

    assl_aes_setkey_enc(&c, key, keybits);
    assl_ccm_b0(b0, aadlen != 0, m, l, nonce, noncelen, ptlen);
    assl_aes_encrypt(&c, b0, cbc);
    assl_ccm_mac(&c, aad, aadlen, pt, ptlen, cbc);
    memcpy(ctr, b0, 16);
    ctr[0] = (uint8_t)(l - 1);
    memset(ctr + 16 - l, 0, l);
    memcpy(s0, ctr, 16);
    assl_aes_encrypt(&c, s0, s0);
    ctr[15] = 1;
    assl_ccm_ctr_xor(key, keybits, ctr, pt, ptlen, ct);
    for (size_t i = 0; i < m; i++) {
        blk[i] = (uint8_t)(s0[i] ^ cbc[i]);
    }
    memcpy(tag, blk, m);
}

int assl_ccm_open(const uint8_t *key, size_t keybits,
                  const uint8_t *nonce, size_t noncelen,
                  const uint8_t *aad, size_t aadlen,
                  const uint8_t *ct, size_t ctlen,
                  const uint8_t *tag, size_t taglen, uint8_t *pt) {
    uint8_t b0[16];
    uint8_t s0[16];
    uint8_t ctr[16];
    uint8_t cbc[16];
    uint8_t t[16];
    assl_aes_ctx c;
    uint32_t bad = 0;
    size_t l = 15 - noncelen;
    size_t m = taglen;

    assl_aes_setkey_enc(&c, key, keybits);
    assl_ccm_b0(b0, aadlen != 0, m, l, nonce, noncelen, ctlen);
    memcpy(ctr, b0, 16);
    ctr[0] = (uint8_t)(l - 1);
    memset(ctr + 16 - l, 0, l);
    memcpy(s0, ctr, 16);
    assl_aes_encrypt(&c, s0, s0);
    ctr[15] = 1;
    assl_ccm_ctr_xor(key, keybits, ctr, ct, ctlen, pt);
    assl_aes_encrypt(&c, b0, cbc);
    assl_ccm_mac(&c, aad, aadlen, pt, ctlen, cbc);
    for (size_t i = 0; i < m; i++) {
        t[i] = (uint8_t)(s0[i] ^ cbc[i]);
    }
    for (size_t i = 0; i < m; i++) bad |= t[i] ^ tag[i];
    return bad ? -1 : 0;
}

static uint32_t assl_chacha_qr(uint32_t *state, int a, int b, int c, int d) {
    uint32_t x, y, z, w;
    w = state[a];
    x = state[b];
    y = state[c];
    z = state[d];
    w += x; z ^= w; z = (z << 16) | (z >> 16);
    y += z; x ^= y; x = (x << 12) | (x >> 20);
    w += x; z ^= w; z = (z << 8) | (z >> 24);
    y += z; x ^= y; x = (x << 7) | (x >> 25);
    state[a] = w;
    state[b] = x;
    state[c] = y;
    state[d] = z;
    return w;
}

void assl_chacha20_block(const uint8_t key[32], const uint8_t nonce[12],
                         uint32_t counter, uint8_t out[64]) {
    static const uint32_t cst[4] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
    uint32_t st[16];
    uint32_t ws[16];

    memcpy(st, cst, 16);
    for (int i = 0; i < 8; i++) st[4 + i] = assl_rd32_le(key + i * 4);
    st[12] = counter;
    st[13] = assl_rd32_le(nonce);
    st[14] = assl_rd32_le(nonce + 4);
    st[15] = assl_rd32_le(nonce + 8);
    memcpy(ws, st, 64);
    for (int i = 0; i < 10; i++) {
        assl_chacha_qr(ws, 0, 4, 8, 12);
        assl_chacha_qr(ws, 1, 5, 9, 13);
        assl_chacha_qr(ws, 2, 6, 10, 14);
        assl_chacha_qr(ws, 3, 7, 11, 15);
        assl_chacha_qr(ws, 0, 5, 10, 15);
        assl_chacha_qr(ws, 1, 6, 11, 12);
        assl_chacha_qr(ws, 2, 7, 8, 13);
        assl_chacha_qr(ws, 3, 4, 9, 14);
    }
    for (int i = 0; i < 16; i++) ws[i] += st[i];
    for (int i = 0; i < 16; i++) assl_wr32_le(out + i * 4, ws[i]);
}

static void assl_chacha_xor(const uint8_t key[32], const uint8_t nonce[12],
                            uint32_t counter, const uint8_t *in, size_t len, uint8_t *out) {
    uint8_t blk[64];
    size_t i = 0;

    while (i < len) {
        size_t t = (len - i) > 64 ? 64 : (len - i);
        assl_chacha20_block(key, nonce, counter++, blk);
        for (size_t j = 0; j < t; j++) out[i + j] = in[i + j] ^ blk[j];
        i += t;
    }
}

void assl_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                       uint32_t counter, const uint8_t *in, size_t len, uint8_t *out) {
    assl_chacha_xor(key, nonce, counter, in, len, out);
}

void assl_poly1305_mac(const uint8_t key[32], const uint8_t *msg, size_t msglen,
                       uint8_t tag[16]) {
    uint32_t r0 = assl_rd32_le(key) & 0x3ffffff;
    uint32_t r1 = (assl_rd32_le(key + 3) >> 2) & 0x3ffff03;
    uint32_t r2 = (assl_rd32_le(key + 6) >> 4) & 0x3ffc0ff;
    uint32_t r3 = (assl_rd32_le(key + 9) >> 6) & 0x3f03fff;
    uint32_t r4 = (assl_rd32_le(key + 12) >> 8) & 0x00fffff;
    uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    size_t i = 0;

    while (msglen - i >= 16) {
        uint64_t d0, d1, d2, d3, d4;
        uint64_t c;
        h0 += assl_rd32_le(msg + i) & 0x3ffffff;
        h1 += (assl_rd32_le(msg + i + 3) >> 2) & 0x3ffffff;
        h2 += (assl_rd32_le(msg + i + 6) >> 4) & 0x3ffffff;
        h3 += (assl_rd32_le(msg + i + 9) >> 6) & 0x3ffffff;
        h4 += (assl_rd32_le(msg + i + 12) >> 8) & 0x3ffffff;
        h4 += 0x1000000;

        d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * (5 * (uint64_t)r4) +
             (uint64_t)h2 * (5 * (uint64_t)r3) + (uint64_t)h3 * (5 * (uint64_t)r2) +
             (uint64_t)h4 * (5 * (uint64_t)r1);
        d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * (5 * (uint64_t)r4) +
             (uint64_t)h3 * (5 * (uint64_t)r3) + (uint64_t)h4 * (5 * (uint64_t)r2);
        d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 +
             (uint64_t)h3 * (5 * (uint64_t)r4) + (uint64_t)h4 * (5 * (uint64_t)r3);
        d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 +
             (uint64_t)h4 * (5 * (uint64_t)r4);
        d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 +
             (uint64_t)h4 * r0;

        c = d0 >> 26; h0 = (uint32_t)(d0 & 0x3ffffff); d1 += c;
        c = d1 >> 26; h1 = (uint32_t)(d1 & 0x3ffffff); d2 += c;
        c = d2 >> 26; h2 = (uint32_t)(d2 & 0x3ffffff); d3 += c;
        c = d3 >> 26; h3 = (uint32_t)(d3 & 0x3ffffff); d4 += c;
        c = d4 >> 26; h4 = (uint32_t)(d4 & 0x3ffffff); h0 += (uint32_t)(c * 5);
        c = h0 >> 26; h0 &= 0x3ffffff;                 h1 += (uint32_t)c;
        c = h1 >> 26; h1 &= 0x3ffffff;                 h2 += (uint32_t)c;
        c = h2 >> 26; h2 &= 0x3ffffff;                 h3 += (uint32_t)c;
        c = h3 >> 26; h3 &= 0x3ffffff;                 h4 += (uint32_t)c;
        h4 &= 0x3ffffff;

        i += 16;
    }

    if (msglen % 16) {
        uint8_t last[16] = {0};
        uint64_t d0, d1, d2, d3, d4;
        uint64_t c;
        size_t rem = msglen % 16;
        memcpy(last, msg + i, rem);
        last[rem] = 1;
        h0 += assl_rd32_le(last) & 0x3ffffff;
        h1 += (assl_rd32_le(last + 3) >> 2) & 0x3ffffff;
        h2 += (assl_rd32_le(last + 6) >> 4) & 0x3ffffff;
        h3 += (assl_rd32_le(last + 9) >> 6) & 0x3ffffff;
        h4 += (assl_rd32_le(last + 12) >> 8) & 0x3ffffff;
        if (rem >= 16) h4 += 0x1000000;

        d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * (5 * (uint64_t)r4) +
             (uint64_t)h2 * (5 * (uint64_t)r3) + (uint64_t)h3 * (5 * (uint64_t)r2) +
             (uint64_t)h4 * (5 * (uint64_t)r1);
        d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * (5 * (uint64_t)r4) +
             (uint64_t)h3 * (5 * (uint64_t)r3) + (uint64_t)h4 * (5 * (uint64_t)r2);
        d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 +
             (uint64_t)h3 * (5 * (uint64_t)r4) + (uint64_t)h4 * (5 * (uint64_t)r3);
        d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 +
             (uint64_t)h4 * (5 * (uint64_t)r4);
        d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 +
             (uint64_t)h4 * r0;

        c = d0 >> 26; h0 = (uint32_t)(d0 & 0x3ffffff); d1 += c;
        c = d1 >> 26; h1 = (uint32_t)(d1 & 0x3ffffff); d2 += c;
        c = d2 >> 26; h2 = (uint32_t)(d2 & 0x3ffffff); d3 += c;
        c = d3 >> 26; h3 = (uint32_t)(d3 & 0x3ffffff); d4 += c;
        c = d4 >> 26; h4 = (uint32_t)(d4 & 0x3ffffff); h0 += (uint32_t)(c * 5);
        c = h0 >> 26; h0 &= 0x3ffffff;                 h1 += (uint32_t)c;
        c = h1 >> 26; h1 &= 0x3ffffff;                 h2 += (uint32_t)c;
        c = h2 >> 26; h2 &= 0x3ffffff;                 h3 += (uint32_t)c;
        c = h3 >> 26; h3 &= 0x3ffffff;                 h4 += (uint32_t)c;
        h4 &= 0x3ffffff;
    }

    {
        uint64_t f0 = (uint64_t)h0 + 5;
        uint64_t f1 = (uint64_t)h1 + (f0 >> 26);
        uint64_t f2 = (uint64_t)h2 + (f1 >> 26);
        uint64_t f3 = (uint64_t)h3 + (f2 >> 26);
        uint64_t f4 = (uint64_t)h4 + (f3 >> 26);
        if (f4 >> 26) {
            h0 = (uint32_t)(f0 & 0x3ffffff);
            h1 = (uint32_t)(f1 & 0x3ffffff);
            h2 = (uint32_t)(f2 & 0x3ffffff);
            h3 = (uint32_t)(f3 & 0x3ffffff);
            h4 = (uint32_t)(f4 & 0x3ffffff);
        }
    }

    {
        uint32_t s0 = assl_rd32_le(key + 16);
        uint32_t s1 = assl_rd32_le(key + 20);
        uint32_t s2 = assl_rd32_le(key + 24);
        uint32_t s3 = assl_rd32_le(key + 28);
        uint64_t q;
        uint32_t w0, w1, w2, w3;
        uint64_t t0, t1, t2, t3;

        q = (uint64_t)h0 + ((uint64_t)h1 << 26);
        w0 = (uint32_t)q;
        q = (q >> 32) + ((uint64_t)h2 << 20);
        w1 = (uint32_t)q;
        q = (q >> 32) + ((uint64_t)h3 << 14);
        w2 = (uint32_t)q;
        q = (q >> 32) + ((uint64_t)h4 << 8);
        w3 = (uint32_t)q;

        t0 = (uint64_t)w0 + s0;
        t1 = (uint64_t)w1 + s1 + (t0 >> 32);
        t2 = (uint64_t)w2 + s2 + (t1 >> 32);
        t3 = (uint64_t)w3 + s3 + (t2 >> 32);
        assl_wr32_le(tag, (uint32_t)t0);
        assl_wr32_le(tag + 4, (uint32_t)t1);
        assl_wr32_le(tag + 8, (uint32_t)t2);
        assl_wr32_le(tag + 12, (uint32_t)t3);
    }
}

static void assl_chacha20_poly1305_tag(const uint8_t polykey[32],
                                       const uint8_t *aad, size_t aadlen,
                                       const uint8_t *ct, size_t ctlen,
                                       uint8_t tag[16]) {
    uint8_t *macdata;
    size_t maclen = aadlen + ((16 - (aadlen % 16)) % 16) + ctlen +
                    ((16 - (ctlen % 16)) % 16) + 16;
    size_t n = 0;
    uint8_t lenblk[16];

    macdata = malloc(maclen);
    if (aadlen) memcpy(macdata + n, aad, aadlen);
    n += aadlen;
    while (n % 16) macdata[n++] = 0;
    if (ctlen) memcpy(macdata + n, ct, ctlen);
    n += ctlen;
    while (n % 16) macdata[n++] = 0;
    assl_wr64_le(lenblk, (uint64_t)aadlen);
    assl_wr64_le(lenblk + 8, (uint64_t)ctlen);
    memcpy(macdata + n, lenblk, 16);
    n += 16;
    assl_poly1305_mac(polykey, macdata, n, tag);
    free(macdata);
}

void assl_chacha20_poly1305_seal(const uint8_t key[32], const uint8_t nonce[12],
                                 const uint8_t *aad, size_t aadlen,
                                 const uint8_t *pt, size_t ptlen,
                                 uint8_t *ct, uint8_t tag[16]) {
    uint8_t polykey[64];

    assl_chacha20_block(key, nonce, 0, polykey);
    if (ct) {
        assl_chacha_xor(key, nonce, 1, pt, ptlen, ct);
        assl_chacha20_poly1305_tag(polykey, aad, aadlen, ct, ptlen, tag);
    } else {
        assl_chacha20_poly1305_tag(polykey, aad, aadlen, NULL, 0, tag);
    }
}

int assl_chacha20_poly1305_open(const uint8_t key[32], const uint8_t nonce[12],
                                const uint8_t *aad, size_t aadlen,
                                const uint8_t *ct, size_t ctlen,
                                const uint8_t tag[16], uint8_t *pt) {
    uint8_t polykey[64];
    uint8_t t[16];
    uint32_t bad = 0;

    assl_chacha20_block(key, nonce, 0, polykey);
    assl_chacha20_poly1305_tag(polykey, aad, aadlen, ct, ctlen, t);
    for (size_t i = 0; i < 16; i++) bad |= t[i] ^ tag[i];
    if (bad) return -1;
    assl_chacha_xor(key, nonce, 1, ct, ctlen, pt);
    return 0;
}