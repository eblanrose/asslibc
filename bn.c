#include "asslibc.h"

#define BN_MASK 0xffffffffu

typedef struct {
    const assl_bn *m;
    size_t n;
    uint32_t n0inv;
    assl_bn Rmod;
    assl_bn R2mod;
} assl_mont;

static void bn_trim(assl_bn *a) {
    while (a->len > 1 && a->d[a->len - 1] == 0) a->len--;
}

static int bn_fit(assl_bn *a, size_t n) {
    uint32_t *p;
    if (a->cap >= n) return 0;
    p = realloc(a->d, n * sizeof(uint32_t));
    if (!p) return -1;
    a->d = p;
    a->cap = n;
    return 0;
}

static uint32_t bn_limb(const assl_bn *a, size_t i) {
    return i < a->len ? a->d[i] : 0;
}



static void bn_set_bit(assl_bn *a, size_t i) {
    if (a->len < (i >> 5) + 1) a->len = (i >> 5) + 1;
    a->d[i >> 5] |= 1u << (i & 31);
}

static int bn_shift_left(assl_bn *a) {
    uint32_t hi = 0;
    if (bn_fit(a, a->len + 1)) return -1;
    for (size_t j = 0; j < a->len; j++) {
        uint32_t nxt = a->d[j] >> 31;
        a->d[j] = (a->d[j] << 1) | hi;
        hi = nxt;
    }
    if (hi) a->d[a->len++] = 1;
    return 0;
}

static int bn_set_bit_of(const assl_bn *a, size_t i) {
    return i < 32 * a->len ? (int)((a->d[i >> 5] >> (i & 31)) & 1) : 0;
}

int assl_bn_reserve(assl_bn *a, size_t n) {
    return bn_fit(a, n);
}

void assl_bn_init(assl_bn *a) {
    a->cap = 0;
    a->len = 0;
    a->d = NULL;
}

void assl_bn_free(assl_bn *a) {
    free(a->d);
    assl_bn_init(a);
}

void assl_bn_zero(assl_bn *a) {
    if (!a->d) {
        if (bn_fit(a, 1)) return;
    }
    a->d[0] = 0;
    a->len = 1;
}

int assl_bn_set_u32(assl_bn *a, uint32_t v) {
    if (bn_fit(a, 1)) return -1;
    a->d[0] = v;
    a->len = 1;
    return 0;
}

int assl_bn_set_u64(assl_bn *a, uint64_t v) {
    if (bn_fit(a, 2)) return -1;
    a->d[0] = (uint32_t)v;
    a->d[1] = (uint32_t)(v >> 32);
    a->len = 2;
    bn_trim(a);
    return 0;
}

int assl_bn_copy(assl_bn *dst, const assl_bn *src) {
    if (dst == src) return 0;
    if (bn_fit(dst, src->len)) return -1;
    memcpy(dst->d, src->d, src->len * sizeof(uint32_t));
    dst->len = src->len;
    return 0;
}

int assl_bn_from_bin(assl_bn *a, const uint8_t *bin, size_t len) {
    size_t nlimbs = (len + 3) / 4;
    if (bn_fit(a, nlimbs)) return -1;
    for (size_t i = 0; i < nlimbs; i++) a->d[i] = 0;
    a->len = nlimbs ? nlimbs : 1;
    for (size_t i = 0; i < len; i++) {
        size_t k = len - 1 - i;
        a->d[k / 4] |= (uint32_t)bin[i] << (8 * (k % 4));
    }
    bn_trim(a);
    return 0;
}

int assl_bn_to_bin(const assl_bn *a, uint8_t *bin, size_t len) {
    size_t want = assl_bn_bytes(a);
    if (len < want) return -1;
    memset(bin, 0, len);
    for (size_t k = 0; k < want; k++) {
        bin[len - 1 - k] = (uint8_t)((a->d[k / 4] >> (8 * (k % 4))) & 0xff);
    }
    return 0;
}

static int bn_hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int assl_bn_from_hex(assl_bn *a, const char *hex) {
    size_t n = strlen(hex);
    uint8_t *buf;
    int r = -1;
    size_t nb, idx;
    if (n > 1 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex += 2;
        n -= 2;
    }
    if (n == 0) {
        assl_bn_zero(a);
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        if (bn_hexval(hex[i]) < 0) return -1;
    }
    nb = (n + 1) / 2;
    buf = malloc(nb);
    if (!buf) return -1;
    idx = nb;
    for (size_t i = n, lo = (n & 1) ? 3 : 2; i >= lo; i -= 2) {
        buf[--idx] = (uint8_t)(bn_hexval(hex[i - 1]) | (bn_hexval(hex[i - 2]) << 4));
    }
    if (n & 1) buf[0] = (uint8_t)bn_hexval(hex[0]);
    r = assl_bn_from_bin(a, buf, nb);
    free(buf);
    return r;
}

int assl_bn_to_hex(const assl_bn *a, char *buf, size_t buflen) {
    static const char dg[] = "0123456789abcdef";
    size_t want = assl_bn_bytes(a);
    size_t t = want, n = 0;
    while (t > 0) {
        uint8_t b = (uint8_t)((a->d[(t - 1) / 4] >> (8 * ((t - 1) % 4))) & 0xff);
        if (b) break;
        t--;
    }
    if (t == 0) {
        if (buflen < 2) return -1;
        buf[0] = '0';
        buf[1] = 0;
        return 1;
    }
    if (buflen < 2 * t + 1) return -1;
    {
        uint8_t tb = (uint8_t)((a->d[(t - 1) / 4] >> (8 * ((t - 1) % 4))) & 0xff);
        if (tb >> 4) buf[n++] = dg[tb >> 4];
        buf[n++] = dg[tb & 15];
    }
    for (size_t j = 1; j < t; j++) {
        uint8_t b = (uint8_t)((a->d[(t - 1 - j) / 4] >> (8 * ((t - 1 - j) % 4))) & 0xff);
        buf[n++] = dg[b >> 4];
        buf[n++] = dg[b & 15];
    }
    buf[n] = 0;
    return (int)n;
}

size_t assl_bn_bitlen(const assl_bn *a) {
    uint32_t top;
    size_t i;
    if (a->len == 0) return 0;
    for (i = a->len; i > 0; i--) {
        if (a->d[i - 1]) break;
    }
    if (i == 0) return 0;
    top = a->d[i - 1];
    return 32 * (i - 1) + (size_t)(32 - __builtin_clz(top));
}

size_t assl_bn_bytes(const assl_bn *a) {
    size_t b = (assl_bn_bitlen(a) + 7) / 8;
    return b ? b : 1;
}

int assl_bn_is_zero(const assl_bn *a) {
    return a->len == 0 || (a->len == 1 && a->d[0] == 0);
}

int assl_bn_is_one(const assl_bn *a) {
    return a->len == 1 && a->d[0] == 1;
}

int assl_bn_is_odd(const assl_bn *a) {
    return a->len > 0 && (a->d[0] & 1);
}

int assl_bn_cmp(const assl_bn *a, const assl_bn *b) {
    size_t n = a->len > b->len ? a->len : b->len;
    for (size_t i = n; i > 0; i--) {
        uint32_t ai = bn_limb(a, i - 1);
        uint32_t bi = bn_limb(b, i - 1);
        if (ai != bi) return ai < bi ? -1 : 1;
    }
    return 0;
}

int assl_bn_add(const assl_bn *a, const assl_bn *b, assl_bn *c) {
    assl_bn t;
    size_t n = (a->len > b->len ? a->len : b->len) + 1;
    uint32_t carry = 0;
    int r = -1;
    assl_bn_init(&t);
    if (bn_fit(&t, n)) goto out;
    memset(t.d, 0, n * sizeof(uint32_t));
    for (size_t i = 0; i < n - 1; i++) {
        uint64_t s = (uint64_t)bn_limb(a, i) + bn_limb(b, i) + carry;
        t.d[i] = (uint32_t)s;
        carry = (uint32_t)(s >> 32);
    }
    t.len = n;
    if (carry) {
        t.d[n - 1] = carry;
    } else {
        t.len = n - 1;
    }
    bn_trim(&t);
    if (assl_bn_copy(c, &t)) goto out;
    r = 0;
out:
    assl_bn_free(&t);
    return r;
}

int assl_bn_sub(const assl_bn *a, const assl_bn *b, assl_bn *c) {
    assl_bn t;
    uint32_t borrow = 0;
    int r = -1;
    assl_bn_init(&t);
    if (bn_fit(&t, a->len)) goto out;
    for (size_t i = 0; i < a->len; i++) {
        uint64_t d = (uint64_t)bn_limb(a, i) - bn_limb(b, i) - borrow;
        t.d[i] = (uint32_t)d;
        borrow = (uint32_t)((d >> 32) & 1);
    }
    t.len = a->len;
    bn_trim(&t);
    if (assl_bn_copy(c, &t)) goto out;
    r = 0;
out:
    assl_bn_free(&t);
    return r;
}

int assl_bn_mul_word(const assl_bn *a, uint32_t w, assl_bn *c) {
    assl_bn t;
    uint32_t carry = 0;
    int r = -1;
    assl_bn_init(&t);
    if (bn_fit(&t, a->len + 1)) goto out;
    memset(t.d, 0, (a->len + 1) * sizeof(uint32_t));
    for (size_t i = 0; i < a->len; i++) {
        uint64_t s = (uint64_t)a->d[i] * w + carry;
        t.d[i] = (uint32_t)s;
        carry = (uint32_t)(s >> 32);
    }
    t.len = a->len;
    if (carry) t.d[t.len++] = carry;
    bn_trim(&t);
    if (assl_bn_copy(c, &t)) goto out;
    r = 0;
out:
    assl_bn_free(&t);
    return r;
}

int assl_bn_mul(const assl_bn *a, const assl_bn *b, assl_bn *c) {
    assl_bn t;
    int r = -1;
    size_t n = a->len + b->len;
    assl_bn_init(&t);
    if (bn_fit(&t, n)) goto out;
    memset(t.d, 0, n * sizeof(uint32_t));
    t.len = n;
    for (size_t i = 0; i < a->len; i++) {
        uint32_t ai = a->d[i];
        uint32_t carry = 0;
        for (size_t j = 0; j < b->len; j++) {
            uint64_t s = (uint64_t)ai * b->d[j] + t.d[i + j] + carry;
            t.d[i + j] = (uint32_t)s;
            carry = (uint32_t)(s >> 32);
        }
        size_t k = i + b->len;
        while (carry) {
            uint64_t s = (uint64_t)t.d[k] + carry;
            t.d[k] = (uint32_t)s;
            carry = (uint32_t)(s >> 32);
            k++;
        }
    }
    bn_trim(&t);
    if (assl_bn_copy(c, &t)) goto out;
    r = 0;
out:
    assl_bn_free(&t);
    return r;
}

int assl_bn_div(const assl_bn *a, const assl_bn *b, assl_bn *q, assl_bn *r) {
    assl_bn Q, R;
    size_t bits;
    int rv = -1;
    if (assl_bn_is_zero(b)) return -1;
    assl_bn_init(&Q);
    assl_bn_init(&R);
    if (q) {
        if (bn_fit(&Q, a->len + 2)) goto out;
        memset(Q.d, 0, (a->len + 2) * sizeof(uint32_t));
    }
    if (bn_fit(&R, a->len + 2)) goto out;
    memset(R.d, 0, (a->len + 2) * sizeof(uint32_t));
    R.len = 1;
    bits = assl_bn_bitlen(a);
    if (assl_bn_cmp(a, b) < 0) {
        if (assl_bn_copy(r, a)) goto out;
        if (q) {
            assl_bn_zero(&Q);
            if (assl_bn_copy(q, &Q)) goto out;
        }
        rv = 0;
        goto out;
    }
    for (size_t i = bits; i > 0; i--) {
        size_t bit = i - 1;
        if (bn_shift_left(&R)) goto out;
        R.d[0] |= (uint32_t)bn_set_bit_of(a, bit);
        if (assl_bn_cmp(&R, b) >= 0) {
            if (assl_bn_sub(&R, b, &R)) goto out;
            if (q) bn_set_bit(&Q, bit);
        }
    }
    if (q && assl_bn_copy(q, &Q)) goto out;
    if (assl_bn_copy(r, &R)) goto out;
    rv = 0;
out:
    assl_bn_free(&Q);
    assl_bn_free(&R);
    return rv;
}

int assl_bn_mod(const assl_bn *a, const assl_bn *m, assl_bn *r) {
    if (assl_bn_is_zero(m)) return -1;
    if (assl_bn_cmp(a, m) < 0) return assl_bn_copy(r, a);
    return assl_bn_div(a, m, NULL, r);
}

int assl_bn_modadd(const assl_bn *a, const assl_bn *b, const assl_bn *m, assl_bn *r) {
    assl_bn t;
    int rv = -1;
    assl_bn_init(&t);
    if (assl_bn_add(a, b, &t)) goto out;
    if (assl_bn_cmp(&t, m) >= 0) {
        if (assl_bn_sub(&t, m, &t)) goto out;
    }
    if (assl_bn_copy(r, &t)) goto out;
    rv = 0;
out:
    assl_bn_free(&t);
    return rv;
}

int assl_bn_modsub(const assl_bn *a, const assl_bn *b, const assl_bn *m, assl_bn *r) {
    assl_bn t;
    int rv = -1;
    assl_bn_init(&t);
    if (assl_bn_cmp(a, b) >= 0) {
        if (assl_bn_sub(a, b, &t)) goto out;
    } else {
        assl_bn d;
        assl_bn_init(&d);
        if (assl_bn_sub(b, a, &d)) {
            assl_bn_free(&d);
            goto out;
        }
        if (assl_bn_sub(m, &d, &t)) {
            assl_bn_free(&d);
            goto out;
        }
        assl_bn_free(&d);
    }
    if (assl_bn_copy(r, &t)) goto out;
    rv = 0;
out:
    assl_bn_free(&t);
    return rv;
}

static uint32_t mont_n0inv(uint32_t v) {
    uint32_t x = 1;
    for (int i = 0; i < 5; i++) x *= 2u - v * x;
    return (uint32_t)(0u - x);
}

static int mont_setup(assl_mont *mo, const assl_bn *m) {
    assl_bn R, R2;
    int rv = -1;
    mo->m = m;
    mo->n = m->len;
    mo->n0inv = mont_n0inv(m->d[0]);
    assl_bn_init(&R);
    assl_bn_init(&R2);
    assl_bn_init(&mo->Rmod);
    assl_bn_init(&mo->R2mod);
    if (bn_fit(&R, mo->n + 1)) goto out;
    memset(R.d, 0, (mo->n + 1) * sizeof(uint32_t));
    R.d[mo->n] = 1;
    R.len = mo->n + 1;
    if (assl_bn_mod(&R, m, &mo->Rmod)) goto out;
    if (bn_fit(&R2, 2 * mo->n + 1)) goto out;
    memset(R2.d, 0, (2 * mo->n + 1) * sizeof(uint32_t));
    R2.d[2 * mo->n] = 1;
    R2.len = 2 * mo->n + 1;
    if (assl_bn_mod(&R2, m, &mo->R2mod)) goto out;
    rv = 0;
out:
    assl_bn_free(&R);
    assl_bn_free(&R2);
    return rv;
}

static void mont_clear(assl_mont *mo) {
    assl_bn_free(&mo->Rmod);
    assl_bn_free(&mo->R2mod);
}

static int mont_mul(const assl_mont *mo, const assl_bn *A, const assl_bn *B, assl_bn *out) {
    const size_t n = mo->n;
    const uint32_t *m = mo->m->d;
    uint32_t *t;
    assl_bn res;
    size_t sz = 2 * n + 2;
    int rv = -1;
    if (n > 256) return -1;
    t = malloc(sz * sizeof(uint32_t));
    if (!t) return -1;
    memset(t, 0, sz * sizeof(uint32_t));
    for (size_t i = 0; i < n; i++) {
        uint32_t ai = bn_limb(A, i);
        uint32_t carry = 0;
        for (size_t j = 0; j < n; j++) {
            uint64_t s = (uint64_t)ai * bn_limb(B, j) + t[i + j] + carry;
            t[i + j] = (uint32_t)s;
            carry = (uint32_t)(s >> 32);
        }
        size_t k = i + n;
        while (carry) {
            uint64_t s = (uint64_t)t[k] + carry;
            t[k] = (uint32_t)s;
            carry = (uint32_t)(s >> 32);
            k++;
        }
    }
    for (size_t i = 0; i < n; i++) {
        uint32_t u = t[0] * mo->n0inv;
        uint64_t carry = 0;
        for (size_t j = 0; j < n; j++) {
            uint64_t s = (uint64_t)u * m[j] + t[j] + carry;
            t[j] = (uint32_t)s;
            carry = s >> 32;
        }
        {
            size_t k = n;
            while (carry) {
                uint64_t s = (uint64_t)t[k] + carry;
                t[k] = (uint32_t)s;
                carry = s >> 32;
                k++;
            }
        }
        for (size_t j = 0; j < sz - 1; j++) t[j] = t[j + 1];
        t[sz - 1] = 0;
    }
    assl_bn_init(&res);
    if (bn_fit(&res, n + 1)) goto out;
    for (size_t j = 0; j <= n; j++) res.d[j] = t[j];
    res.len = n + 1;
    bn_trim(&res);
    while (assl_bn_cmp(&res, mo->m) >= 0) {
        if (assl_bn_sub(&res, mo->m, &res)) goto out;
    }
    if (assl_bn_copy(out, &res)) goto out;
    rv = 0;
out:
    assl_bn_free(&res);
    free(t);
    return rv;
}

int assl_bn_modmul(const assl_bn *a, const assl_bn *b, const assl_bn *m, assl_bn *r) {
    assl_mont mo = {0};
    assl_bn ma, mb, one = {0};
    int rv = -1;
    if (assl_bn_is_zero(m) || !assl_bn_is_odd(m)) return -1;
    assl_bn_init(&ma);
    assl_bn_init(&mb);
    if (assl_bn_set_u32(&one, 1)) goto out;
    if (assl_bn_cmp(a, m) >= 0) {
        if (assl_bn_mod(a, m, &ma)) goto out;
    } else if (assl_bn_copy(&ma, a)) {
        goto out;
    }
    if (assl_bn_cmp(b, m) >= 0) {
        if (assl_bn_mod(b, m, &mb)) goto out;
    } else if (assl_bn_copy(&mb, b)) {
        goto out;
    }
    if (mont_setup(&mo, m)) goto out;
    if (mont_mul(&mo, &ma, &mo.R2mod, &ma)) goto out;
    if (mont_mul(&mo, &mb, &mo.R2mod, &mb)) goto out;
    if (mont_mul(&mo, &ma, &mb, &ma)) goto out;
    if (mont_mul(&mo, &ma, &one, r)) goto out;
    rv = 0;
out:
    mont_clear(&mo);
    assl_bn_free(&ma);
    assl_bn_free(&mb);
    assl_bn_free(&one);
    return rv;
}

int assl_bn_modpow(const assl_bn *base, const assl_bn *e, const assl_bn *m, assl_bn *r) {
    assl_mont mo = {0};
    assl_bn a_, res, bs, one;
    size_t bits;
    int rv = -1;
    if (assl_bn_is_zero(m) || !assl_bn_is_odd(m)) return -1;
    assl_bn_init(&a_);
    assl_bn_init(&res);
    assl_bn_init(&bs);
    assl_bn_init(&one);
    if (assl_bn_set_u32(&one, 1)) goto out;
    if (assl_bn_cmp(base, m) >= 0) {
        if (assl_bn_mod(base, m, &bs)) goto out;
    } else if (assl_bn_copy(&bs, base)) {
        goto out;
    }
    if (mont_setup(&mo, m)) goto out;
    if (mont_mul(&mo, &bs, &mo.R2mod, &a_)) goto out;
    if (assl_bn_copy(&res, &mo.Rmod)) goto out;
    bits = assl_bn_bitlen(e);
    for (size_t i = bits; i > 0; i--) {
        size_t bit = i - 1;
        if (mont_mul(&mo, &res, &res, &res)) goto out;
        if (bn_set_bit_of(e, bit)) {
            if (mont_mul(&mo, &res, &a_, &res)) goto out;
        }
    }
    if (mont_mul(&mo, &res, &one, r)) goto out;
    rv = 0;
out:
    mont_clear(&mo);
    assl_bn_free(&a_);
    assl_bn_free(&res);
    assl_bn_free(&bs);
    assl_bn_free(&one);
    return rv;
}

int assl_bn_modinv(const assl_bn *a, const assl_bn *m, assl_bn *r) {
    assl_bn a0, b0, x0, x1, q, rem, prod, nx;
    int rv = -1;
    if (assl_bn_is_zero(m) || assl_bn_is_zero(a)) return -1;
    assl_bn_init(&a0);
    assl_bn_init(&b0);
    assl_bn_init(&x0);
    assl_bn_init(&x1);
    assl_bn_init(&q);
    assl_bn_init(&rem);
    assl_bn_init(&prod);
    assl_bn_init(&nx);
    if (assl_bn_mod(a, m, &a0)) goto out;
    if (assl_bn_copy(&b0, m)) goto out;
    if (assl_bn_set_u32(&x0, 1)) goto out;
    if (assl_bn_set_u32(&x1, 0)) goto out;
    while (!assl_bn_is_zero(&b0)) {
        if (assl_bn_div(&a0, &b0, &q, &rem)) goto out;
        if (assl_bn_copy(&a0, &b0)) goto out;
        if (assl_bn_copy(&b0, &rem)) goto out;
        if (assl_bn_mul(&q, &x1, &prod)) goto out;
        if (assl_bn_mod(&prod, m, &prod)) goto out;
        if (assl_bn_modsub(&x0, &prod, m, &nx)) goto out;
        if (assl_bn_copy(&x0, &x1)) goto out;
        if (assl_bn_copy(&x1, &nx)) goto out;
    }
    if (!assl_bn_is_one(&a0)) {
        rv = -1;
        goto out;
    }
    if (assl_bn_mod(&x0, m, r)) goto out;
    rv = 0;
out:
    assl_bn_free(&a0);
    assl_bn_free(&b0);
    assl_bn_free(&x0);
    assl_bn_free(&x1);
    assl_bn_free(&q);
    assl_bn_free(&rem);
    assl_bn_free(&prod);
    assl_bn_free(&nx);
    return rv;
}

int assl_bn_gcd(const assl_bn *a, const assl_bn *b, assl_bn *r) {
    assl_bn x, y, rem;
    int rv = -1;
    assl_bn_init(&x);
    assl_bn_init(&y);
    assl_bn_init(&rem);
    if (assl_bn_copy(&x, a)) goto out;
    if (assl_bn_copy(&y, b)) goto out;
    while (!assl_bn_is_zero(&y)) {
        if (assl_bn_mod(&x, &y, &rem)) goto out;
        if (assl_bn_copy(&x, &y)) goto out;
        if (assl_bn_copy(&y, &rem)) goto out;
    }
    if (assl_bn_copy(r, &x)) goto out;
    rv = 0;
out:
    assl_bn_free(&x);
assl_bn_free(&y);
    assl_bn_free(&rem);
    return rv;
}
int assl_bn_rand(assl_bn *r, unsigned bits) {
    size_t nb = (bits + 7) / 8;
    uint8_t *buf = malloc(nb ? nb : 1);
    if (!buf) return -1;
    if (assl_bn_reserve(r, (bits + 31) / 32)) { free(buf); return -1; }
    if (assl_rng_bytes_checked(buf, nb)) { free(buf); return -1; }
    if (assl_bn_from_bin(r, buf, nb)) { free(buf); return -1; }
    free(buf);
    if (bits == 0) return assl_bn_set_u32(r, 0);
    size_t rem = bits & 7;
    uint32_t *d = r->d;
    size_t top = r->len - 1;
    if (rem) d[top] &= (uint32_t)(((uint64_t)1 << rem) - 1);
    d[top] |= (uint32_t)(1u << ((bits - 1) % 32));
    return 0;
}


static int ct_mont_mul(const assl_mont *mo, const assl_bn *A, const assl_bn *B,
                       uint32_t *out, size_t outlen) {
    const size_t n = mo->n;
    const uint32_t *m = mo->m->d;
    uint32_t *t;
    size_t sz = 2 * n + 3;
    int rv = -1;
    if (n == 0 || outlen < n) return -1;
    t = malloc(sz * sizeof(uint32_t));
    if (!t) return -1;
    memset(t, 0, sz * sizeof(uint32_t));
    for (size_t i = 0; i < n; i++) {
        uint32_t ai = bn_limb(A, i);
        uint64_t carry = 0;
        for (size_t j = 0; j < n; j++) {
            uint64_t s = (uint64_t)ai * bn_limb(B, j) + t[i + j] + carry;
            t[i + j] = (uint32_t)s;
            carry = s >> 32;
        }
        for (size_t k = 0; k < 2; k++) {
            uint64_t s = (uint64_t)t[i + n + k] + carry;
            t[i + n + k] = (uint32_t)s;
            carry = s >> 32;
        }
    }
    for (size_t i = 0; i < n; i++) {
        uint32_t u = t[0] * mo->n0inv;
        uint64_t carry = 0;
        for (size_t j = 0; j < n; j++) {
            uint64_t s = (uint64_t)u * m[j] + t[j] + carry;
            t[j] = (uint32_t)s;
            carry = s >> 32;
        }
        for (size_t k = 0; k < n + 2; k++) {
            uint64_t s = (uint64_t)t[n + k] + carry;
            t[n + k] = (uint32_t)s;
            carry = s >> 32;
        }
        for (size_t j = 0; j < sz - 1; j++) t[j] = t[j + 1];
        t[sz - 1] = 0;
    }
    {
        uint32_t *r = t;                
        uint32_t *rsub = t + (n + 1);   
        uint32_t borrow = 0;
        for (size_t j = 0; j <= n; j++) {
            uint64_t d = (uint64_t)r[j] - bn_limb(mo->m, j) - borrow;
            rsub[j] = (uint32_t)d;
            borrow = (uint32_t)((d >> 32) & 1);
        }
        uint32_t keep = 0u - borrow;    
        for (size_t j = 0; j < n; j++)
            out[j] = (r[j] & keep) | (rsub[j] & ~keep);
    }
    rv = 0;
    free(t);
    return rv;
}

int assl_bn_modmul_ct(const assl_bn *a, const assl_bn *b, const assl_bn *m,
                      assl_bn *r) {
    assl_mont mo = {0};
    assl_bn ma, mb, one = {0};
    uint32_t *t;
    size_t n;
    int rv = -1;
    if (assl_bn_is_zero(m) || !assl_bn_is_odd(m)) return -1;
    if (assl_bn_cmp(a, m) >= 0 || assl_bn_cmp(b, m) >= 0) return -1;
    n = m->len;
    t = malloc(n * sizeof(uint32_t));
    if (!t) return -1;
    if (bn_fit(r, n)) goto out;
    assl_bn_init(&ma);
    assl_bn_init(&mb);
    if (assl_bn_copy(&ma, a) || assl_bn_copy(&mb, b)) goto out;
    if (bn_fit(&ma, n) || bn_fit(&mb, n)) goto out;
    if (assl_bn_set_u32(&one, 1)) goto out;
    if (mont_setup(&mo, m)) goto out;
    if (ct_mont_mul(&mo, &ma, &mo.R2mod, ma.d, n)) goto out;
    ma.len = n;
    if (ct_mont_mul(&mo, &mb, &mo.R2mod, mb.d, n)) goto out;
    mb.len = n;
    if (ct_mont_mul(&mo, &ma, &mb, ma.d, n)) goto out;
    if (ct_mont_mul(&mo, &ma, &one, t, n)) goto out;
    memcpy(r->d, t, n * sizeof(uint32_t));
    r->len = n;
    rv = 0;
out:
    mont_clear(&mo);
    assl_bn_free(&ma);
    assl_bn_free(&mb);
    assl_bn_free(&one);
    free(t);
    return rv;
}

int assl_bn_modpow_ct(const assl_bn *base, const assl_bn *exp, const assl_bn *m,
                      assl_bn *r) {
    assl_mont mo = {0};
    assl_bn bs, a_, res, one = {0};
    uint32_t *t0, *t1;
    size_t n, bits;
    int rv = -1;
    if (assl_bn_is_zero(m) || !assl_bn_is_odd(m)) return -1;
    n = m->len;
    bits = 32 * n;
    if (assl_bn_bitlen(exp) > bits) return -1;
    t0 = malloc(n * sizeof(uint32_t));
    t1 = malloc(n * sizeof(uint32_t));
    if (!t0 || !t1) { free(t0); free(t1); return -1; }
    if (bn_fit(r, n)) { free(t0); free(t1); return -1; }
    assl_bn_init(&bs);
    assl_bn_init(&a_);
    assl_bn_init(&res);
    if (assl_bn_cmp(base, m) >= 0) {
        if (assl_bn_mod(base, m, &bs)) goto out;
    } else if (assl_bn_copy(&bs, base)) {
        goto out;
    }
    if (bn_fit(&bs, n)) goto out;
    if (assl_bn_set_u32(&one, 1)) goto out;
    if (bn_fit(&a_, n) || bn_fit(&res, n)) goto out;
    if (mont_setup(&mo, m)) goto out;
    if (ct_mont_mul(&mo, &bs, &mo.R2mod, a_.d, n)) goto out;
    a_.len = n;
    for (size_t j = 0; j < n; j++) res.d[j] = bn_limb(&mo.Rmod, j);
    res.len = n;
    for (size_t i = bits; i > 0; i--) {
        uint32_t bit = (uint32_t)bn_set_bit_of(exp, i - 1);
        if (ct_mont_mul(&mo, &res, &res, t0, n)) goto out;
        for (size_t j = 0; j < n; j++) res.d[j] = t0[j];   
        if (ct_mont_mul(&mo, &res, &a_, t1, n)) goto out;
        uint32_t mask = 0u - bit;   
        for (size_t j = 0; j < n; j++)
            res.d[j] = (t0[j] & ~mask) | (t1[j] & mask);
    }
    if (ct_mont_mul(&mo, &res, &one, t0, n)) goto out;
    memcpy(r->d, t0, n * sizeof(uint32_t));
    r->len = n;
    rv = 0;
out:
    mont_clear(&mo);
    assl_bn_free(&bs);
    assl_bn_free(&a_);
    assl_bn_free(&res);
    assl_bn_free(&one);
    free(t0);
    free(t1);
    return rv;
}

int assl_bn_modadd_ct(const assl_bn *a, const assl_bn *b, const assl_bn *m,
                      assl_bn *r) {
    size_t n = m->len;
    uint32_t *t, *u;
    int rv = -1;
    if (assl_bn_is_zero(m) || !assl_bn_is_odd(m)) return -1;
    if (assl_bn_cmp(a, m) >= 0 || assl_bn_cmp(b, m) >= 0) return -1;
    t = malloc((n + 1) * sizeof(uint32_t));
    u = malloc((n + 1) * sizeof(uint32_t));
    if (!t || !u) { free(t); free(u); return -1; }
    if (bn_fit(r, n)) { free(t); free(u); return -1; }
    {
        uint32_t carry = 0;
        for (size_t j = 0; j < n; j++) {
            uint64_t s = (uint64_t)bn_limb(a, j) + bn_limb(b, j) + carry;
            t[j] = (uint32_t)s;
            carry = (uint32_t)(s >> 32);
        }
        t[n] = carry;
    }
    {
        uint32_t borrow = 0;
        for (size_t j = 0; j <= n; j++) {
            uint64_t d = (uint64_t)t[j] - bn_limb(m, j) - borrow;
            u[j] = (uint32_t)d;
            borrow = (uint32_t)((d >> 32) & 1);
        }
        uint32_t keep = 0u - borrow;
        for (size_t j = 0; j < n; j++)
            r->d[j] = (t[j] & keep) | (u[j] & ~keep);
        r->len = n;
    }
    rv = 0;
    free(t);
    free(u);
    return rv;
}

int assl_bn_modsub_ct(const assl_bn *a, const assl_bn *b, const assl_bn *m,
                      assl_bn *r) {
    size_t n = m->len;
    uint32_t *ar, *br, *t, *u, *tmp;
    int rv = -1;
    if (assl_bn_is_zero(m) || !assl_bn_is_odd(m)) return -1;
    ar = malloc(n * sizeof(uint32_t));
    br = malloc(n * sizeof(uint32_t));
    t = malloc(n * sizeof(uint32_t));
    u = malloc(n * sizeof(uint32_t));
    tmp = malloc(n * sizeof(uint32_t));
    if (!ar || !br || !t || !u || !tmp) {
        free(ar); free(br); free(t); free(u); free(tmp);
        return -1;
    }
    if (bn_fit(r, n)) { free(ar); free(br); free(t); free(u); free(tmp); return -1; }
    {
        uint32_t borrow = 0;
        for (size_t j = 0; j < n; j++) {
            uint64_t d = (uint64_t)bn_limb(a, j) - bn_limb(m, j) - borrow;
            tmp[j] = (uint32_t)d;
            borrow = (uint32_t)((d >> 32) & 1);
        }
        uint32_t keep = 0u - borrow;
        for (size_t j = 0; j < n; j++)
            ar[j] = (bn_limb(a, j) & keep) | (tmp[j] & ~keep);
    }
    {
        uint32_t borrow = 0;
        for (size_t j = 0; j < n; j++) {
            uint64_t d = (uint64_t)bn_limb(b, j) - bn_limb(m, j) - borrow;
            tmp[j] = (uint32_t)d;
            borrow = (uint32_t)((d >> 32) & 1);
        }
        uint32_t keep = 0u - borrow;
        for (size_t j = 0; j < n; j++)
            br[j] = (bn_limb(b, j) & keep) | (tmp[j] & ~keep);
    }
    {
        uint32_t borrow = 0;
        for (size_t j = 0; j < n; j++) {
            uint64_t d = (uint64_t)ar[j] - br[j] - borrow;
            t[j] = (uint32_t)d;
            borrow = (uint32_t)((d >> 32) & 1);
        }
        uint32_t mask = 0u - borrow;
        uint32_t carry = 0;
        for (size_t j = 0; j < n; j++) {
            uint64_t s = (uint64_t)t[j] + (bn_limb(m, j) & mask) + carry;
            u[j] = (uint32_t)s;
            carry = (uint32_t)(s >> 32);
        }
        for (size_t j = 0; j < n; j++) r->d[j] = u[j];
        r->len = n;
    }
    rv = 0;
    free(ar); free(br); free(t); free(u); free(tmp);
    return rv;
}

int assl_bn_modmuladd_ct(const assl_bn *x, const assl_bn *y, const assl_bn *a,
                         const assl_bn *m, assl_bn *r) {
    size_t n = m->len;
    uint32_t *t, *u;
    size_t sz = 2 * n + 3;
    int rv = -1;
    if (assl_bn_is_zero(m) || !assl_bn_is_odd(m)) return -1;
    if (assl_bn_cmp(x, m) >= 0 || assl_bn_cmp(y, m) >= 0 || assl_bn_cmp(a, m) >= 0)
        return -1;
    t = malloc(sz * sizeof(uint32_t));
    u = malloc((n + 1) * sizeof(uint32_t));
    if (!t || !u) { free(t); free(u); return -1; }
    if (bn_fit(r, n)) { free(t); free(u); return -1; }
    memset(t, 0, sz * sizeof(uint32_t));
    for (size_t i = 0; i < n; i++) {
        uint32_t xi = bn_limb(x, i);
        uint64_t carry = 0;
        for (size_t j = 0; j < n; j++) {
            uint64_t s = (uint64_t)xi * bn_limb(y, j) + t[i + j] + carry;
            t[i + j] = (uint32_t)s;
            carry = s >> 32;
        }
        for (size_t k = 0; k < 2; k++) {
            uint64_t s = (uint64_t)t[i + n + k] + carry;
            t[i + n + k] = (uint32_t)s;
            carry = s >> 32;
        }
    }
    {
        uint32_t carry = 0;
        for (size_t j = 0; j < n; j++) {
            uint64_t s = (uint64_t)t[j] + bn_limb(a, j) + carry;
            t[j] = (uint32_t)s;
            carry = (uint32_t)(s >> 32);
        }
        for (size_t k = 0; k < 2; k++) {
            uint64_t s = (uint64_t)t[n + k] + carry;
            t[n + k] = (uint32_t)s;
            carry = (uint32_t)(s >> 32);
        }
    }
    {
        uint32_t borrow = 0;
        for (size_t j = 0; j <= n; j++) {
            uint64_t d = (uint64_t)t[j] - bn_limb(m, j) - borrow;
            u[j] = (uint32_t)d;
            borrow = (uint32_t)((d >> 32) & 1);
        }
        uint32_t keep = 0u - borrow;
        for (size_t j = 0; j < n; j++)
            r->d[j] = (t[j] & keep) | (u[j] & ~keep);
        r->len = n;
    }
    rv = 0;
    free(t);
    free(u);
    return rv;
}

int assl_bn_to_bin_ct(const assl_bn *a, uint8_t *bin, size_t len) {
    for (size_t k = 0; k < len; k++) {
        uint32_t v = bn_limb(a, k / 4);
        bin[len - 1 - k] = (uint8_t)(v >> (8 * (k % 4)));
    }
    return 0;
}

