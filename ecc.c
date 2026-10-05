#include "asslibc.h"

static const char *P256_P  = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
static const char *P256_N  = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
static const char *P256_GX = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
static const char *P256_GY = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
static const char *P256_B  = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";

static assl_bn P, N, GX, GY, B;
static int p256_ready = 0;

typedef assl_bn fe;
typedef struct { fe x, y, z; } jac;

static int jac_zero(jac *r);
static int jac_dbl(jac *r, const jac *a);
static int jac_add(jac *r, const jac *a, const jac *b);
static int jac_copy(jac *r, const jac *a);
static int jac_to_affine(jac *a, fe *x, fe *y);
static int jac_mul(jac *r, const assl_bn *k, const jac *p);

static int p256_init(void) {
    if (p256_ready) return 0;
    assl_bn_init(&P); assl_bn_init(&N); assl_bn_init(&GX); assl_bn_init(&GY); assl_bn_init(&B);
    if (assl_bn_from_hex(&P, P256_P)) return -1;
    if (assl_bn_from_hex(&N, P256_N)) return -1;
    if (assl_bn_from_hex(&GX, P256_GX)) return -1;
    if (assl_bn_from_hex(&GY, P256_GY)) return -1;
    if (assl_bn_from_hex(&B, P256_B)) return -1;
    p256_ready = 1;
    return 0;
}

int assl_p256_init(void) { return p256_init(); }

static int bn_test_bit(const assl_bn *a, size_t i) {
    if (i >= 32 * a->len) return 0;
    return (a->d[i / 32] >> (i % 32)) & 1;
}

static void bn_release(fe *a, fe *b, fe *c, fe *d, fe *e, fe *f, fe *g, fe *h) {
    if (a) assl_bn_free(a);
    if (b) assl_bn_free(b);
    if (c) assl_bn_free(c);
    if (d) assl_bn_free(d);
    if (e) assl_bn_free(e);
    if (f) assl_bn_free(f);
    if (g) assl_bn_free(g);
    if (h) assl_bn_free(h);
}


static int fe_from_be(fe *r, const uint8_t b[32]) {
    if (assl_bn_from_bin(r, b, 32)) return -1;
    return assl_bn_mod(r, &P, r);
}
static int fe_to_be(const fe *a, uint8_t b[32]) {
    assl_bn t;
    int rv = -1;
    assl_bn_init(&t);
    if (assl_bn_mod(a, &P, &t)) goto out;
    if (assl_bn_to_bin(&t, b, 32)) goto out;
    rv = 0;
out:
    assl_bn_free(&t);
    return rv;
}
static int fe_add(fe *r, const fe *a, const fe *b) { return assl_bn_modadd(a, b, &P, r); }
static int fe_sub(fe *r, const fe *a, const fe *b) { return assl_bn_modsub(a, b, &P, r); }
static int fe_mul(fe *r, const fe *a, const fe *b) { return assl_bn_modmul(a, b, &P, r); }
static int fe_sqr(fe *r, const fe *a) { return assl_bn_modmul(a, a, &P, r); }
static int fe_inv(fe *r, const fe *a) {
    assl_bn two, e;
    int rv = -1;
    assl_bn_init(&two); assl_bn_init(&e);
    if (assl_bn_set_u32(&two, 2)) goto out;
    if (assl_bn_sub(&P, &two, &e)) goto out;
    if (assl_bn_modpow(a, &e, &P, r)) goto out;
    rv = 0;
out:
    assl_bn_free(&two); assl_bn_free(&e);
    return rv;
}
static int fe_is_zero(const fe *a) { return assl_bn_is_zero(a); }
static int fe_cmp(const fe *a, const fe *b) { return assl_bn_cmp(a, b); }

static int jac_g(jac *g) {
    if (p256_init()) return -1;
    if (assl_bn_copy(&g->x, &GX)) return -1;
    if (assl_bn_copy(&g->y, &GY)) return -1;
    return assl_bn_set_u32(&g->z, 1);
}


static int jac_zero(jac *r) {
    if (assl_bn_set_u32(&r->x, 0)) return -1;
    if (assl_bn_set_u32(&r->y, 1)) return -1;
    return assl_bn_set_u32(&r->z, 0);
}

static int jac_dbl(jac *r, const jac *a) {
    fe xx, yy, yyyy, s, m, t, u, w;
    int rv = -1;
    assl_bn_init(&xx); assl_bn_init(&yy); assl_bn_init(&yyyy);
    assl_bn_init(&s); assl_bn_init(&m); assl_bn_init(&t); assl_bn_init(&u); assl_bn_init(&w);
    if (fe_is_zero(&a->z)) { rv = jac_zero(r); goto out; }
    if (fe_mul(&w, &a->y, &a->z)) goto out;
    if (fe_add(&w, &w, &w)) goto out;
    if (fe_sqr(&xx, &a->x)) goto out;              
    if (fe_sqr(&yy, &a->y)) goto out;              
    if (fe_sqr(&yyyy, &yy)) goto out;              
    if (fe_sqr(&t, &a->z)) goto out;               
    if (fe_sqr(&u, &t)) goto out;                  
    if (fe_add(&t, &a->x, &yy)) goto out;
    if (fe_sqr(&t, &t)) goto out;
    if (fe_sub(&t, &t, &xx)) goto out;
    if (fe_sub(&t, &t, &yyyy)) goto out;
    if (fe_add(&s, &t, &t)) goto out;
    if (fe_sub(&t, &xx, &u)) goto out;      
    if (fe_add(&m, &t, &t)) goto out;       
    if (fe_add(&m, &m, &t)) goto out;       
    if (fe_sqr(&t, &m)) goto out;
    if (fe_sub(&t, &t, &s)) goto out;
    if (fe_sub(&t, &t, &s)) goto out;
    if (assl_bn_copy(&r->x, &t)) goto out;
    if (fe_sub(&u, &s, &t)) goto out;
    if (fe_mul(&u, &m, &u)) goto out;
    if (fe_add(&t, &yyyy, &yyyy)) goto out;
    if (fe_add(&t, &t, &t)) goto out;
    if (fe_add(&t, &t, &t)) goto out;              
    if (fe_sub(&u, &u, &t)) goto out;
    if (assl_bn_copy(&r->y, &u)) goto out;
    rv = assl_bn_copy(&r->z, &w);
out:
    bn_release(&xx, &yy, &yyyy, &s, &m, &t, &u, &w);
    return rv;
}

static int jac_add(jac *r, const jac *a, const jac *b) {
    fe z1z1, z2z2, u1, u2, s1, s2, h, hh, hhh, v, rr_, t, q;
    int rv = -1;
    assl_bn_init(&z1z1); assl_bn_init(&z2z2); assl_bn_init(&u1); assl_bn_init(&u2);
    assl_bn_init(&s1); assl_bn_init(&s2); assl_bn_init(&h); assl_bn_init(&hh);
    assl_bn_init(&hhh); assl_bn_init(&v); assl_bn_init(&rr_); assl_bn_init(&t); assl_bn_init(&q);
    if (fe_is_zero(&a->z)) {
        rv = jac_copy(r, b); goto out;
    }
    if (fe_is_zero(&b->z)) {
        rv = jac_copy(r, a); goto out;
    }
    if (fe_sqr(&z1z1, &a->z)) goto out;
    if (fe_sqr(&z2z2, &b->z)) goto out;
    if (fe_mul(&u1, &a->x, &z2z2)) goto out;
    if (fe_mul(&u2, &b->x, &z1z1)) goto out;
    if (fe_mul(&t, &b->z, &z2z2)) goto out;
    if (fe_mul(&s1, &a->y, &t)) goto out;
    if (fe_mul(&t, &a->z, &z1z1)) goto out;
    if (fe_mul(&s2, &b->y, &t)) goto out;
    if (fe_cmp(&u1, &u2) == 0) {
        if (fe_cmp(&s1, &s2) == 0) rv = jac_dbl(r, a);
        else rv = jac_zero(r);
        goto out;
    }
    if (fe_sub(&h, &u2, &u1)) goto out;
    if (fe_sub(&rr_, &s2, &s1)) goto out;
    if (fe_sqr(&hh, &h)) goto out;
    if (fe_mul(&hhh, &h, &hh)) goto out;
    if (fe_mul(&v, &u1, &hh)) goto out;
    if (fe_sqr(&t, &rr_)) goto out;
    if (fe_sub(&t, &t, &hhh)) goto out;
    if (fe_sub(&t, &t, &v)) goto out;
    if (fe_sub(&t, &t, &v)) goto out;
    if (assl_bn_copy(&r->x, &t)) goto out;
    if (fe_sub(&q, &v, &t)) goto out;
    if (fe_mul(&q, &rr_, &q)) goto out;
    if (fe_mul(&t, &s1, &hhh)) goto out;
    if (fe_sub(&q, &q, &t)) goto out;
    if (assl_bn_copy(&r->y, &q)) goto out;
    if (fe_mul(&t, &a->z, &b->z)) goto out;
    if (fe_mul(&t, &t, &h)) goto out;
    rv = assl_bn_copy(&r->z, &t);
out:
    bn_release(&z1z1, &z2z2, &u1, &u2, &s1, &s2, &h, &hh);
    bn_release(&hhh, &v, &rr_, &t, &q, NULL, NULL, NULL);
    return rv;
}

static int jac_copy(jac *r, const jac *a) {
    if (assl_bn_copy(&r->x, &a->x)) return -1;
    if (assl_bn_copy(&r->y, &a->y)) return -1;
    return assl_bn_copy(&r->z, &a->z);
}

static int jac_to_affine(jac *a, fe *x, fe *y) {
    fe zi, zi2, zi3, t;
    int rv = -1;
    assl_bn_init(&zi); assl_bn_init(&zi2); assl_bn_init(&zi3); assl_bn_init(&t);
    if (fe_is_zero(&a->z)) return -1;
    if (fe_inv(&zi, &a->z)) goto out;
    if (fe_sqr(&zi2, &zi)) goto out;
    if (fe_mul(&zi3, &zi2, &zi)) goto out;
    if (fe_mul(&t, &a->x, &zi2)) goto out;
    if (assl_bn_copy(x, &t)) goto out;
    if (fe_mul(&t, &a->y, &zi3)) goto out;
    rv = assl_bn_copy(y, &t);
out:
    bn_release(&zi, &zi2, &zi3, &t, NULL, NULL, NULL, NULL);
    return rv;
}

static int jac_mul(jac *r, const assl_bn *k, const jac *p) {
    jac acc;
    assl_bn e, one;
    int rv = -1;
    if (p256_init()) return -1;
    assl_bn_init(&acc.x); assl_bn_init(&acc.y); assl_bn_init(&acc.z);
    assl_bn_init(&e); assl_bn_init(&one);
    if (jac_zero(&acc)) goto out;
    if (assl_bn_mod(k, &N, &e)) goto out;
    if (assl_bn_set_u32(&one, 1)) goto out;
    if (assl_bn_is_zero(&e)) {
        rv = jac_zero(r);
        goto out;
    }
    if (assl_bn_cmp(&e, &one) == 0) {
        rv = jac_copy(r, p);
        goto out;
    }
    for (size_t i = assl_bn_bitlen(&e) - 1;; i--) {
        if (jac_dbl(&acc, &acc)) goto out;
        if (bn_test_bit(&e, i)) {
            if (jac_add(&acc, &acc, p)) goto out;
        }
        if (i == 0) break;
    }
    rv = jac_copy(r, &acc);
out:
    bn_release(&acc.x, &acc.y, &acc.z, &e, &one, NULL, NULL, NULL);
    return rv;
}


int assl_p256_point_mul(const uint8_t k[32], const uint8_t pt[64], uint8_t out[64]) {
    p256_init();
    assl_bn kb; jac q, r; fe x, y;
    int rv = -1;
    assl_bn_init(&kb); assl_bn_init(&q.x); assl_bn_init(&q.y); assl_bn_init(&q.z);
    assl_bn_init(&r.x); assl_bn_init(&r.y); assl_bn_init(&r.z);
    assl_bn_init(&x); assl_bn_init(&y);
    if (assl_bn_from_bin(&kb, k, 32)) goto out;
    if (assl_bn_from_bin(&q.x, pt, 32)) goto out;
    if (assl_bn_from_bin(&q.y, pt + 32, 32)) goto out;
    if (assl_bn_set_u32(&q.z, 1)) goto out;
    if (jac_mul(&r, &kb, &q)) goto out;
    if (jac_to_affine(&r, &x, &y)) goto out;
    if (fe_to_be(&x, out)) goto out;
    rv = fe_to_be(&y, out + 32);
out:
    bn_release(&kb, &x, &y, NULL, NULL, NULL, NULL, NULL);
    bn_release(&q.x, &q.y, &q.z, &r.x, &r.y, &r.z, NULL, NULL);
    return rv;
}

int assl_p256_mul_base(const uint8_t k[32], uint8_t out[64]) {
    p256_init();
    assl_bn kb; jac g, r; fe x, y;
    int rv = -1;
    assl_bn_init(&kb); assl_bn_init(&g.x); assl_bn_init(&g.y); assl_bn_init(&g.z);
    assl_bn_init(&r.x); assl_bn_init(&r.y); assl_bn_init(&r.z);
    assl_bn_init(&x); assl_bn_init(&y);
    if (assl_bn_from_bin(&kb, k, 32)) goto out;
    if (jac_g(&g)) goto out;
    if (jac_mul(&r, &kb, &g)) goto out;
    if (jac_to_affine(&r, &x, &y)) goto out;
    if (fe_to_be(&x, out)) goto out;
    rv = fe_to_be(&y, out + 32);
out:
    bn_release(&kb, &x, &y, NULL, NULL, NULL, NULL, NULL);
    bn_release(&g.x, &g.y, &g.z, &r.x, &r.y, &r.z, NULL, NULL);
    return rv;
}

int assl_p256_add_pt(const uint8_t a[64], const uint8_t b[64], uint8_t out[64]) {
    p256_init();
    jac ja, jb, jr; fe x, y;
    int rv = -1;
    assl_bn_init(&ja.x); assl_bn_init(&ja.y); assl_bn_init(&ja.z);
    assl_bn_init(&jb.x); assl_bn_init(&jb.y); assl_bn_init(&jb.z);
    assl_bn_init(&jr.x); assl_bn_init(&jr.y); assl_bn_init(&jr.z);
    assl_bn_init(&x); assl_bn_init(&y);
    if (assl_bn_from_bin(&ja.x, a, 32)) goto out;
    if (assl_bn_from_bin(&ja.y, a + 32, 32)) goto out;
    if (assl_bn_from_bin(&jb.x, b, 32)) goto out;
    if (assl_bn_from_bin(&jb.y, b + 32, 32)) goto out;
    if (assl_bn_set_u32(&ja.z, 1)) goto out;
    if (assl_bn_set_u32(&jb.z, 1)) goto out;
    if (jac_add(&jr, &ja, &jb)) goto out;
    if (jac_to_affine(&jr, &x, &y)) goto out;
    if (fe_to_be(&x, out)) goto out;
    rv = fe_to_be(&y, out + 32);
out:
    bn_release(&x, &y, NULL, NULL, NULL, NULL, NULL, NULL);
    bn_release(&ja.x, &ja.y, &ja.z, &jb.x, &jb.y, &jb.z, NULL, NULL);
    bn_release(&jr.x, &jr.y, &jr.z, NULL, NULL, NULL, NULL, NULL);
    return rv;
}

int assl_p256_ecdh(const uint8_t priv[32], const uint8_t peer[64], uint8_t out[32]) {
    p256_init();
    assl_bn kb; jac q, r; fe x, y;
    int rv = -1;
    assl_bn_init(&kb); assl_bn_init(&q.x); assl_bn_init(&q.y); assl_bn_init(&q.z);
    assl_bn_init(&r.x); assl_bn_init(&r.y); assl_bn_init(&r.z);
    assl_bn_init(&x); assl_bn_init(&y);
    if (assl_bn_from_bin(&kb, priv, 32)) goto out;
    if (assl_bn_from_bin(&q.x, peer, 32)) goto out;
    if (assl_bn_from_bin(&q.y, peer + 32, 32)) goto out;
    if (assl_bn_set_u32(&q.z, 1)) goto out;
    if (jac_mul(&r, &kb, &q)) goto out;
    if (jac_to_affine(&r, &x, &y)) goto out;
    rv = fe_to_be(&x, out);
out:
    bn_release(&kb, &x, &y, NULL, NULL, NULL, NULL, NULL);
    bn_release(&q.x, &q.y, &q.z, &r.x, &r.y, &r.z, NULL, NULL);
    return rv;
}

int assl_p256_keygen(uint8_t d[32], uint8_t q[64]) {
    assl_bn rnd, n;
    assl_bn_init(&rnd); assl_bn_init(&n);
    if (p256_init()) return -1;
    if (!assl_rng_is_secure()) { assl_bn_free(&rnd); assl_bn_free(&n); return -1; }
    for (;;) {
        if (assl_bn_rand(&rnd, 256)) { assl_bn_free(&rnd); assl_bn_free(&n); return -1; }
        if (assl_bn_cmp(&rnd, &N) < 0 && !assl_bn_is_zero(&rnd)) break;
    }
    if (assl_bn_to_bin(&rnd, d, 32)) { assl_bn_free(&rnd); assl_bn_free(&n); return -1; }
    assl_bn_free(&rnd); assl_bn_free(&n);
    return assl_p256_mul_base(d, q);
}

int assl_p256_on_curve(const uint8_t pt[64]) {
    fe x, y, a, t;
    int rv = 0;
    if (p256_init()) return -1;
    assl_bn_init(&x); assl_bn_init(&y); assl_bn_init(&a); assl_bn_init(&t);
    if (fe_from_be(&x, pt)) goto out;
    if (fe_from_be(&y, pt + 32)) goto out;
    if (fe_sqr(&t, &y)) goto out;                    
    if (fe_sqr(&a, &x)) goto out;                    
    if (fe_mul(&a, &a, &x)) goto out;                
    if (fe_sub(&a, &a, &x)) goto out;                
    if (fe_sub(&a, &a, &x)) goto out;
    if (fe_sub(&a, &a, &x)) goto out;
    if (fe_add(&a, &a, &B)) goto out;                
    rv = (fe_cmp(&t, &a) == 0);
out:
    bn_release(&x, &y, &a, &t, NULL, NULL, NULL, NULL);
    return rv;
}


static int rfc6979_k(const uint8_t x[32], const uint8_t h1[32], uint8_t k[32]) {
    uint8_t V[32], K[32], buf[32 + 1 + 32 + 32];
    static const uint8_t zero = 0x00, one = 0x01;
    memset(V, 0x01, 32);
    memset(K, 0x00, 32);
    memcpy(buf, V, 32);
    buf[32] = zero;
    memcpy(buf + 33, x, 32);
    memcpy(buf + 65, h1, 32);
    assl_hmac(ASSL_H_SHA256, K, 32, buf, sizeof buf, K);
    assl_hmac(ASSL_H_SHA256, K, 32, V, 32, V);
    memcpy(buf, V, 32);
    buf[32] = one;
    assl_hmac(ASSL_H_SHA256, K, 32, buf, sizeof buf, K);
    assl_hmac(ASSL_H_SHA256, K, 32, V, 32, V);
    while (1) {
        assl_hmac(ASSL_H_SHA256, K, 32, V, 32, V);
        memcpy(k, V, 32);
        assl_bn t;
        assl_bn_init(&t);
        assl_bn_from_bin(&t, k, 32);
        if (assl_bn_cmp(&t, &N) < 0 && !assl_bn_is_zero(&t)) { assl_bn_free(&t); return 0; }
        assl_bn_free(&t);
        buf[0] = zero;
        assl_hmac(ASSL_H_SHA256, K, 32, buf, 1, K);
        assl_hmac(ASSL_H_SHA256, K, 32, V, 32, V);
    }
}

int assl_p256_sign(const uint8_t d[32], const uint8_t digest[32],
                   uint8_t r[32], uint8_t s[32]) {
    p256_init();
    assl_bn kb, z, rd, rn, sn, kinv, tmp;
    jac G, R;
    fe rx, ry;
    uint8_t kk[32], rxbytes[32];
    int rv = -1;
    assl_bn_init(&kb); assl_bn_init(&z); assl_bn_init(&rd); assl_bn_init(&rn);
    assl_bn_init(&sn); assl_bn_init(&kinv); assl_bn_init(&tmp);
    assl_bn_init(&G.x); assl_bn_init(&G.y); assl_bn_init(&G.z);
    assl_bn_init(&R.x); assl_bn_init(&R.y); assl_bn_init(&R.z);
    assl_bn_init(&rx); assl_bn_init(&ry);
    if (assl_bn_from_bin(&z, digest, 32)) goto out;
    if (assl_bn_mod(&z, &N, &z)) goto out;           
    if (assl_bn_from_bin(&kb, d, 32)) goto out;
    if (assl_bn_mod(&kb, &N, &kb)) goto out;
    if (jac_g(&G)) goto out;
    for (;;) {
        if (rfc6979_k(d, digest, kk)) goto out;
        if (assl_bn_from_bin(&kinv, kk, 32)) goto out;
        if (assl_bn_cmp(&kinv, &N) >= 0 || assl_bn_is_zero(&kinv)) continue;
        if (jac_mul(&R, &kinv, &G)) goto out;        
        if (jac_to_affine(&R, &rx, &ry)) goto out;
        if (fe_to_be(&rx, rxbytes)) goto out;
        if (assl_bn_from_bin(&rd, rxbytes, 32)) goto out;
        if (assl_bn_mod(&rd, &N, &rd)) goto out;     
        if (assl_bn_is_zero(&rd)) continue;
        if (assl_bn_modinv(&kinv, &N, &kinv)) goto out;  
        if (assl_bn_modmul(&rd, &kb, &N, &tmp)) goto out; 
        if (assl_bn_modadd(&tmp, &z, &N, &tmp)) goto out;
        if (assl_bn_modmul(&kinv, &tmp, &N, &sn)) goto out; 
        if (assl_bn_is_zero(&sn)) continue;
        break;
    }
    if (assl_bn_to_bin(&rd, r, 32)) goto out;
    rv = assl_bn_to_bin(&sn, s, 32);
out:
    bn_release(&kb, &z, &rd, &rn, NULL, NULL, NULL, NULL);
    bn_release(&sn, &kinv, &tmp, NULL, NULL, NULL, NULL, NULL);
    bn_release(&G.x, &G.y, &G.z, &R.x, &R.y, &R.z, NULL, NULL);
    bn_release(&rx, &ry, NULL, NULL, NULL, NULL, NULL, NULL);
    return rv;
}

int assl_p256_verify(const uint8_t q[64], const uint8_t digest[32],
                     const uint8_t r[32], const uint8_t s[32]) {
    p256_init();
    assl_bn rb, sb, w, z, u1, u2, tmp, px;
    jac G, Q, R, add;
    fe rx, ry;
    uint8_t rxbytes[32];
    int rv = 0;
    assl_bn_init(&rb); assl_bn_init(&sb); assl_bn_init(&w); assl_bn_init(&z);
    assl_bn_init(&u1); assl_bn_init(&u2); assl_bn_init(&tmp); assl_bn_init(&px);
    assl_bn_init(&G.x); assl_bn_init(&G.y); assl_bn_init(&G.z);
    assl_bn_init(&Q.x); assl_bn_init(&Q.y); assl_bn_init(&Q.z);
    assl_bn_init(&add.x); assl_bn_init(&add.y); assl_bn_init(&add.z);
    assl_bn_init(&R.x); assl_bn_init(&R.y); assl_bn_init(&R.z);
    assl_bn_init(&rx); assl_bn_init(&ry);
    if (assl_bn_from_bin(&rb, r, 32)) goto out;
    if (assl_bn_from_bin(&sb, s, 32)) goto out;
    if (assl_bn_cmp(&rb, &N) >= 0 || assl_bn_cmp(&sb, &N) >= 0) goto out;
    if (assl_bn_is_zero(&rb) || assl_bn_is_zero(&sb)) goto out;
    if (assl_bn_from_bin(&z, digest, 32)) goto out;
    if (assl_bn_mod(&z, &N, &z)) goto out;
    if (jac_g(&G)) goto out;
    if (assl_bn_from_bin(&Q.x, q, 32)) goto out;
    if (assl_bn_from_bin(&Q.y, q + 32, 32)) goto out;
    if (assl_bn_set_u32(&Q.z, 1)) goto out;
    if (assl_bn_modinv(&sb, &N, &w)) goto out;       
    if (assl_bn_modmul(&z, &w, &N, &u1)) goto out;   


    if (assl_bn_modmul(&rb, &w, &N, &u2)) goto out;  


    if (jac_mul(&R, &u1, &G)) goto out;              

    if (jac_mul(&add, &u2, &Q)) goto out;            
    if (jac_add(&add, &R, &add)) goto out;
    if (jac_to_affine(&add, &rx, &ry)) goto out;
    if (fe_to_be(&rx, rxbytes)) goto out;
    if (assl_bn_from_bin(&px, rxbytes, 32)) goto out;
    if (assl_bn_mod(&px, &N, &px)) goto out;
    rv = (assl_bn_cmp(&px, &rb) == 0);
out:
    bn_release(&rb, &sb, &w, &z, NULL, NULL, NULL, NULL);
    bn_release(&u1, &u2, &tmp, &px, NULL, NULL, NULL, NULL);
    bn_release(&G.x, &G.y, &G.z, &Q.x, &Q.y, &Q.z, NULL, NULL);
    bn_release(&add.x, &add.y, &add.z, &rx, &ry, NULL, NULL, NULL);
    return rv;
}