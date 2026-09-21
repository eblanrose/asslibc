#include "asslibc.h"
#include "rsa_keygen.h"

static void bn_trim(assl_bn *a) {
    while (a->len > 1 && a->d[a->len - 1] == 0) a->len--;
}

static const uint32_t small_primes[] = {
    2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,
    73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,
    151,157,163,167,173,179,181,191,193,197,199,211,223,227,
    229,233,239,241,251,257,263,269,271,277,281,283,293,307,
    311,313,317,331,337,347,349,353,359,367,373,379,383,389,
    397,401,409,419,421,431,433,439,443,449,457,461,463,467,
    479,487,491,499,503,509,521,523,541,547,557,563,569,571,
    577,587,593,599,601,607,613,617,619,631,641,643,647,653,
    659,661,673,677,683,691,701,709,719,727,733,739,743,751,
    757,761,769,773,787,797,809,811,821,823,827,829,839,853,
    857,859,863,877,881,883,887,907,911,919,929,937,941,947,
    953,967,971,977,983,991,997
};
#define NUM_SMALL_PRIMES (sizeof(small_primes)/sizeof(small_primes[0]))

static int trial_division(const assl_bn *n) {
    assl_bn q, r;
    assl_bn_init(&q); assl_bn_init(&r);
    for (size_t i = 0; i < NUM_SMALL_PRIMES; i++) {
        assl_bn_set_u32(&q, small_primes[i]);
        assl_bn_mod(n, &q, &r);
        if (assl_bn_is_zero(&r)) {
            int is_eq = (assl_bn_cmp(n, &q) == 0);
            assl_bn_free(&q); assl_bn_free(&r);
            return is_eq;
        }
    }
    assl_bn_free(&q); assl_bn_free(&r);
    return 1;
}

static void decompose_n1(const assl_bn *n_minus_1, assl_bn *d, int *s) {
    assl_bn tmp;
    assl_bn_init(&tmp);
    assl_bn_copy(&tmp, n_minus_1);
    *s = 0;
    while (!assl_bn_is_odd(&tmp)) {
        uint64_t carry = 0;
        for (size_t i = tmp.len; i > 0; i--) {
            carry = (carry << 32) | tmp.d[i-1];
            tmp.d[i-1] = (uint32_t)(carry >> 1);
        }
        bn_trim(&tmp);
        (*s)++;
    }
    assl_bn_copy(d, &tmp);
    assl_bn_free(&tmp);
}

static void bn_sub1(const assl_bn *n, assl_bn *out) {
    assl_bn one;
    assl_bn_init(&one);
    assl_bn_set_u32(&one, 1);
    assl_bn_sub(n, &one, out);
    assl_bn_free(&one);
}

static int miller_rabin_round(const assl_bn *a, const assl_bn *d,
                              const assl_bn *n, int s) {
    assl_bn x, nm1;
    assl_bn_init(&x); assl_bn_init(&nm1);
    assl_bn_modpow(a, d, n, &x);
    if (assl_bn_is_one(&x)) { assl_bn_free(&x); assl_bn_free(&nm1); return 1; }
    bn_sub1(n, &nm1);
    if (assl_bn_cmp(&x, &nm1) == 0) { assl_bn_free(&x); assl_bn_free(&nm1); return 1; }
    for (int i = 0; i < s - 1; i++) {
        assl_bn t;
        assl_bn_init(&t);
        assl_bn_modmul(&x, &x, n, &t);
        assl_bn_copy(&x, &t);
        assl_bn_free(&t);
        if (assl_bn_is_one(&x)) { assl_bn_free(&x); assl_bn_free(&nm1); return 0; }
        if (assl_bn_cmp(&x, &nm1) == 0) { assl_bn_free(&x); assl_bn_free(&nm1); return 1; }
    }
    assl_bn_free(&x); assl_bn_free(&nm1);
    return 0;
}

int assl_bn_is_prime(const assl_bn *n, int confidence) {
    if (assl_bn_is_zero(n) || assl_bn_is_one(n)) return 0;
    if (!assl_bn_is_odd(n)) {
        assl_bn two; assl_bn_init(&two); assl_bn_set_u32(&two, 2);
        int r = (assl_bn_cmp(n, &two) == 0);
        assl_bn_free(&two);
        return r;
    }
    if (!trial_division(n)) return 0;

    assl_bn n_minus_1, d;
    assl_bn_init(&n_minus_1); assl_bn_init(&d);
    bn_sub1(n, &n_minus_1);
    int s;
    decompose_n1(&n_minus_1, &d, &s);

    if (confidence <= 0) confidence = 20;
    int witnesses[] = {2,3,5,7,11,13,17,19,23,29,31,37};
    int nw = confidence < 12 ? confidence : 12;
    for (int i = 0; i < nw; i++) {
        assl_bn a; assl_bn_init(&a);
        assl_bn_set_u32(&a, witnesses[i]);
        if (assl_bn_cmp(&a, n) >= 0) { assl_bn_free(&a); continue; }
        if (!miller_rabin_round(&a, &d, n, s)) {
            assl_bn_free(&a); assl_bn_free(&n_minus_1); assl_bn_free(&d);
            return 0;
        }
        assl_bn_free(&a);
    }
    assl_bn_free(&n_minus_1); assl_bn_free(&d);
    return 1;
}

int assl_rsa_keygen(assl_rsa_key *k, unsigned bits) {
    if (bits < 512 || bits > 4096 || bits % 2 != 0) return -1;

    assl_bn p, q, n, e, d, phi, p1, q1;
    assl_bn_init(&p); assl_bn_init(&q); assl_bn_init(&n);
    assl_bn_init(&e); assl_bn_init(&d); assl_bn_init(&phi);
    assl_bn_init(&p1); assl_bn_init(&q1);
    assl_bn_set_u32(&e, 65537);
    unsigned half = bits / 2;

    while (1) {
        assl_bn_rand(&p, half);
        size_t tw = (half + 31) / 32 - 1;
        uint32_t msk = 1u << ((half - 1) % 32);
        p.d[tw] |= msk;
        if (msk > 1) p.d[tw] |= msk >> 1;
        p.d[0] |= 1;
        bn_trim(&p);
        if (assl_bn_is_prime(&p, 20)) break;
    }
    while (1) {
        assl_bn_rand(&q, half);
        size_t tw = (half + 31) / 32 - 1;
        uint32_t msk = 1u << ((half - 1) % 32);
        q.d[tw] |= msk;
        if (msk > 1) q.d[tw] |= msk >> 1;
        q.d[0] |= 1;
        bn_trim(&q);
        if (assl_bn_is_prime(&q, 20)) break;
    }

    assl_bn_mul(&p, &q, &n);
    assl_bn_set_u32(&p1, 1); assl_bn_sub(&p, &p1, &p1);
    assl_bn_set_u32(&q1, 1); assl_bn_sub(&q, &q1, &q1);
    assl_bn_mul(&p1, &q1, &phi);
    assl_bn_modinv(&e, &phi, &d);

    assl_bn dp, dq, qinv;
    assl_bn_init(&dp); assl_bn_init(&dq); assl_bn_init(&qinv);
    assl_bn_mod(&d, &p1, &dp);
    assl_bn_mod(&d, &q1, &dq);
    assl_bn_modinv(&q, &p, &qinv);

    assl_rsa_init(k);
    assl_bn_init(&k->n); assl_bn_init(&k->e); assl_bn_init(&k->d);
    assl_bn_init(&k->p); assl_bn_init(&k->q);
    assl_bn_init(&k->dp); assl_bn_init(&k->dq); assl_bn_init(&k->qinv);
    assl_bn_copy(&k->n, &n); assl_bn_copy(&k->e, &e); assl_bn_copy(&k->d, &d);
    assl_bn_copy(&k->p, &p); assl_bn_copy(&k->q, &q);
    assl_bn_copy(&k->dp, &dp); assl_bn_copy(&k->dq, &dq); assl_bn_copy(&k->qinv, &qinv);
    k->have_priv = 1; k->have_crt = 1;

    assl_bn_free(&p); assl_bn_free(&q); assl_bn_free(&n);
    assl_bn_free(&e); assl_bn_free(&d); assl_bn_free(&phi);
    assl_bn_free(&p1); assl_bn_free(&q1);
    assl_bn_free(&dp); assl_bn_free(&dq); assl_bn_free(&qinv);
    return 0;
}
