#include "asslibc.h"

void assl_rsa_init(assl_rsa_key *k) {
    memset(k, 0, sizeof *k);
    assl_bn_init(&k->n); assl_bn_init(&k->e); assl_bn_init(&k->d);
    assl_bn_init(&k->p); assl_bn_init(&k->q);
    assl_bn_init(&k->dp); assl_bn_init(&k->dq); assl_bn_init(&k->qinv);
}

void assl_rsa_free(assl_rsa_key *k) {
    assl_bn_free(&k->n); assl_bn_free(&k->e); assl_bn_free(&k->d);
    assl_bn_free(&k->p); assl_bn_free(&k->q);
    assl_bn_free(&k->dp); assl_bn_free(&k->dq); assl_bn_free(&k->qinv);
}

int assl_rsa_set_key(assl_rsa_key *k,
                     const assl_bn *n, const assl_bn *e, const assl_bn *d,
                     const assl_bn *p, const assl_bn *q,
                     const assl_bn *dp, const assl_bn *dq, const assl_bn *qinv) {
    if (!k || !n) return -1;
    k->have_priv = 0;
    k->have_crt = 0;
    if (assl_bn_copy(&k->n, n)) return -1;
    if (e) { if (assl_bn_copy(&k->e, e)) return -1; }
    if (d) { if (assl_bn_copy(&k->d, d)) return -1; k->have_priv = 1; }
    if (p && q && dp && dq && qinv) {
        if (assl_bn_copy(&k->p, p) || assl_bn_copy(&k->q, q) ||
            assl_bn_copy(&k->dp, dp) || assl_bn_copy(&k->dq, dq) ||
            assl_bn_copy(&k->qinv, qinv)) return -1;
        k->have_crt = 1;
        k->have_priv = 1;
    }
    return 0;
}

size_t assl_rsa_key_size(const assl_rsa_key *k) {
    return assl_bn_bytes(&k->n);
}

static int rsa_ep(const assl_rsa_key *k, const assl_bn *m, assl_bn *c) {
    if (assl_bn_cmp(m, &k->n) >= 0) return -1;
    return assl_bn_modpow(m, &k->e, &k->n, c);
}

static int rsa_dp_op(const assl_rsa_key *k, const assl_bn *c, assl_bn *m) {
    if (assl_bn_cmp(c, &k->n) >= 0) return -1;
    if (k->have_crt) {
        assl_bn m1, m2, h;
        assl_bn_init(&m1); assl_bn_init(&m2); assl_bn_init(&h);
        int r = -1;
        if (assl_bn_modpow_ct(c, &k->dp, &k->p, &m1)) goto done;
        if (assl_bn_modpow_ct(c, &k->dq, &k->q, &m2)) goto done;
        if (assl_bn_modsub_ct(&m1, &m2, &k->p, &h)) goto done;
        if (assl_bn_modmul_ct(&k->qinv, &h, &k->p, &h)) goto done;
        if (assl_bn_modmuladd_ct(&h, &k->q, &m2, &k->n, m)) goto done;
        r = 0;
    done:
        assl_bn_free(&m1); assl_bn_free(&m2); assl_bn_free(&h);
        return r;
    }
    return assl_bn_modpow_ct(c, &k->d, &k->n, m);
}

int assl_rsa_public(const assl_rsa_key *k, const uint8_t *in, size_t inlen, uint8_t *out) {
    size_t ksz = assl_rsa_key_size(k);
    if (!k || inlen != ksz || ksz == 0) return -1;
    assl_bn m, c;
    assl_bn_init(&m); assl_bn_init(&c);
    int r = -1;
    if (assl_bn_from_bin(&m, in, inlen)) goto done;
    if (rsa_ep(k, &m, &c)) goto done;
    if (assl_bn_to_bin(&c, out, ksz)) goto done;
    r = 0;
done:
    assl_bn_free(&m); assl_bn_free(&c);
    return r;
}

int assl_rsa_private(const assl_rsa_key *k, const uint8_t *in, size_t inlen, uint8_t *out) {
    size_t ksz = assl_rsa_key_size(k);
    if (!k || !k->have_priv || inlen != ksz || ksz == 0) return -1;
    assl_bn c, m;
    assl_bn_init(&c); assl_bn_init(&m);
    int r = -1;
    if (assl_bn_from_bin(&c, in, inlen)) goto done;
    if (rsa_dp_op(k, &c, &m)) goto done;
    if (assl_bn_to_bin_ct(&m, out, ksz)) goto done;
    r = 0;
done:
    assl_bn_free(&c); assl_bn_free(&m);
    return r;
}

int assl_rsa_encrypt(const assl_rsa_key *k, const uint8_t *in, size_t inlen, uint8_t *out) {
    size_t ksz = assl_rsa_key_size(k);
    if (!k || ksz < 11 || inlen > ksz - 11) return -1;
    size_t pslen = ksz - 3 - inlen;
    uint8_t *em = (uint8_t *)malloc(ksz);
    if (!em) return -1;
    em[0] = 0x00;
    em[1] = 0x02;
    if (assl_rng_bytes_nonzero(em + 2, pslen)) { free(em); return -1; }
    em[2 + pslen] = 0x00;
    memcpy(em + 3 + pslen, in, inlen);
    int r = assl_rsa_public(k, em, ksz, out);
    free(em);
    return r;
}

int assl_rsa_decrypt(const assl_rsa_key *k, const uint8_t *in, size_t inlen,
                     uint8_t *out, size_t *outlen) {
    size_t ksz = assl_rsa_key_size(k);
    if (!k || !k->have_priv || inlen != ksz || ksz < 11) return -1;
    uint8_t *buf = (uint8_t *)malloc(ksz);
    if (!buf) return -1;
    int r = -1;
    if (assl_rsa_private(k, in, inlen, buf)) goto done;
    if (buf[0] != 0x00 || buf[1] != 0x02) goto done;
    size_t sep = 0;
    for (size_t i = 2; i < ksz; i++) {
        if (buf[i] == 0x00) { sep = i; break; }
    }
    if (sep < 10 || sep == 0) goto done;
    if (sep - 2 < 8) goto done;
    size_t mlen = ksz - sep - 1;
    if (outlen) *outlen = mlen;
    memcpy(out, buf + sep + 1, mlen);
    r = 0;
done:
    free(buf);
    return r;
}

static const uint8_t *di_prefix[] = {
    NULL,                          
    NULL,                          
    NULL,                          
    NULL,                          
    NULL,                          
};
static size_t di_len[] = { 0, 0, 0, 0, 0 };

static int init_digest_info(void) {
    static int done = 0;
    if (done) return 0;
    static uint8_t md5_di[] = {0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x04,0x10};
    static uint8_t sha1_di[] = {0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14};
    static uint8_t sha256_di[] = {0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};
    static uint8_t sha384_di[] = {0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30};
    static uint8_t sha512_di[] = {0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40};
    di_prefix[ASSL_H_MD5] = md5_di;   di_len[ASSL_H_MD5] = sizeof md5_di;
    di_prefix[ASSL_H_SHA1] = sha1_di;  di_len[ASSL_H_SHA1] = sizeof sha1_di;
    di_prefix[ASSL_H_SHA256] = sha256_di; di_len[ASSL_H_SHA256] = sizeof sha256_di;
    di_prefix[ASSL_H_SHA384] = sha384_di; di_len[ASSL_H_SHA384] = sizeof sha384_di;
    di_prefix[ASSL_H_SHA512] = sha512_di; di_len[ASSL_H_SHA512] = sizeof sha512_di;
    done = 1;
    return 0;
}

int assl_rsa_sign(const assl_rsa_key *k, assl_hash_t h, const uint8_t *digest, uint8_t *sig) {
    init_digest_info();
    size_t ksz = assl_rsa_key_size(k);
    if (!k || !k->have_priv || h >= ASSL_H_COUNT || !digest || !sig) return -1;
    unsigned hlen = assl_hash_size(h);
    if (hlen == 0) return -1;
    size_t tlen = di_len[h] + hlen;
    if (ksz < tlen + 11) return -1;
    uint8_t *em = (uint8_t *)malloc(ksz);
    if (!em) return -1;
    em[0] = 0x00; em[1] = 0x01;
    size_t pslen = ksz - tlen - 3;
    memset(em + 2, 0xff, pslen);
    em[2 + pslen] = 0x00;
    memcpy(em + 3 + pslen, di_prefix[h], di_len[h]);
    memcpy(em + 3 + pslen + di_len[h], digest, hlen);
    int r = -1;
    assl_bn m, c;
    assl_bn_init(&m); assl_bn_init(&c);
    if (assl_bn_from_bin(&m, em, ksz)) goto done;
    if (rsa_dp_op(k, &m, &c)) goto done;
    if (assl_bn_to_bin_ct(&c, sig, ksz)) goto done;
    r = 0;
done:
    assl_bn_free(&m); assl_bn_free(&c);
    free(em);
    return r;
}

int assl_rsa_verify(const assl_rsa_key *k, assl_hash_t h, const uint8_t *digest,
                    const uint8_t *sig, size_t siglen) {
    init_digest_info();
    size_t ksz = assl_rsa_key_size(k);
    if (!k || h >= ASSL_H_COUNT || !digest || !sig) return -1;
    if (siglen != ksz) return -1;
    unsigned hlen = assl_hash_size(h);
    if (hlen == 0) return -1;
    size_t tlen = di_len[h] + hlen;
    if (ksz < tlen + 3) return -1;
    uint8_t *em = (uint8_t *)malloc(ksz);
    if (!em) return -1;
    assl_bn m_bn, c_bn;
    assl_bn_init(&m_bn); assl_bn_init(&c_bn);
    int r = -1;
    if (assl_bn_from_bin(&m_bn, sig, siglen)) goto done;
    if (assl_bn_cmp(&m_bn, &k->n) >= 0) goto done;
    if (assl_bn_modpow(&m_bn, &k->e, &k->n, &c_bn)) goto done;
    if (assl_bn_to_bin(&c_bn, em, ksz)) goto done;
    size_t pslen = ksz - tlen - 3;
    uint8_t bad = 0;
    bad |= (uint8_t)(em[0] != 0x00);
    bad |= (uint8_t)(em[1] != 0x01);
    for (size_t i = 2; i < 2 + pslen; i++)
        bad |= (uint8_t)(em[i] != 0xff);
    bad |= (uint8_t)(em[2 + pslen] != 0x00);
    for (size_t i = 0; i < di_len[h]; i++)
        bad |= (uint8_t)(em[3 + pslen + i] != di_prefix[h][i]);
    for (size_t i = 0; i < hlen; i++)
        bad |= (uint8_t)(em[3 + pslen + di_len[h] + i] != digest[i]);
    if (bad) goto done;
    r = 0;
done:
    free(em);
    assl_bn_free(&m_bn); assl_bn_free(&c_bn);
    return r;
}

static void mgf1(assl_hash_t h, const uint8_t *seed, size_t seedlen, size_t len, uint8_t *out) {
    size_t blk = assl_hash_size(h);
    uint8_t *inbuf = (uint8_t *)malloc(seedlen + 4);
    size_t pos = 0;
    uint32_t c = 0;
    while (pos < len) {
        memcpy(inbuf, seed, seedlen);
        assl_wr32_be(inbuf + seedlen, c);
        uint8_t tmp[64];
        assl_hash_one(h, inbuf, seedlen + 4, tmp);
        size_t n = (len - pos < blk) ? len - pos : blk;
        memcpy(out + pos, tmp, n);
        pos += n;
        c++;
    }
    free(inbuf);
}

int assl_rsa_sign_pss(const assl_rsa_key *k, assl_hash_t h, const uint8_t *digest,
                      size_t saltlen, uint8_t *sig) {
    size_t ksz = assl_rsa_key_size(k);
    if (!k || !k->have_priv || h >= ASSL_H_COUNT) return -1;
    unsigned hlen = assl_hash_size(h);
    if (hlen == 0 || ksz < hlen + saltlen + 2) return -1;
    uint8_t *salt = NULL;
    if (saltlen > 0) {
        salt = (uint8_t *)malloc(saltlen);
        if (!salt) return -1;
        if (assl_rng_bytes_checked(salt, saltlen)) { free(salt); return -1; }
    }
    size_t emLen = ksz;
    uint8_t *db = (uint8_t *)malloc(emLen - hlen - 1);
    uint8_t *em = (uint8_t *)malloc(emLen);
    if (!db || !em) { free(salt); free(db); free(em); return -1; }
    size_t mprime_len = 8 + hlen + saltlen;
    uint8_t *mprime = (uint8_t *)calloc(1, mprime_len);
    memcpy(mprime + 8, digest, hlen);
    if (saltlen > 0) memcpy(mprime + 8 + hlen, salt, saltlen);
    uint8_t *H = (uint8_t *)malloc(hlen);
    assl_hash_one(h, mprime, mprime_len, H);
    free(mprime);
    size_t pslen = emLen - saltlen - hlen - 2;
    memset(db, 0, pslen);
    db[pslen] = 0x01;
    if (saltlen > 0) memcpy(db + pslen + 1, salt, saltlen);
    free(salt);
    uint8_t *dbmask = (uint8_t *)malloc(emLen - hlen - 1);
    mgf1(h, H, hlen, emLen - hlen - 1, dbmask);
    for (size_t i = 0; i < emLen - hlen - 1; i++)
        db[i] ^= dbmask[i];
    db[0] &= 0x7f;
    free(dbmask);
    memcpy(em, db, emLen - hlen - 1);
    free(db);
    memcpy(em + emLen - hlen - 1, H, hlen);
    free(H);
    em[emLen - 1] = 0xbc;
    assl_bn m_bn, c_bn;
    assl_bn_init(&m_bn); assl_bn_init(&c_bn);
    int r = -1;
    if (assl_bn_from_bin(&m_bn, em, emLen)) goto done;
    if (rsa_dp_op(k, &m_bn, &c_bn)) goto done;
    if (assl_bn_to_bin_ct(&c_bn, sig, ksz)) goto done;
    r = 0;
done:
    assl_bn_free(&m_bn); assl_bn_free(&c_bn);
    free(em);
    return r;
}

int assl_rsa_verify_pss(const assl_rsa_key *k, assl_hash_t h, const uint8_t *digest,
                        size_t saltlen, const uint8_t *sig, size_t siglen) {
    size_t ksz = assl_rsa_key_size(k);
    if (!k || h >= ASSL_H_COUNT || !sig) return -1;
    if (siglen != ksz) return -1;
    unsigned hlen = assl_hash_size(h);
    if (hlen == 0 || ksz < hlen + saltlen + 2) return -1;
    assl_bn c_bn, em_bn;
    assl_bn_init(&c_bn); assl_bn_init(&em_bn);
    int r = -1;
    if (assl_bn_from_bin(&c_bn, sig, siglen)) goto done;
    if (assl_bn_cmp(&c_bn, &k->n) >= 0) goto done;
    if (assl_bn_modpow(&c_bn, &k->e, &k->n, &em_bn)) goto done;
    size_t emLen = ksz;
    uint8_t *em = (uint8_t *)calloc(1, emLen);
    if (!em) goto done;
    if (assl_bn_to_bin(&em_bn, em, emLen)) goto done;
    if (em[emLen - 1] != 0xbc) { free(em); goto done; }
    uint8_t *maskeddb = (uint8_t *)malloc(emLen - hlen - 1);
    uint8_t *H = (uint8_t *)malloc(hlen);
    uint8_t *db = (uint8_t *)malloc(emLen - hlen - 1);
    if (!maskeddb || !H || !db) { free(em); free(maskeddb); free(H); free(db); goto done; }
    memcpy(maskeddb, em, emLen - hlen - 1);
    memcpy(H, em + emLen - hlen - 1, hlen);
    free(em);
    maskeddb[0] &= 0x7f;
    uint8_t *dbmask = (uint8_t *)malloc(emLen - hlen - 1);
    if (!dbmask) { free(maskeddb); free(H); free(db); goto done; }
    mgf1(h, H, hlen, emLen - hlen - 1, dbmask);
    for (size_t i = 0; i < emLen - hlen - 1; i++)
        db[i] = maskeddb[i] ^ dbmask[i];
    db[0] &= 0x7f;
    free(maskeddb); free(dbmask);
    size_t pslen = emLen - saltlen - hlen - 2;
    for (size_t i = 0; i < pslen; i++) {
        if (db[i] != 0x00) { free(H); free(db); goto done; }
    }
    if (db[pslen] != 0x01) { free(H); free(db); goto done; }
    uint8_t *salt_check = db + pslen + 1;
    size_t mprime_len = 8 + hlen + saltlen;
    uint8_t *mprime = (uint8_t *)calloc(1, mprime_len);
    if (!mprime) { free(H); free(db); goto done; }
    memcpy(mprime + 8, digest, hlen);
    memcpy(mprime + 8 + hlen, salt_check, saltlen);
    uint8_t H_check[64];
    assl_hash_one(h, mprime, mprime_len, H_check);
    free(mprime);
    r = (memcmp(H, H_check, hlen) == 0) ? 0 : -1;
    free(H); free(db);
done:
    assl_bn_free(&c_bn); assl_bn_free(&em_bn);
    return r;
}
