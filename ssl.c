#include "ssl.h"


/* ---- Cipher suite table ---- */
static const ssl3_cipher_spec ssl3_ciphers[] = {
    { SSL3_CK_RSA_WITH_AES_128_CBC_SHA, ASSL_H_SHA1, 20, 16, 16, 16, 0, 0, 0, ASSL_H_SHA256 },
    { SSL3_CK_RSA_WITH_AES_256_CBC_SHA, ASSL_H_SHA1, 20, 32, 16, 16, 0, 0, 0, ASSL_H_SHA256 },
    { TLS12_CK_RSA_WITH_AES_128_CBC_SHA256, ASSL_H_SHA256, 32, 16, 16, 16, 0, 0, 0, ASSL_H_SHA256 },
    { TLS12_CK_RSA_WITH_AES_256_CBC_SHA256, ASSL_H_SHA256, 32, 32, 16, 16, 0, 0, 0, ASSL_H_SHA256 },
    { TLS12_CK_RSA_WITH_AES_128_GCM_SHA256, ASSL_H_SHA256,  0, 16, 12, 16, 0, 1, 0, ASSL_H_SHA256 },
    { TLS12_CK_RSA_WITH_AES_256_GCM_SHA384, ASSL_H_SHA384,  0, 32, 12, 16, 0, 1, 0, ASSL_H_SHA384 },
    { TLS12_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ASSL_H_SHA256, 0, 16, 12, 16, 0, 1, 0, ASSL_H_SHA256 },
    { TLS12_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384, ASSL_H_SHA384, 0, 32, 12, 16, 0, 1, 0, ASSL_H_SHA384 },
    { TLS12_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, ASSL_H_SHA256, 0, 32, 12, 16, 0, 1, 0, ASSL_H_SHA256 },
    { TLS13_CK_AES_128_GCM_SHA256,       ASSL_H_SHA256,  0, 16, 12, 16, 0, 1, 1, ASSL_H_SHA256 },
    { TLS13_CK_AES_256_GCM_SHA384,       ASSL_H_SHA384,  0, 32, 12, 16, 0, 1, 1, ASSL_H_SHA384 },
    { TLS13_CK_CHACHA20_POLY1305_SHA256,  ASSL_H_SHA256,  0, 32, 12, 16, 0, 1, 1, ASSL_H_SHA256 },
};
#define NUM_CIPHERS (sizeof(ssl3_ciphers) / sizeof(ssl3_ciphers[0]))

static const ssl3_cipher_spec *find_cipher(uint16_t suite) {
    for (size_t i = 0; i < NUM_CIPHERS; i++)
        if (ssl3_ciphers[i].cipher_suite == suite)
            return &ssl3_ciphers[i];
    return NULL;
}


static uint8_t ct_eq_u8(uint8_t a, uint8_t b) {
    uint16_t d = (uint16_t)(a ^ b);
    return (uint8_t)(((((d | (uint16_t)(0U - d)) >> 15) ^ 1) & 1) * 0xFF);
}

static size_t ct_mask_ge(size_t a, size_t b) {
    size_t t = (b - a - 1) >> (8 * sizeof(size_t) - 1);
    return 0 - (t & 1);
}

static int is_tls13(uint16_t v) { return v == TLS13_VERSION; }

static int is_ecdhe(uint16_t cs) {
    return cs == TLS12_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
           cs == TLS12_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
           cs == TLS12_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
}
static int is_tls12(uint16_t v) { return v == TLS12_VERSION; }
static int is_tls11(uint16_t v) { return v == TLS11_VERSION; }
static int __attribute__((unused)) is_tls10(uint16_t v) { return v == TLS10_VERSION; }
static int __attribute__((unused)) is_ssl30(uint16_t v) { return v == SSL3_VERSION; }
static int __attribute__((unused)) is_tls(uint16_t v)   { return v >= TLS10_VERSION; }

static uint16_t record_version(uint16_t v) {
    if (v >= TLS12_VERSION) return TLS12_VERSION;
    return v;
}

static void tls12_prf(assl_hash_t h, const void *secret, size_t secretlen,
                      const char *label, const uint8_t *seed, size_t seedlen,
                      uint8_t *out, size_t outlen) {
    size_t labelen = strlen(label);
    uint8_t *combined = malloc(labelen + seedlen);
    if (!combined) return;
    memcpy(combined, label, labelen);
    memcpy(combined + labelen, seed, seedlen);
    assl_p_hash(h, secret, secretlen, combined, labelen + seedlen, out, outlen);
    free(combined);
}

static void tls13_extract(assl_hash_t h, const uint8_t *ikm, size_t ikmlen,
                          const uint8_t *salt, size_t saltlen, uint8_t *prk) {
    assl_hkdf_extract(h, ikm, ikmlen, salt, saltlen, prk);
}

static void tls13_expand_label(assl_hash_t h, const uint8_t *secret, size_t secretlen,
                               const char *label, size_t labellen,
                               const uint8_t *ctx, size_t ctxlen,
                               uint8_t *out, size_t outlen) {
    assl_tls13_hkdf_expand_label(h, secret, secretlen, label, labellen,
                                  ctx, ctxlen, out, outlen);
}

static void tls13_derive_handshake_secrets(assl_ssl *ssl) {
    unsigned hlen = assl_hash_size(ssl->cipher.prf_hash);

    uint8_t zeros[64];
    uint8_t early_secret[64];
    memset(zeros, 0, sizeof zeros);
    tls13_extract(ssl->cipher.prf_hash, zeros, hlen, zeros, hlen, early_secret);

    uint8_t empty_hash[64];
    assl_hash_one(ssl->cipher.prf_hash, NULL, 0, empty_hash);
    uint8_t derived_secret[64];
    tls13_expand_label(ssl->cipher.prf_hash, early_secret, hlen,
                       "derived", 7, empty_hash, hlen,
                       derived_secret, hlen);

    tls13_extract(ssl->cipher.prf_hash, ssl->master_secret, 32,
                  derived_secret, hlen, ssl->handshake_secret);

    uint8_t trans_hash[64];
    assl_hash_one(ssl->cipher.prf_hash, ssl->hs_messages, ssl->hs_messages_len, trans_hash);

    tls13_expand_label(ssl->cipher.prf_hash, ssl->handshake_secret, hlen,
                       "c hs traffic", 12, trans_hash, hlen,
                       ssl->client_handshake_traffic_secret, hlen);
    tls13_expand_label(ssl->cipher.prf_hash, ssl->handshake_secret, hlen,
                       "s hs traffic", 12, trans_hash, hlen,
                       ssl->server_handshake_traffic_secret, hlen);
}

static void tls13_derive_app_secrets(assl_ssl *ssl) {
    unsigned hlen = assl_hash_size(ssl->cipher.prf_hash);
    uint8_t zeros[64];
    uint8_t early_secret[64];
    memset(zeros, 0, sizeof zeros);

    tls13_extract(ssl->cipher.prf_hash, zeros, hlen, zeros, hlen, early_secret);
    uint8_t empty_hash[64];
    assl_hash_one(ssl->cipher.prf_hash, NULL, 0, empty_hash);
    uint8_t derived_secret[64];
    tls13_expand_label(ssl->cipher.prf_hash, early_secret, hlen,
                       "derived", 7, empty_hash, hlen, derived_secret, hlen);

    tls13_extract(ssl->cipher.prf_hash, ssl->master_secret, 32,
                  derived_secret, hlen, ssl->handshake_secret);

    uint8_t derived_2[64];
    tls13_expand_label(ssl->cipher.prf_hash, ssl->handshake_secret, hlen,
                       "derived", 7, empty_hash, hlen, derived_2, hlen);

    tls13_extract(ssl->cipher.prf_hash, zeros, hlen, derived_2, hlen, ssl->master_secret_13);

    uint8_t trans_hash[64];
    assl_hash_one(ssl->cipher.prf_hash, ssl->hs_messages, ssl->hs_messages_len, trans_hash);

    tls13_expand_label(ssl->cipher.prf_hash, ssl->master_secret_13, hlen,
                       "c ap traffic", 12, trans_hash, hlen,
                       ssl->client_application_traffic_secret, hlen);
    tls13_expand_label(ssl->cipher.prf_hash, ssl->master_secret_13, hlen,
                       "s ap traffic", 12, trans_hash, hlen,
                       ssl->server_application_traffic_secret, hlen);
}

static void tls13_derive_traffic_keys(assl_ssl *ssl, const uint8_t *secret,
                                       uint8_t *key, uint8_t *iv) {
    uint8_t empty_ctx[1] = {0};
    unsigned hlen = assl_hash_size(ssl->cipher.prf_hash);
    tls13_expand_label(ssl->cipher.prf_hash, secret, hlen,
                       "key", 3, empty_ctx, 0, key, ssl->cipher.key_len);
    tls13_expand_label(ssl->cipher.prf_hash, secret, hlen,
                       "iv", 2, empty_ctx, 0, iv, ssl->cipher.iv_len);
}

static void tls13_update_traffic_secret(assl_ssl *ssl, uint8_t *secret) {
    uint8_t empty_ctx[1] = {0};
    unsigned hlen = assl_hash_size(ssl->cipher.prf_hash);
    uint8_t next[64];
    tls13_expand_label(ssl->cipher.prf_hash, secret, hlen,
                       "traffic upd", 11, empty_ctx, 0, next, hlen);
    memcpy(secret, next, hlen);
}

static void tls13_update_write_keys(assl_ssl *ssl) {
    uint8_t *secret = ssl->is_client ? ssl->client_application_traffic_secret
                                     : ssl->server_application_traffic_secret;
    uint8_t *key = ssl->is_client ? ssl->client_write_key : ssl->server_write_key;
    uint8_t *iv  = ssl->is_client ? ssl->client_write_iv   : ssl->server_write_iv;
    tls13_update_traffic_secret(ssl, secret);
    tls13_derive_traffic_keys(ssl, secret, key, iv);
    ssl->write_seq_num = 0;
}

static void tls13_update_read_keys(assl_ssl *ssl) {
    uint8_t *secret = ssl->is_client ? ssl->server_application_traffic_secret
                                     : ssl->client_application_traffic_secret;
    uint8_t *key = ssl->is_client ? ssl->server_write_key : ssl->client_write_key;
    uint8_t *iv  = ssl->is_client ? ssl->server_write_iv   : ssl->client_write_iv;
    tls13_update_traffic_secret(ssl, secret);
    tls13_derive_traffic_keys(ssl, secret, key, iv);
    ssl->read_seq_num = 0;
}

static void ssl3_derive_keys(assl_ssl *ssl) {
    uint8_t seed[64];
    memcpy(seed, ssl->server_random, 32);
    memcpy(seed + 32, ssl->client_random, 32);
    uint8_t key_block[256];
    memset(key_block, 0, sizeof key_block);
    if (is_tls12(ssl->version) || is_tls13(ssl->version)) {
        tls12_prf(ssl->cipher.prf_hash, ssl->master_secret, 48, "key expansion", seed, 64, key_block, sizeof key_block);
    } else {
        assl_tls_prf_md5sha1(ssl->master_secret, 48, seed, 64, key_block, sizeof key_block);
    }
    size_t off = 0;
    memcpy(ssl->client_mac_secret, key_block + off, ssl->cipher.mac_key_len); off += ssl->cipher.mac_key_len;
    memcpy(ssl->server_mac_secret, key_block + off, ssl->cipher.mac_key_len); off += ssl->cipher.mac_key_len;
    memcpy(ssl->client_write_key, key_block + off, ssl->cipher.key_len); off += ssl->cipher.key_len;
    memcpy(ssl->server_write_key, key_block + off, ssl->cipher.key_len); off += ssl->cipher.key_len;
    size_t salt_len;
    if (ssl->cipher.cipher_suite == TLS12_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
        salt_len = 12;
    else if (ssl->cipher.is_aead)
        salt_len = 4;
    else
        salt_len = ssl->cipher.iv_len;
    if (salt_len > 0) {
        memcpy(ssl->client_write_iv, key_block + off, salt_len); off += salt_len;
        memcpy(ssl->server_write_iv, key_block + off, salt_len);
    }
}

static void ssl3_compute_master_secret(assl_ssl *ssl,
                                       const uint8_t *pre_master_secret,
                                       size_t pre_master_secret_len) {
    uint8_t seed[64];
    memcpy(seed, ssl->client_random, 32);
    memcpy(seed + 32, ssl->server_random, 32);
    if (ssl->ems_negotiated && !is_tls13(ssl->version)) {
        uint8_t session_hash[64];
        unsigned hlen = assl_hash_size(ssl->cipher.prf_hash);
        assl_hash_one(ssl->cipher.prf_hash, ssl->hs_messages, ssl->hs_messages_len, session_hash);
        if (is_tls12(ssl->version))
            tls12_prf(ssl->cipher.prf_hash, pre_master_secret, pre_master_secret_len,
                      "extended master secret", session_hash, hlen,
                      ssl->master_secret, 48);
        else
            assl_tls_prf_md5sha1(pre_master_secret, pre_master_secret_len,
                                 session_hash, hlen, ssl->master_secret, 48);
        return;
    }
    if (is_tls12(ssl->version)) {
        tls12_prf(ssl->cipher.prf_hash, pre_master_secret, pre_master_secret_len,
                  "master secret", seed, 64, ssl->master_secret, 48);
    } else {
        assl_tls_prf_md5sha1(pre_master_secret, pre_master_secret_len,
                             seed, 64, ssl->master_secret, 48);
    }
}


static int ssl3_write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, p + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        done += (size_t)n;
    }
    return 0;
}

static ssize_t ssl3_read_some(int fd, void *buf, size_t len) {
    for (;;) {
        ssize_t n = read(fd, buf, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        return n;
    }
}


typedef struct {
    const uint8_t *p;
    const uint8_t *end;
    int ok;
} hs_cursor;

static void cur_init(hs_cursor *c, const uint8_t *buf, size_t len) {
    c->p = buf;
    c->end = buf + len;
    c->ok = 1;
}

static size_t cur_left(const hs_cursor *c) {
    if (!c->ok || c->p > c->end) return 0;
    return (size_t)(c->end - c->p);
}

static const uint8_t *cur_take(hs_cursor *c, size_t n) {
    const uint8_t *r;
    if (!c->ok || cur_left(c) < n) { c->ok = 0; return NULL; }
    r = c->p;
    c->p += n;
    return r;
}

static uint8_t cur_u8(hs_cursor *c) {
    const uint8_t *r = cur_take(c, 1);
    return r ? r[0] : 0;
}

static uint16_t cur_u16(hs_cursor *c) {
    const uint8_t *r = cur_take(c, 2);
    return r ? (uint16_t)(((uint16_t)r[0] << 8) | r[1]) : 0;
}

static uint32_t cur_u24(hs_cursor *c) {
    const uint8_t *r = cur_take(c, 3);
    return r ? (((uint32_t)r[0] << 16) | ((uint32_t)r[1] << 8) | r[2]) : 0;
}

static void cur_skip_vec(hs_cursor *c, unsigned lenbytes) {
    size_t n = 0;
    for (unsigned i = 0; i < lenbytes; i++) {
        n = (n << 8) | cur_u8(c);
        if (!c->ok) return;
    }
    (void)cur_take(c, n);
}

static int cur_sub(hs_cursor *c, unsigned lenbytes, hs_cursor *sub) {
    size_t n = 0;
    for (unsigned i = 0; i < lenbytes; i++) {
        n = (n << 8) | cur_u8(c);
        if (!c->ok) return -1;
    }
    if (cur_take(c, n) == NULL) return -1;
    cur_init(sub, c->p - n, n);
    return 0;
}

static int ssl3_write_record(assl_ssl *ssl, int fd,
                             uint8_t type, const void *data, size_t len) {
    uint8_t hdr[SSL3_HEADER_LEN];
    uint16_t rv = record_version(ssl->version);
    if (len > SSL3_MAX_RECORD_LEN) return -1;
    hdr[0] = type;
    hdr[1] = (uint8_t)(rv >> 8);
    hdr[2] = (uint8_t)(rv & 0xFF);
    hdr[3] = (uint8_t)(len >> 8);
    hdr[4] = (uint8_t)len;
    if (ssl3_write_all(fd, hdr, SSL3_HEADER_LEN) < 0) return -1;
    if (len && ssl3_write_all(fd, data, len) < 0) return -1;
    return 0;
}

static int ssl3_write_aead_record(assl_ssl *ssl, int fd,
                                  uint8_t type,
                                  const uint8_t *data, size_t len) {
    const uint8_t *enc_key = ssl->is_client ? ssl->client_write_key : ssl->server_write_key;
    const uint8_t *iv      = ssl->is_client ? ssl->client_write_iv   : ssl->server_write_iv;

    uint8_t seq_buf[8];
    assl_wr64_be(seq_buf, ssl->write_seq_num);

    uint8_t aad[13 + 8 + 8]; 
    size_t aad_len;
    uint8_t nonce[12];
    uint16_t rv = record_version(ssl->version);
    size_t aad_len_field;

    int is_12_chacha = (ssl->cipher.cipher_suite == TLS12_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
    size_t explicit_len;

    if (is_tls13(ssl->version)) {
        aad[0] = type;
        aad[1] = (uint8_t)(rv >> 8);
        aad[2] = (uint8_t)(rv & 0xFF);
        aad_len_field = len + 16; 
        aad[3] = (uint8_t)(aad_len_field >> 8);
        aad[4] = (uint8_t)aad_len_field;
        aad_len = 5;
        memcpy(nonce, iv, 12);
        for (int i = 0; i < 8; i++) nonce[4 + i] ^= seq_buf[i];
        explicit_len = 0;
    } else if (is_12_chacha) {
        memcpy(aad, seq_buf, 8);
        aad[8] = type;
        aad[9] = (uint8_t)(rv >> 8);
        aad[10] = (uint8_t)(rv & 0xFF);
        aad[11] = (uint8_t)(len >> 8);
        aad[12] = (uint8_t)len;
        aad_len = 13;
        memcpy(nonce, iv, 12);
        for (int i = 0; i < 8; i++) nonce[4 + i] ^= seq_buf[i];
        explicit_len = 0;
    } else {
        memcpy(aad, seq_buf, 8);
        aad[8] = type;
        aad[9] = (uint8_t)(rv >> 8);
        aad[10] = (uint8_t)(rv & 0xFF);
        aad[11] = (uint8_t)(len >> 8);
        aad[12] = (uint8_t)len;
        aad_len = 13;
        memcpy(nonce, iv, 4);       
        memcpy(nonce + 4, seq_buf, 8); 
        explicit_len = 8;
    }
    ssl->write_seq_num++;

    size_t total = len + 16;
    total += explicit_len;

    uint8_t ciphertext[SSL3_MAX_RECORD_LEN + 256];
    uint8_t tag[16];

    uint16_t cs = ssl->cipher.cipher_suite;
    if (cs == TLS12_CK_RSA_WITH_AES_128_GCM_SHA256 ||
        cs == TLS12_CK_RSA_WITH_AES_256_GCM_SHA384 ||
        cs == TLS12_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
        cs == TLS12_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
        cs == TLS13_CK_AES_128_GCM_SHA256 ||
        cs == TLS13_CK_AES_256_GCM_SHA384) {
        assl_gcm_seal(enc_key, ssl->cipher.key_len * 8,
                      nonce, 12, aad, aad_len, data, len, ciphertext, tag);
    } else if (cs == TLS12_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
               cs == TLS13_CK_CHACHA20_POLY1305_SHA256) {
        assl_chacha20_poly1305_seal(enc_key, nonce, aad, aad_len, data, len, ciphertext, tag);
    } else {
        return -1;
    }

    uint8_t hdr[SSL3_HEADER_LEN];
    hdr[0] = type;
    hdr[1] = (uint8_t)(rv >> 8);
    hdr[2] = (uint8_t)(rv & 0xFF);
    hdr[3] = (uint8_t)(total >> 8);
    hdr[4] = (uint8_t)total;
    if (ssl3_write_all(fd, hdr, SSL3_HEADER_LEN) < 0) return -1;
    if (explicit_len && ssl3_write_all(fd, seq_buf, explicit_len) < 0) return -1;
    if (ssl3_write_all(fd, ciphertext, len) < 0) return -1;
    if (ssl3_write_all(fd, tag, 16) < 0) return -1;
    return 0;
}

static int ssl3_write_encrypted_record(assl_ssl *ssl, int fd,
                                       uint8_t type,
                                       const uint8_t *data, size_t len) {
    if (len > SSL3_MAX_RECORD_LEN) return -1;

    if (!ssl->write_cipher_active)
        return ssl3_write_record(ssl, fd, type, data, len);

    if (is_tls13(ssl->version)) {
        uint8_t inner[SSL3_MAX_RECORD_LEN + 1];
        memcpy(inner, data, len);
        inner[len] = type; 
        return ssl3_write_aead_record(ssl, fd, SSL3_CT_APPLICATION_DATA, inner, len + 1);
    }

    if (ssl->cipher.is_aead) {
        return ssl3_write_aead_record(ssl, fd, type, data, len);
    }

    const uint8_t *mac_key = ssl->is_client ? ssl->client_mac_secret : ssl->server_mac_secret;
    const uint8_t *enc_key = ssl->is_client ? ssl->client_write_key : ssl->server_write_key;

    unsigned mac_len = ssl->cipher.mac_key_len;
    uint8_t mac_result[32];

    assl_hmac_ctx hmac;
    assl_hmac_init(&hmac, ssl->cipher.mac_algo, mac_key, mac_len);
    uint8_t seq_buf[8];
    assl_wr64_be(seq_buf, ssl->write_seq_num);
    assl_hmac_update(&hmac, seq_buf, 8);
    assl_hmac_update(&hmac, &type, 1);
    uint8_t ver[2];
    uint16_t rv = record_version(ssl->version);
    ver[0] = (uint8_t)(rv >> 8);
    ver[1] = (uint8_t)(rv & 0xFF);
    assl_hmac_update(&hmac, ver, 2);
    uint8_t len_buf[2] = { (uint8_t)(len >> 8), (uint8_t)len };
    assl_hmac_update(&hmac, len_buf, 2);
    assl_hmac_update(&hmac, data, len);
    assl_hmac_final(&hmac, mac_result);
    ssl->write_seq_num++;

    size_t plaintext_len = len + mac_len;
    uint8_t *plaintext = ssl->wbuf;
    memcpy(plaintext, data, len);
    memcpy(plaintext + len, mac_result, mac_len);

    size_t total_len = plaintext_len;
    if (!ssl->cipher.is_stream) {
        size_t bs = ssl->cipher.block_size;
        size_t pad_needed = bs - (total_len % bs);
        for (size_t i = 0; i < pad_needed; i++)
            plaintext[total_len + i] = (uint8_t)(pad_needed - 1);
        total_len += pad_needed;
    }

    if (ssl->cipher.is_stream) {
        return ssl3_write_record(ssl, fd, type, plaintext, total_len);
    } else {
        uint8_t ciphertext[SSL3_MAX_RECORD_LEN + 256];
        const uint8_t *iv_base = ssl->is_client ? ssl->client_write_iv : ssl->server_write_iv;

        if (is_tls12(ssl->version) || is_tls11(ssl->version)) {
            uint8_t explicit_iv[16];
            if (assl_rng_bytes_checked(explicit_iv, ssl->cipher.iv_len)) return -1;
            memcpy(ssl->write_iv_current, explicit_iv, ssl->cipher.iv_len);
            memcpy(ciphertext, explicit_iv, ssl->cipher.iv_len);
            assl_aes_cbc_encrypt(enc_key, ssl->cipher.key_len * 8,
                                 explicit_iv, plaintext, total_len,
                                 ciphertext + ssl->cipher.iv_len);
            size_t out_len = ssl->cipher.iv_len + total_len;
            return ssl3_write_record(ssl, fd, type, ciphertext, out_len);
        } else {
            const uint8_t *use_iv = ssl->write_seq_num == 1 ? iv_base : ssl->write_iv_current;
            assl_aes_cbc_encrypt(enc_key, ssl->cipher.key_len * 8,
                                 use_iv, plaintext, total_len, ciphertext);
            memcpy(ssl->write_iv_current, ciphertext + total_len - ssl->cipher.block_size,
                   ssl->cipher.block_size);
            return ssl3_write_record(ssl, fd, type, ciphertext, total_len);
        }
    }
}

static int ssl3_read_record(assl_ssl *ssl, int fd,
                            uint8_t *out, size_t *out_len) {
    (void)ssl;
    uint8_t hdr[SSL3_HEADER_LEN];
    ssize_t n;
    size_t r = 0;
    while (r < SSL3_HEADER_LEN) {
        n = ssl3_read_some(fd, hdr + r, SSL3_HEADER_LEN - r);
        if (n < 0) return -1;
        if (n == 0) return (r == 0) ? SSL3_RECORD_EOF : -1;
        r += (size_t)n;
    }
    uint8_t type = hdr[0];
    size_t len = ((size_t)hdr[3] << 8) | hdr[4];
    if (len > SSL3_MAX_RECORD_LEN + 256) return -1;
    r = 0;
    while (r < len) {
        n = ssl3_read_some(fd, out + r, len - r);
        if (n < 0) return -1;
        if (n == 0) return -1;
        r += (size_t)n;
    }
    *out_len = len;
    return type;
}

static int ssl3_read_aead_record(assl_ssl *ssl, int fd,
                                 uint8_t *out_type, uint8_t *out, size_t *out_len) {
    uint8_t raw[SSL3_MAX_RECORD_LEN + 256];
    size_t raw_len;
    int type = ssl3_read_record(ssl, fd, raw, &raw_len);
    if (type < 0) return type;
    *out_type = (uint8_t)type;

    if (!ssl->read_cipher_active) {
        memcpy(out, raw, raw_len);
        *out_len = raw_len;
        return type;
    }
    if (raw_len < 16) return -1;

    const uint8_t *dec_key = ssl->is_client ? ssl->server_write_key : ssl->client_write_key;
    const uint8_t *iv      = ssl->is_client ? ssl->server_write_iv   : ssl->client_write_iv;

    uint8_t nonce[12];
    uint8_t seq_buf[8];
    assl_wr64_be(seq_buf, ssl->read_seq_num);

    int is_12_chacha = (ssl->cipher.cipher_suite == TLS12_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
    size_t ct0 = 0;
    if (is_tls13(ssl->version)) {
        memcpy(nonce, iv, 12);
        for (int i = 0; i < 8; i++) nonce[4 + i] ^= seq_buf[i];
    } else if (is_12_chacha) {
        memcpy(nonce, iv, 12);
        for (int i = 0; i < 8; i++) nonce[4 + i] ^= seq_buf[i];
    } else {
        if (raw_len < 8 + 16) return -1;
        memcpy(nonce, iv, 4);       
        memcpy(nonce + 4, raw, 8); 
        ct0 = 8;
    }
    ssl->read_seq_num++;

    size_t ct_len = raw_len - ct0 - 16;
    const uint8_t *ct = raw + ct0;
    const uint8_t *tag = raw + raw_len - 16;

    uint8_t aad[16];
    size_t aad_len;
    uint16_t rv = record_version(ssl->version);
    size_t aad_len_field;
    if (is_tls13(ssl->version)) {
        aad[0] = (uint8_t)type;
        aad[1] = (uint8_t)(rv >> 8);
        aad[2] = (uint8_t)(rv & 0xFF);
        aad_len_field = raw_len; 
        aad[3] = (uint8_t)(aad_len_field >> 8);
        aad[4] = (uint8_t)aad_len_field;
        aad_len = 5;
    } else {
        memcpy(aad, seq_buf, 8);
        aad[8] = (uint8_t)type;
        aad[9] = (uint8_t)(rv >> 8);
        aad[10] = (uint8_t)(rv & 0xFF);
        aad[11] = (uint8_t)(ct_len >> 8);
        aad[12] = (uint8_t)ct_len;
        aad_len = 13;
    }

    int rc = -1;
    uint16_t cs = ssl->cipher.cipher_suite;
    if (cs == TLS12_CK_RSA_WITH_AES_128_GCM_SHA256 ||
        cs == TLS12_CK_RSA_WITH_AES_256_GCM_SHA384 ||
        cs == TLS12_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
        cs == TLS12_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
        cs == TLS13_CK_AES_128_GCM_SHA256 ||
        cs == TLS13_CK_AES_256_GCM_SHA384) {
        rc = assl_gcm_open(dec_key, ssl->cipher.key_len * 8,
                           nonce, 12, aad, aad_len, ct, ct_len, tag, out);
    } else if (cs == TLS12_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 ||
               cs == TLS13_CK_CHACHA20_POLY1305_SHA256) {
        rc = assl_chacha20_poly1305_open(dec_key, nonce, aad, aad_len,
                                          ct, ct_len, tag, out);
    }
    if (rc < 0) return -1;
    *out_len = ct_len;
    return type;
}

static int ssl3_read_encrypted_record(assl_ssl *ssl, int fd,
                                       uint8_t *out, size_t *out_len) {
    if (is_tls13(ssl->version)) {
        uint8_t inner_type;
        uint8_t plaintext[SSL3_MAX_RECORD_LEN + 256];
        size_t pt_len;
        int rtype = ssl3_read_aead_record(ssl, fd, &inner_type, plaintext, &pt_len);
        if (rtype < 0) return rtype;
        if (!ssl->read_cipher_active) {
            memcpy(out, plaintext, pt_len);
            *out_len = pt_len;
            return rtype;
        }
        if (pt_len < 1) return -1;
        int type = plaintext[pt_len - 1];
        memcpy(out, plaintext, pt_len - 1);
        *out_len = pt_len - 1;
        return type;
    }

    if (ssl->cipher.is_aead) {
        uint8_t rtype;
        int rc = ssl3_read_aead_record(ssl, fd, &rtype, out, out_len);
        if (rc < 0) return rc;
        return rtype;
    }

    uint8_t raw[SSL3_MAX_RECORD_LEN + 256];
    size_t raw_len;
    int type = ssl3_read_record(ssl, fd, raw, &raw_len);
    if (type < 0) return type;

    if (!ssl->read_cipher_active) {
        memcpy(out, raw, raw_len);
        *out_len = raw_len;
        return type;
    }

    const uint8_t *mac_key = ssl->is_client ? ssl->server_mac_secret : ssl->client_mac_secret;
    const uint8_t *dec_key = ssl->is_client ? ssl->server_write_key : ssl->client_write_key;

    uint8_t decrypted[SSL3_MAX_RECORD_LEN + 256];

    if (is_tls12(ssl->version) || is_tls11(ssl->version)) {
        if (raw_len < ssl->cipher.block_size) return -1;
        memcpy(ssl->read_iv_current, raw, ssl->cipher.block_size);
        size_t ct_len = raw_len - ssl->cipher.block_size;
        if (ct_len < ssl->cipher.block_size) return -1;
        assl_aes_cbc_decrypt(dec_key, ssl->cipher.key_len * 8,
                             ssl->read_iv_current, raw + ssl->cipher.block_size, ct_len, decrypted);
        if (ct_len >= ssl->cipher.block_size)
            memcpy(ssl->read_iv_current, raw + raw_len - ssl->cipher.block_size,
                   ssl->cipher.block_size);
        raw_len = ct_len;
    } else {
        if (raw_len < ssl->cipher.block_size || raw_len % ssl->cipher.block_size != 0)
            return -1;
        const uint8_t *iv = ssl->is_client ? ssl->server_write_iv : ssl->client_write_iv;
        const uint8_t *use_iv = ssl->read_seq_num == 0 ? iv : ssl->read_iv_current;
        assl_aes_cbc_decrypt(dec_key, ssl->cipher.key_len * 8,
                             use_iv, raw, raw_len, decrypted);
        memcpy(ssl->read_iv_current, raw + raw_len - ssl->cipher.block_size,
               ssl->cipher.block_size);
    }

    unsigned mac_len = ssl->cipher.mac_key_len;
    uint8_t good = 0xFF;
    size_t frag_len;

    if (!ssl->cipher.is_stream) {
        size_t block_size = ssl->cipher.block_size;
        uint8_t last = decrypted[raw_len - 1];
        size_t pad_len = (size_t)last + 1;
        size_t pad_ok = ct_mask_ge(block_size, pad_len);
        for (size_t i = 0; i < block_size; i++) {
            uint8_t b = decrypted[raw_len - 1 - i];
            uint8_t eq = ct_eq_u8(b, last);
            size_t in_pad = ct_mask_ge(pad_len, i + 1); 
            pad_ok &= ((size_t)eq & in_pad) | (size_t)~in_pad;
        }
        good = (uint8_t)pad_ok;
        size_t pl = pad_len & ct_mask_ge(raw_len, pad_len);
        size_t msg_len = raw_len - pl;
        size_t ge = ct_mask_ge(msg_len, mac_len);
        good &= (uint8_t)ge; 
        frag_len = ((msg_len - mac_len) & ge); 
    } else {
        size_t msg_len = raw_len;
        size_t ge = ct_mask_ge(msg_len, mac_len);
        good &= (uint8_t)ge;
        frag_len = ((msg_len - mac_len) & ge);
    }

    assl_hmac_ctx hmac;
    assl_hmac_init(&hmac, ssl->cipher.mac_algo, mac_key, mac_len);
    uint8_t seq_buf[8];
    assl_wr64_be(seq_buf, ssl->read_seq_num);
    assl_hmac_update(&hmac, seq_buf, 8);
    assl_hmac_update(&hmac, &type, 1);
    uint8_t ver[2];
    uint16_t rv = record_version(ssl->version);
    ver[0] = (uint8_t)(rv >> 8);
    ver[1] = (uint8_t)(rv & 0xFF);
    assl_hmac_update(&hmac, ver, 2);
    uint8_t len_buf[2] = { (uint8_t)(frag_len >> 8), (uint8_t)frag_len };
    assl_hmac_update(&hmac, len_buf, 2);
    assl_hmac_update(&hmac, decrypted, frag_len);
    uint8_t computed_mac[32];
    assl_hmac_final(&hmac, computed_mac);

    uint8_t mac_ok = 0xFF;
    for (unsigned i = 0; i < mac_len; i++)
        mac_ok &= ct_eq_u8(decrypted[frag_len + i], computed_mac[i]);
    good &= mac_ok;

    if (good != 0xFF) return -1;
    ssl->read_seq_num++;
    memcpy(out, decrypted, frag_len);
    *out_len = frag_len;
    return type;
}

static void ssl3_hs_update_digest(assl_ssl *ssl,
                                  uint8_t type, const uint8_t *data, size_t len) {
    uint8_t hdr[4];
    hdr[0] = type;
    hdr[1] = (uint8_t)(len >> 16);
    hdr[2] = (uint8_t)(len >> 8);
    hdr[3] = (uint8_t)len;
    if (ssl->hs_messages_len + 4 + len <= sizeof(ssl->hs_messages)) {
        memcpy(ssl->hs_messages + ssl->hs_messages_len, hdr, 4);
        ssl->hs_messages_len += 4;
        if (len) memcpy(ssl->hs_messages + ssl->hs_messages_len, data, len);
        ssl->hs_messages_len += len;
    }
    assl_sha1_update(&ssl->hs_digest, hdr, 4);
    assl_sha1_update(&ssl->hs_digest, data, len);
    assl_md5_update(&ssl->hs_md5_digest, hdr, 4);
    assl_md5_update(&ssl->hs_md5_digest, data, len);
    if (is_tls12(ssl->version) || is_tls13(ssl->version)) {
        assl_sha256_update(&ssl->hs_sha256_digest, hdr, 4);
        assl_sha256_update(&ssl->hs_sha256_digest, data, len);
        ssl->hs_sha256_active = 1;
    }
}

static int ssl3_hs_message_hash(assl_ssl *ssl) {
    unsigned hlen = assl_hash_size(ssl->cipher.prf_hash);
    if (hlen == 0 || hlen > 64) return -1;
    if (4 + hlen > sizeof(ssl->hs_messages)) return -1;

    uint8_t h[64];
    assl_hash_one(ssl->cipher.prf_hash, ssl->hs_messages, ssl->hs_messages_len, h);

    uint8_t hdr[4];
    hdr[0] = 0xFE;
    hdr[1] = (uint8_t)(hlen >> 16);
    hdr[2] = (uint8_t)(hlen >> 8);
    hdr[3] = (uint8_t)hlen;
    memcpy(ssl->hs_messages, hdr, 4);
    memcpy(ssl->hs_messages + 4, h, hlen);
    ssl->hs_messages_len = 4 + hlen;

    assl_sha1_init(&ssl->hs_digest);
    assl_md5_init(&ssl->hs_md5_digest);
    assl_sha256_init(&ssl->hs_sha256_digest);
    assl_sha1_update(&ssl->hs_digest, ssl->hs_messages, ssl->hs_messages_len);
    assl_md5_update(&ssl->hs_md5_digest, ssl->hs_messages, ssl->hs_messages_len);
    assl_sha256_update(&ssl->hs_sha256_digest, ssl->hs_messages, ssl->hs_messages_len);
    ssl->hs_sha256_active = 1;
    return 0;
}

static const uint8_t TLS13_HRR_RANDOM[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};

static int tls13_is_hello_retry_request(const assl_ssl *ssl) {
    return is_tls13(ssl->version) &&
           memcmp(ssl->server_random, TLS13_HRR_RANDOM, sizeof TLS13_HRR_RANDOM) == 0;
}

static size_t ssl3_compute_finished(assl_ssl *ssl, const char *label,
                                    uint8_t verify_data[64]) {
    if (is_tls12(ssl->version)) {
        uint8_t hs_hash[64];
        assl_hash_one(ssl->cipher.prf_hash, ssl->hs_messages,
                      ssl->hs_messages_len, hs_hash);
        size_t hslen = assl_hash_size(ssl->cipher.prf_hash);
        tls12_prf(ssl->cipher.prf_hash, ssl->master_secret, 48, label, hs_hash, hslen,
                  verify_data, SSL3_VERIFY_DATA_LEN);
        return SSL3_VERIFY_DATA_LEN;
    } else if (is_tls13(ssl->version)) {
        unsigned hlen = assl_hash_size(ssl->cipher.prf_hash);
        uint8_t hash[64];
        assl_hash_one(ssl->cipher.prf_hash, ssl->hs_messages, ssl->hs_messages_len, hash);
        const uint8_t *base = (label[0] == 's') ? ssl->server_handshake_traffic_secret
                                                : ssl->client_handshake_traffic_secret;
        uint8_t finished_key[64];
        uint8_t empty_ctx[1] = {0};
        tls13_expand_label(ssl->cipher.prf_hash, base, hlen,
                           "finished", 8, empty_ctx, 0,
                           finished_key, hlen);
        assl_hmac_ctx hmac;
        assl_hmac_init(&hmac, ssl->cipher.prf_hash, finished_key, hlen);
        assl_hmac_update(&hmac, hash, hlen);
        assl_hmac_final(&hmac, hash);
        memcpy(verify_data, hash, hlen);
        return hlen;
    } else {
        uint8_t md5_hash[16], sha_hash[20];
        assl_md5_ctx md5_tmp;
        assl_sha1_ctx sha_tmp;
        memcpy(&md5_tmp, &ssl->hs_md5_digest, sizeof md5_tmp);
        memcpy(&sha_tmp, &ssl->hs_digest, sizeof sha_tmp);
        assl_md5_final(&md5_tmp, md5_hash);
        assl_sha1_final(&sha_tmp, sha_hash);
        size_t labellen = strlen(label);
        uint8_t seed[15 + 16 + 20];
        memcpy(seed, label, labellen);
        memcpy(seed + labellen, md5_hash, 16);
        memcpy(seed + labellen + 16, sha_hash, 20);
        assl_tls_prf_md5sha1(ssl->master_secret, 48,
                             seed, labellen + 16 + 20,
                             verify_data, SSL3_VERIFY_DATA_LEN);
        return SSL3_VERIFY_DATA_LEN;
    }
}

static int ssl3_write_handshake(assl_ssl *ssl, int fd,
                                uint8_t hs_type, const void *data, size_t len) {
    uint8_t *buf = ssl->wbuf;
    buf[0] = hs_type;
    buf[1] = (uint8_t)(len >> 16);
    buf[2] = (uint8_t)(len >> 8);
    buf[3] = (uint8_t)len;
    if (len) memcpy(buf + 4, data, len);
    ssl3_hs_update_digest(ssl, hs_type, data, len);
    return ssl3_write_encrypted_record(ssl, fd, SSL3_CT_HANDSHAKE, buf, len + 4);
}

static int ssl3_write_change_cipher_spec(assl_ssl *ssl, int fd) {
    uint8_t ccs = 1;
    return ssl3_write_record(ssl, fd, SSL3_CT_CHANGE_CIPHER_SPEC, &ccs, 1);
}

static int ssl3_read_dispatch(assl_ssl *ssl, int fd,
                              uint8_t *out, size_t *out_len) {
    return ssl3_read_encrypted_record(ssl, fd, out, out_len);
}

static int ssl3_expect_ccs(assl_ssl *ssl, int fd, uint8_t *rec, size_t *reclen) {
    if (ssl3_read_dispatch(ssl, fd, rec, reclen) != SSL3_CT_CHANGE_CIPHER_SPEC)
        return -1;
    if (*reclen != 1 || rec[0] != 1) return -1;
    return 0;
}

static void ssl3_fatal(assl_ssl *ssl, int fd, uint8_t desc) {
    uint8_t alert[2] = { SSL3_ALERT_FATAL, desc };
    if (ssl->write_cipher_active)
        ssl3_write_encrypted_record(ssl, fd, SSL3_CT_ALERT, alert, 2);
    else
        ssl3_write_record(ssl, fd, SSL3_CT_ALERT, alert, 2);
}

static int ssl3_generate_pre_master_secret(assl_ssl *ssl,
                                           uint8_t *pms, size_t *pms_len) {
    pms[0] = (uint8_t)(ssl->version >> 8);
    pms[1] = (uint8_t)(ssl->version & 0xFF);
    if (!assl_rng_is_secure()) return -1;
    if (assl_rng_bytes_checked(pms + 2, 46)) return -1;
    *pms_len = 48;
    return 0;
}

void assl_ssl_init(assl_ssl *ssl, int is_client) {
    memset(ssl, 0, sizeof *ssl);
    ssl->is_client = is_client;
    ssl->version = TLS12_VERSION; 
    ssl->state = SSL3_STATE_INIT;
    /* Verification is on unless the caller turns it off. Defaulting to "trust
     * anything" made forgetting assl_ssl_set_verify() a silent MITM, which is
     * the worst possible failure mode for a security library: the handshake
     * succeeds and nothing in the API tells the application it was unguarded. */
    ssl->verify_peer = 1;
    assl_sha1_init(&ssl->hs_digest);
    assl_md5_init(&ssl->hs_md5_digest);
    assl_sha256_init(&ssl->hs_sha256_digest);
}

void assl_ssl_set_version(assl_ssl *ssl, uint16_t version) {
    ssl->version = version;
}

void assl_ssl_set_cert(assl_ssl *ssl, const uint8_t *der, size_t der_len,
                       const assl_rsa_key *key) {
    ssl->cert_der = der;
    ssl->cert_der_len = der_len;
    if (key) ssl->rsa_key = *key;
    ssl->have_cert = (der && der_len > 0 && key);
}

int assl_ssl_set_verify(assl_ssl *ssl, int enable, const char *hostname) {
    if (!ssl) return -1;
    ssl->verify_peer = enable ? 1 : 0;
    ssl->verify_hostname_len = 0;
    if (hostname) {
        size_t n = strlen(hostname);
        if (n > sizeof ssl->verify_hostname - 1) return -1;
        memcpy(ssl->verify_hostname, hostname, n);
        ssl->verify_hostname[n] = 0;
        ssl->verify_hostname_len = (int)n;
    }
    return 0;
}

int assl_ssl_add_trust(assl_ssl *ssl, const uint8_t *der, size_t len) {
    assl_x509_cert c;
    if (!ssl || !der || len == 0) return 0;
    if (ssl->trust_store.count >= 8) return 0;
    if (assl_x509_parse(&c, der, len) < 0) return 0;
    assl_x509_free(&c);
    ssl->trust_store.der[ssl->trust_store.count] = der;
    ssl->trust_store.len[ssl->trust_store.count] = len;
    ssl->trust_store.count++;
    return 1;
}

static size_t ssl3_append_common_extensions(assl_ssl *ssl, uint8_t *ext,
                                            size_t e, size_t cap) {
    if (ssl->sni_hostname_len > 0) {
        size_t n = (size_t)ssl->sni_hostname_len;
        if (e + 4 + 2 + 1 + 2 + n > cap) return 0;
        ext[e++] = 0x00; ext[e++] = SSL3_EXT_SERVER_NAME;
        ext[e++] = 0x00; ext[e++] = (uint8_t)(5 + n);
        ext[e++] = 0x00; ext[e++] = (uint8_t)(3 + n);
        ext[e++] = 0x00;
        ext[e++] = (uint8_t)(n >> 8);
        ext[e++] = (uint8_t)n;
        memcpy(ext + e, ssl->sni_hostname, n); e += n;
    }

    if (ssl->alpn_protos_len > 0) {
        size_t n = ssl->alpn_protos_len;
        if (e + 4 + 2 + n > cap) return 0;
        ext[e++] = 0x00; ext[e++] = SSL3_EXT_ALPN;
        ext[e++] = 0x00; ext[e++] = (uint8_t)(2 + n);
        ext[e++] = 0x00; ext[e++] = (uint8_t)n;
        memcpy(ext + e, ssl->alpn_protos, n); e += n;
    }

    if (!is_tls13(ssl->version)) {
        if (e + 4 > cap) return 0;
        ext[e++] = 0x00; ext[e++] = SSL3_EXT_EXTENDED_MASTER_SECRET;
        ext[e++] = 0x00; ext[e++] = 0x00;
        ssl->ems_offered = 1;
    }
    return e;
}

int assl_ssl_set_servername(assl_ssl *ssl, const char *hostname) {
    if (!ssl) return -1;
    if (!hostname || !*hostname) {
        ssl->sni_hostname_len = 0;
        ssl->sni_hostname[0] = 0;
        return 0;
    }
    while (*hostname == '.') hostname++;
    size_t n = strlen(hostname);
    while (n > 0 && hostname[n - 1] == '.') n--;
    if (n == 0) return -1;
    if (n >= sizeof ssl->sni_hostname) return -1;
    memcpy(ssl->sni_hostname, hostname, n);
    ssl->sni_hostname[n] = 0;
    ssl->sni_hostname_len = (int)n;
    return 0;
}

int assl_ssl_set_alpn(assl_ssl *ssl, const uint8_t *protos, size_t len) {
    if (!ssl) return -1;
    if (len == 0) {
        ssl->alpn_protos_len = 0;
        return 0;
    }
    if (!protos || len > sizeof ssl->alpn_protos) return -1;
    size_t off = 0;
    while (off < len) {
        uint8_t n = protos[off];
        if (n == 0 || off + 1 + n > len) return -1;
        off += 1 + (size_t)n;
    }
    memcpy(ssl->alpn_protos, protos, len);
    ssl->alpn_protos_len = len;
    return 0;
}

const char *assl_ssl_get_negotiated_alpn(const assl_ssl *ssl) {
    if (!ssl || ssl->negotiated_alpn_len == 0) return NULL;
    return (const char *)ssl->negotiated_alpn;
}

const char *assl_ssl_get_server_name(const assl_ssl *ssl) {
    if (!ssl || ssl->server_name_len == 0) return NULL;
    return ssl->server_name;
}

uint16_t assl_ssl_get_group(const assl_ssl *ssl) {
    return ssl ? ssl->selected_group : 0;
}

static size_t ssl3_select_alpn(assl_ssl *ssl) {
    size_t so = 0;
    while (so < ssl->alpn_protos_len) {
        size_t slen = ssl->alpn_protos[so];
        if (slen == 0 || so + 1 + slen > ssl->alpn_protos_len) break;
        size_t co = 0;
        while (co < ssl->peer_alpn_protos_len) {
            size_t clen = ssl->peer_alpn_protos[co];
            if (clen == 0 || co + 1 + clen > ssl->peer_alpn_protos_len) break;
            if (clen == slen &&
                memcmp(ssl->alpn_protos + so + 1, ssl->peer_alpn_protos + co + 1, slen) == 0) {
                if (slen < sizeof ssl->negotiated_alpn) {
                    memcpy(ssl->negotiated_alpn, ssl->alpn_protos + so + 1, slen);
                    ssl->negotiated_alpn[slen] = 0;
                    ssl->negotiated_alpn_len = slen;
                }
                return slen;
            }
            co += 1 + clen;
        }
        so += 1 + slen;
    }
    return 0;
}

static void ssl3_put_ext_len(uint8_t *buf, size_t *n, size_t ext_bytes) {
    uint8_t hi = (uint8_t)(ext_bytes >> 8);
    uint8_t lo = (uint8_t)ext_bytes;
    buf[(*n)++] = hi;
    buf[(*n)++] = lo;
}

static size_t build_tls13_client_hello(assl_ssl *ssl, uint8_t *out) {
    size_t p = 0;
    uint8_t ext[512];
    size_t e = 0;

    out[p++] = 0x03; out[p++] = 0x03;

    memcpy(out + p, ssl->client_random, 32); p += 32;

    out[p++] = 0;

    uint16_t suites[] = {
        TLS13_CK_AES_128_GCM_SHA256,
        TLS13_CK_AES_256_GCM_SHA384,
        TLS13_CK_CHACHA20_POLY1305_SHA256,
    };
    uint16_t nsuites = sizeof(suites) / sizeof(suites[0]);
    out[p++] = (uint8_t)(nsuites * 2 >> 8);
    out[p++] = (uint8_t)(nsuites * 2);
    for (uint16_t i = 0; i < nsuites; i++) {
        out[p++] = (uint8_t)(suites[i] >> 8);
        out[p++] = (uint8_t)(suites[i]);
    }
    ssl->client_suites_count = 0;
    for (uint16_t i = 0; i < nsuites && i < sizeof ssl->client_suites / sizeof ssl->client_suites[0]; i++)
        ssl->client_suites[ssl->client_suites_count++] = suites[i];

    out[p++] = 1;
    out[p++] = 0;

    ext[e++] = 0x00; ext[e++] = 0x2b;
    ext[e++] = 0x00; ext[e++] = 0x03;
    ext[e++] = 0x02;
    ext[e++] = 0x03; ext[e++] = 0x04;

    ext[e++] = 0x00; ext[e++] = 0x33;
    ext[e++] = 0x00; ext[e++] = 0x47;
    ext[e++] = 0x00; ext[e++] = 0x45;
    ext[e++] = (uint8_t)(SSL3_GROUP_SECP256R1 >> 8);
    ext[e++] = (uint8_t)(SSL3_GROUP_SECP256R1);
    uint8_t ec_priv[32], ec_pub[64];
    assl_p256_keygen(ec_priv, ec_pub);
    memcpy(ssl->ecdh_priv, ec_priv, 32);
    memcpy(ssl->ecdh_local_pub, ec_pub, 64);
    ext[e++] = 0x00; ext[e++] = 0x41;
    ext[e++] = 0x04;
    memcpy(ext + e, ec_pub, 64); e += 64;

    ext[e++] = 0x00; ext[e++] = 0x0d;
    ext[e++] = 0x00; ext[e++] = 0x0e;
    ext[e++] = 0x00; ext[e++] = 0x0c;
    ext[e++] = 0x08; ext[e++] = 0x04;
    ext[e++] = 0x08; ext[e++] = 0x05;
    ext[e++] = 0x08; ext[e++] = 0x06;
    ext[e++] = 0x04; ext[e++] = 0x01;
    ext[e++] = 0x05; ext[e++] = 0x01;
    ext[e++] = 0x06; ext[e++] = 0x01;

    ext[e++] = 0x00; ext[e++] = 0x0a;
    ext[e++] = 0x00; ext[e++] = 0x04;
    ext[e++] = 0x00; ext[e++] = 0x02;
    ext[e++] = (uint8_t)(SSL3_GROUP_SECP256R1 >> 8);
    ext[e++] = (uint8_t)(SSL3_GROUP_SECP256R1);

    ext[e++] = 0x00; ext[e++] = 0x2d;
    ext[e++] = 0x00; ext[e++] = 0x02;
    ext[e++] = 0x01; ext[e++] = 0x01;

    e = ssl3_append_common_extensions(ssl, ext, e, sizeof ext);
    if (e == 0) return 0;

    ssl3_put_ext_len(out, &p, e);
    memcpy(out + p, ext, e); p += e;

    return p;
}

static size_t build_tls13_server_hello(assl_ssl *ssl, uint8_t *out) {
    size_t p = 0;

    out[p++] = 0x03; out[p++] = 0x03;

    memcpy(out + p, ssl->server_random, 32); p += 32;

    out[p++] = ssl->client_session_id_len;
    memcpy(out + p, ssl->client_session_id, ssl->client_session_id_len);
    p += ssl->client_session_id_len;

    out[p++] = (uint8_t)(ssl->cipher.cipher_suite >> 8);
    out[p++] = (uint8_t)(ssl->cipher.cipher_suite);

    out[p++] = 0;

    size_t ext_start = p;
    p += 2;

    out[p++] = 0x00; out[p++] = 0x2b;
    out[p++] = 0x00; out[p++] = 0x02;
    out[p++] = 0x03; out[p++] = 0x04; 

    out[p++] = 0x00; out[p++] = 0x33;
    size_t ks_len_pos = p;
    p += 2;
    uint16_t named_group = 0x0017; 
    out[p++] = (uint8_t)(named_group >> 8);
    out[p++] = (uint8_t)(named_group);
    uint8_t ec_priv[32], ec_pub[64];
    assl_p256_keygen(ec_priv, ec_pub);
    memcpy(ssl->ecdh_priv, ec_priv, 32);
    memcpy(ssl->ecdh_local_pub, ec_pub, 64);
    uint8_t shared[32];
    assl_p256_ecdh(ec_priv, ssl->ecdh_peer_pub, shared);
    memcpy(ssl->master_secret, shared, 32); 
    out[p++] = 0x00; out[p++] = 0x41; 
    out[p++] = 0x04;
    memcpy(out + p, ec_pub, 64); p += 64;
    size_t ks_len = p - ks_len_pos - 2;
    out[ks_len_pos] = (uint8_t)(ks_len >> 8);
    out[ks_len_pos + 1] = (uint8_t)ks_len;

    size_t ext_len = p - ext_start - 2;
    out[ext_start] = (uint8_t)(ext_len >> 8);
    out[ext_start + 1] = (uint8_t)ext_len;

    return p;
}

static size_t build_tls13_hello_retry_request(assl_ssl *ssl, uint8_t *out) {
    size_t p = 0;

    out[p++] = 0x03; out[p++] = 0x03;
    memcpy(out + p, TLS13_HRR_RANDOM, 32); p += 32;
    out[p++] = ssl->client_session_id_len;
    memcpy(out + p, ssl->client_session_id, ssl->client_session_id_len);
    p += ssl->client_session_id_len;
    out[p++] = (uint8_t)(ssl->cipher.cipher_suite >> 8);
    out[p++] = (uint8_t)ssl->cipher.cipher_suite;
    out[p++] = 0;

    uint8_t ext[16];
    size_t e = 0;
    ext[e++] = 0x00; ext[e++] = SSL3_EXT_SUPPORTED_VERSIONS;
    ext[e++] = 0x00; ext[e++] = 0x02;
    ext[e++] = 0x03; ext[e++] = 0x04;
    ext[e++] = 0x00; ext[e++] = SSL3_EXT_KEY_SHARE;
    ext[e++] = 0x00; ext[e++] = 0x02;
    ext[e++] = (uint8_t)(SSL3_GROUP_SECP256R1 >> 8);
    ext[e++] = (uint8_t)SSL3_GROUP_SECP256R1;

    ssl3_put_ext_len(out, &p, e);
    memcpy(out + p, ext, e); p += e;
    return p;
}

static int ssl3_server_handshake(assl_ssl *ssl, int in_fd, int out_fd) {
    uint8_t recbuf[SSL3_MAX_RECORD_LEN + 256];
    size_t reclen;
    int rtype;
    int secure_renegotiation = 0;
    int ccs_seen = 0;

    for (int ch_round = 0; ch_round < 2; ch_round++) {
        for (;;) {
            rtype = ssl3_read_dispatch(ssl, in_fd, recbuf, &reclen);
            if (rtype == SSL3_CT_CHANGE_CIPHER_SPEC) {
                if (reclen != 1 || recbuf[0] != 1) return -1;
                ccs_seen = 1;
                continue;
            }
            break;
        }
        if (rtype != SSL3_CT_HANDSHAKE) return -1;

        hs_cursor c;
        cur_init(&c, recbuf, reclen);
        uint8_t hs_type = cur_u8(&c);
        uint32_t hs_len = cur_u24(&c);
        if (!c.ok) return -1;
        if (hs_type != SSL3_HS_CLIENT_HELLO) return -1;
        if (hs_len != cur_left(&c)) return -1;

        const uint8_t *body = c.p;
        hs_cursor b;
        cur_init(&b, body, hs_len);

        uint16_t client_version = cur_u16(&b);
        const uint8_t *crand = cur_take(&b, 32);
        if (crand == NULL) return -1;
        memcpy(ssl->client_random, crand, 32);

        const uint8_t *sid_len_p = cur_take(&b, 1);
        if (sid_len_p == NULL) return -1;
        size_t sid_len = *sid_len_p;
        const uint8_t *sid = cur_take(&b, sid_len);
        if (sid_len && sid == NULL) return -1;
        if (sid_len <= 32) {
            ssl->client_session_id_len = (uint8_t)sid_len;
            memcpy(ssl->client_session_id, sid, sid_len);
        } else {
            ssl->client_session_id_len = 0;
        }

        hs_cursor suites;
        if (cur_sub(&b, 2, &suites) < 0) return -1;
        if (suites.p[-2] | suites.p[-1]) {  }
        if ((cur_left(&suites) & 1) != 0) return -1;

        ssl->cipher.cipher_suite = 0;
        int scsv_seen = 0;
        while (cur_left(&suites) >= 2) {
            uint16_t suite = cur_u16(&suites);
            if (suite == 0x5600) {
                scsv_seen = 1;
                secure_renegotiation = 1;
                continue;
            }
            const ssl3_cipher_spec *spec = find_cipher(suite);
            if (!spec) continue;
            if (is_tls13(ssl->version) && !spec->is_tls13) continue;
            if (!is_tls13(ssl->version)) {
                if (spec->is_tls13) continue;
                if (is_ecdhe(suite) && !is_tls12(ssl->version)) continue;
            }
            ssl->cipher = *spec;
            break;
        }

        if (ssl->cipher.cipher_suite == 0) {
            uint8_t alert[2] = { SSL3_ALERT_FATAL, SSL3_ALERT_HANDSHAKE_FAILURE };
            ssl3_write_record(ssl, out_fd, SSL3_CT_ALERT, alert, 2);
            return -1;
        }
        if (scsv_seen && !is_tls13(ssl->version) && ssl->version > client_version) {
            uint8_t alert[2] = { SSL3_ALERT_FATAL, 86 };
            ssl3_write_record(ssl, out_fd, SSL3_CT_ALERT, alert, 2);
            return -1;
        }

        uint8_t comp_len = cur_u8(&b);
        if (comp_len == 0) return -1;
        for (uint8_t i = 0; i < comp_len; i++)
            if (cur_u8(&b) != 0) return -1;

        int want_hrr = 0;
        int offered_secp256r1 = 0;
        if (cur_left(&b) >= 2) {
            hs_cursor exts, ext;
            if (cur_sub(&b, 2, &exts) < 0) return -1;
            int saw_supported_versions = 0;
            while (cur_left(&exts) >= 4) {
                uint16_t ext_type = cur_u16(&exts);
                if (cur_sub(&exts, 2, &ext) < 0) return -1;

                if (ext_type == SSL3_EXT_SUPPORTED_VERSIONS) {
                    saw_supported_versions = 1;
                    if (!is_tls13(ssl->version)) continue;
                    if (cur_left(&ext) < 1) return -1;
                    uint8_t vlen = ext.p[0];
                    if (vlen < 2 || cur_left(&ext) != 1 + (size_t)vlen) return -1;
                    if ((vlen & 1) != 0) return -1;
                    int has_1_3 = 0;
                    for (size_t vi = 0; vi + 1 < vlen; vi += 2)
                        if (ext.p[1 + vi] == 0x03 && ext.p[1 + vi + 1] == 0x04)
                            has_1_3 = 1;
                    if (!has_1_3) {
                        ssl3_fatal(ssl, out_fd, SSL3_ALERT_PROTOCOL_VERSION);
                        return -1;
                    }
                } else if (ext_type == SSL3_EXT_SUPPORTED_GROUPS) {
                    while (cur_left(&ext) >= 2)
                        if (cur_u16(&ext) == SSL3_GROUP_SECP256R1) offered_secp256r1 = 1;
                } else if (ext_type == SSL3_EXT_KEY_SHARE) {
                    if (!is_tls13(ssl->version)) continue;
                    hs_cursor shares;
                    if (cur_sub(&ext, 2, &shares) < 0) return -1;
                    while (cur_left(&shares) >= 4) {
                        uint16_t group = cur_u16(&shares);
                        uint32_t klen = cur_u16(&shares);
                        const uint8_t *entry = cur_take(&shares, klen);
                        if (entry == NULL) return -1;
                        if (group == SSL3_GROUP_SECP256R1) {
                            if (klen != 65 || entry[0] != 0x04) {
                                ssl3_fatal(ssl, out_fd, SSL3_ALERT_ILLEGAL_PARAMETER);
                                return -1;
                            }
                            memcpy(ssl->ecdh_peer_pub, entry + 1, 64);
                            ssl->selected_group = SSL3_GROUP_SECP256R1;
                        }
                    }
                } else if (ext_type == SSL3_EXT_SERVER_NAME) {
                    if (cur_left(&ext) < 2) return -1;
                    size_t list_len = ((size_t)ext.p[0] << 8) | ext.p[1];
                    if (list_len == 0 || cur_left(&ext) != 2 + list_len) return -1;
                    size_t off = 2, stop = 2 + list_len;
                    while (off + 3 <= stop) {
                        uint8_t name_type = ext.p[off];
                        size_t name_len = ((size_t)ext.p[off + 1] << 8) | ext.p[off + 2];
                        off += 3;
                        if (off + name_len > stop) return -1;
                        if (name_type == 0) {
                            if (name_len == 0 || name_len >= sizeof ssl->server_name)
                                return -1;
                            memcpy(ssl->server_name, ext.p + off, name_len);
                            ssl->server_name[name_len] = 0;
                            ssl->server_name_len = name_len;
                        }
                        off += name_len;
                    }
                    if (off != stop) return -1;
                } else if (ext_type == SSL3_EXT_ALPN) {
                    if (cur_left(&ext) < 2) return -1;
                    uint16_t plen = ((uint16_t)ext.p[0] << 8) | ext.p[1];
                    if (cur_left(&ext) != 2 + (size_t)plen) return -1;
                    if (plen > 0 && plen <= sizeof ssl->peer_alpn_protos) {
                        memcpy(ssl->peer_alpn_protos, ext.p + 2, plen);
                        ssl->peer_alpn_protos_len = plen;
                    }
                } else if (ext_type == SSL3_EXT_EXTENDED_MASTER_SECRET) {
                    if (!is_tls13(ssl->version) && cur_left(&ext) == 0)
                        ssl->ems_negotiated = 1;
                } else if (ext_type == 0xff01) {
                    secure_renegotiation = 1;
                    if (cur_left(&ext) == 1) {
                        if (ext.p[0] != 0x00) return -1;
                    } else if (cur_left(&ext) != 0) {
                        return -1;
                    }
                }
            }
            if (!b.ok || !exts.ok) return -1;
            if (is_tls13(ssl->version)) {
                if (!saw_supported_versions) {
                    ssl3_fatal(ssl, out_fd, SSL3_ALERT_PROTOCOL_VERSION);
                    return -1;
                }
                if (ssl->selected_group == 0) {
                    if (offered_secp256r1 && ch_round == 0) {
                        want_hrr = 1;
                    } else {
                        ssl3_fatal(ssl, out_fd, SSL3_ALERT_HANDSHAKE_FAILURE);
                        return -1;
                    }
                }
            }
        } else if (is_tls13(ssl->version)) {
            ssl3_fatal(ssl, out_fd, SSL3_ALERT_DECODE_ERROR);
            return -1;
        }

        ssl3_hs_update_digest(ssl, SSL3_HS_CLIENT_HELLO, body, hs_len);
        ssl->state = SSL3_STATE_CLIENT_HELLO_SENT;

        if (want_hrr) {
            if (ssl3_hs_message_hash(ssl) < 0) return -1;
            uint8_t hrr[128];
            size_t hp = build_tls13_hello_retry_request(ssl, hrr);
            if (ssl3_write_handshake(ssl, out_fd, SSL3_HS_SERVER_HELLO, hrr, hp) < 0)
                return -1;
            ssl->hrr_done = 1;
            ssl->selected_group = 0;
            continue;
        }
        break;
    }

    if (!assl_rng_is_secure()) return -1;
    if (assl_rng_bytes_checked(ssl->server_random, SSL3_RANDOM_LEN)) return -1;

    if (is_tls13(ssl->version)) {
        uint8_t sh[256];
        size_t p = build_tls13_server_hello(ssl, sh);
        ssl3_write_handshake(ssl, out_fd, SSL3_HS_SERVER_HELLO, sh, p);
    } else {
        uint8_t sh[128];
        uint8_t ext[64];
        size_t e = 0;
        size_t p = 0;
        uint16_t rv = record_version(ssl->version);
        sh[p++] = (uint8_t)(rv >> 8); sh[p++] = (uint8_t)(rv & 0xFF);
        memcpy(sh + p, ssl->server_random, 32); p += 32;
        sh[p++] = 0;
        sh[p++] = (uint8_t)(ssl->cipher.cipher_suite >> 8);
        sh[p++] = (uint8_t)ssl->cipher.cipher_suite;
        sh[p++] = 0;

        if (secure_renegotiation) {
            ext[e++] = 0xff; ext[e++] = 0x01;
            ext[e++] = 0x00; ext[e++] = 0x01;
            ext[e++] = 0x00;
        }
        if (ssl->ems_negotiated) {
            ext[e++] = 0x00; ext[e++] = SSL3_EXT_EXTENDED_MASTER_SECRET;
            ext[e++] = 0x00; ext[e++] = 0x00;
        }
        size_t alpn_len = ssl3_select_alpn(ssl);
        if (alpn_len > 0) {
            ext[e++] = 0x00; ext[e++] = SSL3_EXT_ALPN;
            ext[e++] = 0x00; ext[e++] = (uint8_t)(3 + alpn_len);
            ext[e++] = 0x00; ext[e++] = (uint8_t)(1 + alpn_len);
            ext[e++] = (uint8_t)alpn_len;
            memcpy(ext + e, ssl->negotiated_alpn, alpn_len); e += alpn_len;
        }

        if (e > 0) {
            ssl3_put_ext_len(sh, &p, e);
            memcpy(sh + p, ext, e); p += e;
        }
        if (p > sizeof sh) return -1;
        ssl3_write_handshake(ssl, out_fd, SSL3_HS_SERVER_HELLO, sh, p);
    }
    ssl->state = SSL3_STATE_SERVER_HELLO_RECEIVED;

    if (is_tls13(ssl->version)) {
        tls13_derive_handshake_secrets(ssl);
        {
            uint8_t hs_key[32], hs_iv[16];
            tls13_derive_traffic_keys(ssl, ssl->server_handshake_traffic_secret, hs_key, hs_iv);
            memcpy(ssl->server_write_key, hs_key, ssl->cipher.key_len);
            memcpy(ssl->server_write_iv, hs_iv, ssl->cipher.iv_len);
            uint8_t chs_key[32], chs_iv[16];
            tls13_derive_traffic_keys(ssl, ssl->client_handshake_traffic_secret, chs_key, chs_iv);
            memcpy(ssl->client_write_key, chs_key, ssl->cipher.key_len);
            memcpy(ssl->client_write_iv, chs_iv, ssl->cipher.iv_len);
        }

        ssl3_write_change_cipher_spec(ssl, out_fd);
        ssl->write_cipher_active = 1;
        ssl->write_seq_num = 0;


        {
            uint8_t ee[128];
            size_t e = 2;
            size_t alpn_len = ssl3_select_alpn(ssl);
            if (alpn_len > 0) {
                ee[e++] = 0x00; ee[e++] = SSL3_EXT_ALPN;
                ee[e++] = 0x00; ee[e++] = (uint8_t)(3 + alpn_len);
                ee[e++] = 0x00; ee[e++] = (uint8_t)(1 + alpn_len);
                ee[e++] = (uint8_t)alpn_len;
                memcpy(ee + e, ssl->negotiated_alpn, alpn_len); e += alpn_len;
            }
            if (e > sizeof ee) return -1;
            size_t ext_bytes = e - 2;
            ee[0] = (uint8_t)(ext_bytes >> 8);
            ee[1] = (uint8_t)ext_bytes;
            ssl3_write_handshake(ssl, out_fd, SSL3_HS_ENCRYPTED_EXTENSIONS, ee, e);
        }

        if (ssl->have_cert && ssl->cert_der && ssl->cert_der_len > 0) {
            size_t cert_total = 1 + 3 + 3 + ssl->cert_der_len + 2;
            uint8_t *cert_msg = malloc(cert_total);
            if (!cert_msg) return -1;
            uint32_t cl = ssl->cert_der_len;
            cert_msg[0] = 0;                      
            size_t list_len = 3 + ssl->cert_der_len + 2;
            cert_msg[1] = (uint8_t)(list_len >> 16);
            cert_msg[2] = (uint8_t)(list_len >> 8);
            cert_msg[3] = (uint8_t)list_len;
            cert_msg[4] = (uint8_t)(cl >> 16);
            cert_msg[5] = (uint8_t)(cl >> 8);
            cert_msg[6] = (uint8_t)cl;
            memcpy(cert_msg + 7, ssl->cert_der, ssl->cert_der_len);
            cert_msg[7 + ssl->cert_der_len] = 0; 
            cert_msg[8 + ssl->cert_der_len] = 0;
            ssl3_write_handshake(ssl, out_fd, SSL3_HS_CERTIFICATE, cert_msg, cert_total);
            free(cert_msg);
            ssl->state = SSL3_STATE_CERTIFICATE_RECEIVED;
        }

        {
            uint8_t hash[64];
            assl_hash_one(ssl->cipher.prf_hash, ssl->hs_messages, ssl->hs_messages_len, hash);
            unsigned hlen = assl_hash_size(ssl->cipher.prf_hash);
            uint8_t content[64 + 36 + 1 + 64];
            size_t cp = 0;
            memset(content, 0x20, 64); cp += 64;
            const char *cv_label = "TLS 1.3, server CertificateVerify";
            memcpy(content + cp, cv_label, strlen(cv_label)); cp += strlen(cv_label);
            content[cp++] = 0;
            memcpy(content + cp, hash, hlen); cp += hlen;
            uint8_t digest[64];
            assl_hash_one(ssl->cipher.prf_hash, content, cp, digest);

            uint8_t cv[2 + 2 + 512];
            size_t siglen = 0;
            if (ssl->have_cert) {
                uint16_t scheme = 0x0804; 
                if (ssl->cipher.prf_hash == ASSL_H_SHA384) scheme = 0x0805;
                size_t ksz = assl_rsa_key_size(&ssl->rsa_key);
                uint8_t sig[512];
                assl_rsa_sign_pss(&ssl->rsa_key, ssl->cipher.prf_hash, digest, hlen, sig);
                cv[0] = (uint8_t)(scheme >> 8); cv[1] = (uint8_t)scheme;
                cv[2] = (uint8_t)(ksz >> 8); cv[3] = (uint8_t)ksz;
                memcpy(cv + 4, sig, ksz);
                siglen = 4 + ksz;
            }
            ssl3_write_handshake(ssl, out_fd, SSL3_HS_CERTIFICATE_VERIFY, cv, siglen);
        }

        {
            uint8_t verify_data[64];
            size_t vd_len = ssl3_compute_finished(ssl, "server finished", verify_data);
            ssl3_write_handshake(ssl, out_fd, SSL3_HS_FINISHED, verify_data, vd_len);
        }

        if (!ccs_seen && ssl3_expect_ccs(ssl, in_fd, recbuf, &reclen) < 0) return -1;
        ssl->read_cipher_active = 1;
        ssl->read_seq_num = 0;

        rtype = ssl3_read_dispatch(ssl, in_fd, recbuf, &reclen);
        if (rtype != SSL3_CT_HANDSHAKE) return -1;
        {
            uint8_t hs_type2 = recbuf[0];
            if (hs_type2 != SSL3_HS_FINISHED) return -1;
            uint8_t verify_data[64];
            size_t vd_len = ssl3_compute_finished(ssl, "client finished", verify_data);
            uint8_t cmpv = 0;
            for (size_t i = 0; i < vd_len; i++) cmpv |= recbuf[4 + i] ^ verify_data[i];
            if (cmpv) return -1;
        }

        tls13_derive_app_secrets(ssl);
        {
            uint8_t s_key[32], s_iv[16];
            tls13_derive_traffic_keys(ssl, ssl->server_application_traffic_secret, s_key, s_iv);
            memcpy(ssl->server_write_key, s_key, ssl->cipher.key_len);
            memcpy(ssl->server_write_iv, s_iv, ssl->cipher.iv_len);
            uint8_t c_key[32], c_iv[16];
            tls13_derive_traffic_keys(ssl, ssl->client_application_traffic_secret, c_key, c_iv);
            memcpy(ssl->client_write_key, c_key, ssl->cipher.key_len);
            memcpy(ssl->client_write_iv, c_iv, ssl->cipher.iv_len);
        }
        ssl->read_seq_num = 0;
        ssl->write_seq_num = 0;

        ssl->state = SSL3_STATE_CONNECTED;
        return 0;
    }

    if (!is_tls13(ssl->version) && ssl->have_cert && ssl->cert_der && ssl->cert_der_len > 0) {
        size_t cert_total = 3 + 3 + ssl->cert_der_len;
        uint8_t *cert_msg = malloc(cert_total);
        if (!cert_msg) return -1;
        uint32_t cl = (uint32_t)ssl->cert_der_len;
        uint32_t list_len = 3 + (uint32_t)ssl->cert_der_len;
        cert_msg[0] = (uint8_t)(list_len >> 16);
        cert_msg[1] = (uint8_t)(list_len >> 8);
        cert_msg[2] = (uint8_t)list_len;
        cert_msg[3] = (uint8_t)(cl >> 16);
        cert_msg[4] = (uint8_t)(cl >> 8);
        cert_msg[5] = (uint8_t)cl;
        memcpy(cert_msg + 6, ssl->cert_der, ssl->cert_der_len);
        ssl3_write_handshake(ssl, out_fd, SSL3_HS_CERTIFICATE, cert_msg, cert_total);
        free(cert_msg);
        ssl->state = SSL3_STATE_CERTIFICATE_RECEIVED;
    }

    if (is_tls12(ssl->version) && is_ecdhe(ssl->cipher.cipher_suite)) {
        if (assl_p256_keygen(ssl->ecdh_priv, ssl->ecdh_local_pub) < 0) return -1;
        uint8_t params[69];
        params[0] = 0x03;      
        params[1] = 0x00; params[2] = 0x17; 
        params[3] = 0x41;      
        params[4] = 0x04;      
        memcpy(params + 5, ssl->ecdh_local_pub, 64);

        uint8_t signed_data[32 + 32 + 69];
        memcpy(signed_data, ssl->client_random, 32);
        memcpy(signed_data + 32, ssl->server_random, 32);
        memcpy(signed_data + 64, params, 69);
        uint8_t digest[32];
        assl_hash_one(ASSL_H_SHA256, signed_data, sizeof signed_data, digest);
        uint8_t sig[512];
        if (assl_rsa_sign(&ssl->rsa_key, ASSL_H_SHA256, digest, sig) < 0) return -1;
        size_t sig_len = assl_rsa_key_size(&ssl->rsa_key);
        if (sig_len > 0xFFFF) return -1;

        size_t ske_len = 69 + 2 + 2 + sig_len;
        uint8_t *ske = malloc(ske_len);
        if (!ske) return -1;
        memcpy(ske, params, 69);
        ske[69] = 0x04; ske[70] = 0x01; 
        ske[71] = (uint8_t)(sig_len >> 8);
        ske[72] = (uint8_t)(sig_len & 0xFF);
        memcpy(ske + 73, sig, sig_len);
        ssl3_write_handshake(ssl, out_fd, SSL3_HS_SERVER_KEY_EXCHANGE, ske, ske_len);
        free(ske);
    }

    if (!is_tls13(ssl->version)) {
        ssl3_write_handshake(ssl, out_fd, SSL3_HS_SERVER_DONE, NULL, 0);
        ssl->state = SSL3_STATE_KEY_EXCHANGE_DONE;
    }

    {
        rtype = ssl3_read_dispatch(ssl, in_fd, recbuf, &reclen);
        if (rtype != SSL3_CT_HANDSHAKE) return -1;
        uint8_t hs_type = recbuf[0];
        size_t hs_len = ((size_t)recbuf[1] << 16) | ((size_t)recbuf[2] << 8) | recbuf[3];
        if (hs_type != SSL3_HS_CLIENT_KEY_EXCHANGE) return -1;

        uint8_t pre_master_secret[256];
        size_t pms_len = 0;
        if (is_tls12(ssl->version) && is_ecdhe(ssl->cipher.cipher_suite)) {
            if (hs_len < 2) return -1;
            uint8_t pt_len = recbuf[4];
            if (pt_len != hs_len - 1 || pt_len != 65) return -1;
            if (recbuf[5] != 0x04) return -1;
            memcpy(ssl->ecdh_peer_pub, recbuf + 6, 64);
            uint8_t shared[32];
            if (assl_p256_ecdh(ssl->ecdh_priv, ssl->ecdh_peer_pub, shared) < 0) return -1;
            memcpy(pre_master_secret, shared, 32);
            pms_len = 32;
        } else if (ssl->have_cert) {
            if (hs_len < 3) return -1;
            size_t ek_len = ((size_t)recbuf[4] << 8) | recbuf[5];
            int rc = -1;
            if (ek_len == hs_len - 2)
                rc = assl_rsa_decrypt(&ssl->rsa_key, recbuf + 6, ek_len,
                                      pre_master_secret, sizeof pre_master_secret,
                                      &pms_len);
            if (rc == 0) {
                uint8_t v_ok = ct_eq_u8(pre_master_secret[0], (uint8_t)(ssl->version >> 8)) &
                               ct_eq_u8(pre_master_secret[1], (uint8_t)ssl->version);
                uint8_t len_ok = ct_eq_u8((uint8_t)pms_len, 48);
                if ((v_ok & len_ok) != 0xFF) rc = -1;
            }
            if (rc < 0) {
                if (ssl3_generate_pre_master_secret(ssl, pre_master_secret, &pms_len) < 0)
                    return -1;
            }
        } else {
            return -1;
        }

        ssl3_hs_update_digest(ssl, SSL3_HS_CLIENT_KEY_EXCHANGE, recbuf + 4, hs_len);

        ssl3_compute_master_secret(ssl, pre_master_secret, pms_len);
        ssl3_derive_keys(ssl);
        if (ssl->cipher.key_len > 0 && !ssl->cipher.is_stream && !ssl->cipher.is_aead) {
            assl_aes_setkey_enc(&ssl->write_ctx, ssl->server_write_key,
                                ssl->cipher.key_len * 8);
            assl_aes_setkey_dec(&ssl->read_ctx, ssl->client_write_key,
                                ssl->cipher.key_len * 8);
            memcpy(ssl->write_iv_current, ssl->server_write_iv, ssl->cipher.iv_len);
            memcpy(ssl->read_iv_current, ssl->client_write_iv, ssl->cipher.iv_len);
        }
    }

    {
        if (ssl3_expect_ccs(ssl, in_fd, recbuf, &reclen) < 0) return -1;
        ssl->read_cipher_active = 1;
    }

    {
        rtype = ssl3_read_dispatch(ssl, in_fd, recbuf, &reclen);
        if (rtype != SSL3_CT_HANDSHAKE) return -1;
        uint8_t hs_type = recbuf[0];
        size_t hs_len = ((size_t)recbuf[1] << 16) | ((size_t)recbuf[2] << 8) | recbuf[3];
        if (hs_type != SSL3_HS_FINISHED) return -1;

        uint8_t verify_data[64];
        size_t vd_len = ssl3_compute_finished(ssl, "client finished", verify_data);
        uint8_t cmpv = 0;
        for (size_t i = 0; i < vd_len; i++) cmpv |= recbuf[4 + i] ^ verify_data[i];
        if (cmpv) return -1;
        ssl3_hs_update_digest(ssl, SSL3_HS_FINISHED, recbuf + 4, hs_len);
    }

    ssl3_write_change_cipher_spec(ssl, out_fd);
    ssl->write_cipher_active = 1;

    {
        uint8_t verify_data[64];
        size_t vd_len = ssl3_compute_finished(ssl, "server finished", verify_data);
        ssl3_write_handshake(ssl, out_fd, SSL3_HS_FINISHED, verify_data, vd_len);
    }

    ssl->state = SSL3_STATE_CONNECTED;
    return 0;
}

static int tls13_cv_hash_for_scheme(uint16_t scheme, assl_hash_t *h, int *pss) {
    switch (scheme) {
        case 0x0804: *h = ASSL_H_SHA256; *pss = 1; return 0;
        case 0x0805: *h = ASSL_H_SHA384; *pss = 1; return 0;
        case 0x0806: *h = ASSL_H_SHA512; *pss = 1; return 0;
        case 0x0401: *h = ASSL_H_SHA256; *pss = 0; return 0;
        case 0x0501: *h = ASSL_H_SHA384; *pss = 0; return 0;
        case 0x0601: *h = ASSL_H_SHA512; *pss = 0; return 0;
        default: return -1;
    }
}

static int tls13_verify_certificate_verify(assl_ssl *ssl, int out_fd,
                                           const uint8_t *msg, size_t msg_len) {
    if (!ssl->have_peer_key) {
        ssl3_fatal(ssl, out_fd, SSL3_ALERT_UNEXPECTED_MSG);
        return -1;
    }
    if (msg_len < 4) {
        ssl3_fatal(ssl, out_fd, SSL3_ALERT_DECODE_ERROR);
        return -1;
    }
    uint16_t scheme = ((uint16_t)msg[0] << 8) | msg[1];
    size_t sig_len = ((size_t)msg[2] << 8) | msg[3];
    if (sig_len != msg_len - 4) {
        ssl3_fatal(ssl, out_fd, SSL3_ALERT_DECODE_ERROR);
        return -1;
    }
    const uint8_t *sig = msg + 4;

    assl_hash_t hash;
    int pss;
    if (tls13_cv_hash_for_scheme(scheme, &hash, &pss) != 0) {
        ssl3_fatal(ssl, out_fd, SSL3_ALERT_ILLEGAL_PARAMETER);
        return -1;
    }
    unsigned hlen = assl_hash_size(hash);
    if (hlen == 0 || hlen > 64) return -1;

    uint8_t transcript[64];
    assl_hash_one(hash, ssl->hs_messages, ssl->hs_messages_len, transcript);

    static const char ctx[] = "TLS 1.3, server CertificateVerify";
    uint8_t content[64 + sizeof(ctx) + 1 + 64];
    size_t cp = 0;
    memset(content, 0x20, 64); cp = 64;
    memcpy(content + cp, ctx, sizeof(ctx) - 1); cp += sizeof(ctx) - 1;
    content[cp++] = 0x00;
    memcpy(content + cp, transcript, hlen); cp += hlen;

    uint8_t digest[64];
    assl_hash_one(hash, content, cp, digest);

    int ok;
    if (pss)
        ok = assl_rsa_verify_pss(&ssl->peer_rsa_key, hash, digest, hlen, sig, sig_len);
    else
        ok = assl_rsa_verify(&ssl->peer_rsa_key, hash, digest, sig, sig_len);
    if (ok < 0) {
        ssl3_fatal(ssl, out_fd, SSL3_ALERT_DECRYPT_ERROR);
        return -1;
    }
    return 0;
}

static int ssl3_client_handshake(assl_ssl *ssl, int in_fd, int out_fd) {
    uint8_t recbuf[SSL3_MAX_RECORD_LEN + 256];
    size_t reclen;
    int rtype;

    if (!assl_rng_is_secure()) return -1;
    if (assl_rng_bytes_checked(ssl->client_random, SSL3_RANDOM_LEN)) return -1;

    if (is_tls13(ssl->version)) {
        uint8_t ch[512];
        size_t p = build_tls13_client_hello(ssl, ch);
        if (ssl3_write_handshake(ssl, out_fd, SSL3_HS_CLIENT_HELLO, ch, p) < 0) return -1;
    } else {
        uint8_t ch[2 + 32 + 1 + 2 + 24 + 1 + 1 + 2 + 512];
        size_t p = 0;
        uint16_t rv = record_version(ssl->version);
        ch[p++] = (uint8_t)(rv >> 8); ch[p++] = (uint8_t)(rv & 0xFF);
        memcpy(ch + p, ssl->client_random, 32); p += 32;
        ch[p++] = 0;

        uint8_t suite_buf[24];
        size_t ns = 0;
        ssl->client_suites_count = 0;
        if (is_tls12(ssl->version)) {
            static const uint16_t tls12_suites[] = {
                TLS12_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS12_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS12_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            };
            for (size_t i = 0; i < sizeof tls12_suites / sizeof tls12_suites[0]; i++) {
                suite_buf[ns++] = (uint8_t)(tls12_suites[i] >> 8);
                suite_buf[ns++] = (uint8_t)tls12_suites[i];
                if (ssl->client_suites_count < sizeof(ssl->client_suites)/sizeof(ssl->client_suites[0]))
                    ssl->client_suites[ssl->client_suites_count++] = tls12_suites[i];
            }
        } else {
            static const uint16_t ssl3_suites[] = {
                SSL3_CK_RSA_WITH_AES_128_CBC_SHA,
                SSL3_CK_RSA_WITH_AES_256_CBC_SHA,
            };
            for (size_t i = 0; i < sizeof ssl3_suites / sizeof ssl3_suites[0]; i++) {
                suite_buf[ns++] = (uint8_t)(ssl3_suites[i] >> 8);
                suite_buf[ns++] = (uint8_t)ssl3_suites[i];
                if (ssl->client_suites_count < sizeof(ssl->client_suites)/sizeof(ssl->client_suites[0]))
                    ssl->client_suites[ssl->client_suites_count++] = ssl3_suites[i];
            }
        }
        ch[p++] = (uint8_t)(ns >> 8);
        ch[p++] = (uint8_t)ns;
        memcpy(ch + p, suite_buf, ns); p += ns;

        ch[p++] = 1; ch[p++] = 0;

        uint8_t ext[512];
        size_t e = 0;
        if (is_tls12(ssl->version)) {
            ext[e++] = 0x00; ext[e++] = 0x0d;
            ext[e++] = 0x00; ext[e++] = 0x08;
            ext[e++] = 0x00; ext[e++] = 0x06;
            ext[e++] = 0x04; ext[e++] = 0x01;
            ext[e++] = 0x05; ext[e++] = 0x01;
            ext[e++] = 0x06; ext[e++] = 0x01;
            ext[e++] = 0x00; ext[e++] = 0x0a;
            ext[e++] = 0x00; ext[e++] = 0x04;
            ext[e++] = 0x00; ext[e++] = 0x02;
            ext[e++] = (uint8_t)(SSL3_GROUP_SECP256R1 >> 8);
            ext[e++] = (uint8_t)SSL3_GROUP_SECP256R1;
            ext[e++] = 0x00; ext[e++] = 0x0b;
            ext[e++] = 0x00; ext[e++] = 0x02;
            ext[e++] = 0x01;
            ext[e++] = 0x00;
        }
        e = ssl3_append_common_extensions(ssl, ext, e, sizeof ext);
        if (e == 0) return -1;

        ssl3_put_ext_len(ch, &p, e);
        memcpy(ch + p, ext, e); p += e;

        if (p > sizeof ch) return -1;
        if (ssl3_write_handshake(ssl, out_fd, SSL3_HS_CLIENT_HELLO, ch, p) < 0) return -1;
    }
    ssl->state = SSL3_STATE_CLIENT_HELLO_SENT;

    int ccs_seen = 0;
    for (int hrr_count = 0; ; hrr_count++) {
        rtype = ssl3_read_dispatch(ssl, in_fd, recbuf, &reclen);
        if (rtype != SSL3_CT_HANDSHAKE && rtype != SSL3_CT_CHANGE_CIPHER_SPEC)
            return -1;
        if (rtype == SSL3_CT_CHANGE_CIPHER_SPEC) {
            if (reclen != 1 || recbuf[0] != 1) return -1;
            ccs_seen = 1;
            continue;
        }
        uint8_t hs_type = recbuf[0];
        size_t hs_len = ((size_t)recbuf[1] << 16) | ((size_t)recbuf[2] << 8) | recbuf[3];
        if (hs_type != SSL3_HS_SERVER_HELLO) return -1;
        const uint8_t *p = recbuf + 4;
        uint16_t sh_legacy_version = ((uint16_t)p[0] << 8) | p[1];
        p += 2;
        memcpy(ssl->server_random, p, 32); p += 32;
        uint8_t sid_len = *p++; p += sid_len;
        uint16_t chosen_suite = ((uint16_t)p[0] << 8) | p[1];
        const ssl3_cipher_spec *chosen_cipher = find_cipher(chosen_suite);
        if (!chosen_cipher) return -1;
        {
            int found = 0;
            for (size_t i = 0; i < ssl->client_suites_count; i++) {
                if (ssl->client_suites[i] == chosen_suite) { found = 1; break; }
            }
            if (!found) return -1;
        }
        ssl->cipher = *chosen_cipher;
        p += 2;
        p += 1;

        if (!is_tls13(ssl->version)) {
            const uint8_t *sh_end = recbuf + 4 + hs_len;
            if (p + 2 <= sh_end) {
                size_t ext_total = ((size_t)p[0] << 8) | p[1];
                const uint8_t *q = p + 2;
                const uint8_t *q_end = q + ext_total;
                if (q_end > sh_end) q_end = sh_end;
                int saw_ems = 0;
                while (q + 4 <= q_end) {
                    uint16_t ext_type = ((uint16_t)q[0] << 8) | q[1];
                    size_t ext_len = ((size_t)q[2] << 8) | q[3];
                    q += 4;
                    if (q + ext_len > q_end) break;
                    if (ext_type == SSL3_EXT_EXTENDED_MASTER_SECRET && ext_len == 0) {
                        saw_ems = 1;
                    } else if (ext_type == SSL3_EXT_ALPN && ext_len >= 3) {
                        size_t plen = q[2];
                        if (plen > 0 && 3 + plen == ext_len &&
                            plen < sizeof ssl->negotiated_alpn) {
                            memcpy(ssl->negotiated_alpn, q + 3, plen);
                            ssl->negotiated_alpn[plen] = 0;
                            ssl->negotiated_alpn_len = plen;
                        }
                    }
                    q += ext_len;
                }
                if (ssl->ems_offered) {
                    if (!saw_ems) {
                        ssl3_fatal(ssl, out_fd, SSL3_ALERT_INSUFFICIENT_SECURITY);
                        return -1;
                    }
                    ssl->ems_negotiated = 1;
                }
            }
        }

        if (is_tls13(ssl->version) && tls13_is_hello_retry_request(ssl)) {
            if (hrr_count != 0) return -1;
            if (sh_legacy_version != TLS12_VERSION) return -1;
            if (sid_len != ssl->client_session_id_len) return -1;
            if (sid_len && memcmp(p - sid_len, ssl->client_session_id, sid_len) != 0)
                return -1;

            uint16_t selected_group = 0;
            int saw_supported_versions = 0;
            if (p + 2 > recbuf + 4 + hs_len) return -1;
            uint16_t ext_total = ((uint16_t)p[0] << 8) | p[1];
            const uint8_t *q = p + 2;
            const uint8_t *q_end = q + ext_total;
            if (q_end > recbuf + 4 + hs_len) return -1;
            while (q + 4 <= q_end) {
                uint16_t ext_type = ((uint16_t)q[0] << 8) | q[1];
                uint16_t ext_len = ((uint16_t)q[2] << 8) | q[3];
                q += 4;
                if (q + ext_len > q_end) return -1;
                if (ext_type == 0x002b && ext_len == 2) {
                    if ((((uint16_t)q[0] << 8) | q[1]) != TLS13_VERSION) return -1;
                    saw_supported_versions = 1;
                } else if (ext_type == 0x0033 && ext_len == 2) {
                    selected_group = ((uint16_t)q[0] << 8) | q[1];
                }
                q += ext_len;
            }
            if (!saw_supported_versions) return -1;
            if (selected_group != 0x0017) return -1;

            if (ssl3_hs_message_hash(ssl) < 0) return -1;
            ssl3_hs_update_digest(ssl, SSL3_HS_SERVER_HELLO, recbuf + 4, hs_len);

            uint8_t ch2[512];
            size_t p2 = build_tls13_client_hello(ssl, ch2);
            if (p2 > sizeof ch2) return -1;
            if (ssl3_write_handshake(ssl, out_fd, SSL3_HS_CLIENT_HELLO, ch2, p2) < 0)
                return -1;
            continue;
        }

            uint16_t negotiated_version = sh_legacy_version;
                if (is_tls13(ssl->version) && p < recbuf + 4 + hs_len) {
                uint16_t ext_total = ((uint16_t)p[0] << 8) | p[1]; p += 2;
                const uint8_t *ext_end = p + ext_total;
                while (p + 4 <= ext_end) {
                uint16_t ext_type = ((uint16_t)p[0] << 8) | p[1];
                uint16_t ext_len = ((uint16_t)p[2] << 8) | p[3];
                p += 4;
                if (ext_type == 0x002b && ext_len == 2 && p + 2 <= ext_end) {
                    negotiated_version = ((uint16_t)p[0] << 8) | p[1];
                } else if (ext_type == 0x0033 && ext_len >= 4) {
                    uint16_t ks_group = ((uint16_t)p[0] << 8) | p[1];
                    uint16_t ks_len = ((uint16_t)p[2] << 8) | p[3];
                    if (ks_group == 0x0017 && ks_len == 65 && p[4] == 0x04) {
                            memcpy(ssl->ecdh_peer_pub, p + 5, 64);
                        }
                }
                p += ext_len;
            }

            if (negotiated_version < TLS13_VERSION) {
                static const uint8_t sentinel_tls12[8] = {0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01};
                static const uint8_t sentinel_older[8] = {0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00};
                if (is_tls13(ssl->version)) {
                    if (memcmp(ssl->server_random + 24, sentinel_tls12, 8) == 0 ||
                        memcmp(ssl->server_random + 24, sentinel_older, 8) == 0)
                        return -1;
                } else if (negotiated_version <= TLS11_VERSION) {
                    if (memcmp(ssl->server_random + 24, sentinel_older, 8) == 0)
                        return -1;
                }
            }
            uint8_t shared[32];
            assl_p256_ecdh(ssl->ecdh_priv, ssl->ecdh_peer_pub, shared);
            memcpy(ssl->master_secret, shared, 32);
        }
        ssl3_hs_update_digest(ssl, SSL3_HS_SERVER_HELLO, recbuf + 4, hs_len);
        ssl->state = SSL3_STATE_SERVER_HELLO_RECEIVED;
        break;
    }

    if (is_tls13(ssl->version)) {
        tls13_derive_handshake_secrets(ssl);

        {
            uint8_t chs_key[32], chs_iv[16];
            tls13_derive_traffic_keys(ssl, ssl->client_handshake_traffic_secret, chs_key, chs_iv);
            memcpy(ssl->client_write_key, chs_key, ssl->cipher.key_len);
            memcpy(ssl->client_write_iv, chs_iv, ssl->cipher.iv_len);
            uint8_t shs_key[32], shs_iv[16];
            tls13_derive_traffic_keys(ssl, ssl->server_handshake_traffic_secret, shs_key, shs_iv);
            memcpy(ssl->server_write_key, shs_key, ssl->cipher.key_len);
            memcpy(ssl->server_write_iv, shs_iv, ssl->cipher.iv_len);
        }

        if (!ccs_seen && ssl3_expect_ccs(ssl, in_fd, recbuf, &reclen) < 0)
            return -1;
        ssl->read_cipher_active = 1;
        ssl->read_seq_num = 0;

        {
            rtype = ssl3_read_dispatch(ssl, in_fd, recbuf, &reclen);
            if (rtype != SSL3_CT_HANDSHAKE) return -1;
            size_t ee_len = ((size_t)recbuf[1] << 16) | ((size_t)recbuf[2] << 8) | recbuf[3];
            ssl3_hs_update_digest(ssl, SSL3_HS_ENCRYPTED_EXTENSIONS, recbuf + 4, ee_len);

            if (ssl->alpn_protos_len > 0 && ee_len >= 2) {
                size_t ext_total = ((size_t)recbuf[4] << 8) | recbuf[5];
                const uint8_t *q = recbuf + 6;
                const uint8_t *q_end = q + ext_total;
                const uint8_t *ee_end = recbuf + 4 + ee_len;
                if (q_end > ee_end) q_end = ee_end;
                while (q + 4 <= q_end) {
                    uint16_t ext_type = ((uint16_t)q[0] << 8) | q[1];
                    size_t ext_len = ((size_t)q[2] << 8) | q[3];
                    q += 4;
                    if (q + ext_len > q_end) break;
                    if (ext_type == SSL3_EXT_ALPN && ext_len >= 3) {
                        size_t plen = q[2];
                        if (plen > 0 && 3 + plen == ext_len &&
                            plen < sizeof ssl->negotiated_alpn) {
                            memcpy(ssl->negotiated_alpn, q + 3, plen);
                            ssl->negotiated_alpn[plen] = 0;
                            ssl->negotiated_alpn_len = plen;
                        }
                    }
                    q += ext_len;
                }
            }
        }

        {
            rtype = ssl3_read_dispatch(ssl, in_fd, recbuf, &reclen);
            if (rtype != SSL3_CT_HANDSHAKE) return -1;
            uint8_t hs_t = recbuf[0];
            size_t hs_l = ((size_t)recbuf[1] << 16) | ((size_t)recbuf[2] << 8) | recbuf[3];
            if (hs_t != SSL3_HS_CERTIFICATE) return -1;
            ssl3_hs_update_digest(ssl, SSL3_HS_CERTIFICATE, recbuf + 4, hs_l);

            hs_cursor cc;
            cur_init(&cc, recbuf + 4, hs_l);
            hs_cursor list;
            cur_init(&list, NULL, 0);
            cur_skip_vec(&cc, 1);
            if (cur_sub(&cc, 3, &list) < 0) cc.ok = 0;

            const uint8_t *pieces[ASSL_X509_MAX_CHAIN];
            size_t plen[ASSL_X509_MAX_CHAIN];
            size_t cnt = 0;
            while (list.ok && cur_left(&list) >= 3 && cnt < ASSL_X509_MAX_CHAIN) {
                hs_cursor certdata;
                if (cur_sub(&list, 3, &certdata) < 0) break;
                size_t cert_len = cur_left(&certdata);
                if (cert_len == 0) break;
                const uint8_t *cert_der = cur_take(&certdata, cert_len);
                assl_x509_cert pc;
                if (assl_x509_parse(&pc, cert_der, cert_len) == 0) {
                    if (pc.pk_algo == ASSL_X509_PK_RSA && !ssl->have_peer_key) {
                        if (assl_rsa_set_key(&ssl->peer_rsa_key,
                                             &pc.pubkey.n, &pc.pubkey.e,
                                             NULL, NULL, NULL, NULL, NULL, NULL) == 0)
                            ssl->have_peer_key = 1;
                    }
                    assl_x509_free(&pc);
                    if (ssl->verify_peer) {
                        pieces[cnt] = cert_der;
                        plen[cnt] = cert_len;
                        cnt++;
                    }
                }
                cur_skip_vec(&list, 2);
                if (!list.ok) break;
            }
            if (!cc.ok || !list.ok || cur_left(&list) != 0) {
                uint8_t alert[2] = { SSL3_ALERT_FATAL, SSL3_ALERT_DECODE_ERROR };
                ssl3_write_encrypted_record(ssl, out_fd, SSL3_CT_ALERT, alert, 2);
                return -1;
            }
            if (ssl->verify_peer && cnt > 0) {
                if (assl_x509_verify_chain(pieces, plen, cnt,
                                           &ssl->trust_store,
                                           ssl->verify_hostname_len
                                               ? ssl->verify_hostname
                                               : NULL,
                                           -1) < 0) {
                    uint8_t alert[2] = { SSL3_ALERT_FATAL, SSL3_ALERT_HANDSHAKE_FAILURE };
                    ssl3_write_encrypted_record(ssl, out_fd, SSL3_CT_ALERT, alert, 2);
                    return -1;
                }
            }
        }

        {
            rtype = ssl3_read_dispatch(ssl, in_fd, recbuf, &reclen);
            if (rtype != SSL3_CT_HANDSHAKE) return -1;
            uint8_t cv_type = recbuf[0];
            size_t cv_len = ((size_t)recbuf[1] << 16) | ((size_t)recbuf[2] << 8) | recbuf[3];
            if (cv_type != SSL3_HS_CERTIFICATE_VERIFY) {
                ssl3_fatal(ssl, out_fd, SSL3_ALERT_UNEXPECTED_MSG);
                return -1;
            }
            if (4 + cv_len > reclen) {
                ssl3_fatal(ssl, out_fd, SSL3_ALERT_DECODE_ERROR);
                return -1;
            }
            if (tls13_verify_certificate_verify(ssl, out_fd, recbuf + 4, cv_len) < 0)
                return -1;
            ssl3_hs_update_digest(ssl, SSL3_HS_CERTIFICATE_VERIFY, recbuf + 4, cv_len);
        }

        rtype = ssl3_read_dispatch(ssl, in_fd, recbuf, &reclen);
        if (rtype != SSL3_CT_HANDSHAKE) return -1;
        {
            uint8_t hs_type2 = recbuf[0];
            size_t hs_len2 = ((size_t)recbuf[1] << 16) | ((size_t)recbuf[2] << 8) | recbuf[3];
            if (hs_type2 != SSL3_HS_FINISHED) return -1;
            uint8_t expected[64];
            size_t vd_len = ssl3_compute_finished(ssl, "server finished", expected);
            uint8_t cmpv = 0;
        for (size_t i = 0; i < vd_len; i++) cmpv |= recbuf[4 + i] ^ expected[i];
        if (cmpv) return -1;
            ssl3_hs_update_digest(ssl, SSL3_HS_FINISHED, recbuf + 4, hs_len2);
        }

        tls13_derive_app_secrets(ssl);

        ssl3_write_change_cipher_spec(ssl, out_fd);
        ssl->write_cipher_active = 1;
        ssl->write_seq_num = 0;

        {
            uint8_t verify_data[64];
            size_t vd_len2 = ssl3_compute_finished(ssl, "client finished", verify_data);
            ssl3_write_handshake(ssl, out_fd, SSL3_HS_FINISHED, verify_data, vd_len2);
        }

        {
            uint8_t c_key[32], c_iv[16];
            tls13_derive_traffic_keys(ssl, ssl->client_application_traffic_secret, c_key, c_iv);
            memcpy(ssl->client_write_key, c_key, ssl->cipher.key_len);
            memcpy(ssl->client_write_iv, c_iv, ssl->cipher.iv_len);
            uint8_t s_key[32], s_iv[16];
            tls13_derive_traffic_keys(ssl, ssl->server_application_traffic_secret, s_key, s_iv);
            memcpy(ssl->server_write_key, s_key, ssl->cipher.key_len);
            memcpy(ssl->server_write_iv, s_iv, ssl->cipher.iv_len);
        }
        ssl->write_cipher_active = 1;
        ssl->write_seq_num = 0;
        ssl->read_seq_num = 0;

        ssl->state = SSL3_STATE_CONNECTED;
        return 0;
    }

    if (!is_tls13(ssl->version)) {
        rtype = ssl3_read_dispatch(ssl, in_fd, recbuf, &reclen);
        if (rtype != SSL3_CT_HANDSHAKE) return -1;
        uint8_t hs_type_cert = recbuf[0];
        size_t hs_len_cert = ((size_t)recbuf[1] << 16) | ((size_t)recbuf[2] << 8) | recbuf[3];
        if (hs_type_cert != SSL3_HS_CERTIFICATE) return -1;
        ssl3_hs_update_digest(ssl, SSL3_HS_CERTIFICATE, recbuf + 4, hs_len_cert);
        ssl->state = SSL3_STATE_CERTIFICATE_RECEIVED;

        {
            hs_cursor cc;
            cur_init(&cc, recbuf + 4, hs_len_cert);
            hs_cursor list;
            cur_init(&list, NULL, 0);
            if (cur_sub(&cc, 3, &list) < 0) { cc.ok = 0; }

            const uint8_t *pieces[ASSL_X509_MAX_CHAIN];
            size_t plen[ASSL_X509_MAX_CHAIN];
            size_t cnt = 0;
            while (cc.ok && cur_left(&list) > 3 && cnt < ASSL_X509_MAX_CHAIN) {
                hs_cursor entry;
                if (cur_sub(&list, 3, &entry) < 0) break;
                size_t cert_len = cur_left(&entry);
                if (cert_len == 0) break;
                const uint8_t *cert_der = cur_take(&entry, cert_len);
                assl_x509_cert pc;
                if (assl_x509_parse(&pc, cert_der, cert_len) == 0) {
                    if (pc.pk_algo == ASSL_X509_PK_RSA && !ssl->have_peer_key) {
                        if (assl_rsa_set_key(&ssl->peer_rsa_key,
                                             &pc.pubkey.n,
                                             &pc.pubkey.e, NULL,
                                             NULL, NULL, NULL, NULL, NULL) == 0)
                            ssl->have_peer_key = 1;
                    }
                    assl_x509_free(&pc);
                    if (ssl->verify_peer) {
                        pieces[cnt] = cert_der;
                        plen[cnt] = cert_len;
                        cnt++;
                    }
                }
            }

            if (cc.ok && (!list.ok || cur_left(&list) != 0)) {
                uint8_t alert[2] = { SSL3_ALERT_FATAL, SSL3_ALERT_DECODE_ERROR };
                ssl3_write_encrypted_record(ssl, out_fd, SSL3_CT_ALERT, alert, 2);
                return -1;
            }

            if (ssl->verify_peer && cnt > 0) {
                if (assl_x509_verify_chain(pieces, plen, cnt,
                                           &ssl->trust_store,
                                           ssl->verify_hostname_len
                                               ? ssl->verify_hostname
                                               : NULL,
                                           -1) < 0) {
                    uint8_t alert[2] = { SSL3_ALERT_FATAL, SSL3_ALERT_HANDSHAKE_FAILURE };
                    ssl3_write_encrypted_record(ssl, out_fd, SSL3_CT_ALERT, alert, 2);
                    return -1;
                }
            }
        }

        rtype = ssl3_read_dispatch(ssl, in_fd, recbuf, &reclen);
        if (rtype != SSL3_CT_HANDSHAKE) return -1;
        uint8_t hs_type = recbuf[0];
        size_t hs_len = ((size_t)recbuf[1] << 16) | ((size_t)recbuf[2] << 8) | recbuf[3];

        if (is_tls12(ssl->version) && is_ecdhe(ssl->cipher.cipher_suite)) {
            if (hs_type != SSL3_HS_SERVER_KEY_EXCHANGE) return -1;
            const uint8_t *ske = recbuf + 4;
            if (hs_len < 69 + 2 + 2) return -1;
            if (ske[0] != 0x03) return -1;           
            if (ske[1] != 0x00 || ske[2] != 0x17) return -1; 
            if (ske[3] != 0x41 || ske[4] != 0x04) return -1; 
            memcpy(ssl->ecdh_peer_pub, ske + 5, 64);
            uint8_t halg = ske[69];
            uint8_t salg = ske[70];
            if (salg != 0x01 && salg != 0x03 && salg != 0x04) return -1;
            size_t sig_len = ((size_t)ske[71] << 8) | ske[72];
            if (sig_len < 64 || 69 + 2 + 2 + sig_len > hs_len) return -1;

            uint8_t signed_data[32 + 32 + 69];
            memcpy(signed_data, ssl->client_random, 32);
            memcpy(signed_data + 32, ssl->server_random, 32);
            memcpy(signed_data + 64, ske, 69);
            uint8_t digest[64];
            assl_hash_t hash = 0;
            switch (halg) {
                case 0x04: hash = ASSL_H_SHA256; break;
                case 0x05: hash = ASSL_H_SHA384; break;
                case 0x06: hash = ASSL_H_SHA512; break;
                default: return -1;
            }
            assl_hash_one(hash, signed_data, sizeof signed_data, digest);
            const assl_rsa_key *ske_key = ssl->have_peer_key
                                          ? &ssl->peer_rsa_key
                                          : &ssl->rsa_key;
            if (assl_rsa_verify(ske_key, hash, digest,
                                ske + 73, sig_len) < 0) {
                return -1;
            }
            ssl3_hs_update_digest(ssl, SSL3_HS_SERVER_KEY_EXCHANGE,
                                  recbuf + 4, hs_len);

            if (assl_p256_keygen(ssl->ecdh_priv, ssl->ecdh_local_pub) < 0) return -1;

            rtype = ssl3_read_dispatch(ssl, in_fd, recbuf, &reclen);
            if (rtype != SSL3_CT_HANDSHAKE) return -1;
            uint8_t hs_type2 = recbuf[0];
            size_t hs_len2 = ((size_t)recbuf[1] << 16) | ((size_t)recbuf[2] << 8) | recbuf[3];
            if (hs_type2 != SSL3_HS_SERVER_DONE) return -1;
            ssl3_hs_update_digest(ssl, SSL3_HS_SERVER_DONE, recbuf + 4, hs_len2);
        } else {
            if (hs_type != SSL3_HS_SERVER_DONE) return -1;
            ssl3_hs_update_digest(ssl, SSL3_HS_SERVER_DONE, recbuf + 4, hs_len);
        }
        ssl->state = SSL3_STATE_KEY_EXCHANGE_DONE;
    }

    {
        uint8_t pre_master_secret[48];
        size_t pms_len = 0;

        if (is_tls12(ssl->version) && is_ecdhe(ssl->cipher.cipher_suite)) {
            uint8_t *cke = malloc(66);
            if (!cke) return -1;
            cke[0] = 0x41;
            cke[1] = 0x04;
            memcpy(cke + 2, ssl->ecdh_local_pub, 64);
            ssl3_write_handshake(ssl, out_fd, SSL3_HS_CLIENT_KEY_EXCHANGE, cke, 66);
            free(cke);
            uint8_t shared[32];
            if (assl_p256_ecdh(ssl->ecdh_priv, ssl->ecdh_peer_pub, shared) < 0) return -1;
            memcpy(pre_master_secret, shared, 32);
            pms_len = 32;
        } else {
            if (ssl3_generate_pre_master_secret(ssl, pre_master_secret, &pms_len) < 0)
                return -1;
            uint8_t enc[256];
            if (ssl->have_peer_key) {
                int rc = assl_rsa_encrypt(&ssl->peer_rsa_key, pre_master_secret, pms_len, enc);
                if (rc < 0) return -1;
            } else if (ssl->have_cert) {
                int rc = assl_rsa_encrypt(&ssl->rsa_key, pre_master_secret, pms_len, enc);
                if (rc < 0) return -1;
            } else {
                return -1;
            }
            size_t enc_len = ssl->have_peer_key ? assl_rsa_key_size(&ssl->peer_rsa_key)
                                                : assl_rsa_key_size(&ssl->rsa_key);
            if (enc_len > 0xFFFF || enc_len < 6) return -1;
            uint8_t *cke = malloc(2 + enc_len);
            if (!cke) return -1;
            cke[0] = (uint8_t)(enc_len >> 8);
            cke[1] = (uint8_t)(enc_len & 0xFF);
            memcpy(cke + 2, enc, enc_len);
            ssl3_write_handshake(ssl, out_fd, SSL3_HS_CLIENT_KEY_EXCHANGE, cke, 2 + enc_len);
            free(cke);
        }
        ssl3_compute_master_secret(ssl, pre_master_secret, pms_len);
        ssl3_derive_keys(ssl);
        if (ssl->cipher.key_len > 0 && !ssl->cipher.is_stream && !ssl->cipher.is_aead) {
            assl_aes_setkey_enc(&ssl->write_ctx, ssl->client_write_key,
                                ssl->cipher.key_len * 8);
            assl_aes_setkey_dec(&ssl->read_ctx, ssl->server_write_key,
                                ssl->cipher.key_len * 8);
            memcpy(ssl->write_iv_current, ssl->client_write_iv, ssl->cipher.iv_len);
            memcpy(ssl->read_iv_current, ssl->server_write_iv, ssl->cipher.iv_len);
        }
    }

    ssl3_write_change_cipher_spec(ssl, out_fd);
    ssl->write_cipher_active = 1;

    {
        uint8_t verify_data[64];
        size_t vd_len = ssl3_compute_finished(ssl, "client finished", verify_data);
        ssl3_write_handshake(ssl, out_fd, SSL3_HS_FINISHED, verify_data, vd_len);
    }

    {
        if (ssl3_expect_ccs(ssl, in_fd, recbuf, &reclen) < 0) return -1;
        ssl->read_cipher_active = 1;
    }

    {
        rtype = ssl3_read_dispatch(ssl, in_fd, recbuf, &reclen);
        if (rtype != SSL3_CT_HANDSHAKE) return -1;
        uint8_t hs_type = recbuf[0];
        size_t hs_len = ((size_t)recbuf[1] << 16) | ((size_t)recbuf[2] << 8) | recbuf[3];
        if (hs_type != SSL3_HS_FINISHED) return -1;
        uint8_t expected[64];
        size_t vd_len = ssl3_compute_finished(ssl, "server finished", expected);
        uint8_t cmpv = 0;
        for (size_t i = 0; i < vd_len; i++) cmpv |= recbuf[4 + i] ^ expected[i];
        if (cmpv) return -1;
        ssl3_hs_update_digest(ssl, SSL3_HS_FINISHED, recbuf + 4, hs_len);
    }

    if (is_tls13(ssl->version)) {
        tls13_derive_app_secrets(ssl);
    }

    ssl->state = SSL3_STATE_CONNECTED;
    return 0;
}

int assl_ssl_handshake(assl_ssl *ssl, int in_fd, int out_fd) {
    if (ssl->is_client)
        return ssl3_client_handshake(ssl, in_fd, out_fd);
    else
        return ssl3_server_handshake(ssl, in_fd, out_fd);
}

int assl_ssl_key_update(assl_ssl *ssl, int fd, int request) {
    if (!ssl || !is_tls13(ssl->version)) return -1;
    if (ssl->state != SSL3_STATE_CONNECTED) return -1;
    if (ssl->write_seq_num == UINT64_MAX) return -1;
    uint8_t body = request ? 1 : 0;
    if (ssl3_write_handshake(ssl, fd, SSL3_HS_KEY_UPDATE, &body, 1) < 0) return -1;
    tls13_update_write_keys(ssl);
    return 0;
}

int assl_ssl_read(assl_ssl *ssl, int fd, void *buf, size_t len) {
    uint8_t recbuf[SSL3_MAX_RECORD_LEN + 256];

    if (len == 0) return 0;

    for (;;) {
        if (ssl->app_off < ssl->app_len) {
            size_t n = ssl->app_len - ssl->app_off;
            if (n > len) n = len;
            memcpy(buf, ssl->app_buf + ssl->app_off, n);
            ssl->app_off += n;
            if (ssl->app_off == ssl->app_len) ssl->app_len = ssl->app_off = 0;
            return (int)n;
        }

        size_t reclen = 0;
        int rtype = ssl3_read_encrypted_record(ssl, fd, recbuf, &reclen);
        if (rtype == SSL3_RECORD_EOF)
            return ssl->close_notify_received ? 0 : -1;
        if (rtype < 0) return -1;

        if (rtype == SSL3_CT_ALERT) {
            if (reclen < 2) return -1;
            uint8_t level = recbuf[0], desc = recbuf[1];
            if (desc == SSL3_ALERT_CLOSE_NOTIFY) {
                ssl->close_notify_received = 1;
                return level == SSL3_ALERT_WARNING ? 0 : -1;
            }
            if (level == SSL3_ALERT_FATAL) return -1;
            continue;
        }
        if (rtype == SSL3_CT_CHANGE_CIPHER_SPEC) continue;
        if (rtype == SSL3_CT_HANDSHAKE && is_tls13(ssl->version) &&
            recbuf[0] == SSL3_HS_KEY_UPDATE) {
            size_t ku_len = ((size_t)recbuf[1] << 16) | ((size_t)recbuf[2] << 8) | recbuf[3];
            if (ku_len != 1 || reclen < 5 || recbuf[4] > 1) return -1;
            tls13_update_read_keys(ssl);
            if (recbuf[4] == 1) {
                if (assl_ssl_key_update(ssl, fd, 0) < 0) return -1;
            }
            continue;
        }
        if (rtype == SSL3_CT_HANDSHAKE && is_tls13(ssl->version) &&
            recbuf[0] == SSL3_HS_NEW_SESSION_TICKET) {
            continue;
        }
        if (rtype == SSL3_CT_HANDSHAKE && is_tls13(ssl->version)) {
            ssl3_fatal(ssl, fd, SSL3_ALERT_UNEXPECTED_MSG);
            return -1;
        }
        if (rtype != SSL3_CT_APPLICATION_DATA) continue;

        if (reclen > SSL3_MAX_RECORD_LEN) return -1;
        if (reclen > len) {
            size_t keep = reclen - len;
            if (keep > sizeof ssl->app_buf) return -1;
            memcpy(ssl->app_buf, recbuf + len, keep);
            ssl->app_len = keep;
            ssl->app_off = 0;
            memcpy(buf, recbuf, len);
            return (int)len;
        }
        if (reclen == 0) continue;
        memcpy(buf, recbuf, reclen);
        return (int)reclen;
    }
}

int assl_ssl_write(assl_ssl *ssl, int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        size_t m = len - off;
        if (m > SSL3_MAX_RECORD_LEN) m = SSL3_MAX_RECORD_LEN;
        if (ssl3_write_encrypted_record(ssl, fd, SSL3_CT_APPLICATION_DATA,
                                        p + off, m) < 0)
            return -1;
        off += m;
    }
    return (int)len;
}

void assl_ssl_shutdown(assl_ssl *ssl, int fd) {
    uint8_t alert[2] = { SSL3_ALERT_WARNING, SSL3_ALERT_CLOSE_NOTIFY };
    ssl3_write_encrypted_record(ssl, fd, SSL3_CT_ALERT, alert, 2);
    (void)ssl;
}

uint16_t assl_ssl_get_cipher(const assl_ssl *ssl) {
    return ssl->cipher.cipher_suite;
}

uint16_t assl_ssl_get_version(const assl_ssl *ssl) {
    return ssl->version;
}
